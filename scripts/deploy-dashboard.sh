#!/usr/bin/env bash
# 대시보드 코드를 기존 대시보드 EC2 에 SSM 으로 제자리 배포한다(terraform apply 이후 단계). Git Bash 용.
#
# terraform apply 는 S3(deploy/dashboard.zip)만 갱신한다. 기존 대시보드 EC2 는 교체되지 않으므로
# (modules/compute/main.tf ignore_changes=[user_data], 수동 조치 이력이 서버 로컬 SQLite 에 있다),
# 이 스크립트가 서버에 zip 을 받아 풀고 dashboard.service 를 재시작한다.
#
# 하는 일: 계정 확인 -> 서버 찾기·SSM 확인 -> 사용자 확인 -> 서버에서 교체 -> /health·버전 확인 -> 실패 시 복구.
# 하지 않는 일: terraform plan/apply, /opt/dashboard/instance(SQLite) 변경, dashboard.env 변경, 서버 교체.
# 사전 조건: AWS CLI 설치, 계정 455958489281 에 대한 자격 증명, terraform apply 완료.
#
# 사용:  bash scripts/deploy-dashboard.sh [--rollback] [--yes] [--instance-id i-xxxx]
#                                          [--region eu-west-3] [--account 455958489281] [--prefix soar-sec-dev]
#   --rollback  직전 배포 전 코드(app-src.prev)로 되돌린다. 다시 실행하면 앞으로 되돌린다(서로 교체).
#   --yes       확인 질문 없이 진행한다.

set -uo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash 가 /opt/... 같은 인자를 Windows 경로로 바꾸지 않게 한다
export AWS_PAGER=""

REGION="eu-west-3"
ACCOUNT="455958489281"
PREFIX="soar-sec-dev"
INSTANCE_ID=""
ROLLBACK=0
YES=0

while [ $# -gt 0 ]; do
  case "$1" in
    --rollback) ROLLBACK=1 ;;
    --yes) YES=1 ;;
    --instance-id) INSTANCE_ID="${2:-}"; shift ;;
    --region) REGION="${2:-}"; shift ;;
    --account) ACCOUNT="${2:-}"; shift ;;
    --prefix) PREFIX="${2:-}"; shift ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "알 수 없는 옵션: $1" >&2; exit 1 ;;
  esac
  shift
done

step() { printf '\n== %s\n' "$1"; }
die() { printf '중단: %s\n' "$1" >&2; exit 1; }

# aws 를 실행하고 출력을 돌려준다(Windows 의 \r 제거). 실패하면 중단한다.
aws_run() {
  local out code
  out=$(aws "$@" 2>&1); code=$?
  out=$(printf '%s' "$out" | tr -d '\r')
  if [ $code -ne 0 ]; then die "aws $1 $2 실패: $out"; fi
  printf '%s' "$out"
}

# ── 0. 준비 ─────────────────────────────────────────────
step "0. 준비"
command -v aws >/dev/null 2>&1 || die "aws 명령을 찾을 수 없습니다. AWS CLI 를 설치하고 Git Bash 를 다시 여세요."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INDEX_HTML="$REPO_ROOT/dashboard/frontend/templates/index.html"
EXPECTED_CSS=""
if [ -f "$INDEX_HTML" ]; then
  EXPECTED_CSS=$(grep -o 'local\.css?v=[^"]*' "$INDEX_HTML" | head -1 | tr -d '\r')
fi
if [ $ROLLBACK -eq 1 ]; then
  echo "모드: 이전 코드로 되돌리기(--rollback)"
elif [ -n "$EXPECTED_CSS" ]; then
  echo "이 저장소의 기대 버전: $EXPECTED_CSS"
else
  echo "이 저장소의 index.html 에서 버전을 읽지 못해 버전 비교는 건너뜁니다."
fi

# ── 1. 계정 확인 ────────────────────────────────────────
step "1. 계정 확인"
CALLER_ACCOUNT=$(aws_run sts get-caller-identity --region "$REGION" --query Account --output text)
CALLER_ARN=$(aws_run sts get-caller-identity --region "$REGION" --query Arn --output text)
echo "계정: $CALLER_ACCOUNT"
echo "주체: $CALLER_ARN"
[ "$CALLER_ACCOUNT" = "$ACCOUNT" ] || die "계정이 의도한 $ACCOUNT 와 다릅니다. 올바른 자격 증명으로 다시 실행하세요."

# ── 2. 서버 찾기 · SSM 확인 ─────────────────────────────
step "2. 대시보드 서버 확인"
if [ -z "$INSTANCE_ID" ]; then
  IDS=$(aws_run ec2 describe-instances --region "$REGION" \
    --filters "Name=tag:Name,Values=${PREFIX}-dashboard" "Name=instance-state-name,Values=running" \
    --query 'Reservations[].Instances[].InstanceId' --output text)
  COUNT=$(printf '%s' "$IDS" | wc -w | tr -d ' ')
  [ "$COUNT" -ge 1 ] || die "실행 중인 '${PREFIX}-dashboard' 인스턴스가 없습니다."
  [ "$COUNT" -eq 1 ] || die "'${PREFIX}-dashboard' 인스턴스가 여러 개입니다($IDS). --instance-id 로 하나를 지정하세요."
  INSTANCE_ID=$(printf '%s' "$IDS" | tr -d ' \t')
fi
echo "대상 인스턴스: $INSTANCE_ID"
SSM_INFO=$(aws_run ssm describe-instance-information --region "$REGION" \
  --filters "Key=InstanceIds,Values=$INSTANCE_ID" \
  --query 'InstanceInformationList[0].[PingStatus,PlatformType]' --output text)
echo "SSM 상태: $SSM_INFO"
PING=$(printf '%s' "$SSM_INFO" | awk '{print $1}')
PLATFORM=$(printf '%s' "$SSM_INFO" | awk '{print $2}')
[ "$PING" = "Online" ] || die "SSM 에이전트가 온라인이 아닙니다. 인스턴스 상태와 IAM 역할을 확인하세요."
[ "$PLATFORM" = "Linux" ] || die "플랫폼이 Linux 가 아닙니다($PLATFORM)."

# ── 3. 배포 대상 zip 확인 ───────────────────────────────
BUCKET="${PREFIX}-scan-results-${REGION}-${ACCOUNT}"
if [ $ROLLBACK -eq 0 ]; then
  step "3. 배포할 zip 확인"
  HEAD=$(aws_run s3api head-object --region "$REGION" --bucket "$BUCKET" --key deploy/dashboard.zip \
    --query '[LastModified,ContentLength]' --output text)
  echo "s3://$BUCKET/deploy/dashboard.zip  (수정 시각 / 크기): $HEAD"
  echo "apply 직후 시각이 맞는지 확인하세요. 옛 시각이면 terraform apply 가 zip 을 올리지 않은 것입니다."
fi

# ── 4. 확인 ─────────────────────────────────────────────
step "4. 실행 확인"
if [ $ROLLBACK -eq 1 ]; then
  WHAT="app-src 와 app-src.prev 를 서로 바꾸고 서비스를 재시작"
else
  WHAT="새 zip 으로 app-src 를 교체(이전 코드는 app-src.prev)하고 서비스를 재시작"
fi
echo "대상 $INSTANCE_ID 에서 $WHAT 합니다. /opt/dashboard/instance 는 건드리지 않습니다."
if [ $YES -eq 0 ]; then
  read -r -p "진행할까요? (y/N) " ANSWER
  case "$ANSWER" in y|Y) ;; *) die "사용자가 취소했습니다." ;; esac
fi

# ── 5. 서버에서 실행 ────────────────────────────────────
step "5. 서버에서 배포 실행"
COMMON='APP=/opt/dashboard
health() {
  ok=0
  for i in $(seq 1 20); do
    if curl -fsS http://127.0.0.1:5000/health >/dev/null 2>&1; then ok=1; break; fi
    sleep 2
  done
  [ "$ok" = 1 ]
}'

DEPLOY_BODY='set -e
aws s3 cp "s3://__BUCKET__/deploy/dashboard.zip" /tmp/dashboard.zip --region __REGION__ --only-show-errors
rm -rf $APP/app-src.new && mkdir -p $APP/app-src.new
unzip -oq /tmp/dashboard.zip -d $APP/app-src.new
test -f $APP/app-src.new/backend/run.py
$APP/venv/bin/pip install -q -r $APP/app-src.new/backend/requirements.txt
rm -rf $APP/app-src.prev
mv $APP/app-src $APP/app-src.prev
mv $APP/app-src.new $APP/app-src
systemctl restart dashboard.service
if health; then
  echo HEALTH_OK
else
  echo HEALTH_FAILED_ROLLING_BACK
  rm -rf $APP/app-src.failed
  mv $APP/app-src $APP/app-src.failed
  mv $APP/app-src.prev $APP/app-src
  systemctl restart dashboard.service
  if health; then echo ROLLED_BACK_HEALTH_OK; fi
  exit 1
fi'

ROLLBACK_BODY='set -e
test -d $APP/app-src.prev
mv $APP/app-src $APP/app-src.swap
mv $APP/app-src.prev $APP/app-src
mv $APP/app-src.swap $APP/app-src.prev
systemctl restart dashboard.service
if health; then echo HEALTH_OK; else echo HEALTH_FAILED; exit 1; fi'

TAIL='echo "CSS_VERSION=$(grep -o '"'"'local.css?v=[^"]*'"'"' $APP/app-src/frontend/templates/index.html | head -1)"'

if [ $ROLLBACK -eq 1 ]; then BODY="$ROLLBACK_BODY"; else BODY="$DEPLOY_BODY"; fi
REMOTE="$COMMON
$BODY
$TAIL"
REMOTE="${REMOTE//__BUCKET__/$BUCKET}"
REMOTE="${REMOTE//__REGION__/$REGION}"

# SSM 에 줄 배열(JSON)을 만든다. 역슬래시와 큰따옴표만 이스케이프하면 된다.
JSON_LINES=$(printf '%s\n' "$REMOTE" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/^/"/' -e 's/$/"/' | paste -sd, -)
PAYLOAD="{\"commands\":[${JSON_LINES}]}"
TMP_FILE=$(mktemp)
trap 'rm -f "$TMP_FILE"' EXIT
printf '%s' "$PAYLOAD" > "$TMP_FILE"
if command -v cygpath >/dev/null 2>&1; then TMP_URI="file://$(cygpath -m "$TMP_FILE")"; else TMP_URI="file://$TMP_FILE"; fi

COMMAND_ID=$(aws_run ssm send-command --region "$REGION" \
  --document-name AWS-RunShellScript --instance-ids "$INSTANCE_ID" \
  --comment "dashboard in-place deploy" --timeout-seconds 900 \
  --parameters "$TMP_URI" --query 'Command.CommandId' --output text)
echo "SSM 명령 ID: $COMMAND_ID"

# ── 6. 결과 기다리기 ────────────────────────────────────
step "6. 실행 결과 기다리는 중"
STATUS=""
for _ in $(seq 1 120); do
  sleep 5
  S=$(aws ssm get-command-invocation --region "$REGION" --command-id "$COMMAND_ID" --instance-id "$INSTANCE_ID" \
      --query Status --output text 2>/dev/null | tr -d '\r') || true
  [ -n "$S" ] || continue   # 등록 직후 잠깐 조회되지 않을 수 있다
  echo "  상태: $S"
  STATUS="$S"
  case "$S" in Success|Failed|Cancelled|TimedOut) break ;; esac
done
case "$STATUS" in
  Success|Failed|Cancelled|TimedOut) ;;
  *) die "결과를 끝까지 확인하지 못했습니다. SSM 콘솔에서 명령 ID $COMMAND_ID 를 확인하세요." ;;
esac

STDOUT=$(aws ssm get-command-invocation --region "$REGION" --command-id "$COMMAND_ID" --instance-id "$INSTANCE_ID" \
  --query StandardOutputContent --output text 2>/dev/null | tr -d '\r') || true
STDERR=$(aws ssm get-command-invocation --region "$REGION" --command-id "$COMMAND_ID" --instance-id "$INSTANCE_ID" \
  --query StandardErrorContent --output text 2>/dev/null | tr -d '\r') || true
echo
echo "--- 서버 출력 ---"
printf '%s\n' "$STDOUT"
if [ -n "$STDERR" ] && [ "$STDERR" != "None" ]; then
  echo "--- 서버 오류 출력 ---"
  printf '%s\n' "$STDERR"
fi

# ── 7. 검증 ─────────────────────────────────────────────
step "7. 결과 판정"
SERVER_CSS=$(printf '%s\n' "$STDOUT" | sed -n 's/^CSS_VERSION=//p' | head -1)
if [ "$STATUS" != "Success" ] || ! printf '%s\n' "$STDOUT" | grep -q '^HEALTH_OK'; then
  if printf '%s\n' "$STDOUT" | grep -q 'ROLLED_BACK_HEALTH_OK'; then
    echo "배포 후 /health 가 실패해 이전 코드로 복구했고, 복구 후 /health 는 정상입니다. 새 코드는 app-src.failed 에 남아 있습니다."
  else
    echo "배포가 성공으로 확인되지 않았습니다(상태 $STATUS). 위 서버 출력 전체를 확인하세요."
  fi
  exit 1
fi

echo "서버 /health: 정상"
echo "서버 버전: $SERVER_CSS"
if [ $ROLLBACK -eq 0 ] && [ -n "$EXPECTED_CSS" ]; then
  if [ "$SERVER_CSS" = "$EXPECTED_CSS" ]; then
    echo "버전 일치: $SERVER_CSS — 배포 완료. 브라우저에서 Ctrl+Shift+R 로 새로고침하세요."
  else
    echo "경고: 서버 버전($SERVER_CSS)이 이 저장소의 버전($EXPECTED_CSS)과 다릅니다. S3 의 zip 이 옛 것이면 terraform apply 를 다시 확인하세요."
    exit 2
  fi
else
  echo "완료. 브라우저에서 Ctrl+Shift+R 로 새로고침하세요."
fi
