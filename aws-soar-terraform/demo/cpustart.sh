#!/usr/bin/env bash
# SEC-10 CPU/메모리 알람 시연: 알람 대상 인스턴스에 stress-ng 로 부하를 겁니다.
#
#   ./cpustart.sh                      # 알람 대상 전체 (기본 15분, CPU 85%)
#   ./cpustart.sh --skip dashboard     # 대시보드만 빼고
#   ./cpustart.sh --only web-dvwa,db   # 지정한 것만
#   ./cpustart.sh --duration 1200      # 20분
#   ./cpustart.sh --stop               # 즉시 중단
#
# 알람은 period 300 x evaluation_periods 2 이므로 최소 10분은 지나야 울립니다.
# duration 을 900 미만으로 줄이면 알람이 뜨기 전에 부하가 끝납니다.
#
# 프로젝트 루트에서 terraform apply 후 실행하세요.
set -euo pipefail
cd "$(dirname "$0")/.."

REGION=$(terraform output -raw region 2>/dev/null || aws configure get region || echo ap-northeast-2)
DURATION=900
LOAD=85
ONLY=""
SKIP=""
STOP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --stop)     STOP=1; shift ;;
    --duration) DURATION="$2"; shift 2 ;;
    --load)     LOAD="$2"; shift 2 ;;
    --only)     ONLY="$2"; shift 2 ;;
    --skip)     SKIP="$2"; shift 2 ;;
    *) echo "알 수 없는 옵션: $1" >&2; exit 2 ;;
  esac
done

# 알람 대상과 같은 목록을 써야 부하와 알람이 어긋나지 않습니다.
# JSON 은 한 줄로 나오고 값에 특수문자가 없어 sed/tr 로 충분합니다(python/jq 불필요).
mapfile -t PAIRS < <(
  terraform output -json instance_ids     | tr -d '{}"' | tr ',' '
' | sed 's/:/	/'     | while IFS=$'	' read -r name iid; do
        [[ -z "$name" ]] && continue
        if [[ -n "$ONLY" ]] && [[ ",$ONLY," != *",$name,"* ]]; then continue; fi
        if [[ -n "$SKIP" ]] && [[ ",$SKIP," == *",$name,"* ]]; then continue; fi
        printf '%s	%s
' "$name" "$iid"
      done | sort
)

if [[ ${#PAIRS[@]} -eq 0 ]]; then
  echo "대상이 없습니다. --only / --skip 값을 확인하세요." >&2
  exit 1
fi

IDS=()
echo "== 대상 =="
for p in "${PAIRS[@]}"; do
  name="${p%%$'\t'*}"; iid="${p##*$'\t'}"
  printf '  %-14s %s\n' "$name" "$iid"
  IDS+=("$iid")
done

if [[ $STOP -eq 1 ]]; then
  CMD='pkill -f stress-ng || true'
  LABEL="부하 중단"
else
  # --cpu 0 = 코어 전부. timeout 을 줘서 끄는 걸 잊어도 알아서 멈춥니다.
  CMD="apt-get install -y stress-ng >/dev/null 2>&1 || true; nohup stress-ng --cpu 0 --cpu-load ${LOAD} --timeout ${DURATION}s >/dev/null 2>&1 &"
  LABEL="CPU ${LOAD}% x ${DURATION}초"
fi

echo "== $LABEL =="
CID=$(aws ssm send-command --region "$REGION" \
  --document-name AWS-RunShellScript \
  --instance-ids "${IDS[@]}" \
  --parameters commands="$CMD" \
  --comment "SEC-10 $LABEL" \
  --query Command.CommandId --output text)
echo "CommandId: $CID"

echo "== 전달 결과 =="
for _ in $(seq 1 10); do
  sleep 3
  OUT=$(aws ssm list-command-invocations --region "$REGION" --command-id "$CID" \
        --query "CommandInvocations[].[InstanceId,Status]" --output text)
  [[ -n "$OUT" ]] && ! grep -qE 'Pending|InProgress' <<<"$OUT" && break
done
echo "$OUT" | awk '{printf "  %-22s %s\n", $1, $2}'

[[ $STOP -eq 1 ]] && exit 0

cat <<MSG

알람은 약 10분 뒤부터 울립니다(5분 평균 x 2회).
  상태 확인 : aws cloudwatch describe-alarms --region $REGION --state-value ALARM --query "MetricAlarms[].AlarmName" --output table
  중단      : ./demo/cpustart.sh --stop
부하는 ${DURATION}초 뒤 자동으로 멈춥니다.
MSG
