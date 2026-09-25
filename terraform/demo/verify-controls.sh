#!/bin/bash
# 차단 검증 + 기능 검증을 한 번에 돌린다.
#
# 학생가이드 9.3 "보안 조치는 막혔다만으로 성공이 아니다"에 대응한다.
#   차단되어야 할 것은 실패해야 하고, 필요한 통신은 성공해야 한다.
#
# 실행:  ./verify-controls.sh              (terraform output 에서 값 자동 수집)
#        ./verify-controls.sh --json       (증적 첨부용 JSON)
#
# 본인 PC에서 돌립니다. 차단 항목은 "외부에서 안 된다"를 보는 것이므로,
# admin_cidr 안에서 돌려도 3306/5000 은 어차피 막혀 있어야 합니다.
#
# 이 프로젝트는 SSH 22 를 쓰지 않습니다(Session Manager 전용). SG에 22 규칙이
# 없는지도 함께 확인합니다.
set -uo pipefail
cd "$(dirname "$0")/.."

JSON=0
[ "${1:-}" = "--json" ] && JSON=1

TIMEOUT=5
PASS=0
FAIL=0
RESULTS=()

# $1 결과(PASS/FAIL) $2 항목 $3 상세
record() {
  RESULTS+=("$1|$2|$3")
  if [ "$1" = "PASS" ]; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); fi
  [ "$JSON" = "1" ] && return
  if [ "$1" = "PASS" ]; then printf '  \033[32m[PASS]\033[0m %-38s %s\n' "$2" "$3"
  else printf '  \033[31m[FAIL]\033[0m %-38s %s\n' "$2" "$3"; fi
}

# 열려 있으면 안 되는 포트. 연결이 "실패"해야 PASS.
must_be_blocked() {
  local host=$1 port=$2 label=$3
  if [ -z "$host" ] || [ "$host" = "null" ]; then
    record FAIL "$label" "대상 주소를 못 찾음 (terraform output 확인)"
    return
  fi
  if timeout "$TIMEOUT" bash -c "cat < /dev/null > /dev/tcp/$host/$port" 2>/dev/null; then
    record FAIL "$label" "$host:$port 연결됨 — 열려 있다"
  else
    record PASS "$label" "$host:$port 연결 실패(정상)"
  fi
}

# 되어야 하는 것. 연결이 "성공"해야 PASS.
must_work() {
  local url=$1 label=$2
  local code
  code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" "$url" 2>/dev/null)
  if [ "$code" != "000" ] && [ -n "$code" ]; then
    record PASS "$label" "HTTP $code"
  else
    record FAIL "$label" "응답 없음 ($url)"
  fi
}

# SG 규칙이 아예 없어야 하는 것. describe 결과가 비어야 PASS.
sg_rule_absent() {
  local sg=$1 port=$2 label=$3
  local n
  n=$(aws ec2 describe-security-group-rules \
    --filters "Name=group-id,Values=$sg" \
    --query "length(SecurityGroupRules[?FromPort==\`$port\` && IsEgress==\`false\`])" \
    --output text 2>/dev/null)
  if [ "$n" = "0" ]; then
    record PASS "$label" "인바운드 $port 규칙 없음"
  else
    record FAIL "$label" "인바운드 $port 규칙 ${n}개 남아 있음"
  fi
}

tfout() { terraform output -raw "$1" 2>/dev/null; }

WEB_URL=$(tfout web_url)
WEB_HOST=$(echo "$WEB_URL" | sed -e 's|https\?://||' -e 's|/.*||')
ALB_HOST=$(tfout alb_dns_name)

[ "$JSON" = "0" ] && {
  echo
  echo "=============================================="
  echo " 차단 · 기능 검증   $(date '+%Y-%m-%d %H:%M:%S')"
  echo "=============================================="
  echo
  echo "[1] 차단되어야 하는 것"
}

must_be_blocked "$WEB_HOST" 3306 "MySQL 3306 외부 차단"
must_be_blocked "$WEB_HOST" 5000 "Flask 5000 외부 차단"
must_be_blocked "$ALB_HOST" 3306 "ALB 경유 3306 차단"

[ "$JSON" = "0" ] && { echo; echo "[2] 되어야 하는 것"; }

must_work "$WEB_URL" "웹(DVWA) HTTP 접근"

[ "$JSON" = "0" ] && { echo; echo "[3] SG 규칙 직접 확인 (AWS CLI 필요)"; }

if command -v aws >/dev/null 2>&1; then
  SGS=$(terraform output -json target_security_groups 2>/dev/null | python -c "import sys,json;d=json.load(sys.stdin);print(d.get('auto_remediated',''),d.get('manual_only',''))" 2>/dev/null)
  AUTO_SG=$(echo "$SGS" | awk '{print $1}')
  MANUAL_SG=$(echo "$SGS" | awk '{print $2}')
  if [ -n "$AUTO_SG" ]; then
    sg_rule_absent "$AUTO_SG" 22 "db(auto) SG - 22 규칙 부재"
    sg_rule_absent "$MANUAL_SG" 22 "db(manual) SG - 22 규칙 부재"
    sg_rule_absent "$MANUAL_SG" 5000 "db(manual) SG - 5000 규칙 부재"
  else
    record FAIL "SG 직접 확인" "target_security_groups output 없음 - 건너뜀"
  fi
else
  record FAIL "SG 직접 확인" "aws CLI 없음 — 건너뜀"
fi

if [ "$JSON" = "1" ]; then
  printf '{"timestamp":"%s","pass":%d,"fail":%d,"results":[' "$(date -Iseconds)" "$PASS" "$FAIL"
  first=1
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r st item detail <<<"$r"
    [ $first = 0 ] && printf ','
    printf '{"status":"%s","item":"%s","detail":"%s"}' "$st" "$item" "$detail"
    first=0
  done
  printf ']}\n'
else
  echo
  echo "----------------------------------------------"
  printf " PASS %d  /  FAIL %d\n" "$PASS" "$FAIL"
  echo "----------------------------------------------"
  echo
  echo " 증적으로 남길 때:  ./verify-controls.sh --json > docs/evidence/verify_$(date +%Y%m%d).json"
  echo
fi

[ "$FAIL" -eq 0 ]
