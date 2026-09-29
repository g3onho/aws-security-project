#!/bin/bash
# 허니팟 AI 시연: 공격자 4대(사례 1~4)를 순서대로 실행하고, 자동 차단과 AI 분석 결과를 한 화면에 모은다.
#
# 실행 위치: AWS CloudShell (서울 리전)
# 사전 조건: terraform apply 로 허니팟 + 시연 공격자 4대(honeypot_demo_attacker_count = 4)가 떠 있어야 한다.
#            시연 중에는 honeypot_alarm_period = 60, block_expiry_rate_minutes = 1 을 권장한다.
# 이 스크립트는 조회와 SSM 실행만 한다. NACL·DynamoDB 는 수정하지 않는다(해제는 TTL 과 block_expiry 가 한다).
#
# 사용법: bash scripts/honeypot-ai-demo.sh [이름접두사]   (기본 soar-sec-dev)
set -uo pipefail

P="${1:-soar-sec-dev}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-ap-northeast-2}"
DOC="ATK-HoneypotAiDemo"
ALARM="${P}-honeypot"
LOG_GROUP="/honeypot/${P}"
POLL=20            # 폴링 간격(초)
BLOCK_TIMEOUT=360  # 차단 확인 최대 대기(초)
OK_TIMEOUT=600     # 알람 OK 복귀 최대 대기(초)
MAX_EXISTING_DENY=6

START_EPOCH=$(date +%s)
declare -a RESULT_LINES=()

say() { printf '%s\n' "$*"; }
die() { printf '중단: %s\n' "$*" >&2; exit 1; }
mmss() { printf '%02d:%02d' $(($1 / 60)) $(($1 % 60)); }

soar_denies() {  # 인바운드 Deny 중 규칙 번호 1~99: "번호<TAB>CIDR"
  aws ec2 describe-network-acls \
    --query 'NetworkAcls[].Entries[?RuleAction==`deny` && RuleNumber<`100` && Egress==`false`].[RuleNumber,CidrBlock]' \
    --output text | awk 'NF==2'
}

alarm_state() {
  aws cloudwatch describe-alarms --alarm-names "$ALARM" \
    --query 'MetricAlarms[0].StateValue' --output text 2>/dev/null
}

# ---------- 1. 사전 점검 ----------
say "== 사전 점검 =="
HP_IP=$(aws ec2 describe-instances \
  --filters Name=tag:Role,Values=honeypot-decoy Name=instance-state-name,Values=running \
  --query 'Reservations[].Instances[].PrivateIpAddress' --output text | awk '{print $1}')
[ -n "$HP_IP" ] && [ "$HP_IP" != "None" ] || die "실행 중인 허니팟(Role=honeypot-decoy)을 찾지 못했습니다."
say "허니팟: $HP_IP"

declare -A FLEET_ID FLEET_IP
for n in 1 2 3 4; do
  row=$(aws ec2 describe-instances \
    --filters "Name=tag:DemoCase,Values=$n" Name=tag:Scenario,Values=HONEYPOT Name=instance-state-name,Values=running \
    --query 'Reservations[].Instances[].[InstanceId,PrivateIpAddress]' --output text | head -1)
  [ -n "$row" ] || die "사례 $n 공격자를 찾지 못했습니다(honeypot_demo_attacker_count = 4 로 apply 했는지 확인)."
  FLEET_ID[$n]=$(awk '{print $1}' <<<"$row")
  FLEET_IP[$n]=$(awk '{print $2}' <<<"$row")
  say "사례 $n 공격자: ${FLEET_ID[$n]} (${FLEET_IP[$n]})"
  online=$(aws ssm describe-instance-information \
    --filters "Key=InstanceIds,Values=${FLEET_ID[$n]}" \
    --query 'InstanceInformationList[0].PingStatus' --output text 2>/dev/null)
  [ "$online" = "Online" ] || die "사례 $n 공격자의 SSM 상태가 Online 이 아닙니다($online). 부팅 후 몇 분 뒤 다시 실행하세요."
done

deny_count=$(soar_denies | wc -l)
[ "$deny_count" -le "$MAX_EXISTING_DENY" ] || die "SOAR 차단(1~99)이 ${deny_count}개입니다. 상한 10개라 4건을 더 넣을 수 없습니다. 만료를 기다리거나 정리하세요."
say "현재 SOAR 차단 규칙: ${deny_count}개 (여유 충분)"

state=$(alarm_state)
[ "$state" = "OK" ] || die "허니팟 알람이 OK 가 아닙니다(현재: $state). OK 로 돌아온 뒤 다시 실행하세요."
say "알람 $ALARM: OK"
say

# ---------- 2. 사례 1~4 순차 실행 ----------
for n in 1 2 3 4; do
  ip="${FLEET_IP[$n]}"
  t0=$(date +%s)
  say "== [Case $n] 공격 시작: ${FLEET_ID[$n]} ($ip) → $HP_IP =="
  cmd_id=$(aws ssm send-command --instance-ids "${FLEET_ID[$n]}" --document-name "$DOC" \
    --parameters "HoneypotHost=$HP_IP,DemoCase=$n" \
    --query 'Command.CommandId' --output text) || die "SSM 명령 전송 실패(사례 $n)"

  blocked_rule=""
  while [ $(( $(date +%s) - t0 )) -lt "$BLOCK_TIMEOUT" ]; do
    blocked_rule=$(soar_denies | awk -v ip="$ip/32" '$2==ip {print $1; exit}')
    [ -n "$blocked_rule" ] && break
    sleep "$POLL"
  done
  if [ -n "$blocked_rule" ]; then
    took=$(( $(date +%s) - t0 ))
    say "[Case $n] IP $ip → NACL 규칙 #$blocked_rule 차단 ($(mmss $took))"
    RESULT_LINES+=("Case $n|$ip|#$blocked_rule|$(mmss $took)")
  else
    say "[Case $n] 경고: ${BLOCK_TIMEOUT}초 안에 $ip 차단을 확인하지 못했습니다(asr_trigger 로그 확인)."
    RESULT_LINES+=("Case $n|$ip|미확인|-")
  fi

  # 알람이 OK 로 돌아와야 다음 사례가 새로 트리거된다(알람 1개 = 트리거 1회에 IP 1개).
  if [ "$n" -lt 4 ]; then
    say "[Case $n] 알람 OK 복귀 대기..."
    w0=$(date +%s)
    while [ $(( $(date +%s) - w0 )) -lt "$OK_TIMEOUT" ]; do
      [ "$(alarm_state)" = "OK" ] && break
      sleep "$POLL"
    done
    [ "$(alarm_state)" = "OK" ] || say "경고: 알람이 ${OK_TIMEOUT}초 안에 OK 로 돌아오지 않았습니다. 다음 사례는 차단되지 않을 수 있습니다."
  fi
  say
done

# ---------- 3. 요약 ----------
say "== 자동 차단 요약 =="
printf '%-8s %-14s %-10s %s\n' 사례 공격자IP NACL규칙 소요
for line in "${RESULT_LINES[@]}"; do
  IFS='|' read -r a b c d <<<"$line"
  printf '%-8s %-14s %-10s %s\n' "$a" "$b" "$c" "$d"
done
say

# ---------- 4. AI 분석 (Logs Insights) ----------
say "== AI 분석 결과 (session_end) =="
say "분석 로그가 적재될 때까지 잠시 기다립니다..."
sleep 30
QUERY='fields @timestamp, src_ip, analysis.intent as intent, analysis.severity as severity, analysis.summary as summary | filter event = "session_end" | sort @timestamp asc | limit 50'
qid=$(aws logs start-query --log-group-name "$LOG_GROUP" \
  --start-time "$START_EPOCH" --end-time "$(( $(date +%s) + 60 ))" \
  --query-string "$QUERY" --query 'queryId' --output text) || die "Logs Insights 쿼리 시작 실패"
for _ in $(seq 1 30); do
  qs=$(aws logs get-query-results --query-id "$qid" --query 'status' --output text)
  [ "$qs" = "Complete" ] && break
  sleep 2
done
aws logs get-query-results --query-id "$qid" --output json | python3 -c '
import json, sys
rows = json.load(sys.stdin).get("results", [])
if not rows:
    print("session_end 로그가 없습니다. 세션 종료 후 분석까지 수 초~수십 초 걸립니다. 잠시 뒤 다시 조회하세요.")
    sys.exit(0)
fallback = 0
print("%-10s %-22s %-10s %s" % ("src_ip", "intent", "severity", "summary"))
for r in rows:
    d = {c["field"]: c["value"] for c in r}
    summary = d.get("summary", "")
    if "AI 분석 미적용" in summary:
        fallback += 1
    print("%-10s %-22s %-10s %s" % (d.get("src_ip", ""), d.get("intent", ""), d.get("severity", ""), summary))
intents = {(dict((c["field"], c["value"]) for c in r)).get("intent") for r in rows}
print()
print("intent 종류: %d개" % len(intents))
if fallback:
    print("경고: %d건이 규칙 기반 대체 분석입니다(AI 분석 미적용). Bedrock 모델 액세스 허용, 모델 ID, 타임아웃을 확인하세요." % fallback)
else:
    print("AI 분석 정상: 대체 분석(AI 분석 미적용) 없음")
'
say
say "완료. 차단은 TTL 만료 후 block_expiry 가 자동 해제합니다."
