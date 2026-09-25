#!/usr/bin/env bash
# SEC-03 자동조치 시연: SG 에 3306/0.0.0.0/0 을 넣고(침해 재현) 조치 전/후를 보여줍니다.
#
#   ./trigger-auto-remediation.sh          # db-auto-sg 대상 (자동 회수됨)
#   ./trigger-auto-remediation.sh --manual # db-manual-sg 대상 (알림만, 대조군)
#
# 프로젝트 루트에서 terraform apply 후 실행하세요.
set -euo pipefail
cd "$(dirname "$0")/.."

REGION=$(terraform output -raw region 2>/dev/null || aws configure get region || echo ap-northeast-2)
ACCOUNT=$(aws sts get-caller-identity --query Account --output text --region "$REGION")
ASR_FN=$(terraform output -raw asr_trigger_function_name)

if [[ "${1:-}" == "--manual" ]]; then
  KEY=manual_only;    LABEL="[대조군] db-manual-sg (태그 없음 -> 알림만)"
else
  KEY=auto_remediated; LABEL="[자동] db-auto-sg (AutoRemediation=enabled -> 자동 회수)"
fi
SG=$(terraform output -json target_security_groups | python3 -c "import sys,json;print(json.load(sys.stdin)['$KEY'])")
echo "$LABEL : $SG"

echo "== BEFORE =="
aws ec2 describe-security-groups --group-ids "$SG" --region "$REGION" \
  --query "SecurityGroups[0].IpPermissions" --output json

echo "== 침해 재현: 3306/0.0.0.0/0 인바운드 추가 =="
aws ec2 authorize-security-group-ingress --group-id "$SG" --region "$REGION" \
  --protocol tcp --port 3306 --cidr 0.0.0.0/0 2>/dev/null || echo "(이미 존재)"

echo "== 즉시 시연: asr-trigger 를 Security Hub 이벤트로 호출 =="
cat > /tmp/sh-event.json <<JSON
{ "detail": { "findings": [{
  "Title": "Security group allows ingress from 0.0.0.0/0 to port 3306",
  "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
  "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/EC2.19",
  "Compliance": {"Status": "FAILED"}, "RecordState": "ACTIVE",
  "Resources": [{"Type":"AwsEc2SecurityGroup","Id":"arn:aws:ec2:${REGION}:${ACCOUNT}:security-group/${SG}"}]
}]}}
JSON
aws lambda invoke --function-name "$ASR_FN" --region "$REGION" \
  --cli-binary-format raw-in-base64-out --payload fileb:///tmp/sh-event.json /tmp/asr-out.json
echo "asr-trigger 응답:"; cat /tmp/asr-out.json; echo

echo "== AFTER (자동 대상이면 3306 규칙이 사라져 있어야 함) =="
sleep 6
aws ec2 describe-security-groups --group-ids "$SG" --region "$REGION" \
  --query "SecurityGroups[0].IpPermissions" --output json

echo; echo "조치 이력(Before/After) 테이블: $(terraform output -raw remediation_actions_table)"
