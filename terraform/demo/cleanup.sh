#!/usr/bin/env bash
# 실습 종료 전 정리: 시연이 넣은 3306/0.0.0.0/0 규칙을 원복하고,
# 테스트로 만든 노출 액세스 키가 있으면 안내합니다.
# 이후 프로젝트 루트에서 terraform destroy 를 실행하세요.
set -euo pipefail
cd "$(dirname "$0")/.."
REGION=$(terraform output -raw region 2>/dev/null || aws configure get region || echo ap-northeast-2)

for KEY in auto_remediated manual_only; do
  SG=$(terraform output -json target_security_groups | python3 -c "import sys,json;print(json.load(sys.stdin)['$KEY'])")
  echo "SG $SG 에서 3306/0.0.0.0/0 규칙 회수 시도..."
  aws ec2 revoke-security-group-ingress --group-id "$SG" --region "$REGION" \
    --protocol tcp --port 3306 --cidr 0.0.0.0/0 2>/dev/null && echo "  회수됨" || echo "  (없음)"
done

echo
echo "다음 순서로 마무리하세요:"
echo "  1) terraform destroy"
echo "  2) 콘솔에서 GuardDuty / Security Hub / Inspector2 / Config 비활성화 확인"
echo "  3) CloudTrail S3 버킷·KMS 키는 보존 설정이라 수동 삭제"
