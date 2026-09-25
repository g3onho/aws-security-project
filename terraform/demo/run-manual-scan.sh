#!/usr/bin/env bash
# 수동 모니터링 시연: 포트/웹 점검(SCAN-PortAndWeb) 또는 이미지 점검(SCAN-ContainerImage)을
# SSM Run Command 로 실행하고 결과를 S3 에 올립니다.
#
#   ./run-manual-scan.sh port    <대상IP>   # nmap + HTTP 헤더
#   ./run-manual-scan.sh image             # docker-host 에서 Trivy
set -euo pipefail
cd "$(dirname "$0")/.."
REGION=$(terraform output -raw region 2>/dev/null || aws configure get region || echo ap-northeast-2)
BUCKET=$(terraform output -raw scan_results_bucket)
DOCKER_HOST=$(terraform output -json instance_ids | python3 -c "import sys,json;print(json.load(sys.stdin)['docker-host'])")
DOCS=$(terraform output -json manual_scan_documents)

case "${1:-}" in
  port)
    TARGET="${2:?대상 IP 를 입력하세요}"
    DOC=$(echo "$DOCS" | python3 -c "import sys,json;print(json.load(sys.stdin)['port_and_web'])")
    aws ssm send-command --region "$REGION" --document-name "$DOC" \
      --instance-ids "$DOCKER_HOST" \
      --parameters "TargetHost=$TARGET,ScanBucket=$BUCKET" \
      --query "Command.CommandId" --output text ;;
  image)
    DOC=$(echo "$DOCS" | python3 -c "import sys,json;print(json.load(sys.stdin)['container_image'])")
    aws ssm send-command --region "$REGION" --document-name "$DOC" \
      --instance-ids "$DOCKER_HOST" \
      --parameters "ScanBucket=$BUCKET" \
      --query "Command.CommandId" --output text ;;
  *) echo "사용법: $0 port <IP> | image"; exit 1 ;;
esac
echo "결과는 s3://$BUCKET/ 에 적재됩니다. aws s3 ls s3://$BUCKET/ --recursive"
