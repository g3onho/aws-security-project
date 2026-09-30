#!/usr/bin/env bash
# 3계층 '비정상' 해소: web 이미지(app-1.0.0)를 ECR 에 올리고 docker-host 의 app 서비스를 기동한다. (OPEN-020 / DEC-040)
# 실행 전 계정을 보여 주고 확인을 받는다. 키·토큰은 출력하지 않는다. 필요: aws cli, docker(실행 중), 이 저장소.
set -euo pipefail
REGION="${REGION:-eu-west-3}"
TAG="app-1.0.0"
DIR="$(cd "$(dirname "$0")/.." && pwd)/terraform/modules/compute/app-image"

echo "== 1) 계정 확인 =="
aws sts get-caller-identity --region "$REGION" --query '{Account:Account,Arn:Arn}' --output table
read -r -p "이 계정(리전 $REGION)에서 진행할까요? [y/N] " ok
[ "$ok" = "y" ] || { echo "중단"; exit 1; }

echo "== 2) ECR 저장소 찾기 =="
REPO=$(aws ecr describe-repositories --region "$REGION" --query "repositories[?ends_with(repositoryName,'/app')].repositoryUri | [0]" --output text)
[ -n "$REPO" ] && [ "$REPO" != "None" ] || { echo "ECR 저장소(…/app)를 찾지 못했습니다"; exit 1; }
echo "저장소: $REPO"
if aws ecr describe-images --region "$REGION" --repository-name "${REPO#*/}" --image-ids imageTag="$TAG" >/dev/null 2>&1; then
  echo "이미 $TAG 이미지가 있습니다 — push 는 건너뜁니다"
else
  echo "== 3) 빌드·push (대체 앱, DEC-040) =="
  aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "${REPO%%/*}"
  docker build -t "$REPO:$TAG" "$DIR"
  docker push "$REPO:$TAG"
fi

echo "== 4) docker-host 에서 app 서비스 기동(SSM, 읽기 외 변경은 systemctl start app 하나) =="
IID=$(aws ec2 describe-instances --region "$REGION" --filters "Name=tag:Role,Values=service-3tier" "Name=instance-state-name,Values=running" --query 'Reservations[].Instances[].InstanceId' --output text)
[ "$(echo "$IID" | wc -w)" = "1" ] || { echo "대상 인스턴스가 정확히 1대가 아닙니다: '$IID'"; exit 1; }
CMD=$(aws ssm send-command --region "$REGION" --instance-ids "$IID" --document-name AWS-RunShellScript \
  --parameters 'commands=["systemctl reset-failed app || true","systemctl restart app","sleep 20","docker compose -f /opt/app/compose.yaml ps"]' \
  --query Command.CommandId --output text)
for _ in $(seq 1 30); do
  S=$(aws ssm get-command-invocation --region "$REGION" --command-id "$CMD" --instance-id "$IID" --query Status --output text 2>/dev/null || echo Pending)
  case "$S" in Pending|InProgress|Delayed) sleep 4;; *) break;; esac
done
echo "SSM 상태: $S"
aws ssm get-command-invocation --region "$REGION" --command-id "$CMD" --instance-id "$IID" --query StandardOutputContent --output text
echo "끝. tier_check 는 5분 주기라 대시보드 '3계층'이 바뀌는 데 최대 5분 걸립니다."
