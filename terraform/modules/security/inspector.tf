############################################
# Inspector2 — EC2 / ECR 이미지 CVE 스캔 (SEC-04)
############################################

resource "aws_inspector2_enabler" "this" {
  count = var.enable_inspector2 ? 1 : 0

  account_ids    = [var.account_id]
  resource_types = ["EC2", "ECR"]

  # 비활성화는 보통 10~15분 걸립니다. 기본 5분이라 destroy 가 타임아웃으로
  # 먼저 죽고, 정작 AWS 쪽은 계속 DISABLING 이라 재실행해야 했습니다.
  timeouts {
    create = "20m"
    delete = "20m"
  }
}
