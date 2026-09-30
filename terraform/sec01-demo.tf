############################################
# SEC-01([전부 실행]) 시연용 보안그룹 — 과도하게 공개된 SSH
#
# 왜 루트에 두는가: override-demo.tf 와 같은 이유. modules/network 안에 넣으면
# module.compute 의 depends_on = [module.network] 때문에 compute 의 AMI 조회가
# apply 시점으로 밀려 EC2 전부가 재생성된다. vpc_id 만 필요하므로 모듈 밖에 둔다.
#
# 왜 이 SG 가 필요한가: SEC-01 은 "SSH 가 과도하게 열린 보안그룹 구성" 탐지·자동 회수를
# 보여준다. 실제 서비스 SG(docker-host·db 등)의 SSH 규칙을 건드리면 관리자 접속이 끊기므로,
# 어디에도 연결하지 않은 전용 SG 를 만들어 그 위에서만 열고/회수한다.
# db_auto·db_manual(SEC-03) 과 달리 대조군이 없다 — SEC-01 은 자동 회수 하나만 보여준다.
############################################

resource "aws_security_group" "sec01_demo" {
  count = var.enable_sec01_demo_sg ? 1 : 0

  name        = "${local.name_prefix}-sec01-ssh-demo-sg"
  description = "Unattached SG for SEC-01 auto-remediation demo (no real traffic)"
  vpc_id      = module.network.vpc_id

  # AutoRemediation=enabled — asr_trigger 가 Security Hub SG finding 을 받으면 이 태그를 보고
  # 자동 회수를 실행한다(수동 승인 없음). Scenario 태그는 대시보드 IAM 의 실행 범위 한정에도 쓴다
  # (compute/iam.tf RunSgViolationDrill — db-auto/db-manual 의 기존 Scenario 태그와 같은 방식).
  tags = merge(local.common_tags, {
    Name            = "${local.name_prefix}-sec01-ssh-demo-sg"
    Scenario        = "SEC-01"
    AutoRemediation = "enabled"
  })
}
