############################################
# 대시보드 '위험 확인 후 조치'(오버라이드) 시연용 보안그룹
#
# 왜 루트에 두는가: modules/network 안에 넣으면 module.compute 의
# depends_on = [module.network] (main.tf) 때문에 compute 의 data.aws_ami.ubuntu
# 조회가 apply 시점으로 밀리고, AMI 가 unknown 이 되어 EC2 전부가 재생성된다.
# 이 SG 는 vpc_id 만 필요하므로 모듈 밖에 두어 그 연쇄를 끊는다.
#
# 왜 이 SG 가 필요한가: 태그 없는 서비스용 SG 의 전체공개 규칙 회수는
# provider.revocable_group() 이 기본 차단하고, 대시보드 팝업에서 위험을 확인해야
# 실행된다. 그 경로를 실제 서비스(ALB SG 등)로 시연하면 대시보드 자신이 끊기므로
# 어디에도 연결하지 않은 이 SG 를 대상으로 쓴다.
############################################

resource "aws_security_group" "override_demo" {
  count = var.enable_override_demo_sg ? 1 : 0

  name        = "${local.name_prefix}-override-demo-sg"
  description = "Unattached SG for demonstrating confirm-then-remediate (no tags on purpose)"
  vpc_id      = module.network.vpc_id

  # AutoRemediation·RemediationGroup 태그를 일부러 붙이지 않는다 — 이것이 차단 조건이다.
  tags = merge(local.common_tags, {
    Name     = "${local.name_prefix}-override-demo-sg"
    Scenario = "REMEDIATION-OVERRIDE"
    Attached = "none"
  })
}

# 전체 공개 규칙 — Security Hub FSBP EC2.19(공통 포트 전체 개방)가 잡는다.
# 3389(RDP)는 이 VPC 에서 쓰지 않는 포트라 실제 트래픽과 혼동되지 않는다.
resource "aws_vpc_security_group_ingress_rule" "override_demo_open" {
  count = var.enable_override_demo_sg ? 1 : 0

  security_group_id = aws_security_group.override_demo[0].id
  description       = "Intentional violation for override demo - revoking this affects nothing"
  ip_protocol       = "tcp"
  from_port         = 3389
  to_port           = 3389
  cidr_ipv4         = "0.0.0.0/0"
}
