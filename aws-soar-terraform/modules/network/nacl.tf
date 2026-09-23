############################################
# NACL — 서브넷 단위 1차 방어 (SG 는 인스턴스 단위 2차 방어)
# 기획서 아키텍처: 이중 방어. SEC-06 수동 개선(공격 IP 차단)이 쓰는 대상이기도 합니다.
#
# 소유권 경계 (docs/OWNERSHIP.md):
#   규칙은 aws_network_acl_rule 로만 선언합니다. aws_network_acl 안에 ingress/egress
#   블록을 쓰면 Terraform 이 규칙 목록 전체를 소유해서, ASR-BlockIpWithNacl 이 넣은
#   Deny 를 다음 apply 에서 지웁니다(차단 해제). 두 방식은 혼용할 수도 없습니다.
#   aws_default_network_acl 도 같은 이유로 쓰지 않습니다.
#   1 ~ 99 번은 SOAR 전용이라 이 파일에 선언하지 않습니다.
############################################

resource "aws_network_acl" "public" {
  vpc_id     = aws_vpc.this.id
  subnet_ids = [aws_subnet.public_web.id, aws_subnet.public_web_b.id]

  tags = merge(var.tags, { Name = "${var.name_prefix}-nacl-public" })
}

resource "aws_network_acl_rule" "public_in_http" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 100
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 80
  to_port        = 80
}

resource "aws_network_acl_rule" "public_in_https" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 443
  to_port        = 443
}

resource "aws_network_acl_rule" "public_in_ephemeral" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 120
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 65535
}

resource "aws_network_acl_rule" "public_out_all" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 100
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 0
  to_port        = 0
}

############################################
# Private NACL — VPC 내부 통신과 응답 트래픽만
#
# 규칙 번호 운영 원칙 (SEC-06 수동 개선):
#   1  ~  99 : 차단(Deny) 규칙 — 공격 IP 차단이 여기에 들어갑니다. SOAR 소유, 코드에 선언 금지.
#   100 이상 : 허용(Allow) 규칙 — Terraform 소유.
# NACL 은 번호 순으로 평가되므로 Deny 를 Allow 보다 앞 번호에 넣어야 합니다.
# 번호대 강제는 ASR-BlockIpWithNacl 문서가 합니다(1~99 외 번호·/32 외 CIDR 거부).
############################################

resource "aws_network_acl" "private" {
  vpc_id     = aws_vpc.this.id
  subnet_ids = [aws_subnet.private_app.id, aws_subnet.private_db.id]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-nacl-private"
    DenyRules = "1-99 reserved for SEC-06 manual IP blocking"
  })
}

resource "aws_network_acl_rule" "private_in_vpc" {
  network_acl_id = aws_network_acl.private.id
  rule_number    = 100
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = var.vpc_cidr
  from_port      = 0
  to_port        = 0
}

resource "aws_network_acl_rule" "private_in_ephemeral" {
  network_acl_id = aws_network_acl.private.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 65535
}

resource "aws_network_acl_rule" "private_out_all" {
  network_acl_id = aws_network_acl.private.id
  rule_number    = 100
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 0
  to_port        = 0
}
