############################################
# 보안 그룹
#
# 규칙은 aws_vpc_security_group_*_rule 리소스로 분리해서 선언합니다.
# 인라인 ingress 블록을 쓰면 Terraform 이 "선언되지 않은 규칙"을 모두 삭제하므로,
# 시연 스크립트가 넣은 3306/0.0.0.0/0 규칙과 계속 충돌합니다.
#
# 소유권 경계 (terraform/infrastructure-design.md § IAM과 Terraform/SOAR 소유권 경계):
#   시연용 취약 규칙(0.0.0.0/0 인바운드)은 이 파일에 리소스로 선언하지 않습니다.
#   demo/trigger-auto-remediation.sh 로만 주입합니다. 리소스(또는 변수 토글)로 선언하면
#   ASR-RevokeSecurityGroupIngress 가 회수한 규칙을 다음 apply 가 다시 만듭니다.
############################################

# --- ALB -----------------------------------------------------------------
resource "aws_security_group" "alb" {
  name        = "${var.name_prefix}-alb-sg"
  description = "ALB ingress from Internet"
  vpc_id      = aws_vpc.this.id

  tags = merge(var.tags, { Name = "${var.name_prefix}-alb-sg" })
}

resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  security_group_id = aws_security_group.alb.id
  description       = "HTTP from Internet (redirected to HTTPS)"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  security_group_id = aws_security_group.alb.id
  description       = "HTTPS from Internet"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "alb_all" {
  security_group_id = aws_security_group.alb.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

# --- Docker Host (Nginx + Flask + MySQL 컨테이너) -------------------------
resource "aws_security_group" "docker_host" {
  name        = "${var.name_prefix}-docker-host-sg"
  description = "Nginx is the only exposed port (Docker checklist #13)"
  vpc_id      = aws_vpc.this.id

  tags = merge(var.tags, { Name = "${var.name_prefix}-docker-host-sg" })
}

resource "aws_vpc_security_group_ingress_rule" "docker_host_from_alb_http" {
  count = var.enable_alb ? 1 : 0

  security_group_id            = aws_security_group.docker_host.id
  description                  = "HTTP from ALB only"
  ip_protocol                  = "tcp"
  from_port                    = 80
  to_port                      = 80
  referenced_security_group_id = aws_security_group.alb.id
}

resource "aws_vpc_security_group_ingress_rule" "docker_host_from_alb_https" {
  count = var.enable_alb ? 1 : 0

  security_group_id            = aws_security_group.docker_host.id
  description                  = "HTTPS from ALB only"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.alb.id
}

# ALB 를 끈 상태에서도 팀이 점검(nmap/ZAP/curl)할 수 있도록 관리자 IP 는 허용
resource "aws_vpc_security_group_ingress_rule" "docker_host_from_admin_http" {
  security_group_id = aws_security_group.docker_host.id
  description       = "HTTP from admin IP for manual scanning (SEC-02)"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = var.admin_cidr
}

resource "aws_vpc_security_group_ingress_rule" "docker_host_from_admin_https" {
  security_group_id = aws_security_group.docker_host.id
  description       = "HTTPS from admin IP for manual scanning (SEC-02)"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = var.admin_cidr
}

resource "aws_vpc_security_group_egress_rule" "docker_host_all" {
  security_group_id = aws_security_group.docker_host.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

# --- 보안 대시보드 --------------------------------------------------------
resource "aws_security_group" "dashboard" {
  name        = "${var.name_prefix}-dashboard-sg"
  description = "SOAR dashboard, reached via SSM port forwarding"
  vpc_id      = aws_vpc.this.id

  tags = merge(var.tags, { Name = "${var.name_prefix}-dashboard-sg" })
}

resource "aws_vpc_security_group_ingress_rule" "dashboard_app" {
  security_group_id = aws_security_group.dashboard.id
  description       = "Flask dashboard from inside the VPC (SSM port forwarding)"
  ip_protocol       = "tcp"
  from_port         = 5000
  to_port           = 5000
  cidr_ipv4         = var.vpc_cidr
}

resource "aws_vpc_security_group_egress_rule" "dashboard_all" {
  security_group_id = aws_security_group.dashboard.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

# --- DVWA 웹 서버 (SEC-08) ------------------------------------------------
resource "aws_security_group" "web_dvwa" {
  name        = "${var.name_prefix}-web-dvwa-sg"
  description = "Intentionally vulnerable web app for SEC-08 demonstration"
  vpc_id      = aws_vpc.this.id

  tags = merge(var.tags, {
    Name     = "${var.name_prefix}-web-dvwa-sg"
    Scenario = "SEC-08"
  })
}

resource "aws_vpc_security_group_ingress_rule" "web_dvwa_from_alb" {
  count = var.enable_alb ? 1 : 0

  security_group_id            = aws_security_group.web_dvwa.id
  description                  = "HTTP from ALB"
  ip_protocol                  = "tcp"
  from_port                    = 80
  to_port                      = 80
  referenced_security_group_id = aws_security_group.alb.id
}

resource "aws_vpc_security_group_ingress_rule" "web_dvwa_from_admin" {
  security_group_id = aws_security_group.web_dvwa.id
  description       = "HTTP from admin IP only - never open this to 0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = var.admin_cidr
}

resource "aws_vpc_security_group_egress_rule" "web_dvwa_all" {
  security_group_id = aws_security_group.web_dvwa.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

############################################
# MySQL EC2 용 보안 그룹 2개 — 자동/수동 대조군
#
# DB EC2 는 1대지만 보안 그룹을 2개 붙입니다.
# AWS Config 규칙은 EC2 가 아니라 '보안 그룹' 단위로 평가하므로,
# 같은 위반(3306/0.0.0.0/0)을 두 SG 에 넣으면
#   - AutoRemediation=enabled 태그가 있는 db-auto-sg  -> SSM 이 즉시 회수
#   - 태그가 없는 db-manual-sg                        -> SNS 알림만, 승인 후 조치
# 를 한 화면에서 비교할 수 있습니다. (기획서 최종 시연 목표 ①②)
############################################

resource "aws_security_group" "db_auto" {
  name        = "${var.name_prefix}-db-auto-sg"
  description = "MySQL SG - automatic remediation target (SEC-03)"
  vpc_id      = aws_vpc.this.id

  tags = merge(var.tags, {
    Name             = "${var.name_prefix}-db-auto-sg"
    AutoRemediation  = "enabled"
    Scenario         = "SEC-03"
    RemediationGroup = "auto"
  })
}

resource "aws_vpc_security_group_ingress_rule" "db_auto_from_docker_host" {
  security_group_id            = aws_security_group.db_auto.id
  description                  = "MySQL from Docker host by security group reference, not CIDR"
  ip_protocol                  = "tcp"
  from_port                    = 3306
  to_port                      = 3306
  referenced_security_group_id = aws_security_group.docker_host.id
}

resource "aws_vpc_security_group_ingress_rule" "db_auto_from_dashboard" {
  security_group_id            = aws_security_group.db_auto.id
  description                  = "MySQL from dashboard by security group reference"
  ip_protocol                  = "tcp"
  from_port                    = 3306
  to_port                      = 3306
  referenced_security_group_id = aws_security_group.dashboard.id
}

resource "aws_vpc_security_group_egress_rule" "db_auto_all" {
  security_group_id = aws_security_group.db_auto.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_security_group" "db_manual" {
  name        = "${var.name_prefix}-db-manual-sg"
  description = "MySQL SG - control group, notification only (SEC-03 / SEC-06)"
  vpc_id      = aws_vpc.this.id

  # AutoRemediation 태그를 일부러 붙이지 않습니다. 이것이 대조군입니다.
  tags = merge(var.tags, {
    Name             = "${var.name_prefix}-db-manual-sg"
    Scenario         = "SEC-03/SEC-06"
    RemediationGroup = "manual"
  })
}

resource "aws_vpc_security_group_ingress_rule" "db_manual_from_docker_host" {
  security_group_id            = aws_security_group.db_manual.id
  description                  = "MySQL from Docker host by security group reference"
  ip_protocol                  = "tcp"
  from_port                    = 3306
  to_port                      = 3306
  referenced_security_group_id = aws_security_group.docker_host.id
}

resource "aws_vpc_security_group_egress_rule" "db_manual_all" {
  security_group_id = aws_security_group.db_manual.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

# --- 내부 공격용 EC2 (옵션) ----------------------------------------------
resource "aws_security_group" "attacker" {
  # 단일 공격자 또는 허니팟 시연 fleet 이 있으면 만든다(주소 [0] 유지).
  count = var.enable_attacker_instance || var.honeypot_demo_attacker_count > 0 ? 1 : 0

  name        = "${var.name_prefix}-attacker-sg"
  description = "Internal attack simulation host, egress only"
  vpc_id      = aws_vpc.this.id

  tags = merge(var.tags, { Name = "${var.name_prefix}-attacker-sg" })
}

resource "aws_vpc_security_group_egress_rule" "attacker_all" {
  count = var.enable_attacker_instance || var.honeypot_demo_attacker_count > 0 ? 1 : 0

  security_group_id = aws_security_group.attacker[0].id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

# 공격용 EC2 가 있을 때만 DB 로 들어가는 경로를 엽니다 (SEC-06 Hydra 재현용).
resource "aws_vpc_security_group_ingress_rule" "db_manual_from_attacker" {
  count = var.enable_attacker_instance ? 1 : 0

  security_group_id            = aws_security_group.db_manual.id
  description                  = "MySQL from internal attack host for SEC-06 brute force demo"
  ip_protocol                  = "tcp"
  from_port                    = 3306
  to_port                      = 3306
  referenced_security_group_id = aws_security_group.attacker[0].id
}

# --- VPC 엔드포인트 -------------------------------------------------------
resource "aws_security_group" "vpce" {
  name        = "${var.name_prefix}-vpce-sg"
  description = "HTTPS from inside the VPC to interface endpoints"
  vpc_id      = aws_vpc.this.id

  tags = merge(var.tags, { Name = "${var.name_prefix}-vpce-sg" })
}

resource "aws_vpc_security_group_ingress_rule" "vpce_https" {
  security_group_id = aws_security_group.vpce.id
  description       = "HTTPS from VPC"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = var.vpc_cidr
}

resource "aws_vpc_security_group_egress_rule" "vpce_all" {
  security_group_id = aws_security_group.vpce.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

# 대시보드 전용 포트.
# ALB 는 경로 재작성을 못 한다. /dashboard 로 보내면 Flask 가 그 경로를 몰라 404 다.
# 그래서 포트로 가른다 — 8080 은 통째로 대시보드 타겟 그룹이 받는다.
# 공개 범위는 dashboard_ingress_cidr 로 조절한다(기본 전체 공개).
resource "aws_vpc_security_group_ingress_rule" "alb_dashboard" {
  count = var.enable_alb ? 1 : 0

  security_group_id = aws_security_group.alb.id
  description       = "Security dashboard via ALB"
  ip_protocol       = "tcp"
  from_port         = 8080
  to_port           = 8080
  cidr_ipv4         = var.dashboard_ingress_cidr
}

# DVWA 전용 포트(8081). 취약 앱이라 관리자 IP 만 — 절대 0.0.0.0/0 금지.
resource "aws_vpc_security_group_ingress_rule" "alb_dvwa" {
  count = var.enable_alb ? 1 : 0

  security_group_id = aws_security_group.alb.id
  description       = "DVWA via ALB - admin IP only"
  ip_protocol       = "tcp"
  from_port         = 8081
  to_port           = 8081
  cidr_ipv4         = var.admin_cidr
}
