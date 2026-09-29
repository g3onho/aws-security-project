############################################
# EC2 — 기획서 아키텍처 시트 기준
#
#  docker-host (Private-App) : Nginx + Flask + MySQL 컨테이너 = 보호 대상 3-Tier 서비스
#  db          (Private-DB)  : MySQL EC2 1대. SG 2개(db-auto / db-manual)를 함께 붙여
#                              자동 / 수동 대조군을 한 인스턴스에서 시연합니다.
#  dashboard   (Private-App) : SOAR 보안 대시보드
#  web-dvwa    (Public-Web)  : SEC-08 웹 공격 시연 대상 (옵션)
#  attacker    (Private-App) : 내부 공격 재현용 (옵션)
############################################

locals {
  common_metadata = {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 강제
    http_put_response_hop_limit = 2          # 컨테이너에서의 호출 허용
  }
}

# --- Docker Host : 보호 대상 3-Tier 서비스 -------------------------------
resource "aws_instance" "docker_host" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.docker_host_instance_type
  subnet_id              = var.private_app_subnet_id
  vpc_security_group_ids = [var.sg_docker_host_id]
  iam_instance_profile   = aws_iam_instance_profile.docker_host.name

  metadata_options {
    http_endpoint               = local.common_metadata.http_endpoint
    http_tokens                 = local.common_metadata.http_tokens
    http_put_response_hop_limit = local.common_metadata.http_put_response_hop_limit
  }

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = templatefile("${path.module}/templates/docker-host.sh.tftpl", {
    region              = var.region
    project             = var.name_prefix
    db_secret_name      = aws_secretsmanager_secret.db.name
    db_name             = var.db_name
    db_app_user         = var.db_app_user
    log_group_nginx     = var.log_group_nginx
    scan_results_bucket = var.scan_results_bucket
    ecr_repository_url  = aws_ecr_repository.app.repository_url
  })

  user_data_replace_on_change = true

  tags = merge(var.tags, {
    Name     = "${var.name_prefix}-docker-host"
    Role     = "service-3tier"
    Scenario = "SEC-02/SEC-04/SEC-07"
  })
}

# --- MySQL EC2 : 탐지·조치 대상 -----------------------------------------
resource "aws_instance" "db" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.db_instance_type
  subnet_id     = var.private_db_subnet_id

  # 보안 그룹 2개를 함께 붙입니다. Config 는 SG 단위로 평가하므로
  # 태그가 있는 db-auto-sg 만 자동 회수되고 db-manual-sg 는 알림만 갑니다.
  vpc_security_group_ids = [var.sg_db_auto_id, var.sg_db_manual_id]
  iam_instance_profile   = aws_iam_instance_profile.db.name

  metadata_options {
    http_endpoint               = local.common_metadata.http_endpoint
    http_tokens                 = local.common_metadata.http_tokens
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = templatefile("${path.module}/templates/mysql-db.sh.tftpl", {
    region          = var.region
    project         = var.name_prefix
    db_secret_name  = aws_secretsmanager_secret.db.name
    db_name         = var.db_name
    db_app_user     = var.db_app_user
    log_group_mysql = var.log_group_mysql
  })

  user_data_replace_on_change = true

  tags = merge(var.tags, {
    Name     = "${var.name_prefix}-db"
    Role     = "database"
    Scenario = "SEC-03/SEC-06"
  })

  depends_on = [aws_secretsmanager_secret_version.db]
}

# --- 보안 대시보드 -------------------------------------------------------
resource "aws_instance" "dashboard" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = var.private_app_subnet_id
  vpc_security_group_ids = [var.sg_dashboard_id]
  iam_instance_profile   = aws_iam_instance_profile.dashboard.name

  metadata_options {
    http_endpoint               = local.common_metadata.http_endpoint
    http_tokens                 = local.common_metadata.http_tokens
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = templatefile("${path.module}/templates/dashboard.sh.tftpl", {
    region                    = var.region
    project                   = var.name_prefix
    correlated_findings_table = var.correlated_findings_table
    automation_role_arn       = local.ssm_automation_role_arn
    remediation_actions_table = var.remediation_actions_table
    ip_blocklist_table        = var.ip_blocklist_table
    assistant_enabled         = var.enable_assistant
    assistant_model           = var.assistant_model
    honeypot_log_group        = var.honeypot_log_group
    honeypot_alarm_name       = var.honeypot_alarm_name
    private_nacl_id           = var.private_nacl_id
    vpc_cidr                  = var.vpc_cidr
    findings_table            = var.findings_table
    vulnerabilities_table     = var.vulnerabilities_table
    event_source              = var.dashboard_event_source
    vulnerability_source      = var.dashboard_vulnerability_source
    scan_results_bucket       = var.scan_results_bucket
    sns_topic_arn             = var.sns_topic_arn
    auto_remediable_patterns  = join(",", var.auto_remediable_patterns)
    auto_remediable_controls  = join(",", var.auto_remediable_controls)
    enable_auto_remediation   = tostring(var.enable_auto_remediation)
    # 지리별 웹보안검사 [시작] 대상 DVWA 공인 IP (없으면 실행 경로는 409로 비활성).
    dvwa_target_ip = var.enable_dvwa_instance ? aws_instance.web_dvwa[0].public_ip : ""
    # 웹 공격(hydra) 대상 URL — ALB:8081(WAF 경유). DVWA IP 직접은 WAF 를 안 타 빨간선이 안 뜬다.
    dvwa_web_url = var.enable_alb && var.enable_dvwa_instance ? "http://${aws_lb.main[0].dns_name}:8081" : ""
    # 코드 zip 의 MD5. 코드가 바뀌면 user_data 가 바뀌어 인스턴스가 새로 뜬다.
    code_version = var.enable_dashboard_deploy ? data.archive_file.dashboard[0].output_md5 : "none"
  })

  # 코드가 S3 에 올라간 뒤에 인스턴스가 떠야 한다. 순서가 바뀌면 부팅 때 zip 이 없다.
  depends_on = [aws_s3_object.dashboard_code]

  user_data_replace_on_change = true

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-dashboard"
    Role = "soar-dashboard"
  })
}

# --- DVWA 웹 서버 (SEC-08) ----------------------------------------------
resource "aws_instance" "web_dvwa" {
  count = var.enable_dvwa_instance ? 1 : 0

  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = var.public_web_subnet_id
  vpc_security_group_ids = [var.sg_web_dvwa_id]
  iam_instance_profile   = aws_iam_instance_profile.web_dvwa[0].name

  metadata_options {
    http_endpoint               = local.common_metadata.http_endpoint
    http_tokens                 = local.common_metadata.http_tokens
    http_put_response_hop_limit = 2
  }

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = templatefile("${path.module}/templates/web-dvwa.sh.tftpl", {
    region          = var.region
    project         = var.name_prefix
    log_group_nginx = var.log_group_nginx
  })

  user_data_replace_on_change = true

  tags = merge(var.tags, {
    Name     = "${var.name_prefix}-web-dvwa"
    Role     = "vulnerable-web"
    Scenario = "SEC-08"
  })
}

# --- 내부 공격용 EC2 (옵션) ---------------------------------------------
resource "aws_instance" "attacker" {
  count = var.enable_attacker_instance ? 1 : 0

  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = var.private_app_subnet_id
  vpc_security_group_ids = [var.sg_attacker_id]
  iam_instance_profile   = aws_iam_instance_profile.attacker[0].name

  metadata_options {
    http_endpoint               = local.common_metadata.http_endpoint
    http_tokens                 = local.common_metadata.http_tokens
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = templatefile("${path.module}/templates/attacker.sh.tftpl", {
    region              = var.region
    project             = var.name_prefix
    scan_results_bucket = var.scan_results_bucket
  })

  user_data_replace_on_change = true

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-attacker"
    Role = "attack-simulation"
    Note = "Team-owned isolated VPC only"
  })
}
