############################################
# 루트 — 모듈이 공유하는 이름은 여기서 먼저 확정합니다.
# (모듈 간 순환 참조 방지: soar 가 만드는 리소스의 '이름'을 compute 도
#  참조해야 하므로, 이름은 루트 locals 에서 정하고 생성만 각 모듈이 맡습니다.)
############################################

locals {
  name_prefix = "${var.project}-${var.env}"
  account_id  = data.aws_caller_identity.current.account_id
  region      = data.aws_region.current.region
  partition   = data.aws_partition.current.partition

  # 관리자 CIDR. admin_cidr 가 비었을 때만 실행 PC 공인 IP/32 를 자동 감지합니다.
  admin_cidr = var.admin_cidr != "" ? var.admin_cidr : "${chomp(data.http.my_ip[0].response_body)}/32"

  log_group_nginx    = "/${var.project}/${var.env}/web/nginx"
  log_group_mysql    = "/${var.project}/${var.env}/db/mysql"
  log_group_flowlogs = "/${var.project}/${var.env}/vpc/flowlogs"

  correlated_findings_table = "${local.name_prefix}-correlated-findings"
  remediation_actions_table = "${local.name_prefix}-remediation-actions"
  scan_results_bucket       = "${local.name_prefix}-scan-results-${local.account_id}"

  # SSM Automation 역할 이름 — compute(대시보드 PassRole 범위)와 soar 가 공유
  ssm_automation_role_name = "${local.name_prefix}-ssm-automation-role"

  # SNS 토픽 ARN 을 이름으로 조립합니다. compute -> soar 순환 참조를 끊기 위함
  # (soar 가 이 이름 그대로 토픽을 생성합니다).
  sns_topic_arn = "arn:${local.partition}:sns:${local.region}:${local.account_id}:${local.name_prefix}-alerts"

  common_tags = {
    Project = var.project
    Env     = var.env
  }
}

module "network" {
  source = "./modules/network"

  name_prefix        = local.name_prefix
  region             = local.region
  vpc_cidr           = var.vpc_cidr
  az_primary         = var.az_primary
  az_secondary       = var.az_secondary
  subnet_cidrs       = var.subnet_cidrs
  admin_cidr         = local.admin_cidr
  log_group_flowlogs = local.log_group_flowlogs
  log_retention_days = var.log_retention_days

  enable_nat_gateway       = var.enable_nat_gateway
  enable_vpc_endpoints     = var.enable_vpc_endpoints
  enable_alb               = var.enable_alb
  enable_flow_logs         = var.enable_flow_logs
  enable_attacker_instance = var.enable_attacker_instance

  tags = local.common_tags
}

module "security" {
  source = "./modules/security"

  name_prefix = local.name_prefix
  region      = local.region
  account_id  = local.account_id
  partition   = local.partition

  enable_guardduty               = var.enable_guardduty
  enable_guardduty_ai_protection = var.enable_guardduty_ai_protection
  enable_inspector2              = var.enable_inspector2
  enable_config                  = var.enable_config
  enable_security_hub            = var.enable_security_hub
  enable_access_analyzer         = var.enable_access_analyzer
  enable_cloudtrail              = var.enable_cloudtrail

  tags = local.common_tags
}

module "soar" {
  source = "./modules/soar"

  name_prefix = local.name_prefix
  region      = local.region
  account_id  = local.account_id
  partition   = local.partition

  log_group_nginx    = local.log_group_nginx
  log_group_mysql    = local.log_group_mysql
  log_retention_days = var.log_retention_days

  correlated_findings_table = local.correlated_findings_table
  remediation_actions_table = local.remediation_actions_table
  scan_results_bucket       = local.scan_results_bucket

  enable_auto_remediation  = var.enable_auto_remediation
  auto_remediable_patterns = var.auto_remediable_patterns
  alert_email              = var.alert_email

  enable_guardduty    = var.enable_guardduty
  enable_security_hub = var.enable_security_hub

  cpu_alarm_threshold       = var.cpu_alarm_threshold
  memory_alarm_threshold    = var.memory_alarm_threshold
  mysql_auth_fail_threshold = var.mysql_auth_fail_threshold

  monitored_instances = module.compute.monitored_instances

  tags = local.common_tags
}

module "compute" {
  source = "./modules/compute"

  name_prefix = local.name_prefix
  region      = local.region
  account_id  = local.account_id
  partition   = local.partition

  vpc_id                = module.network.vpc_id
  public_subnet_ids     = module.network.public_subnet_ids
  public_web_subnet_id  = module.network.public_web_subnet_id
  private_app_subnet_id = module.network.private_app_subnet_id
  private_db_subnet_id  = module.network.private_db_subnet_id

  sg_alb_id         = module.network.sg_alb_id
  sg_docker_host_id = module.network.sg_docker_host_id
  sg_dashboard_id   = module.network.sg_dashboard_id
  sg_web_dvwa_id    = module.network.sg_web_dvwa_id
  sg_db_auto_id     = module.network.sg_db_auto_id
  sg_db_manual_id   = module.network.sg_db_manual_id
  sg_attacker_id    = module.network.sg_attacker_id

  instance_type             = var.instance_type
  docker_host_instance_type = var.docker_host_instance_type
  db_instance_type          = var.db_instance_type
  db_name                   = var.db_name
  db_app_user               = var.db_app_user
  mysql_root_password       = var.mysql_root_password
  mysql_app_password        = var.mysql_app_password

  enable_alb               = var.enable_alb
  enable_waf               = var.enable_waf
  enable_dvwa_instance     = var.enable_dvwa_instance
  enable_attacker_instance = var.enable_attacker_instance

  log_group_nginx = local.log_group_nginx
  log_group_mysql = local.log_group_mysql

  correlated_findings_table = local.correlated_findings_table
  remediation_actions_table = local.remediation_actions_table
  scan_results_bucket       = local.scan_results_bucket

  ssm_automation_role_name = local.ssm_automation_role_name
  sns_topic_arn            = local.sns_topic_arn

  tags = local.common_tags
}
