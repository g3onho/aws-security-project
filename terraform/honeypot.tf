############################################
# A6 AI 미끼서버(허니팟) — 모듈 호출
#
# enable_honeypot = true 일 때만 생성. private-db 서브넷에 미끼 1대.
# 자동 차단(NACL)까지 켜려면 auto_remediable_controls 에 "HONEYPOT" 을 추가한다.
# (없으면 탐지·AI 분석은 되고, 차단은 '수동 대응 필요'로만 기록된다.)
#
# 주의: 미끼는 Bedrock·CloudWatch Logs·패키지 설치에 아웃바운드가 필요하다.
#       private-db 서브넷은 enable_nat_gateway = true 여야 한다.
############################################

module "honeypot" {
  count  = var.enable_honeypot ? 1 : 0
  source = "./modules/honeypot"

  name_prefix = local.name_prefix
  region      = local.region
  partition   = local.partition
  tags        = local.common_tags

  vpc_id    = module.network.vpc_id
  vpc_cidr  = var.vpc_cidr
  subnet_id = module.network.private_db_subnet_id

  instance_type = var.honeypot_instance_type
  enable_ai     = var.enable_honeypot_ai
  ai_model_id   = var.honeypot_ai_model_id
  listen_port   = 22

  log_retention_days = var.log_retention_days
  alarm_period       = var.honeypot_alarm_period
  # 알람 SNS 는 연결하지 않는다: 자동 차단은 soar EventBridge→asr_trigger 로 가고,
  # 알림은 asr_trigger 가 자체 SNS 로 보낸다. (soar↔honeypot 순환 의존 방지)
}
