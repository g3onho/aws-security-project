############################################
# 지리별 공격자 fleet — 5개 리전에 공인 공격자 EC2 1대씩
#
# 대상은 파리(홈 리전) DVWA 공인 IP(module.compute.web_dvwa_public_ip).
# enable_geo_attackers = true 이고 DVWA 인스턴스가 켜져 있을 때만 생성된다.
# 비용: 리전당 t3.micro 1대 상시 과금 → 시연 후 false 로 되돌려 제거.
#
# provider alias 는 module 블록마다 정적으로 지정해야 하므로 for_each 를 못 쓴다.
# → 리전 수(5)만큼 module 블록을 나열한다.
############################################

locals {
  geo_attackers_on = var.enable_geo_attackers && var.enable_dvwa_instance
  dvwa_target_ip   = module.compute.web_dvwa_public_ip

  # 공격 SSM 문서: 원본 YAML 하나를 읽어 각 리전 모듈에 넘긴다.
  atk_document_name    = "${local.name_prefix}-ATK-WebAttack"
  atk_document_content = file("${path.module}/modules/soar/documents/ATK-WebAttack.yaml")
}

module "attacker_us_virginia" {
  source    = "./modules/attacker"
  providers = { aws = aws.us_east_1 }

  name_prefix   = local.name_prefix
  region_label  = "us-virginia"
  instance_type = var.attacker_instance_type
  target_ip     = local.dvwa_target_ip
  enabled       = local.geo_attackers_on
  tags          = local.common_tags

  attack_document_name    = local.atk_document_name
  attack_document_content = local.atk_document_content
}

module "attacker_singapore" {
  source    = "./modules/attacker"
  providers = { aws = aws.ap_southeast_1 }

  name_prefix   = local.name_prefix
  region_label  = "singapore"
  instance_type = var.attacker_instance_type
  target_ip     = local.dvwa_target_ip
  enabled       = local.geo_attackers_on
  tags          = local.common_tags

  attack_document_name    = local.atk_document_name
  attack_document_content = local.atk_document_content
}

module "attacker_sydney" {
  source    = "./modules/attacker"
  providers = { aws = aws.ap_southeast_2 }

  name_prefix   = local.name_prefix
  region_label  = "sydney"
  instance_type = var.attacker_instance_type
  target_ip     = local.dvwa_target_ip
  enabled       = local.geo_attackers_on
  tags          = local.common_tags

  attack_document_name    = local.atk_document_name
  attack_document_content = local.atk_document_content
}

module "attacker_mumbai" {
  source    = "./modules/attacker"
  providers = { aws = aws.ap_south_1 }

  name_prefix   = local.name_prefix
  region_label  = "mumbai"
  instance_type = var.attacker_instance_type
  target_ip     = local.dvwa_target_ip
  enabled       = local.geo_attackers_on
  tags          = local.common_tags

  attack_document_name    = local.atk_document_name
  attack_document_content = local.atk_document_content
}

module "attacker_tokyo" {
  source    = "./modules/attacker"
  providers = { aws = aws.ap_northeast_1 }

  name_prefix   = local.name_prefix
  region_label  = "tokyo"
  instance_type = var.attacker_instance_type
  target_ip     = local.dvwa_target_ip
  enabled       = local.geo_attackers_on
  tags          = local.common_tags

  attack_document_name    = local.atk_document_name
  attack_document_content = local.atk_document_content
}

############################################
# 출력 — 대시보드/시연에서 쓰는 리전별 공격자 정보
############################################

output "geo_attackers" {
  description = "리전별 공격자 { 지역 => { instance_id, public_ip } }. 대시보드 SSM 타깃."
  value = local.geo_attackers_on ? {
    "us-virginia" = { instance_id = module.attacker_us_virginia.instance_id, public_ip = module.attacker_us_virginia.public_ip }
    "singapore"   = { instance_id = module.attacker_singapore.instance_id, public_ip = module.attacker_singapore.public_ip }
    "sydney"      = { instance_id = module.attacker_sydney.instance_id, public_ip = module.attacker_sydney.public_ip }
    "mumbai"      = { instance_id = module.attacker_mumbai.instance_id, public_ip = module.attacker_mumbai.public_ip }
    "tokyo"       = { instance_id = module.attacker_tokyo.instance_id, public_ip = module.attacker_tokyo.public_ip }
  } : {}
}
