############################################
# 지리별 공격 시연용 리전 provider alias (5개)
#
#   미국(버지니아)  us-east-1
#   싱가포르        ap-southeast-1
#   시드니          ap-southeast-2
#   인도(뭄바이)    ap-south-1
#   도쿄            ap-northeast-1
#
# 각 리전에 공인 공격자 EC2 1대씩. 서로 다른 국가 공인 IP로 파리(홈 리전) DVWA를
# 인터넷 경유 공격 → GuardDuty가 remoteIpDetails.geoLocation 으로 출발지
# 국가를 태깅한다. 대시보드 지도에 "미국발/싱가포르발/..." 로 표시된다.
#
# 태그는 루트 provider(providers.tf)와 동일 규칙 + Role=attacker 를 붙인다.
############################################

locals {
  attacker_tags = {
    Project     = var.project
    Environment = var.env
    Team        = var.team_name
    Owner       = var.owner
    ManagedBy   = "terraform"
    Role        = "attacker"
  }
}

provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
  default_tags { tags = local.attacker_tags }
}

provider "aws" {
  alias  = "ap_southeast_1"
  region = "ap-southeast-1"
  default_tags { tags = local.attacker_tags }
}

provider "aws" {
  alias  = "ap_southeast_2"
  region = "ap-southeast-2"
  default_tags { tags = local.attacker_tags }
}

provider "aws" {
  alias  = "ap_south_1"
  region = "ap-south-1"
  default_tags { tags = local.attacker_tags }
}

provider "aws" {
  alias  = "ap_northeast_1"
  region = "ap-northeast-1"
  default_tags { tags = local.attacker_tags }
}
