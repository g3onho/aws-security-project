provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = var.project
      Environment = var.env
      Team        = var.team_name
      Owner       = var.owner
      ManagedBy   = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

# 실습 PC의 현재 공인 IP 자동 감지.
# admin_cidr 를 직접 넣으면 호출하지 않습니다 — CI(GitHub Actions)에서는
# 러너의 IP가 잡혀 엉뚱한 SG가 만들어지므로 반드시 admin_cidr 를 지정하세요.
data "http" "my_ip" {
  count = var.admin_cidr == "" ? 1 : 0

  url = "https://checkip.amazonaws.com/"
}
