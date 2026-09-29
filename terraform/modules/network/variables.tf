variable "name_prefix" { type = string }
variable "vpc_cidr" { type = string }
variable "az_primary" { type = string }
variable "az_secondary" { type = string }
variable "admin_cidr" { type = string }
variable "region" { type = string }
variable "log_group_flowlogs" { type = string }

variable "subnet_cidrs" {
  type = object({
    public_web   = string
    private_db   = string
    private_app  = string
    public_web_b = string
  })
}

variable "enable_nat_gateway" { type = bool }
variable "enable_vpc_endpoints" { type = bool }
variable "enable_alb" { type = bool }
variable "enable_flow_logs" { type = bool }
variable "enable_attacker_instance" { type = bool }
variable "honeypot_demo_attacker_count" {
  type    = number
  default = 0
}
variable "log_retention_days" { type = number }

variable "tags" {
  type    = map(string)
  default = {}
}

# 대시보드 공개 범위. 실제 취약점 목록이 보이는 화면이므로 좁힐 수 있게 뺐다.
# 팀원이 여러 네트워크에 흩어져 있어 기본값은 전체 공개다.
variable "dashboard_ingress_cidr" {
  type    = string
  default = "0.0.0.0/0"
}
