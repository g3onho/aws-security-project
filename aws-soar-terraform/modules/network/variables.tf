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
variable "log_retention_days" { type = number }

variable "tags" {
  type    = map(string)
  default = {}
}
