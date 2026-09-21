variable "name_prefix" { type = string }
variable "region" { type = string }
variable "account_id" { type = string }
variable "partition" { type = string }

variable "enable_guardduty" { type = bool }
variable "enable_guardduty_ai_protection" { type = bool }
variable "enable_inspector2" { type = bool }
variable "enable_config" { type = bool }
variable "enable_security_hub" { type = bool }
variable "enable_access_analyzer" { type = bool }
variable "enable_cloudtrail" { type = bool }

variable "tags" {
  type    = map(string)
  default = {}
}
