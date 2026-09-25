############################################
# Secrets Manager — DB 자격증명
# Docker 체크리스트 #9 (코드 하드코딩 금지) / #12 (Secret Manager 전환)
# SEC-07 수동 개선의 최종 목표 상태이기도 합니다.
############################################

resource "random_password" "db_root" {
  length           = 24
  special          = true
  override_special = "!#$%*_-+="
}

resource "random_password" "db_app" {
  length           = 24
  special          = true
  override_special = "!#$%*_-+="
}

locals {
  db_root_password = var.mysql_root_password != "" ? var.mysql_root_password : random_password.db_root.result
  db_app_password  = var.mysql_app_password != "" ? var.mysql_app_password : random_password.db_app.result
}

resource "aws_secretsmanager_secret" "db" {
  name                    = "${var.name_prefix}/mysql"
  description             = "MySQL credentials for the 3-tier service and the standalone DB instance"
  recovery_window_in_days = 0 # 실습용. 운영에서는 7일 이상을 권장합니다.

  tags = merge(var.tags, { Scenario = "SEC-07" })
}

resource "aws_secretsmanager_secret_version" "db" {
  secret_id = aws_secretsmanager_secret.db.id

  secret_string = jsonencode({
    root_password = local.db_root_password
    app_user      = var.db_app_user
    app_password  = local.db_app_password
    db_name       = var.db_name
  })
}
