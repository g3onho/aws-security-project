############################################
# 대시보드 코드 배포
#
# 코드를 user_data 에 넣을 수 없다(16KB 제한). S3 에 올려두고 인스턴스가 받아간다.
# 버킷은 scan-results 를 deploy/ 접두사로 재사용한다 — 대시보드 역할에 이미
# s3:GetObject + s3:ListBucket 이 있어서(compute/iam.tf ReadScanResults)
# 새 버킷을 만들면 IAM 까지 같이 고쳐야 한다.
############################################

locals {
  dashboard_src = "${path.module}/../../../dashboard"
}

# instance/ 는 제외한다 — 비밀번호 평문 파일 · SQLite DB · 세션키가 들어있다.
data "archive_file" "dashboard" {
  count = var.enable_dashboard_deploy ? 1 : 0

  type        = "zip"
  source_dir  = local.dashboard_src
  output_path = "${path.module}/.build/dashboard.zip"

  excludes = [
    "backend/instance",
    "backend/instance/local.sqlite3",
    "backend/instance/session.key",
    "backend/instance/initial-login.txt",
    "backend/__pycache__",
    "backend/app/__pycache__",
    "backend/tests",
    "frontend/tests",
  ]
}

resource "aws_s3_object" "dashboard_code" {
  count = var.enable_dashboard_deploy ? 1 : 0

  bucket = var.scan_results_bucket
  key    = "deploy/dashboard.zip"
  source = data.archive_file.dashboard[0].output_path

  # 내용이 바뀌면 이 해시가 바뀌고, user_data 가 해시를 참조하므로
  # 코드만 고쳐도 인스턴스가 새 코드를 받아간다.
  etag = data.archive_file.dashboard[0].output_md5
}
