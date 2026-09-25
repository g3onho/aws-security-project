############################################
# AWS Config — 설정 값 상시 평가 (자동 모니터링, SEC-01/03 1차 탐지)
# 비용 절감: 전체 기록 대신 필요한 리소스 타입만 기록.
############################################

# --- 기록기용 S3 ---------------------------------------------------------
resource "aws_s3_bucket" "config" {
  count = var.enable_config ? 1 : 0

  bucket        = "${var.name_prefix}-config-${var.account_id}"
  force_destroy = true

  tags = var.tags
}

resource "aws_s3_bucket_public_access_block" "config" {
  count  = var.enable_config ? 1 : 0
  bucket = aws_s3_bucket.config[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "config_bucket" {
  count = var.enable_config ? 1 : 0

  statement {
    sid       = "AWSConfigBucketPermissionsCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.config[0].arn]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }

  statement {
    sid       = "AWSConfigBucketDelivery"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config[0].arn}/AWSLogs/${var.account_id}/Config/*"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "config" {
  count  = var.enable_config ? 1 : 0
  bucket = aws_s3_bucket.config[0].id
  policy = data.aws_iam_policy_document.config_bucket[0].json
}

# --- 기록기 역할 ---------------------------------------------------------
data "aws_iam_policy_document" "config_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "config" {
  count              = var.enable_config ? 1 : 0
  name               = "${var.name_prefix}-config-role"
  assume_role_policy = data.aws_iam_policy_document.config_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "config_managed" {
  count      = var.enable_config ? 1 : 0
  role       = aws_iam_role.config[0].name
  policy_arn = "arn:${var.partition}:iam::aws:policy/service-role/AWS_ConfigRole"
}

data "aws_iam_policy_document" "config_s3_write" {
  count = var.enable_config ? 1 : 0

  statement {
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config[0].arn}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.config[0].arn]
  }
}

resource "aws_iam_role_policy" "config_s3_write" {
  count  = var.enable_config ? 1 : 0
  name   = "${var.name_prefix}-config-s3"
  role   = aws_iam_role.config[0].id
  policy = data.aws_iam_policy_document.config_s3_write[0].json
}

# --- 기록기 / 전송 채널 ---------------------------------------------------
resource "aws_config_configuration_recorder" "this" {
  count = var.enable_config ? 1 : 0

  name     = "${var.name_prefix}-recorder"
  role_arn = aws_iam_role.config[0].arn

  recording_group {
    all_supported                 = false
    include_global_resource_types = false
    resource_types = [
      "AWS::EC2::SecurityGroup",
      "AWS::EC2::Instance",
      "AWS::EC2::NetworkAcl",
      "AWS::IAM::Role",
      "AWS::IAM::User",
      "AWS::S3::Bucket",
      "AWS::CloudTrail::Trail",
    ]
  }
}

resource "aws_config_delivery_channel" "this" {
  count = var.enable_config ? 1 : 0

  name           = "${var.name_prefix}-delivery"
  s3_bucket_name = aws_s3_bucket.config[0].id

  depends_on = [aws_config_configuration_recorder.this]
}

resource "aws_config_configuration_recorder_status" "this" {
  count = var.enable_config ? 1 : 0

  name       = aws_config_configuration_recorder.this[0].name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.this]
}

# --- 관리형 규칙 4개 -----------------------------------------------------
# SEC-01: SSH 22 전체 개방 / SEC-03: 공통 포트(3306 포함) 전체 개방
resource "aws_config_config_rule" "restricted_ssh" {
  count = var.enable_config ? 1 : 0

  name = "${var.name_prefix}-restricted-ssh"

  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }

  tags       = merge(var.tags, { Scenario = "SEC-01" })
  depends_on = [aws_config_configuration_recorder_status.this]
}

resource "aws_config_config_rule" "restricted_common_ports" {
  count = var.enable_config ? 1 : 0

  name = "${var.name_prefix}-restricted-common-ports"

  input_parameters = jsonencode({
    blockedPort1 = "22"
    blockedPort2 = "3306"
    blockedPort3 = "3389"
    blockedPort4 = "23"
  })

  source {
    owner             = "AWS"
    source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
  }

  tags       = merge(var.tags, { Scenario = "SEC-03" })
  depends_on = [aws_config_configuration_recorder_status.this]
}

# SEC-05: 조건 없는 IAM 정책 / SEC-09: CloudTrail 활성 여부
resource "aws_config_config_rule" "iam_no_admin" {
  count = var.enable_config ? 1 : 0

  name = "${var.name_prefix}-iam-no-full-admin"

  source {
    owner             = "AWS"
    source_identifier = "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS"
  }

  tags       = merge(var.tags, { Scenario = "SEC-05" })
  depends_on = [aws_config_configuration_recorder_status.this]
}

resource "aws_config_config_rule" "cloudtrail_enabled" {
  count = var.enable_config ? 1 : 0

  name = "${var.name_prefix}-cloudtrail-enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }

  tags       = merge(var.tags, { Scenario = "SEC-09" })
  depends_on = [aws_config_configuration_recorder_status.this]
}
