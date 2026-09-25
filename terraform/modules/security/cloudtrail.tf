############################################
# CloudTrail (+ S3 + KMS) — 감사 로그 (SEC-09)
# 기획서: 로그 무결성(버저닝·KMS), finding/조치 상세에서 CloudTrail 이벤트 링크
############################################

data "aws_iam_policy_document" "trail_kms" {
  count = var.enable_cloudtrail ? 1 : 0

  statement {
    sid       = "EnableRoot"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${var.partition}:iam::${var.account_id}:root"]
    }
  }

  statement {
    sid       = "AllowCloudTrailEncrypt"
    actions   = ["kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "trail" {
  count = var.enable_cloudtrail ? 1 : 0

  description             = "${var.name_prefix} CloudTrail log encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.trail_kms[0].json

  tags = merge(var.tags, { Scenario = "SEC-09" })
}

resource "aws_kms_alias" "trail" {
  count = var.enable_cloudtrail ? 1 : 0

  name          = "alias/${var.name_prefix}-cloudtrail"
  target_key_id = aws_kms_key.trail[0].key_id
}

resource "aws_s3_bucket" "trail" {
  count = var.enable_cloudtrail ? 1 : 0

  bucket        = "${var.name_prefix}-cloudtrail-${var.account_id}"
  force_destroy = false # 로그는 실수 삭제 방지. destroy 시 수동 정리.

  tags = merge(var.tags, { Scenario = "SEC-09" })
}

resource "aws_s3_bucket_versioning" "trail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.trail[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.trail[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.trail[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.trail[0].arn
    }
    bucket_key_enabled = true
  }
}

data "aws_iam_policy_document" "trail_bucket" {
  count = var.enable_cloudtrail ? 1 : 0

  statement {
    sid       = "AWSCloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail[0].arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:${var.partition}:cloudtrail:${var.region}:${var.account_id}:trail/${var.name_prefix}-trail"]
    }
  }

  statement {
    sid       = "AWSCloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail[0].arn}/AWSLogs/${var.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.trail[0].id
  policy = data.aws_iam_policy_document.trail_bucket[0].json
}

resource "aws_cloudtrail" "this" {
  count = var.enable_cloudtrail ? 1 : 0

  name                          = "${var.name_prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.trail[0].id
  kms_key_id                    = aws_kms_key.trail[0].arn
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  tags = merge(var.tags, { Scenario = "SEC-09" })

  depends_on = [aws_s3_bucket_policy.trail]
}
