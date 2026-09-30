############################################
# tier_check — 3계층(Nginx·Flask·MySQL) 점검 결과 저장
#
#  EventBridge(주기) ─► tier_check Lambda ─► SSM Run Command(TIER-Check, 읽기 전용) ─► docker-host
#                              └─► DynamoDB(tier_status) ◄── 대시보드 /api/infra/status 가 읽음
#
# 대시보드는 컨테이너에 접속하지 않고 이 표에 저장된 증거만 읽는다(DEC-016).
# 점검 주기와 '오래된 결과' 기준은 근거가 확정되지 않은 임시값이다(DEC-039 미결정 항목). 변수로만 바꾼다.
############################################

# 계층당 1행(tier/web · tier/app · tier/db)의 최신 결과만 둔다. 이력은 쌓지 않는다.
resource "aws_dynamodb_table" "tier_status" {
  name         = var.tier_status_table
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "tier_id"

  attribute {
    name = "tier_id"
    type = "S"
  }

  tags = merge(var.tags, { Purpose = "three-tier-health-evidence" })
}

data "archive_file" "tier_check" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_src/tier_check"
  output_path = "${path.module}/build/tier_check.zip"
}

resource "aws_iam_role" "tier_check" {
  count = var.enable_tier_check ? 1 : 0

  name               = "${var.name_prefix}-tier-check-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "tier_check_basic" {
  count = var.enable_tier_check ? 1 : 0

  role       = aws_iam_role.tier_check[0].name
  policy_arn = "arn:${var.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "tier_check" {
  statement {
    sid       = "FindTarget"
    actions   = ["ec2:DescribeInstances"]
    resources = ["*"]
  }

  # 읽기 전용 점검 문서 하나만, Role=service-3tier 태그가 붙은 인스턴스에만 실행한다.
  statement {
    sid       = "RunTierCheckDocument"
    actions   = ["ssm:SendCommand"]
    resources = ["arn:${var.partition}:ssm:${var.region}:${var.account_id}:document/${aws_ssm_document.command["TIER-Check"].name}"]
  }
  statement {
    sid       = "RunOnServiceInstanceOnly"
    actions   = ["ssm:SendCommand"]
    resources = ["arn:${var.partition}:ec2:${var.region}:${var.account_id}:instance/*"]
    condition {
      test     = "StringEquals"
      variable = "ssm:resourceTag/Role"
      values   = ["service-3tier"]
    }
  }

  statement {
    sid       = "ReadCommandResult"
    actions   = ["ssm:GetCommandInvocation"]
    resources = ["*"]
  }

  statement {
    sid       = "WriteTierStatus"
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.tier_status.arn]
  }
}

resource "aws_iam_role_policy" "tier_check" {
  count = var.enable_tier_check ? 1 : 0

  name   = "${var.name_prefix}-tier-check-policy"
  role   = aws_iam_role.tier_check[0].id
  policy = data.aws_iam_policy_document.tier_check.json
}

resource "aws_lambda_function" "tier_check" {
  count = var.enable_tier_check ? 1 : 0

  function_name = "${var.name_prefix}-tier-check"
  role          = aws_iam_role.tier_check[0].arn
  runtime       = "python3.12"
  handler       = "handler.handler"
  # SSM 결과를 최대 60초 기다린다(TIER_WAIT_SECONDS). 그 안에 못 받으면 확인 불가로 기록하고 끝낸다.
  timeout     = 90
  memory_size = 128

  filename         = data.archive_file.tier_check.output_path
  source_code_hash = data.archive_file.tier_check.output_base64sha256

  environment {
    variables = {
      TIER_STATUS_TABLE        = aws_dynamodb_table.tier_status.name
      TIER_CHECK_DOCUMENT      = aws_ssm_document.command["TIER-Check"].name
      TIER_STALE_AFTER_SECONDS = tostring(var.tier_stale_after_minutes * 60)
      TARGET_TAG_KEY           = "Role"
      TARGET_TAG_VALUE         = "service-3tier"
    }
  }

  depends_on = [aws_iam_role_policy.tier_check, aws_iam_role_policy_attachment.tier_check_basic]

  tags = var.tags
}

# 점검은 읽기 전용이지만 실행 요청을 중복으로 만들지 않도록 자동 재시도는 하지 않는다(다음 주기가 다시 점검한다).
resource "aws_lambda_function_event_invoke_config" "tier_check" {
  count = var.enable_tier_check ? 1 : 0

  function_name          = aws_lambda_function.tier_check[0].function_name
  maximum_retry_attempts = 0
}

resource "aws_cloudwatch_event_rule" "tier_check" {
  count = var.enable_tier_check ? 1 : 0

  name                = "${var.name_prefix}-tier-check"
  description         = "Every ${var.tier_check_rate_minutes} minute(s): check Nginx/Flask/MySQL containers on docker-host and store the result"
  schedule_expression = var.tier_check_rate_minutes == 1 ? "rate(1 minute)" : "rate(${var.tier_check_rate_minutes} minutes)"
  tags                = var.tags
}

resource "aws_cloudwatch_event_target" "tier_check" {
  count = var.enable_tier_check ? 1 : 0

  rule      = aws_cloudwatch_event_rule.tier_check[0].name
  target_id = "tier-check"
  arn       = aws_lambda_function.tier_check[0].arn
}

resource "aws_lambda_permission" "tier_check" {
  count = var.enable_tier_check ? 1 : 0

  statement_id  = "AllowTierCheckSchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.tier_check[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.tier_check[0].arn
}
