############################################
# finding_sync (v21, PR-4) — 탐지·취약점을 DynamoDB 에 적재
#
#  ① Security Hub Findings - Imported (Inspector 제외) ─┐
#  ② Inspector2 Finding                                 ├─► finding_sync ─► findings / vulnerabilities 테이블
#  ③ 스케줄(finding_sync_schedule) — 원본 전체 대조      ┘        │ 실패(재시도 후) → SQS DLQ
#                                                              └ 오류·DLQ 알람 → SNS
# 대시보드는 이 테이블을 읽는다(EVENT_SOURCE / VULNERABILITY_SOURCE = dynamodb).
# 최초 백필은 ③과 같은 코드: aws lambda invoke --payload '{"action":"reconcile"}'
############################################

data "archive_file" "finding_sync" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_src/finding_sync"
  output_path = "${path.module}/build/finding_sync.zip"
}

# --- 실패 보관(DLQ) ----------------------------------------------------------
# 비동기 호출이 재시도 후에도 실패하면 원래 이벤트를 여기에 남긴다(조용히 사라지지 않게).
resource "aws_sqs_queue" "finding_sync_dlq" {
  name                      = "${var.name_prefix}-finding-sync-dlq"
  message_retention_seconds = 1209600 # 14일
  sqs_managed_sse_enabled   = true
  tags                      = var.tags
}

# --- 실행 역할 ----------------------------------------------------------------
resource "aws_iam_role" "finding_sync" {
  name               = "${var.name_prefix}-finding-sync-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "finding_sync_basic" {
  role       = aws_iam_role.finding_sync.name
  policy_arn = "arn:${var.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "finding_sync" {
  # 대조용 원본 목록. 두 API 는 리소스 수준 권한을 지원하지 않는다.
  statement {
    sid       = "ReadSources"
    actions   = ["securityhub:GetFindings", "inspector2:ListFindings"]
    resources = ["*"]
  }
  # 조건부 쓰기(PutItem), 대조 닫기·실패 기록(UpdateItem), 열린 행 조회(인덱스 Query). 두 테이블로 제한.
  statement {
    sid     = "WriteFindingTables"
    actions = ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query", "dynamodb:GetItem"]
    resources = [
      aws_dynamodb_table.findings.arn,
      "${aws_dynamodb_table.findings.arn}/index/*",
      aws_dynamodb_table.vulnerabilities.arn,
      "${aws_dynamodb_table.vulnerabilities.arn}/index/*",
    ]
  }
  statement {
    sid       = "DeadLetter"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.finding_sync_dlq.arn]
  }
}

resource "aws_iam_role_policy" "finding_sync" {
  name   = "${var.name_prefix}-finding-sync-policy"
  role   = aws_iam_role.finding_sync.id
  policy = data.aws_iam_policy_document.finding_sync.json
}

# --- 함수 ---------------------------------------------------------------------
resource "aws_lambda_function" "finding_sync" {
  function_name = "${var.name_prefix}-finding-sync"
  role          = aws_iam_role.finding_sync.arn
  runtime       = "python3.12"
  handler       = "handler.handler"
  # 대조는 Inspector 수천 건(ListFindings 100건/페이지 순차, 실측 약 22초) + 변경분 쓰기.
  # 취약점이 3만 건을 넘으면서 256MB 로는 대조 중 OOM 급 타임아웃(2026-10-02 실측 255/256MB). 1024 로 상향.
  timeout     = 300
  memory_size = 1024

  filename         = data.archive_file.finding_sync.output_path
  source_code_hash = data.archive_file.finding_sync.output_base64sha256

  dead_letter_config {
    target_arn = aws_sqs_queue.finding_sync_dlq.arn
  }

  environment {
    variables = {
      FINDINGS_TABLE        = aws_dynamodb_table.findings.name
      VULNERABILITIES_TABLE = aws_dynamodb_table.vulnerabilities.name
      FINDING_TTL_DAYS      = tostring(var.finding_ttl_days)
    }
  }

  # 역할 정책이 붙기 전에 첫 이벤트가 오면 AccessDenied → DLQ 로 간다. 정책을 먼저 붙인다.
  depends_on = [aws_iam_role_policy.finding_sync, aws_iam_role_policy_attachment.finding_sync_basic]

  tags = var.tags
}

# 비동기 호출(EventBridge) 재시도 2회, 1시간 넘은 이벤트는 DLQ 로.
resource "aws_lambda_function_event_invoke_config" "finding_sync" {
  function_name                = aws_lambda_function.finding_sync.function_name
  maximum_retry_attempts       = 2
  maximum_event_age_in_seconds = 3600
}

# --- EventBridge ① Security Hub (Inspector 제외) ------------------------------
resource "aws_cloudwatch_event_rule" "sh_to_finding_sync" {
  count = var.enable_security_hub ? 1 : 0

  name        = "${var.name_prefix}-sh-finding-sync"
  description = "Security Hub findings (except Inspector) to finding_sync"

  # 배치 안에 Inspector 가 섞여 와도 함수가 한 번 더 거른다.
  event_pattern = jsonencode({
    source        = ["aws.securityhub"]
    "detail-type" = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        ProductName = [{ "anything-but" = ["Inspector"] }]
      }
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "sh_to_finding_sync" {
  count = var.enable_security_hub ? 1 : 0

  rule      = aws_cloudwatch_event_rule.sh_to_finding_sync[0].name
  target_id = "finding-sync"
  arn       = aws_lambda_function.finding_sync.arn
}

resource "aws_lambda_permission" "sh_to_finding_sync" {
  count = var.enable_security_hub ? 1 : 0

  statement_id  = "AllowSecurityHubFindingSync"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.finding_sync.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.sh_to_finding_sync[0].arn
}

# --- EventBridge ② Inspector ---------------------------------------------------
# 재탐지(lastObservedAt 만 변경)마다 이벤트가 오는지는 AWS 문서에 명시가 없다 → ③ 대조가 보완.
resource "aws_cloudwatch_event_rule" "inspector_to_finding_sync" {
  name        = "${var.name_prefix}-inspector-finding-sync"
  description = "Inspector2 findings to finding_sync"

  event_pattern = jsonencode({
    source        = ["aws.inspector2"]
    "detail-type" = ["Inspector2 Finding"]
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "inspector_to_finding_sync" {
  rule      = aws_cloudwatch_event_rule.inspector_to_finding_sync.name
  target_id = "finding-sync"
  arn       = aws_lambda_function.finding_sync.arn
}

resource "aws_lambda_permission" "inspector_to_finding_sync" {
  statement_id  = "AllowInspectorFindingSync"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.finding_sync.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.inspector_to_finding_sync.arn
}

# --- EventBridge ③ 주기 대조 ----------------------------------------------------
resource "aws_cloudwatch_event_rule" "finding_sync_schedule" {
  name                = "${var.name_prefix}-finding-sync-schedule"
  description         = "Reconcile Security Hub / Inspector findings into DynamoDB"
  schedule_expression = var.finding_sync_schedule
  tags                = var.tags
}

resource "aws_cloudwatch_event_target" "finding_sync_schedule" {
  rule      = aws_cloudwatch_event_rule.finding_sync_schedule.name
  target_id = "finding-sync"
  arn       = aws_lambda_function.finding_sync.arn
}

resource "aws_lambda_permission" "finding_sync_schedule" {
  statement_id  = "AllowScheduleFindingSync"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.finding_sync.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.finding_sync_schedule.arn
}

# --- 알람 → SNS ----------------------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "finding_sync_errors" {
  alarm_name          = "${var.name_prefix}-finding-sync-errors"
  alarm_description   = "finding_sync 실패(대조·적재). 대시보드 탐지/취약점이 늦거나 빠질 수 있음"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.finding_sync.function_name }
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = var.tags
}

resource "aws_cloudwatch_metric_alarm" "finding_sync_dlq" {
  alarm_name          = "${var.name_prefix}-finding-sync-dlq"
  alarm_description   = "finding_sync 가 처리하지 못한 이벤트가 DLQ 에 있음"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.finding_sync_dlq.name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = var.tags
}
