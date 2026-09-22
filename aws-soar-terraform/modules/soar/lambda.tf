############################################
# Lambda 2개 — correlator / asr_trigger
############################################

data "archive_file" "correlator" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_src/correlator"
  output_path = "${path.module}/build/correlator.zip"
}

data "archive_file" "asr_trigger" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_src/asr_trigger"
  output_path = "${path.module}/build/asr_trigger.zip"
}

# --- Lambda 실행 역할 ----------------------------------------------------
data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# correlator 역할
resource "aws_iam_role" "correlator" {
  name               = "${var.name_prefix}-correlator-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "correlator_basic" {
  role       = aws_iam_role.correlator.name
  policy_arn = "arn:${var.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "correlator" {
  statement {
    sid       = "ReadInspector"
    actions   = ["inspector2:ListFindings"]
    resources = ["*"]
  }
  statement {
    sid       = "WriteCorrelation"
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.correlated.arn]
  }
}

resource "aws_iam_role_policy" "correlator" {
  name   = "${var.name_prefix}-correlator-policy"
  role   = aws_iam_role.correlator.id
  policy = data.aws_iam_policy_document.correlator.json
}

# asr_trigger 역할
resource "aws_iam_role" "asr_trigger" {
  name               = "${var.name_prefix}-asr-trigger-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "asr_trigger_basic" {
  role       = aws_iam_role.asr_trigger.name
  policy_arn = "arn:${var.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "asr_trigger" {
  statement {
    sid       = "InspectSecurityGroups"
    actions   = ["ec2:DescribeSecurityGroups"]
    resources = ["*"]
  }

  statement {
    sid     = "StartApprovedPlaybooks"
    actions = ["ssm:StartAutomationExecution"]
    # 세 리소스 타입을 모두 둔다. 2026-09-21 실계정에서 automation-definition 하나로는
    # AccessDenied 가 났고, 나머지 둘을 인라인 정책으로 **추가**해서 통과했다.
    # 검증된 것은 "더하면 된다" 이지 "automation-definition 을 빼도 된다" 가 아니다.
    # 대시보드 쪽(compute/iam.tf local.asr_document_arns)과 같은 조합을 유지한다.
    resources = [
      "arn:${var.partition}:ssm:${var.region}:${var.account_id}:automation-definition/ASR-*",
      "arn:${var.partition}:ssm:${var.region}:${var.account_id}:document/ASR-*",
      "arn:${var.partition}:ssm:${var.region}:${var.account_id}:automation-execution/*",
    ]
  }

  statement {
    sid       = "PassAutomationRole"
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.ssm_automation.arn]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ssm.amazonaws.com"]
    }
  }

  statement {
    sid       = "RecordActions"
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.actions.arn]
  }

  statement {
    sid       = "Notify"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
}

resource "aws_iam_role_policy" "asr_trigger" {
  name   = "${var.name_prefix}-asr-trigger-policy"
  role   = aws_iam_role.asr_trigger.id
  policy = data.aws_iam_policy_document.asr_trigger.json
}

# --- 함수 ----------------------------------------------------------------
resource "aws_lambda_function" "correlator" {
  function_name = "${var.name_prefix}-correlator"
  role          = aws_iam_role.correlator.arn
  runtime       = "python3.12"
  handler       = "handler.handler"
  timeout       = 60
  memory_size   = 128

  filename         = data.archive_file.correlator.output_path
  source_code_hash = data.archive_file.correlator.output_base64sha256

  environment {
    variables = {
      CORRELATED_FINDINGS_TABLE = aws_dynamodb_table.correlated.name
    }
  }

  tags = var.tags
}

resource "aws_lambda_function" "asr_trigger" {
  function_name = "${var.name_prefix}-asr-trigger"
  role          = aws_iam_role.asr_trigger.arn
  runtime       = "python3.12"
  handler       = "handler.handler"
  timeout       = 60
  memory_size   = 128

  filename         = data.archive_file.asr_trigger.output_path
  source_code_hash = data.archive_file.asr_trigger.output_base64sha256

  environment {
    variables = {
      ACCOUNT_ID                = var.account_id
      REMEDIATION_ACTIONS_TABLE = aws_dynamodb_table.actions.name
      SNS_TOPIC_ARN             = aws_sns_topic.alerts.arn
      ENABLE_AUTO_REMEDIATION   = tostring(var.enable_auto_remediation)
      AUTO_REMEDIABLE_PATTERNS  = join(",", var.auto_remediable_patterns)
      DOC_REVOKE_SG             = aws_ssm_document.automation["ASR-RevokeSecurityGroupIngress"].name
      DOC_DISABLE_KEY           = aws_ssm_document.automation["ASR-DisableExposedAccessKey"].name
      DOC_NGINX_HARDEN          = aws_ssm_document.command["ASR-HardenNginx"].name
      AUTOMATION_ROLE_ARN       = aws_iam_role.ssm_automation.arn
    }
  }

  tags = var.tags
}
