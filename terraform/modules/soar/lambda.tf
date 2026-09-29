############################################
# Lambda 3개 — correlator / asr_trigger / waf_finding(옵션)
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
    # (fix/ssm-automation-arn 는 automation-definition 을 뺐지만, Allow 의 Resource 에
    #  항목을 더하는 것은 권한을 넓힐 뿐 AccessDenied 를 만들 수 없어 오진으로 보고 유지한다.)
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

  # 반복 판정은 같은 행의 횟수만 갱신(Query → UpdateItem), SSM 종료 결과도 같은 행에 갱신한다.
  # 인덱스(finding_id-created_at)는 같은 finding 의 자동 실행이 진행 중인지 볼 때 쓴다(DEC-017).
  statement {
    sid       = "RecordActions"
    actions   = ["dynamodb:PutItem", "dynamodb:Query", "dynamodb:UpdateItem"]
    resources = [aws_dynamodb_table.actions.arn, "${aws_dynamodb_table.actions.arn}/index/*"]
  }

  # SEC-06A·06B·HONEYPOT — 알람 구간의 MySQL 인증 실패 로그 / VPC Flow Logs 22번 거부 기록 /
  # 미끼서버 접속 로그에서 출발지 IP 를 읽는다. (허니팟 로그 그룹이 빠지면 HONEYPOT 차단이 AccessDenied 로 실패)
  statement {
    sid     = "ReadBruteforceLogs"
    actions = ["logs:FilterLogEvents"]
    resources = concat(
      [aws_cloudwatch_log_group.mysql.arn, "${aws_cloudwatch_log_group.mysql.arn}:*"],
      var.log_group_flowlogs == "" ? [] : [
        "arn:${var.partition}:logs:${var.region}:${var.account_id}:log-group:${var.log_group_flowlogs}",
        "arn:${var.partition}:logs:${var.region}:${var.account_id}:log-group:${var.log_group_flowlogs}:*",
      ],
      var.honeypot_log_group == null || var.honeypot_log_group == "" ? [] : [
        "arn:${var.partition}:logs:${var.region}:${var.account_id}:log-group:${var.honeypot_log_group}",
        "arn:${var.partition}:logs:${var.region}:${var.account_id}:log-group:${var.honeypot_log_group}:*",
      ],
    )
  }

  # SEC-06A·06B — 보호 자산 주소(보호 역할 인스턴스, ALB·VPC 엔드포인트 등 AWS 관리 ENI) 확인,
  # NACL 빈 규칙 번호·중복 차단 확인(읽기 전용).
  statement {
    sid       = "InspectBlockTargets"
    actions   = ["ec2:DescribeInstances", "ec2:DescribeNetworkAcls", "ec2:DescribeNetworkInterfaces"]
    resources = ["*"]
  }

  # v25: 차단 IP 목록 — 오탐 예외 확인(GetItem), 차단 기록·차단 실패 표시(UpdateItem)
  statement {
    sid       = "IpBlocklist"
    actions   = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
    resources = [aws_dynamodb_table.ip_blocklist.arn]
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
      ACTION_TTL_DAYS           = tostring(var.action_history_ttl_days)
      AUTO_REMEDIABLE_CONTROLS  = join(",", var.auto_remediable_controls)
      DOC_DEFAULT_SG            = aws_ssm_document.automation["ASR-RemoveDefaultSgRules"].name
      DOC_EBS_ENCRYPTION        = aws_ssm_document.automation["ASR-EnableEbsDefaultEncryption"].name
      DOC_SNAPSHOT_BPA          = aws_ssm_document.automation["ASR-BlockEbsSnapshotPublicAccess"].name
      DOC_S3_ACCOUNT_BPA        = aws_ssm_document.automation["ASR-BlockS3AccountPublicAccess"].name
      IP_BLOCKLIST_TABLE        = aws_dynamodb_table.ip_blocklist.name
      IP_BLOCK_TTL_HOURS        = tostring(var.ip_block_default_ttl_hours)
      IP_BLOCK_TTL_MINUTES      = tostring(var.ip_block_ttl_minutes_override)
      DOC_PASSWORD_POLICY       = aws_ssm_document.automation["ASR-SetIamPasswordPolicy"].name
      DOC_SSM_AUTOMATION_LOG    = aws_ssm_document.automation["ASR-EnableSsmAutomationLogging"].name
      DOC_SSM_PUBLIC_SHARING    = aws_ssm_document.automation["ASR-BlockSsmDocumentPublicSharing"].name
      DOC_BLOCK_IP              = aws_ssm_document.automation["ASR-BlockIpWithNacl"].name
      ACTIONS_FINDING_INDEX     = "finding_id-created_at"
      MYSQL_ALARM_NAME          = aws_cloudwatch_metric_alarm.mysql_bruteforce.alarm_name
      MYSQL_LOG_GROUP           = aws_cloudwatch_log_group.mysql.name
      SSH_ALARM_NAME            = local.enable_ssh_reject ? aws_cloudwatch_metric_alarm.ssh_reject[0].alarm_name : ""
      HONEYPOT_ALARM_NAME       = var.honeypot_alarm_name != null ? var.honeypot_alarm_name : ""
      HONEYPOT_LOG_GROUP        = var.honeypot_log_group != null ? var.honeypot_log_group : ""
      FLOWLOG_GROUP             = var.log_group_flowlogs
      FLOWLOG_REJECT_PATTERN    = local.ssh_reject_pattern
      ALARM_WINDOW_SECONDS      = tostring(local.bruteforce_alarm_period * local.bruteforce_alarm_evaluation_periods)
      PRIVATE_NACL_ID           = var.private_nacl_id
      PROJECT_VPC_ID            = var.vpc_id
      VPC_CIDR                  = var.vpc_cidr
      PROTECTED_ROLES           = "service-3tier,database,soar-dashboard"
    }
  }

  tags = var.tags
}

# --- waf_finding (SEC-08) --------------------------------------------------
# WAF 차단 알람을 Security Hub finding 으로 가져온다. 대시보드는 finding 만 읽는다.
data "archive_file" "waf_finding" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_src/waf_finding"
  output_path = "${path.module}/build/waf_finding.zip"
}

resource "aws_iam_role" "waf_finding" {
  count = var.enable_waf_finding ? 1 : 0

  name               = "${var.name_prefix}-waf-finding-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "waf_finding_basic" {
  count = var.enable_waf_finding ? 1 : 0

  role       = aws_iam_role.waf_finding[0].name
  policy_arn = "arn:${var.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "waf_finding" {
  statement {
    sid     = "ImportOwnFindings"
    actions = ["securityhub:BatchImportFindings"]
    # 계정 자체 제품(default)으로만 가져온다.
    resources = ["arn:${var.partition}:securityhub:${var.region}:${var.account_id}:product/${var.account_id}/default"]
  }

  statement {
    # 차단된 요청의 공격자 IP 를 읽어 finding 에 출발지로 붙인다(지도 공격 흐름선).
    sid       = "ReadSampledRequests"
    actions   = ["wafv2:GetSampledRequests"]
    resources = [var.waf_web_acl_arn]
  }
}

resource "aws_iam_role_policy" "waf_finding" {
  count = var.enable_waf_finding ? 1 : 0

  name   = "${var.name_prefix}-waf-finding-policy"
  role   = aws_iam_role.waf_finding[0].id
  policy = data.aws_iam_policy_document.waf_finding.json
}

resource "aws_lambda_function" "waf_finding" {
  count = var.enable_waf_finding ? 1 : 0

  function_name = "${var.name_prefix}-waf-finding"
  role          = aws_iam_role.waf_finding[0].arn
  runtime       = "python3.12"
  handler       = "handler.handler"
  timeout       = 30
  memory_size   = 128

  filename         = data.archive_file.waf_finding.output_path
  source_code_hash = data.archive_file.waf_finding.output_base64sha256

  environment {
    variables = {
      ACCOUNT_ID  = var.account_id
      WEB_ACL_ARN = var.waf_web_acl_arn
    }
  }

  tags = var.tags
}

# --- block_expiry (v25, DEC-021) --------------------------------------------
# 만료된 IP 차단(NACL 1~99 Deny)을 5분마다 해제하고, 대시보드 오탐 해제(RELEASING)를 마무리한다.
# enable_block_expiry = false 면 만들지 않는다(만료 시각이 지나도 차단 유지, 대시보드에서만 해제).
data "archive_file" "block_expiry" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_src/block_expiry"
  output_path = "${path.module}/build/block_expiry.zip"
}

resource "aws_iam_role" "block_expiry" {
  count = var.enable_block_expiry ? 1 : 0

  name               = "${var.name_prefix}-block-expiry-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "block_expiry_basic" {
  count = var.enable_block_expiry ? 1 : 0

  role       = aws_iam_role.block_expiry[0].name
  policy_arn = "arn:${var.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "block_expiry" {
  statement {
    sid       = "Blocklist"
    actions   = ["dynamodb:Scan", "dynamodb:UpdateItem"]
    resources = [aws_dynamodb_table.ip_blocklist.arn]
  }

  statement {
    sid       = "RecordActions"
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.actions.arn]
  }

  statement {
    # 해제 문서 하나만 실행한다(ASR-* 전체가 아니다).
    sid     = "StartUnblockPlaybook"
    actions = ["ssm:StartAutomationExecution"]
    # 세 리소스 타입을 두는 이유는 asr_trigger 정책 주석 참고.
    resources = [
      "arn:${var.partition}:ssm:${var.region}:${var.account_id}:automation-definition/ASR-UnblockIpWithNacl:*",
      "arn:${var.partition}:ssm:${var.region}:${var.account_id}:document/ASR-UnblockIpWithNacl",
      "arn:${var.partition}:ssm:${var.region}:${var.account_id}:automation-execution/*",
    ]
  }

  statement {
    sid       = "TrackExecution"
    actions   = ["ssm:GetAutomationExecution"]
    resources = ["*"]
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
    sid       = "InspectNacl"
    actions   = ["ec2:DescribeNetworkAcls"]
    resources = ["*"]
  }

  statement {
    sid       = "Notify"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
}

resource "aws_iam_role_policy" "block_expiry" {
  count = var.enable_block_expiry ? 1 : 0

  name   = "${var.name_prefix}-block-expiry-policy"
  role   = aws_iam_role.block_expiry[0].id
  policy = data.aws_iam_policy_document.block_expiry.json
}

resource "aws_lambda_function" "block_expiry" {
  count = var.enable_block_expiry ? 1 : 0

  function_name = "${var.name_prefix}-block-expiry"
  role          = aws_iam_role.block_expiry[0].arn
  runtime       = "python3.12"
  handler       = "handler.handler"
  timeout       = 60
  memory_size   = 128

  filename         = data.archive_file.block_expiry.output_path
  source_code_hash = data.archive_file.block_expiry.output_base64sha256

  environment {
    variables = {
      IP_BLOCKLIST_TABLE        = aws_dynamodb_table.ip_blocklist.name
      REMEDIATION_ACTIONS_TABLE = aws_dynamodb_table.actions.name
      DOC_UNBLOCK_IP            = aws_ssm_document.automation["ASR-UnblockIpWithNacl"].name
      AUTOMATION_ROLE_ARN       = aws_iam_role.ssm_automation.arn
      SNS_TOPIC_ARN             = aws_sns_topic.alerts.arn
      ACTION_TTL_DAYS           = tostring(var.action_history_ttl_days)
    }
  }

  tags = var.tags
}

resource "aws_cloudwatch_event_rule" "block_expiry" {
  count = var.enable_block_expiry ? 1 : 0

  name                = "${var.name_prefix}-block-expiry"
  description         = "Every ${var.block_expiry_rate_minutes} minute(s): release expired IP blocks and finish pending releases"
  schedule_expression = var.block_expiry_rate_minutes == 1 ? "rate(1 minute)" : "rate(${var.block_expiry_rate_minutes} minutes)"
  tags                = var.tags
}

resource "aws_cloudwatch_event_target" "block_expiry" {
  count = var.enable_block_expiry ? 1 : 0

  rule      = aws_cloudwatch_event_rule.block_expiry[0].name
  target_id = "block-expiry"
  arn       = aws_lambda_function.block_expiry[0].arn
}

resource "aws_lambda_permission" "block_expiry" {
  count = var.enable_block_expiry ? 1 : 0

  statement_id  = "AllowBlockExpirySchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.block_expiry[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.block_expiry[0].arn
}
