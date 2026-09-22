############################################
# EC2 IAM 역할
#
# 설계 포인트: 대시보드 역할은 '읽기 전용 정책'과
# 'ASR-* 실행 전용 정책'을 분리해서 붙입니다.
# 대시보드 코드에 버그가 있어도 조회 화면 때문에 조치가 실행되지 않습니다.
############################################

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

locals {
  ssm_core_policy = "arn:${var.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
  cw_agent_policy = "arn:${var.partition}:iam::aws:policy/CloudWatchAgentServerPolicy"

  secret_arn_prefix = "arn:${var.partition}:secretsmanager:${var.region}:${var.account_id}:secret:${var.name_prefix}/*"
  scan_bucket_arn   = "arn:${var.partition}:s3:::${var.scan_results_bucket}"

  # StartAutomationExecution 은 document/* (실행할 문서) + automation-execution/* (생성되는 실행 ID)
  # 두 리소스 타입을 모두 요구합니다. automation-definition/* 은 유효한 리소스 타입이 아니라
  # AccessDenied 가 났습니다. (2026-09-21 실계정 확인, tmp-policy.json)
  asr_document_arns = [
    "arn:${var.partition}:ssm:${var.region}:${var.account_id}:document/ASR-*",
    "arn:${var.partition}:ssm:${var.region}:${var.account_id}:automation-execution/*",
  ]
  ssm_automation_role_arn = "arn:${var.partition}:iam::${var.account_id}:role/${var.ssm_automation_role_name}"

  dynamodb_table_arns = [
    "arn:${var.partition}:dynamodb:${var.region}:${var.account_id}:table/${var.correlated_findings_table}",
    "arn:${var.partition}:dynamodb:${var.region}:${var.account_id}:table/${var.remediation_actions_table}",
  ]
}

############################################
# 공통 — 점검 결과 업로드 정책
############################################

data "aws_iam_policy_document" "scan_upload" {
  statement {
    sid       = "PutScanResults"
    actions   = ["s3:PutObject", "s3:PutObjectAcl"]
    resources = ["${local.scan_bucket_arn}/*"]
  }

  statement {
    sid       = "ListScanBucket"
    actions   = ["s3:ListBucket", "s3:GetBucketLocation"]
    resources = [local.scan_bucket_arn]
  }
}

resource "aws_iam_policy" "scan_upload" {
  name        = "${var.name_prefix}-scan-upload"
  description = "Upload manual scan results (nmap / ZAP / Trivy) to S3"
  policy      = data.aws_iam_policy_document.scan_upload.json

  tags = var.tags
}

############################################
# Docker Host
############################################

resource "aws_iam_role" "docker_host" {
  name               = "${var.name_prefix}-docker-host-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "docker_host_ssm" {
  role       = aws_iam_role.docker_host.name
  policy_arn = local.ssm_core_policy
}

resource "aws_iam_role_policy_attachment" "docker_host_cw" {
  role       = aws_iam_role.docker_host.name
  policy_arn = local.cw_agent_policy
}

resource "aws_iam_role_policy_attachment" "docker_host_scan" {
  role       = aws_iam_role.docker_host.name
  policy_arn = aws_iam_policy.scan_upload.arn
}

data "aws_iam_policy_document" "docker_host" {
  statement {
    sid       = "ReadDbSecret"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = [local.secret_arn_prefix]
  }

  statement {
    sid = "PullFromEcr"
    actions = [
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "docker_host" {
  name   = "${var.name_prefix}-docker-host-policy"
  role   = aws_iam_role.docker_host.id
  policy = data.aws_iam_policy_document.docker_host.json
}

resource "aws_iam_instance_profile" "docker_host" {
  name = "${var.name_prefix}-docker-host-profile"
  role = aws_iam_role.docker_host.name
  tags = var.tags
}

############################################
# MySQL EC2
############################################

resource "aws_iam_role" "db" {
  name               = "${var.name_prefix}-db-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "db_ssm" {
  role       = aws_iam_role.db.name
  policy_arn = local.ssm_core_policy
}

resource "aws_iam_role_policy_attachment" "db_cw" {
  role       = aws_iam_role.db.name
  policy_arn = local.cw_agent_policy
}

data "aws_iam_policy_document" "db" {
  statement {
    sid       = "ReadDbSecret"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = [local.secret_arn_prefix]
  }
}

resource "aws_iam_role_policy" "db" {
  name   = "${var.name_prefix}-db-policy"
  role   = aws_iam_role.db.id
  policy = data.aws_iam_policy_document.db.json
}

resource "aws_iam_instance_profile" "db" {
  name = "${var.name_prefix}-db-profile"
  role = aws_iam_role.db.name
  tags = var.tags
}

############################################
# 보안 대시보드 — 읽기 / 실행 권한 분리
############################################

resource "aws_iam_role" "dashboard" {
  name               = "${var.name_prefix}-dashboard-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "dashboard_ssm" {
  role       = aws_iam_role.dashboard.name
  policy_arn = local.ssm_core_policy
}

resource "aws_iam_role_policy_attachment" "dashboard_cw" {
  role       = aws_iam_role.dashboard.name
  policy_arn = local.cw_agent_policy
}

# (1) 읽기 전용 — finding 과 조치 이력 조회
data "aws_iam_policy_document" "dashboard_read" {
  statement {
    sid = "ReadFindings"
    actions = [
      "securityhub:GetFindings",
      "securityhub:DescribeHub",
      "guardduty:ListDetectors",
      "guardduty:ListFindings",
      "guardduty:GetFindings",
      "inspector2:ListFindings",
      "inspector2:ListCoverage",
      "config:DescribeComplianceByConfigRule",
      "config:GetComplianceDetailsByConfigRule",
      "config:DescribeConfigRules",
      "access-analyzer:ListFindings",
      "access-analyzer:ListAnalyzers",
    ]
    resources = ["*"]
  }

  statement {
    sid = "ReadInfrastructureState"
    actions = [
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSecurityGroupRules",
      "ec2:DescribeInstances",
      "ec2:DescribeNetworkAcls",
      "cloudwatch:GetMetricData",
      "cloudwatch:GetMetricStatistics",
      "cloudwatch:DescribeAlarms",
      "logs:FilterLogEvents",
      "logs:StartQuery",
      "logs:GetQueryResults",
      "cloudtrail:LookupEvents",
      # SEC-05 재검증(iam_key_status) — 노출된 키가 정말 Inactive 가 됐는지 확인한다.
      # 읽기 전용이며 키 값 자체는 반환되지 않는다(메타데이터만).
      "iam:ListAccessKeys",
      "iam:GetAccessKeyLastUsed",
    ]
    resources = ["*"]
  }

  statement {
    sid = "ReadCorrelationAndActionHistory"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:Query",
      "dynamodb:Scan",
      "dynamodb:DescribeTable",
    ]
    resources = local.dynamodb_table_arns
  }

  statement {
    sid       = "ReadScanResults"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [local.scan_bucket_arn, "${local.scan_bucket_arn}/*"]
  }
}

resource "aws_iam_policy" "dashboard_read" {
  name        = "${var.name_prefix}-dashboard-read"
  description = "Dashboard read-only access to findings and action history"
  policy      = data.aws_iam_policy_document.dashboard_read.json
  tags        = var.tags
}

resource "aws_iam_role_policy_attachment" "dashboard_read" {
  role       = aws_iam_role.dashboard.name
  policy_arn = aws_iam_policy.dashboard_read.arn
}

# (2) 실행 전용 — ASR-* 플레이북만 실행할 수 있습니다.
data "aws_iam_policy_document" "dashboard_execute" {
  statement {
    sid       = "RunApprovedPlaybooksOnly"
    actions   = ["ssm:StartAutomationExecution"]
    resources = local.asr_document_arns
  }

  statement {
    sid = "TrackExecution"
    actions = [
      "ssm:GetAutomationExecution",
      "ssm:DescribeAutomationExecutions",
      "ssm:DescribeAutomationStepExecutions",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "PassAutomationRole"
    actions   = ["iam:PassRole"]
    resources = [local.ssm_automation_role_arn]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ssm.amazonaws.com"]
    }
  }

  statement {
    sid       = "RecordActionHistory"
    actions   = ["dynamodb:PutItem", "dynamodb:UpdateItem"]
    resources = ["arn:${var.partition}:dynamodb:${var.region}:${var.account_id}:table/${var.remediation_actions_table}"]
  }

  # user_data 가 SNS_TOPIC_ARN 을 넘겨주는데 권한이 없어 발행이 실패하던 것을 보완합니다.
  dynamic "statement" {
    for_each = var.sns_topic_arn != "" ? [1] : []
    content {
      sid       = "NotifyOnManualAction"
      actions   = ["sns:Publish"]
      resources = [var.sns_topic_arn]
    }
  }
}

resource "aws_iam_policy" "dashboard_execute" {
  name        = "${var.name_prefix}-dashboard-execute"
  description = "Dashboard may only start ASR-* automation documents"
  policy      = data.aws_iam_policy_document.dashboard_execute.json
  tags        = var.tags
}

resource "aws_iam_role_policy_attachment" "dashboard_execute" {
  role       = aws_iam_role.dashboard.name
  policy_arn = aws_iam_policy.dashboard_execute.arn
}

resource "aws_iam_instance_profile" "dashboard" {
  name = "${var.name_prefix}-dashboard-profile"
  role = aws_iam_role.dashboard.name
  tags = var.tags
}

############################################
# DVWA 웹 서버 / 내부 공격용 EC2
############################################

resource "aws_iam_role" "web_dvwa" {
  count              = var.enable_dvwa_instance ? 1 : 0
  name               = "${var.name_prefix}-web-dvwa-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "web_dvwa_ssm" {
  count      = var.enable_dvwa_instance ? 1 : 0
  role       = aws_iam_role.web_dvwa[0].name
  policy_arn = local.ssm_core_policy
}

resource "aws_iam_role_policy_attachment" "web_dvwa_cw" {
  count      = var.enable_dvwa_instance ? 1 : 0
  role       = aws_iam_role.web_dvwa[0].name
  policy_arn = local.cw_agent_policy
}

resource "aws_iam_instance_profile" "web_dvwa" {
  count = var.enable_dvwa_instance ? 1 : 0
  name  = "${var.name_prefix}-web-dvwa-profile"
  role  = aws_iam_role.web_dvwa[0].name
  tags  = var.tags
}

resource "aws_iam_role" "attacker" {
  count              = var.enable_attacker_instance ? 1 : 0
  name               = "${var.name_prefix}-attacker-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "attacker_ssm" {
  count      = var.enable_attacker_instance ? 1 : 0
  role       = aws_iam_role.attacker[0].name
  policy_arn = local.ssm_core_policy
}

resource "aws_iam_role_policy_attachment" "attacker_scan" {
  count      = var.enable_attacker_instance ? 1 : 0
  role       = aws_iam_role.attacker[0].name
  policy_arn = aws_iam_policy.scan_upload.arn
}

resource "aws_iam_instance_profile" "attacker" {
  count = var.enable_attacker_instance ? 1 : 0
  name  = "${var.name_prefix}-attacker-profile"
  role  = aws_iam_role.attacker[0].name
  tags  = var.tags
}
