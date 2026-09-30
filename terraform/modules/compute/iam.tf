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

  # ssm:StartAutomationExecution 의 리소스. 세 가지를 모두 둔다.
  #   automation-definition/ASR-*  문서의 실행 정의. AWS 문서상 이 액션의 필수 리소스 타입.
  #   document/ASR-*               실행할 문서 자체.
  #   automation-execution/*       실행할 때 생성되는 실행 ID.
  # 2026-09-21 실계정에서 automation-definition 하나만으로는 AccessDenied 가 났고,
  # 뒤의 두 개를 인라인 정책으로 **추가**해서 통과했다. 즉 검증된 것은 "두 개를 더하면
  # 된다" 이지 "automation-definition 을 빼도 된다" 가 아니다. 빼면 다시 막힐 수 있어
  # 셋 다 유지한다. 범위는 여전히 ASR-* 로 묶여 있어 최소권한을 해치지 않는다.
  # (fix/ssm-automation-arn 는 automation-definition 을 뺐지만, Allow 의 Resource 목록에
  #  항목을 더하는 것은 권한을 넓힐 뿐 AccessDenied 를 만들 수 없어 오진으로 보고 유지한다.)
  asr_document_arns = [
    "arn:${var.partition}:ssm:${var.region}:${var.account_id}:automation-definition/ASR-*",
    "arn:${var.partition}:ssm:${var.region}:${var.account_id}:document/ASR-*",
    "arn:${var.partition}:ssm:${var.region}:${var.account_id}:automation-execution/*",
  ]
  ssm_automation_role_arn = "arn:${var.partition}:iam::${var.account_id}:role/${var.ssm_automation_role_name}"

  dynamodb_table_arns = [
    "arn:${var.partition}:dynamodb:${var.region}:${var.account_id}:table/${var.correlated_findings_table}",
    "arn:${var.partition}:dynamodb:${var.region}:${var.account_id}:table/${var.remediation_actions_table}",
    # 조치 이력 finding_id 인덱스 조회(modules/soar storage.tf 의 finding_id-created_at GSI). 읽기 전용.
    "arn:${var.partition}:dynamodb:${var.region}:${var.account_id}:table/${var.remediation_actions_table}/index/*",
    # 탐지·취약점 적재 테이블(v21, modules/soar finding_sync)과 기간 조회 인덱스. 읽기 전용.
    "arn:${var.partition}:dynamodb:${var.region}:${var.account_id}:table/${var.findings_table}",
    "arn:${var.partition}:dynamodb:${var.region}:${var.account_id}:table/${var.findings_table}/index/*",
    "arn:${var.partition}:dynamodb:${var.region}:${var.account_id}:table/${var.vulnerabilities_table}",
    "arn:${var.partition}:dynamodb:${var.region}:${var.account_id}:table/${var.vulnerabilities_table}/index/*",
    # 차단 IP 목록(v25, modules/soar storage.tf). 읽기는 여기서, 쓰기는 dashboard_execute 의 RecordBlocklist.
    "arn:${var.partition}:dynamodb:${var.region}:${var.account_id}:table/${var.ip_blocklist_table}",
    # 3계층 점검 결과(modules/soar tier_check.tf). 읽기 전용.
    "arn:${var.partition}:dynamodb:${var.region}:${var.account_id}:table/${var.tier_status_table}",
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

  # 파리 리전 이전용 mysqldump 백업 업로드(2026-09-30). migration-backup/ 경로로만 한정한다 —
  # scan_bucket_arn 전체(트리비/스캔 결과 등)에는 쓰기 권한을 안 준다.
  statement {
    sid       = "UploadMigrationBackup"
    actions   = ["s3:PutObject"]
    resources = ["${local.scan_bucket_arn}/migration-backup/*"]
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

  # 대시보드 원클릭 조치(v29)의 재검증 — ASR-* 문서가 바꾼 값을 같은 기준으로 다시 읽는다. 읽기 전용이며
  # 보안그룹·EC2 설정 조회(ec2:DescribeSecurityGroups)와 SSM 실행 조회(ssm:GetAutomationExecution)는 아래·dashboard_execute 에 이미 있다.
  statement {
    sid = "ReadRemediationVerification"
    actions = [
      "ec2:GetEbsEncryptionByDefault",
      "ec2:GetSnapshotBlockPublicAccessState",
      "s3:GetAccountPublicAccessBlock",
      "iam:GetAccountPasswordPolicy",
      "ssm:GetServiceSetting",
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
      # 허니팟 타임라인(v25): 탐지 알람이 ALARM 으로 바뀐 시각
      "cloudwatch:DescribeAlarmHistory",
      "logs:FilterLogEvents",
      "logs:StartQuery",
      "logs:GetQueryResults",
      "cloudtrail:LookupEvents",
      # SEC-05 재검증(iam_key_status) — 노출된 키가 정말 Inactive 가 됐는지 확인한다.
      # 읽기 전용이며 키 값 자체는 반환되지 않는다(메타데이터만).
      "iam:ListAccessKeys",
      "iam:GetAccessKeyLastUsed",
      # SEC-09([전부 실행]) — 감사·구성·로그 수집이 실제로 기록 중인지 조회만 한다. 쓰기 없음.
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
      "config:DescribeConfigurationRecorderStatus",
      "ec2:DescribeFlowLogs",
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

  # 공격·대응 실습([전부 실행]) — 팀 소유 격리 랩의 지정 문서만, 대상 EC2 에 한해 SendCommand.
  statement {
    sid     = "RunDrillCommands"
    actions = ["ssm:SendCommand"]
    resources = [
      # 지리별 웹 공격 문서(SEC-08/06B) — 공격자 리전마다 등록되므로 리전 와일드카드.
      "arn:${var.partition}:ssm:*:${var.account_id}:document/${var.name_prefix}-ATK-WebAttack",
      # 파리(홈 리전) 로컬 실습 문서(SEC-02/07/10).
      "arn:${var.partition}:ssm:${var.region}:${var.account_id}:document/SCAN-PortAndWeb",
      "arn:${var.partition}:ssm:${var.region}:${var.account_id}:document/SCAN-ContainerImage",
      "arn:${var.partition}:ssm:${var.region}:${var.account_id}:document/SCAN-Secrets",
      "arn:${var.partition}:ssm:${var.region}:${var.account_id}:document/LOAD-Stress",
      # 내부 침투 시연(공격자 EC2 → 미끼서버 SSH, HONEYPOT).
      "arn:${var.partition}:ssm:${var.region}:${var.account_id}:document/ATK-HoneypotProbe",
      # MySQL 무차별 대입 시연(공격자 EC2 → DB EC2, SEC-06A).
      "arn:${var.partition}:ssm:${var.region}:${var.account_id}:document/ATK-MysqlBruteForce",
      # 대상 인스턴스(공격자·파리 실습 대상). 실행 시 태그로 탐색하므로 계정 내 인스턴스로 한정.
      "arn:${var.partition}:ec2:*:${var.account_id}:instance/*",
    ]
  }

  # SEC-01/03 시연([전부 실행]) — 격리된 실습 SG(기존 Scenario 태그: db-auto-sg="SEC-03",
  # db-manual-sg="SEC-03/SEC-06", sec01-demo="SEC-01")에만 위반 규칙을 추가하고, asr_trigger 를
  # 직접 호출해 즉시 회수 결과를 본다(demo/trigger-auto-remediation.sh 와 같은 기법). 새 태그를 넣지
  # 않는 이유: modules/network 안의 리소스를 바꾸면 module.compute 의 AMI 조회가 apply 시점으로
  # 밀려 EC2 전부가 재생성된다(override-demo.tf 참고) — 기존 태그만 그대로 재사용한다.
  # 실서비스 SG(docker-host·web-dvwa 등)에는 이 태그값이 없어 대상이 될 수 없다.
  statement {
    sid       = "RunSgViolationDrill"
    actions   = ["ec2:AuthorizeSecurityGroupIngress"]
    resources = ["arn:${var.partition}:ec2:${var.region}:${var.account_id}:security-group/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Scenario"
      values   = ["SEC-01", "SEC-03", "SEC-03/SEC-06"]
    }
  }

  statement {
    sid       = "InvokeAsrTriggerForDrill"
    actions   = ["lambda:InvokeFunction"]
    resources = ["arn:${var.partition}:lambda:${var.region}:${var.account_id}:function:${var.name_prefix}-asr-trigger"]
  }

  statement {
    sid = "TrackDrillCommands"
    actions = [
      "ssm:GetCommandInvocation",
      "ssm:ListCommands",
      "ssm:ListCommandInvocations",
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

  # 대시보드 도우미(v27): Bedrock 호출만. 모델·추론 프로파일 ARN 은 리전·계정마다 달라 * 로 둔다(호출만 허용, 모델 관리 권한 없음).
  dynamic "statement" {
    for_each = var.enable_assistant ? [1] : []
    content {
      sid       = "AssistantBedrockInvoke"
      actions   = ["bedrock:InvokeModel"]
      resources = ["*"]
    }
  }

  # 오탐 해제·차단 기간 변경(v25): 차단 IP 목록 행만 조건부로 갱신한다. 삭제·전체 쓰기는 주지 않는다.
  dynamic "statement" {
    for_each = var.ip_blocklist_table != "" ? [1] : []
    content {
      sid       = "RecordBlocklist"
      actions   = ["dynamodb:UpdateItem", "dynamodb:PutItem"]
      resources = ["arn:${var.partition}:dynamodb:${var.region}:${var.account_id}:table/${var.ip_blocklist_table}"]
    }
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
  count              = local.attacker_iam_enabled ? 1 : 0
  name               = "${var.name_prefix}-attacker-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "attacker_ssm" {
  count      = local.attacker_iam_enabled ? 1 : 0
  role       = aws_iam_role.attacker[0].name
  policy_arn = local.ssm_core_policy
}

# 메모리 지표(CloudWatch Agent PutMetricData) — SEC-10 메모리 알람이 이 호스트도 본다.
resource "aws_iam_role_policy_attachment" "attacker_cw" {
  count      = local.attacker_iam_enabled ? 1 : 0
  role       = aws_iam_role.attacker[0].name
  policy_arn = local.cw_agent_policy
}

resource "aws_iam_role_policy_attachment" "attacker_scan" {
  count      = local.attacker_iam_enabled ? 1 : 0
  role       = aws_iam_role.attacker[0].name
  policy_arn = aws_iam_policy.scan_upload.arn
}

resource "aws_iam_instance_profile" "attacker" {
  count = local.attacker_iam_enabled ? 1 : 0
  name  = "${var.name_prefix}-attacker-profile"
  role  = aws_iam_role.attacker[0].name
  tags  = var.tags
}
