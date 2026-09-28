############################################
# SSM Automation 실행 역할
# ASR-* 플레이북이 실제 조치를 수행할 때 assume 하는 역할입니다.
############################################

data "aws_iam_policy_document" "ssm_automation_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ssm.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ssm_automation" {
  name               = "${var.name_prefix}-ssm-automation-role"
  assume_role_policy = data.aws_iam_policy_document.ssm_automation_assume.json
  tags               = var.tags
}

data "aws_iam_policy_document" "ssm_automation" {
  # SG 회수 (자동개선 #1)
  statement {
    sid = "RevokeSecurityGroup"
    actions = [
      "ec2:DescribeSecurityGroups",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:DescribeNetworkAcls",
      "ec2:CreateNetworkAclEntry",
    ]
    resources = ["*"]
  }

  # IAM 키 비활성화 (자동개선 #2)
  statement {
    sid = "DisableAccessKey"
    actions = [
      "iam:ListAccessKeys",
      "iam:GetAccessKeyLastUsed",
      "iam:UpdateAccessKey",
    ]
    resources = ["*"]
  }

  # 시크릿 로테이션 (수동개선 #2)
  statement {
    sid = "RotateSecret"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue",
    ]
    resources = ["arn:${var.partition}:secretsmanager:${var.region}:${var.account_id}:secret:${var.name_prefix}/*"]
  }

  # Run Command (Nginx 강화 / 점검 문서)
  statement {
    sid = "RunCommandOnInstances"
    actions = [
      "ssm:SendCommand",
      "ssm:GetCommandInvocation",
      "ssm:ListCommandInvocations",
    ]
    resources = ["*"]
  }

  # 규칙 ID 자동 조치 (DEC-017) — 각 문서가 현재 상태를 읽고(Get/Describe) 위반일 때만 바꾼다.
  # EC2.2 — 문서가 이름이 default 인지 확인한 뒤에만 회수한다.
  statement {
    sid = "DefaultSecurityGroupRules"
    actions = [
      "ec2:DescribeSecurityGroups",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupEgress",
    ]
    resources = ["*"]
  }

  # EC2.7 · EC2.182
  statement {
    sid = "EbsAccountSettings"
    actions = [
      "ec2:GetEbsEncryptionByDefault",
      "ec2:EnableEbsEncryptionByDefault",
      "ec2:GetSnapshotBlockPublicAccessState",
      "ec2:EnableSnapshotBlockPublicAccess",
    ]
    resources = ["*"]
  }

  # S3.1
  statement {
    sid       = "S3AccountPublicAccessBlock"
    actions   = ["s3:GetAccountPublicAccessBlock", "s3:PutAccountPublicAccessBlock"]
    resources = ["*"]
  }

  # IAM.7
  statement {
    sid       = "IamPasswordPolicy"
    actions   = ["iam:GetAccountPasswordPolicy", "iam:UpdateAccountPasswordPolicy"]
    resources = ["*"]
  }

  # SSM.6 · SSM.7
  statement {
    sid     = "SsmServiceSettings"
    actions = ["ssm:GetServiceSetting", "ssm:UpdateServiceSetting"]
    resources = [
      "arn:${var.partition}:ssm:${var.region}:${var.account_id}:servicesetting/ssm/automation/customer-script-log-destination",
      "arn:${var.partition}:ssm:${var.region}:${var.account_id}:servicesetting/ssm/documents/console/public-sharing-permission",
    ]
  }

  # executeScript 를 위한 CloudWatch Logs. SSM.6 조치로 스크립트 로그를 켜면 그룹·스트림 조회도 쓴다.
  statement {
    sid = "AutomationLogs"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "ssm_automation" {
  name   = "${var.name_prefix}-ssm-automation-policy"
  role   = aws_iam_role.ssm_automation.id
  policy = data.aws_iam_policy_document.ssm_automation.json
}

############################################
# SSM 문서 등록
############################################

locals {
  # 아래 7개(ASR-RemoveDefaultSgRules ~ ASR-BlockSsmDocumentPublicSharing)는 규칙 ID 자동 조치(DEC-017) 문서다.
  # EC2.2 · EC2.7 · EC2.182 · S3.1 · IAM.7 · SSM.6 · SSM.7 순서. 재부팅 없음, Terraform 이 관리하지 않는 설정만 바꾼다.
  automation_docs = {
    "ASR-RevokeSecurityGroupIngress"    = "${path.module}/documents/ASR-RevokeSecurityGroupIngress.yaml"
    "ASR-DisableExposedAccessKey"       = "${path.module}/documents/ASR-DisableExposedAccessKey.yaml"
    "ASR-BlockIpWithNacl"               = "${path.module}/documents/ASR-BlockIpWithNacl.yaml"
    "ASR-RotateDbSecret"                = "${path.module}/documents/ASR-RotateDbSecret.yaml"
    "ASR-RemoveDefaultSgRules"          = "${path.module}/documents/ASR-RemoveDefaultSgRules.yaml"
    "ASR-EnableEbsDefaultEncryption"    = "${path.module}/documents/ASR-EnableEbsDefaultEncryption.yaml"
    "ASR-BlockEbsSnapshotPublicAccess"  = "${path.module}/documents/ASR-BlockEbsSnapshotPublicAccess.yaml"
    "ASR-BlockS3AccountPublicAccess"    = "${path.module}/documents/ASR-BlockS3AccountPublicAccess.yaml"
    "ASR-SetIamPasswordPolicy"          = "${path.module}/documents/ASR-SetIamPasswordPolicy.yaml"
    "ASR-EnableSsmAutomationLogging"    = "${path.module}/documents/ASR-EnableSsmAutomationLogging.yaml"
    "ASR-BlockSsmDocumentPublicSharing" = "${path.module}/documents/ASR-BlockSsmDocumentPublicSharing.yaml"
  }

  command_docs = {
    "ASR-HardenNginx"     = "${path.module}/documents/ASR-HardenNginx.yaml"
    "SCAN-PortAndWeb"     = "${path.module}/documents/SCAN-PortAndWeb.yaml"
    "SCAN-ContainerImage" = "${path.module}/documents/SCAN-ContainerImage.yaml"
  }
  # 주: ATK-WebAttack 문서는 공격자 노드가 있는 각 리전에 등록해야 한다
  #     (SSM Command 문서는 리전별 리소스). → modules/attacker 에서 등록한다.
}

resource "aws_ssm_document" "automation" {
  for_each = local.automation_docs

  name            = each.key
  document_type   = "Automation"
  document_format = "YAML"
  content         = file(each.value)

  tags = var.tags
}

resource "aws_ssm_document" "command" {
  for_each = local.command_docs

  name            = each.key
  document_type   = "Command"
  document_format = "YAML"
  content         = file(each.value)

  tags = var.tags
}
