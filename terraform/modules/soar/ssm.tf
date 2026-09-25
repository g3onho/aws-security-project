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

  # executeScript 를 위한 CloudWatch Logs
  statement {
    sid       = "AutomationLogs"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
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
  automation_docs = {
    "ASR-RevokeSecurityGroupIngress" = "${path.module}/documents/ASR-RevokeSecurityGroupIngress.yaml"
    "ASR-DisableExposedAccessKey"    = "${path.module}/documents/ASR-DisableExposedAccessKey.yaml"
    "ASR-BlockIpWithNacl"            = "${path.module}/documents/ASR-BlockIpWithNacl.yaml"
    "ASR-RotateDbSecret"             = "${path.module}/documents/ASR-RotateDbSecret.yaml"
  }

  command_docs = {
    "ASR-HardenNginx"     = "${path.module}/documents/ASR-HardenNginx.yaml"
    "SCAN-PortAndWeb"     = "${path.module}/documents/SCAN-PortAndWeb.yaml"
    "SCAN-ContainerImage" = "${path.module}/documents/SCAN-ContainerImage.yaml"
  }
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
