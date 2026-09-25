############################################
# VPC Flow Logs (SEC-09)
# 기획서 탐지 경로: VPC -> Flow Logs -> GuardDuty / CloudWatch Logs
# Flow Logs 는 finding 을 받는 쪽이 아니라 로그를 만드는 쪽입니다.
############################################

resource "aws_cloudwatch_log_group" "flowlogs" {
  count             = var.enable_flow_logs ? 1 : 0
  name              = var.log_group_flowlogs
  retention_in_days = var.log_retention_days

  tags = merge(var.tags, { Scenario = "SEC-09" })
}

data "aws_iam_policy_document" "flowlogs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flowlogs" {
  count              = var.enable_flow_logs ? 1 : 0
  name               = "${var.name_prefix}-flowlogs-role"
  assume_role_policy = data.aws_iam_policy_document.flowlogs_assume.json

  tags = var.tags
}

data "aws_iam_policy_document" "flowlogs" {
  count = var.enable_flow_logs ? 1 : 0

  statement {
    sid = "WriteFlowLogs"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
    ]
    resources = ["${aws_cloudwatch_log_group.flowlogs[0].arn}:*"]
  }

  statement {
    sid       = "DescribeLogGroups"
    actions   = ["logs:DescribeLogGroups"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "flowlogs" {
  count  = var.enable_flow_logs ? 1 : 0
  name   = "${var.name_prefix}-flowlogs-policy"
  role   = aws_iam_role.flowlogs[0].id
  policy = data.aws_iam_policy_document.flowlogs[0].json
}

resource "aws_flow_log" "vpc" {
  count = var.enable_flow_logs ? 1 : 0

  vpc_id                   = aws_vpc.this.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flowlogs[0].arn
  iam_role_arn             = aws_iam_role.flowlogs[0].arn
  max_aggregation_interval = 60

  tags = merge(var.tags, {
    Name     = "${var.name_prefix}-flowlog"
    Scenario = "SEC-09"
  })
}
