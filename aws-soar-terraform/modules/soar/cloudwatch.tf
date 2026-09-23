############################################
# CloudWatch Logs 그룹 (Nginx / MySQL / Flow Logs 는 각 모듈에서 생성)
############################################

# 서비스/DB 로그 그룹은 CloudWatch Agent 가 자동 생성하지만,
# 보존기간을 관리하기 위해 명시적으로 선언합니다.
resource "aws_cloudwatch_log_group" "nginx" {
  name              = var.log_group_nginx
  retention_in_days = var.log_retention_days
  tags              = merge(var.tags, { Scenario = "SEC-02/SEC-09" })
}

resource "aws_cloudwatch_log_group" "mysql" {
  name              = var.log_group_mysql
  retention_in_days = var.log_retention_days
  tags              = merge(var.tags, { Scenario = "SEC-06" })
}

############################################
# 자동 모니터링 #3 (NMS) — CPU/메모리 임계치 알람
# 기획서 프로젝트 목표 3) : 80% 초과 시 CloudWatch + SNS
############################################

resource "aws_cloudwatch_metric_alarm" "cpu" {
  for_each = var.monitored_instances

  alarm_name          = "${var.name_prefix}-${each.key}-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = var.cpu_alarm_threshold
  alarm_description   = "CPU > ${var.cpu_alarm_threshold}% on ${each.key}"
  treat_missing_data  = "notBreaching"

  dimensions = {
    InstanceId = each.value
  }

  alarm_actions = [aws_sns_topic.alerts.arn]
  ok_actions    = [aws_sns_topic.alerts.arn]

  tags = merge(var.tags, { Scenario = "SEC-10" })
}

# 메모리는 CloudWatch Agent 커스텀 지표(${name_prefix}/host, MemoryUsedPercent)
resource "aws_cloudwatch_metric_alarm" "memory" {
  for_each = var.monitored_instances

  alarm_name          = "${var.name_prefix}-${each.key}-mem-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "MemoryUsedPercent"
  namespace           = "${var.name_prefix}/host"
  period              = 300
  statistic           = "Average"
  threshold           = var.memory_alarm_threshold
  alarm_description   = "Memory > ${var.memory_alarm_threshold}% on ${each.key}"
  treat_missing_data  = "notBreaching"

  dimensions = {
    InstanceId = each.value
  }

  alarm_actions = [aws_sns_topic.alerts.arn]

  tags = merge(var.tags, { Scenario = "SEC-10" })
}

############################################
# SEC-06 — MySQL 무차별 대입 탐지
# GuardDuty 는 EC2 자체 설치 MySQL 로그인 실패를 잡지 못하므로
# CloudWatch Logs 메트릭 필터 -> Alarm -> SNS 경로로 탐지합니다.
############################################

resource "aws_cloudwatch_log_metric_filter" "mysql_auth_fail" {
  name           = "${var.name_prefix}-mysql-auth-fail"
  log_group_name = aws_cloudwatch_log_group.mysql.name
  pattern        = "\"Access denied for user\""

  metric_transformation {
    name          = "MySQLAuthFailure"
    namespace     = "${var.name_prefix}/security"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "mysql_bruteforce" {
  alarm_name          = "${var.name_prefix}-mysql-bruteforce"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "MySQLAuthFailure"
  namespace           = "${var.name_prefix}/security"
  period              = 300
  statistic           = "Sum"
  threshold           = var.mysql_auth_fail_threshold
  alarm_description   = "MySQL auth failures >= ${var.mysql_auth_fail_threshold} in 5 min (possible brute force)"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.alerts.arn]

  tags = merge(var.tags, { Scenario = "SEC-06" })
}

############################################
# SEC-08 — WAF 차단 급증 탐지
# 대시보드는 Security Hub finding 만 이벤트로 읽으므로, 알람 -> EventBridge ->
# waf_finding Lambda 가 finding 으로 가져온다(eventbridge.tf ④).
# Rule 차원 값은 alb.tf 각 규칙의 visibility_config.metric_name 이다.
############################################

locals {
  waf_rules = var.enable_waf_finding ? {
    sqli   = "SQLiRuleSet"
    common = "CommonRuleSet"
    rate   = "RateLimitPerIp"
  } : {}
}

resource "aws_cloudwatch_metric_alarm" "waf_block" {
  for_each = local.waf_rules

  # 이름 끝(-waf-<key>)을 waf_finding Lambda 가 심각도·제목 매핑에 쓴다.
  alarm_name          = "${var.name_prefix}-waf-${each.key}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = 60
  statistic           = "Sum"
  threshold           = var.waf_block_alarm_threshold
  alarm_description   = "WAF ${each.value} blocked >= ${var.waf_block_alarm_threshold} requests in 1 min"
  treat_missing_data  = "notBreaching"

  dimensions = {
    WebACL = var.waf_web_acl_name
    Region = var.region
    Rule   = each.value
  }

  alarm_actions = [aws_sns_topic.alerts.arn]

  tags = merge(var.tags, { Scenario = "SEC-08" })
}

############################################
# CloudWatch 대시보드 (인프라 모니터링 탭 백업 뷰)
############################################

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${var.name_prefix}-overview"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "EC2 CPU"
          region = var.region
          view   = "timeSeries"
          metrics = [
            for k, v in var.monitored_instances :
            ["AWS/EC2", "CPUUtilization", "InstanceId", v, { label = k }]
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "MySQL auth failures (SEC-06)"
          region = var.region
          view   = "timeSeries"
          metrics = [
            ["${var.name_prefix}/security", "MySQLAuthFailure"]
          ]
        }
      }
    ]
  })
}
