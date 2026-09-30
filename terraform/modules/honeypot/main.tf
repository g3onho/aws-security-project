############################################
# A6 AI 미끼서버(허니팟) — MVP
#
# 정상 트래픽이 닿을 이유가 없는 미끼 서버. 접속 자체가 곧 공격 신호이므로
# 오탐 걱정 없이 자동 차단 대상으로 쓴다(기존 ASR-BlockIpWithNacl 재사용).
#
# AI(Amazon Bedrock): ① 실시간 가짜 셸  ② 세션 사후 분석·IOC  ③ 위험도 판정.
# 상세 로직은 templates/honeypot.py.tftpl 참고. Bedrock 실패 시에도 로깅·탐지·차단은 계속.
#
# 탐지 연결: 접속 로그 → 지표 필터(HoneypotHitCount) → 알람 → (soar) EventBridge → asr_trigger.
############################################

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd*/ubuntu-noble-24.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

locals {
  honeypot_py = templatefile("${path.module}/templates/honeypot.py.tftpl", {
    region      = var.region
    log_group   = aws_cloudwatch_log_group.honeypot.name
    ai_enabled  = var.enable_ai ? "true" : "false"
    ai_model_id = var.ai_model_id
    listen_port = var.listen_port
  })
}

resource "aws_cloudwatch_log_group" "honeypot" {
  name              = "/honeypot/${var.name_prefix}"
  retention_in_days = var.log_retention_days
  tags              = merge(var.tags, { Scenario = "HONEYPOT" })
}

# --- 격리 보안그룹: 내부(VPC)에서 미끼 포트로 들어오는 것만 허용, 나머지 리소스와 공유하지 않음 ---
resource "aws_security_group" "honeypot" {
  name        = "${var.name_prefix}-honeypot"
  description = "AI honeypot decoy - any inbound is a signal"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = "${var.name_prefix}-honeypot", Scenario = "HONEYPOT" })

  ingress {
    description = "Decoy SSH (any connection is an attack signal)"
    from_port   = var.listen_port
    to_port     = var.listen_port
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "Bedrock / CloudWatch Logs / package install (via NAT)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- 최소 권한 IAM: CloudWatch Logs 전송 + Bedrock 호출 + SSM(관리 접속) ---
data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "honeypot" {
  name               = "${var.name_prefix}-honeypot"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "honeypot_ssm" {
  role       = aws_iam_role.honeypot.name
  policy_arn = "arn:${var.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "honeypot" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
    resources = ["${aws_cloudwatch_log_group.honeypot.arn}:*"]
  }
  dynamic "statement" {
    for_each = var.enable_ai ? [1] : []
    content {
      sid       = "BedrockInvoke"
      actions   = ["bedrock:InvokeModel"]
      resources = ["*"] # 모델·추론 프로파일 ARN 은 리전·계정마다 달라 * 로 둔다(호출만 허용).
    }
  }
}

resource "aws_iam_role_policy" "honeypot" {
  name   = "${var.name_prefix}-honeypot"
  role   = aws_iam_role.honeypot.id
  policy = data.aws_iam_policy_document.honeypot.json
}

resource "aws_iam_instance_profile" "honeypot" {
  name = "${var.name_prefix}-honeypot"
  role = aws_iam_role.honeypot.name
}

resource "aws_instance" "honeypot" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [aws_security_group.honeypot.id]
  iam_instance_profile   = aws_iam_instance_profile.honeypot.name

  # 미끼는 공인 IP 를 두지 않는다(내부 정찰 유인). 관리 접속은 SSM Session Manager.
  associate_public_ip_address = false

  # honeypot.py 를 base64 로 한 번 더 인코딩해 넣다 보니 원본(12KB대)이 인플레이션(+33%)으로
  # EC2 user_data 16KB 한도를 넘었다. gzip 압축으로 우회한다 — cloud-init 은 gzip user-data 를
  # 자동 압축 해제하므로 부트스트랩 스크립트 자체는 그대로 두고 전달 방식만 바꾼다.
  user_data_base64 = base64gzip(templatefile("${path.module}/templates/user_data.sh.tftpl", {
    honeypot_py_b64 = base64encode(local.honeypot_py)
  }))
  user_data_replace_on_change = true

  # v36.1: 팀원 PC마다 줄바꿈(CRLF/LF)이 달라 user_data 가 바뀐 것처럼 보여 인스턴스가 교체되는 것을 막는다.
  # 부팅 스크립트를 실제로 바꿨다면 terraform apply -replace=<이 리소스 주소> 로 직접 교체한다.
  lifecycle {
    ignore_changes = [user_data]
  }

  metadata_options {
    http_tokens = "required" # IMDSv2 강제
  }

  tags = merge(var.tags, {
    Name     = "${var.name_prefix}-honeypot"
    Scenario = "HONEYPOT"
    Role     = "honeypot-decoy" # 보호 자산 아님. asr_trigger PROTECTED_ROLES 에 넣지 말 것.
  })
}

# --- 접속 신호 → 지표 → 알람 (SEC-06 패턴과 동일) ---
resource "aws_cloudwatch_log_metric_filter" "honeypot_hit" {
  name           = "${var.name_prefix}-honeypot-hit"
  log_group_name = aws_cloudwatch_log_group.honeypot.name
  pattern        = "{ $.event = \"connect\" }"

  metric_transformation {
    name          = "HoneypotHitCount"
    namespace     = "${var.name_prefix}/security"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "honeypot" {
  alarm_name          = "${var.name_prefix}-honeypot"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = var.alarm_evaluation_periods
  metric_name         = "HoneypotHitCount"
  namespace           = "${var.name_prefix}/security"
  period              = var.alarm_period
  statistic           = "Sum"
  threshold           = var.hit_threshold
  alarm_description   = "Honeypot connection(s) detected — any hit is an attack signal (HONEYPOT)"
  treat_missing_data  = "notBreaching"

  alarm_actions = compact([var.sns_topic_arn])

  tags = merge(var.tags, { Scenario = "HONEYPOT" })
}
