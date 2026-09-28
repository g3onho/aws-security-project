############################################
# 공격자 노드 1대 (리전당 하나)
#
# - 리전 기본 VPC/기본 서브넷 사용. 공격자는 아웃바운드 인터넷 + SSM 만 필요하다.
#   ponytail: 공격 노드용으로 리전마다 VPC를 새로 만들지 않는다. 기본 VPC의
#             IGW를 그대로 쓴다. 전용 네트워크가 필요해지면 그때 만든다.
# - Docker 설치 후 hydra+nmap 이미지를 부팅 시 빌드.
# - 인바운드 SG 없음(SSM은 에이전트가 아웃바운드로 붙는다). 키페어 불필요.
# - 실제 공격은 대시보드 → SSM(ATK-*) → 이 노드에서 docker run 으로 실행.
############################################

data "aws_vpc" "default" {
  count   = var.enabled ? 1 : 0
  default = true
}

data "aws_subnets" "default" {
  count = var.enabled ? 1 : 0
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default[0].id]
  }
  filter {
    name   = "default-for-az"
    values = ["true"]
  }
}

# 리전별 Ubuntu 22.04 최신 AMI (Canonical). 기존 attacker.sh 가 apt 기반이라 Ubuntu 로 맞춘다.
data "aws_ami" "ubuntu" {
  count       = var.enabled ? 1 : 0
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

############################################
# IAM — SSM 관리 + 결과 CloudWatch Logs 업로드
############################################

data "aws_iam_policy_document" "assume" {
  count = var.enabled ? 1 : 0
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "this" {
  count              = var.enabled ? 1 : 0
  name               = "${var.name_prefix}-attacker-${var.region_label}"
  assume_role_policy = data.aws_iam_policy_document.assume[0].json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "ssm" {
  count      = var.enabled ? 1 : 0
  role       = aws_iam_role.this[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "cwagent" {
  count      = var.enabled ? 1 : 0
  role       = aws_iam_role.this[0].name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_instance_profile" "this" {
  count = var.enabled ? 1 : 0
  name  = "${var.name_prefix}-attacker-${var.region_label}"
  role  = aws_iam_role.this[0].name
}

############################################
# SG — 인바운드 전면 차단, 아웃바운드만 허용
############################################

resource "aws_security_group" "this" {
  count       = var.enabled ? 1 : 0
  name        = "${var.name_prefix}-attacker-${var.region_label}"
  description = "Attacker node - egress only"
  vpc_id      = data.aws_vpc.default[0].id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-attacker-${var.region_label}" })
}

############################################
# EC2
############################################

resource "aws_instance" "this" {
  count                       = var.enabled ? 1 : 0
  ami                         = data.aws_ami.ubuntu[0].id
  instance_type               = var.instance_type
  subnet_id                   = data.aws_subnets.default[0].ids[0]
  vpc_security_group_ids      = [aws_security_group.this[0].id]
  iam_instance_profile        = aws_iam_instance_profile.this[0].name
  associate_public_ip_address = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 강제
    http_put_response_hop_limit = 2          # 컨테이너에서의 호출 허용
  }

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = templatefile("${path.module}/templates/attacker.sh.tftpl", {
    region_label = var.region_label
  })
  user_data_replace_on_change = true

  tags = merge(var.tags, {
    Name        = "${var.name_prefix}-attacker-${var.region_label}"
    Role        = "attack-simulation"
    AttackerFor = "dvwa"
    RegionLabel = var.region_label
    Note        = "Team-owned lab attack source only"
  })
}

############################################
# 이 리전의 공격 SSM Command 문서
# (SSM 문서는 리전별 리소스라, 공격자가 있는 각 리전에 등록해야 SendCommand 가능)
############################################

resource "aws_ssm_document" "atk" {
  count           = var.enabled ? 1 : 0
  name            = var.attack_document_name
  document_type   = "Command"
  document_format = "YAML"
  content         = var.attack_document_content
  tags            = var.tags
}
