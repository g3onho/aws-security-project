############################################
# AMI — Ubuntu 24.04 LTS (실습 가이드와 동일한 OS)
# SSM Agent 가 기본 탑재되어 있어 SSH 22 를 열지 않고 접속할 수 있습니다.
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

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
}
