############################################
# VPC / IGW
# 기획서 아키텍처 시트: VPC 10.0.0.0/16 (ap-northeast-2a)
############################################

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(var.tags, { Name = "${var.name_prefix}-vpc" })
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = merge(var.tags, { Name = "${var.name_prefix}-igw" })
}

############################################
# 서브넷 3종 + ALB 용 보조 Public 서브넷
#
#  Public-Web  10.0.0.0/24 : ALB, DVWA 웹서버, NAT
#  Private-DB  10.0.1.0/24 : MySQL EC2 1대
#  Private-App 10.0.2.0/24 : Docker Host, 보안 대시보드
#
#  ALB 는 서로 다른 AZ 2개가 필요합니다. 서브넷 자체는 과금이 없으므로
#  보조 서브넷을 항상 만들어 두고, enable_alb = true 일 때만 ALB 가 함께 씁니다.
############################################

resource "aws_subnet" "public_web" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.subnet_cidrs.public_web
  availability_zone       = var.az_primary
  map_public_ip_on_launch = true

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-public-web"
    Tier = "public-web"
  })
}

resource "aws_subnet" "public_web_b" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.subnet_cidrs.public_web_b
  availability_zone       = var.az_secondary
  map_public_ip_on_launch = true

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-public-web-b"
    Tier = "public-web"
    Note = "ALB 2AZ requirement only"
  })
}

resource "aws_subnet" "private_db" {
  vpc_id            = aws_vpc.this.id
  cidr_block        = var.subnet_cidrs.private_db
  availability_zone = var.az_primary

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-private-db"
    Tier = "private-db"
  })
}

resource "aws_subnet" "private_app" {
  vpc_id            = aws_vpc.this.id
  cidr_block        = var.subnet_cidrs.private_app
  availability_zone = var.az_primary

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-private-app"
    Tier = "private-app"
  })
}

############################################
# NAT Gateway — 부트스트랩 때만 켭니다 (비용)
############################################

resource "aws_eip" "nat" {
  count  = var.enable_nat_gateway ? 1 : 0
  domain = "vpc"

  tags = merge(var.tags, { Name = "${var.name_prefix}-nat-eip" })
}

resource "aws_nat_gateway" "this" {
  count         = var.enable_nat_gateway ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public_web.id

  tags = merge(var.tags, { Name = "${var.name_prefix}-nat" })

  depends_on = [aws_internet_gateway.this]
}

############################################
# 라우팅
############################################

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  tags = merge(var.tags, { Name = "${var.name_prefix}-rt-public" })
}

resource "aws_route" "public_default" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public_web" {
  subnet_id      = aws_subnet.public_web.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_web_b" {
  subnet_id      = aws_subnet.public_web_b.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id

  tags = merge(var.tags, { Name = "${var.name_prefix}-rt-private" })
}

resource "aws_route" "private_nat" {
  count                  = var.enable_nat_gateway ? 1 : 0
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this[0].id
}

resource "aws_route_table_association" "private_db" {
  subnet_id      = aws_subnet.private_db.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_app" {
  subnet_id      = aws_subnet.private_app.id
  route_table_id = aws_route_table.private.id
}

############################################
# VPC 엔드포인트 — NAT 없이 SSM Session Manager 접속
# 기획서 트래픽 허용표 ⑥ 관리자 접속: SSM (HTTPS 443), SSH 22 미개방
############################################

locals {
  # SSM Session Manager 접속용 3종만 둡니다.
  #
  # user_data 는 apt / PyPI / download.docker.com 을 쓰므로 엔드포인트로는
  # 못 덮습니다. 실습 중에는 enable_nat_gateway = true 로 두세요.
  # NAT 를 끈 채로 CloudWatch Agent 로그 수집(SEC-06 알람)과 Secrets Manager
  # 조회까지 살리려면 "secretsmanager", "logs", "monitoring" 을 추가하세요.
  # 엔드포인트당 시간당 과금이라 개수를 늘리면 NAT 1개보다 비싸집니다.
  interface_endpoints = var.enable_vpc_endpoints ? toset(["ssm", "ssmmessages", "ec2messages"]) : toset([])
}

resource "aws_vpc_endpoint" "interface" {
  for_each = local.interface_endpoints

  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private_app.id]
  security_group_ids  = [aws_security_group.vpce.id]
  private_dns_enabled = true

  tags = merge(var.tags, { Name = "${var.name_prefix}-vpce-${each.value}" })
}

# S3 게이트웨이 엔드포인트는 무료입니다. 점검 결과 업로드·패키지 다운로드에 사용.
resource "aws_vpc_endpoint" "s3" {
  count = var.enable_vpc_endpoints ? 1 : 0

  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id, aws_route_table.public.id]

  tags = merge(var.tags, { Name = "${var.name_prefix}-vpce-s3" })
}
