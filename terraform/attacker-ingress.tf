############################################
# 지리별 공격 노드 → 파리 DVWA 접근 허용 (SEC-08)
#
# 왜 루트에 두는가: 규칙은 파리의 ALB·DVWA SG(파리 프로바이더)를 대상으로 하고
# 공격 노드의 공인 IP(다른 리전 프로바이더)를 소스로 쓴다. 공격 모듈은
# module.compute.web_dvwa_public_ip 에 의존하고 compute 는 module.network 에 의존하므로,
# 이 규칙을 network 모듈 안에 넣으면 network→attacker→compute→network 순환이 생긴다.
# 루트의 독립 리소스로 두면 순환이 없다(규칙→network, 규칙→attacker 만 성립).
#
# 왜 SG 참조가 아니라 /32 CIDR 인가: 공격 노드는 파리가 아닌 5개 리전에 있어
# 교차 리전 SG 참조가 불가능하다. 공인 IP 를 /32 로 넣는다.
# 공격 노드에 EIP 가 없어 재부팅 시 IP 가 바뀌면 terraform apply 가 재동기화한다.
#
# 범위: DVWA:80·22 직접(nmap·hydra)과 ALB:8081(WAF 경유 웹 공격)만 연다.
# 취약 앱이므로 전체공개(0.0.0.0/0)는 절대 열지 않는다 — 공격자 노드 /32 로만 한정.
# 2026-09-30: SSH(22)도 공격자 IP 에 추가로 열었다. hydra SSH 브루트포스가 SG 에서 막혀
# GuardDuty SSHBruteForce 탐지·지도 공격선이 전혀 안 뜨고 있었다(nmap 결과 22 filtered).
############################################

# for_each 키는 plan 시점에 알 수 있어야 한다. 공격 노드 공인 IP 는 인스턴스를 새로 만들거나 교체할 때 apply 전까지 모르는 값이라,
# IP(또는 "<IP>/32")를 키로 쓰면 "Invalid for_each argument ... known only after apply" 로 plan 이 실패한다.
# → 키는 리전 이름(정적)으로 두고, 알 수 없는 IP 는 값(cidr_ipv4)으로만 쓴다.
# 공격 노드가 꺼져 있으면(geo_attackers_on=false) 빈 map 이라 규칙이 없다. 켜져 있으면 5개 노드의 공인 IP 가 모두 있어야 한다(없으면 apply 가 실패해 알려 준다).
locals {
  attacker_public_ips = local.geo_attackers_on ? {
    us-virginia = module.attacker_us_virginia.public_ip
    singapore   = module.attacker_singapore.public_ip
    sydney      = module.attacker_sydney.public_ip
    mumbai      = module.attacker_mumbai.public_ip
    tokyo       = module.attacker_tokyo.public_ip
  } : {}
}

resource "aws_vpc_security_group_ingress_rule" "dvwa_from_attackers" {
  for_each = local.attacker_public_ips

  security_group_id = module.network.sg_web_dvwa_id
  description       = "HTTP from geo attacker node (SEC-08 direct)"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = "${each.value}/32"
}

resource "aws_vpc_security_group_ingress_rule" "dvwa_ssh_from_attackers" {
  for_each = local.attacker_public_ips

  security_group_id = module.network.sg_web_dvwa_id
  description       = "SSH from geo attacker node (SEC-06B/08 direct) - 2026-09-30 added for GuardDuty SSHBruteForce demo"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = "${each.value}/32"
}

resource "aws_vpc_security_group_ingress_rule" "alb_dvwa_from_attackers" {
  for_each = var.enable_alb ? local.attacker_public_ips : {}

  security_group_id = module.network.sg_alb_id
  description       = "DVWA via ALB from geo attacker node (SEC-08 web)"
  ip_protocol       = "tcp"
  from_port         = 8081
  to_port           = 8081
  cidr_ipv4         = "${each.value}/32"
}
