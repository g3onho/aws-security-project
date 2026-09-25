# OWNERSHIP — Terraform 관리 영역 / SOAR 조치 영역

`terraform`

SOAR 조치(asr_trigger → SSM Automation, 대시보드 수동 조치)가 바꾼 값을
다음 `terraform apply` 가 되돌리지 않도록 리소스·속성마다 소유자를 하나로 정한다.

- 기준: 2026-09-23 코드 대조
- 관련 코드: `modules/network/nacl.tf`, `modules/network/sg.tf`, `modules/soar/documents/ASR-*.yaml`

---

## 1. 원칙

- Terraform 은 **state 에 있는 리소스**를 코드(+속성 기본값) 기준으로 맞춘다. state 밖 리소스는 건드리지 않는다.
- SOAR 는 Terraform 이 소유하지 않는 칸에만 쓴다.
  - 조치가 Terraform 소유 리소스·속성을 바꿈 → 다음 apply 에서 원복
  - 조치가 코드가 비워 둔 칸에 씀 → apply 와 무관하게 유지
- `terraform apply -refresh-only` 는 state 만 현실에 맞춘다. 코드가 그대로면 다음 일반 apply 에서 다시 원복한다. **원복 방지 수단 아님**(탐지·기록용).
- `lifecycle { ignore_changes }` 는 속성 단위로만. 리소스가 교체(replace)되면 무시한 속성도 코드 값으로 새로 만들어진다.

---

## 2. 소유자 표

| 조치 | SEC | SOAR 가 바꾸는 것 | Terraform 선언 | 소유 | 다음 apply |
|---|---|---|---|---|---|
| `ASR-RevokeSecurityGroupIngress` (자동) | 01·03 | SG 의 `0.0.0.0/0`·`::/0` 인바운드 규칙 | `sg.tf` 전부 `aws_vpc_security_group_*_rule` 개별 선언. 취약 규칙·토글 없음 | 취약 규칙 = demo 스크립트 주입(Terraform 밖) | **유지** |
| `ASR-DisableExposedAccessKey` (자동) | 05 | access key `Status` | `aws_iam_access_key` 없음 | Terraform 밖 | **유지** |
| `ASR-BlockIpWithNacl` (수동) | 06 | NACL 인바운드 Deny 1~99 | `nacl.tf` 인라인 블록 없음, `aws_network_acl_rule` 개별 선언(100 이상만) | 1~99 = SOAR | **유지** |
| `ASR-RotateDbSecret` (수동) | 07 | Secrets Manager 시크릿 새 버전(`AWSCURRENT`) | `compute/secrets.tf` `aws_secretsmanager_secret_version.db` 가 초기 값 소유 | 공유 | **조건부 — 확인 필요** (3장) |
| `ASR-HardenNginx` (미배선·수동) | 02 | docker-host 내부 `nginx/default.conf` | 인스턴스 내부 파일. Terraform 속성 아님 | Terraform 밖 | 유지. 단 인스턴스 재생성·user_data 재실행 시 사라짐 |
| WAF 관리형·Rate 규칙 | 08 | Web ACL 규칙 | `compute/alb.tf` `aws_wafv2_web_acl.main` (`enable_alb && enable_waf`) | Terraform | 콘솔 변경은 **원복**. 규칙 변경은 코드로 |
| 스케일업 | 10 | `instance_type` | `compute/main.tf` 변수 | Terraform | 콘솔 변경은 **원복**. 변수로 변경 |
| 조치 이력 | 공통 | DynamoDB 아이템 | 테이블만 선언 | 아이템 = SOAR | 유지 |

- Terraform 코드에 `lifecycle { ignore_changes }` 는 현재 0건.
- `aws_default_network_acl`, `aws_default_security_group` 사용 0건.

---

## 3. 번호대·규칙

### NACL (Public·Private 공통)

| 번호 | 소유 | 선언 위치 |
|---|---|---|
| 1 ~ 99 | SOAR (`ASR-BlockIpWithNacl` Deny) | 코드에 선언 금지 |
| 100 이상 | Terraform (Allow) | `nacl.tf` `aws_network_acl_rule` |

- 현재 Terraform 규칙 번호: Public 인바운드 100·110·120 / 아웃바운드 100, Private 인바운드 100·110 / 아웃바운드 100. 1~99 사용 0건.
- IAM 에 규칙 번호 조건 키가 없어서 `ASR-BlockIpWithNacl` 문서가 강제한다.
  - `RuleNumber` 1~99 외 → 스크립트 단계 실패
  - `AttackerCidr` IPv4 `/32` 외 → 시작 거부(`allowedPattern`) + 스크립트 재검증
  - `NetworkAclId` `acl-` 형식 외 → 시작 거부
  - 1~99 Deny 가 이미 10개 이상 → 실패 (NACL 규칙 할당량: 방향별 기본 20개, 허용 규칙 포함)
- 해제(TTL)는 아직 없음. 테스트·만료 규칙은 수동 삭제.

### 보안 그룹

- 시연용 취약 규칙(`0.0.0.0/0` 인바운드)은 **Terraform 리소스·변수 토글로 만들지 않는다.** `demo/trigger-auto-remediation.sh` 로만 주입한다.
- 토글을 새로 만들면: 토글 `true` 인 채로 apply → SOAR 가 회수한 규칙이 재생성된다. 만들 경우 조치 후 토글 `false` 를 코드에 반영한다.
- `ASR-RevokeSecurityGroupIngress` 는 포트 무관 `0.0.0.0/0`·`::/0` 을 전부 회수한다. 정상 공개 SG(ALB)에 `AutoRemediation=enabled` 태그 금지.

### 금지 목록

- `aws_network_acl` 안 `ingress`/`egress` 인라인 블록 (규칙 목록 전체 소유 → SOAR Deny 삭제)
- 인라인 블록을 빼려고 `ingress = []` / `egress = []` 사용 (규칙 전체 삭제)
- `aws_default_network_acl` 로 SOAR 대상 NACL 관리
- SOAR 대상 SG 에 인라인 `ingress` 블록
- 테스트 키를 `aws_iam_access_key` 로 발급 (`status` 기본값 `Active` → SOAR 의 `Inactive` 원복. secret 도 state 에 남음)
- `ignore_changes = all` 또는 리소스 전체 무시

---

## 4. 조건부 항목 — 확인 필요

- **`ASR-RotateDbSecret` ↔ `aws_secretsmanager_secret_version.db`**
  - SOAR 는 `PutSecretValue` 로 새 버전을 만든다. Terraform 버전은 `AWSPREVIOUS` 로 밀린다.
  - `random_password.db_*` 재생성, `mysql_*_password`·`db_app_user`·`db_name` 변경 시 Terraform 이 새 버전을 올려 **로테이션한 값을 덮을 수 있다.**
  - 라벨만 바뀐 상태에서 plan 에 diff 가 나오는지 확인 필요 (provider 동작, 실계정 plan 으로 확인).
  - 해결 후보(팀 결정): 초기 값만 Terraform, 이후는 `ignore_changes = [secret_string]` / 버전 리소스를 Terraform 밖으로.
- **향후 추가 시 규칙**
  - WAF 동적 IP 차단 도입 시: `aws_wafv2_ip_set` + `lifecycle { ignore_changes = [addresses] }`
  - SEC-05 테스트 키를 Terraform 으로 관리하게 되면: `lifecycle { ignore_changes = [status] }` 또는 Terraform 밖 발급

---

## 5. apply 전 점검

plan 출력에 아래가 보이면 **apply 중단**, 원인부터 확인한다.

| plan 에 보이는 것 | 의미 |
|---|---|
| NACL 1~99 규칙 삭제(`-`), `aws_network_acl` 의 `ingress`/`egress` 변경(`~`) | 인라인 블록·기본 NACL 이 끼어듦 |
| SOAR 가 회수한 SG 규칙 `+ create` (`0.0.0.0/0`) | 취약 규칙이 Terraform 소유가 됨 |
| access key `status → Active` | 키가 Terraform 소유 |
| `aws_secretsmanager_secret_version.db` 교체·새 버전 | 로테이션 값 덮어씀 (4장) |

### 경계 확인 절차 (팀 격리 계정, 사람이 실행)

```bash
cd terraform
aws sts get-caller-identity                            # 계정 확인

terraform plan -detailed-exitcode; echo "exit=$?"      # 0 기대 (0 변경없음 / 1 오류 / 2 변경있음)

NACL=$(terraform output -json target_security_groups | python -c "import sys,json;print(json.load(sys.stdin)['private_nacl_id'])")
ROLE=$(aws iam get-role --role-name soar-sec-dev-ssm-automation-role --query Role.Arn --output text)

# 1~99 칸에 테스트 Deny (192.0.2.10/32 = RFC 5737 문서용 대역)
aws ssm start-automation-execution --document-name ASR-BlockIpWithNacl \
  --parameters "NetworkAclId=$NACL,AttackerCidr=192.0.2.10/32,RuleNumber=90,AutomationAssumeRole=$ROLE"
terraform plan -detailed-exitcode; echo "exit=$?"      # 0 기대 (Deny 가 삭제 대상으로 안 나옴)

# 경계 밖 번호 → 실행 Failed, NACL 에 150번 규칙 없어야 함
aws ssm start-automation-execution --document-name ASR-BlockIpWithNacl \
  --parameters "NetworkAclId=$NACL,AttackerCidr=192.0.2.11/32,RuleNumber=150,AutomationAssumeRole=$ROLE"

# 경계 밖 CIDR → 시작 거부(ValidationException)
aws ssm start-automation-execution --document-name ASR-BlockIpWithNacl \
  --parameters "NetworkAclId=$NACL,AttackerCidr=0.0.0.0/0,RuleNumber=91,AutomationAssumeRole=$ROLE"

# 정리
aws ec2 delete-network-acl-entry --network-acl-id "$NACL" --ingress --rule-number 90
terraform plan -detailed-exitcode; echo "exit=$?"      # 0 기대
```

- 역할 이름 `soar-sec-dev-…` 은 기본 `name_prefix` 기준. tfvars 가 다르면 맞춰 바꾼다.
- PowerShell 은 `echo "exit=$?"` 대신 `echo $LASTEXITCODE`.
