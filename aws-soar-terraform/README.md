# AWS SOAR / SIEM / NMS 보안 관제 대시보드 — Terraform v10

2팀 · 2차 클라우드 보안 프로젝트 인프라 코드입니다. 기본기획서(2026-09-17)와 설계문서 v10을 코드로 구현했습니다.

- **모듈 4개**: `network` / `compute` / `security` / `soar` + `bootstrap`(선택)
- **tf 파일 36개(약 3,600줄)** + Lambda 2개(258줄) + SSM 문서 7종 + user_data 5종 + 데모 3종
- Terraform `>= 1.6`, AWS Provider `~> 6.0`

---

## 1. 실행 순서 (Windows PowerShell)

실습 가이드(`6-Windows...실습가이드`)의 절차를 그대로 씁니다.

```powershell
# 압축 해제 후 폴더로 이동
cd .\aws-soar-terraform

# (선택) 변수 파일
Copy-Item .\terraform.tfvars.example .\terraform.tfvars
notepad .\terraform.tfvars

terraform init
terraform fmt -recursive
terraform validate
terraform plan -out=tfplan
terraform apply tfplan
```

접속은 SSH 22를 열지 않고 **SSM Session Manager**를 씁니다.

```powershell
terraform output ssh_commands          # 인스턴스별 세션 접속 명령
terraform output dashboard_ssm_port_forward   # 대시보드 5000 포트포워딩
terraform output cost_warning          # 지금 켜져 있는 유료 리소스
```

> `admin_cidr`을 비워두면 실행 PC의 현재 공인 IP/32가 자동으로 SG에 들어갑니다(`detected_admin_cidr` 출력으로 확인). IP가 바뀌면 다시 `apply`.

---

## 2. 무엇이 만들어지나

### 네트워크 (network)
VPC `10.0.0.0/16`, Public-Web(`10.0.0.0/24`, ALB용 보조 AZ 서브넷 포함) / Private-DB(`10.0.1.0/24`) / Private-App(`10.0.2.0/24`), IGW, NAT(옵션), NACL 이중 방어, VPC Flow Logs, SSM용 VPC 엔드포인트.

**보안그룹 8종** — 핵심은 DB용 2개:

| SG | AutoRemediation 태그 | 역할 |
|---|---|---|
| `db-auto-sg` | enabled | 자동 회수 대상 |
| `db-manual-sg` | 없음 | 대조군(알림만) |

DB EC2는 **1대**지만 두 SG를 함께 붙입니다. Config는 SG 단위로 평가하므로, 같은 위반(3306/0.0.0.0/0)을 두 SG에 넣으면 "태그 유무로 결과가 갈리는" 시연이 한 인스턴스에서 됩니다.

### 컴퓨팅 (compute)
- `docker-host` — Nginx + Flask + MySQL 컨테이너(3-Tier). frontend/backend 네트워크 분리, DB 포트 미공개.
- `db` — MySQL EC2 1대(로그 수집형 탐지용, RDS 아님).
- `dashboard` — SOAR 대시보드. **읽기 전용 정책 / ASR-* 실행 전용 정책 분리**.
- `web-dvwa`(옵션) — SEC-08 웹 공격 대상.
- `attacker`(옵션) — 내부 점검용 최소 호스트. 공격 자동화는 팀이 격리 환경에서 직접.
- ALB + WAFv2(옵션), Secrets Manager, ECR.

### 탐지 (security)
GuardDuty(+feature), Inspector2(EC2·ECR), AWS Config **규칙 4개**, IAM Access Analyzer, Security Hub(FSBP), CloudTrail(+S3+KMS). Config는 비용 절감을 위해 7개 리소스 타입만 기록.

### 자동조치·모니터링 (soar)
EventBridge 3규칙, Lambda 2개(`correlator`/`asr_trigger`), SSM 문서 7종, DynamoDB 2개, SNS, CloudWatch 알람·메트릭 필터·대시보드.

---

## 3. 기획서 성공 기준 매핑

| 구분 | 기획서 기능명 | 구현 |
|---|---|---|
| 자동 모니터링 ①| AWS 보안 설정 자동 점검(CSPM) | Config 4규칙 + Security Hub + Access Analyzer |
| 자동 모니터링 ②| 위협·취약점 상관분석 | GuardDuty×Inspector → `correlator` → DynamoDB |
| 자동 모니터링 ③| 인프라 임계치 알림(NMS) | CloudWatch 알람 CPU·메모리 **80%** → SNS |
| 수동 모니터링 ①| 외부 포트·웹 점검 | `SCAN-PortAndWeb`(nmap·curl) → S3 |
| 수동 모니터링 ②| 컨테이너 이미지 점검 | `SCAN-ContainerImage`(Trivy) → S3 |
| 자동 개선 ①| SG 규칙 자동 회수 | `ASR-RevokeSecurityGroupIngress` |
| 자동 개선 ②| Nginx 보안 설정 적용 | `ASR-HardenNginx` |
| 자동 개선 ③| 노출 IAM 키 비활성화 | `ASR-DisableExposedAccessKey` |
| 수동 개선 ①| 공격 IP 차단 | `ASR-BlockIpWithNacl`(승인 후) |
| 수동 개선 ②| 시크릿·DB 계정 분리 | `ASR-RotateDbSecret` + Secrets Manager |
| 수동 개선 ③| 취약 이미지 교체 | ECR+Inspector, 절차는 아래 |

> **자동/수동 분류 기준은 팀이 확정해야 합니다.** 기획서는 "Nginx 보안 설정 적용"을 승인 후 실행인데도 자동으로 분류했습니다. 코드는 이를 `ASR-HardenNginx`(Run Command)로 두었고, 발표 전 한 가지 정의로 통일하세요.

---

## 4. 자동조치 안전장치 3중

`asr_trigger` Lambda가 순서대로 확인합니다.

1. **화이트리스트 매칭** (`auto_remediable_patterns`) — 1차 판단 기준(finding 유형)
2. **대상 SG의 `AutoRemediation=enabled` 태그** — 2차(자원 허용 여부)
3. **`enable_auto_remediation` 변수** — 전체 dry-run 스위치

셋 다 통과해야 SSM을 실행하고, 아니면 SNS 알림만 보냅니다(수동 경로). 되돌릴 수 있는 조치만 자동화합니다(SG 회수·키 비활성화).

---

## 5. Before / After

자동 조치는 대시보드를 거치지 않으므로, `asr_trigger`가 조치 전/후 상태를 **DynamoDB 조치 이력 테이블에 직접 기록**합니다. SSM 플레이북은 `before`/`after`를 반환하고, 대시보드는 이 테이블을 boto3로 읽습니다.

```powershell
terraform output remediation_actions_table
terraform output correlated_findings_table
```

---

## 6. 시연

```bash
# SEC-03 자동조치 — 자동 대상
./demo/trigger-auto-remediation.sh
# SEC-03 대조군 — 태그 없는 SG (알림만)
./demo/trigger-auto-remediation.sh --manual

# 수동 모니터링
./demo/run-manual-scan.sh port <대상IP>
./demo/run-manual-scan.sh image

# 정리
./demo/cleanup.sh
```

---

## 7. 비용

`enable_nat_gateway` / `enable_alb` / `enable_waf`는 **기본 false**. 탐지 서비스는 기본 true지만 개별 변수로 끌 수 있습니다. 발표·시연 직전에만 켜세요.

```powershell
terraform output cost_warning
terraform output cleanup_checklist
```

실습 종료: `demo/cleanup.sh` → `terraform destroy` → 콘솔에서 탐지 서비스 비활성화 확인. CloudTrail S3·KMS는 보존 설정이라 수동 삭제.

---

## 8. 검증 상태 — 팀이 반드시 확인할 것

작업 환경에서 **Terraform 레지스트리 접근이 막혀 `terraform validate`/`plan`을 실행하지 못했습니다.** 대신 아래 정적 검사를 통과했습니다.

- HCL 파싱(python-hcl2) 36파일 오류 0
- 모듈 변수 선언 ↔ 전달 인자 일치, `module.*` output 참조 28건 전부 유효
- **모듈 순환 참조 없음** (network → compute → soar, security 독립)
- templatefile 인자 ↔ 템플릿 `${}` 변수 일치, bash `$$` escape 확인
- Lambda Python / SSM YAML / 셸 스크립트 문법 통과
- AWS Provider 6.x 기준 작성: `aws_region.*.region`(구 `.name` 미사용), `aws_guardduty_detector_feature`, `aws_inspector2_enabler`, `aws_vpc_security_group_*_rule`

**팀 계정에서 `terraform init && validate && plan`을 한 번 돌려** provider 스키마를 검증하고, 걸리는 지점부터 고치세요. 특히 확인할 것:

- 리전의 실제 AZ 이름(`az_primary`/`az_secondary`) — 기본 `ap-northeast-2a/2c`
- AWS Config·Security Hub·GuardDuty가 계정에 이미 활성화돼 있으면 중복 활성화 충돌 가능
- ECR 이미지(`app-1.0.0`)를 push하기 전에는 docker-host의 compose가 web 컨테이너를 못 올림 — 서비스 이미지는 팀이 빌드·push
