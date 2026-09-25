# AS-IS / TO-BE

`terraform` (v10 + A 병합본) · 학생가이드 기준 · 2026-09-18

- **AS-IS** = 가이드 대조 전 상태
- **TO-BE** = 최종 목표 상태
- **현재** ✅완료 / 🔜계획 / ⚠️미충족(잔여 위험)

---

## 1. 네트워크 · 접근통제

| # | 항목 | AS-IS | TO-BE | 현재 |
|---:|---|---|---|:---:|
| 1 | Flask 5000 | — | VPC CIDR 안에서만 (SSM 포트 포워딩) | ✅ 원래부터 |
| 2 | MySQL 3306 | app/web SG 참조만 허용 | 동일 | ✅ |
| 3 | SSH 22 | — | 규칙 자체가 없음 (Session Manager 전용) | ✅ 원래부터 |
| 4 | SG 규칙 방식 | 계층 SG 참조 사용 | 동일 | ✅ |
| 5 | MySQL 위치 | Private-DB 서브넷, Public IP 없음 | 동일 | ✅ |
| 6 | NACL | 서브넷 단위 이중 방어 적용 | 동일 | ✅ |
| 7 | HTTPS / TLS | 인증서 미발급 | `acm_certificate_arn` 주입 시 활성 | ⚠️ 코드 준비됨 |

## 2. EC2 · 스토리지 · 권한

| # | 항목 | AS-IS | TO-BE | 현재 |
|---:|---|---|---|:---:|
| 8 | IMDSv2 | 5대 전부 `http_tokens = required` | 동일 | ✅ |
| 9 | EBS | gp3 + `encrypted = true` | 동일 | ✅ |
| 10 | 자격증명 | IAM Role 3종 (Access Key 미사용) | 동일 | ✅ |
| 11 | DB 비밀번호 | Secrets Manager + Role 조회 | 동일 | ✅ |
| 12 | 태그 | Project / Env / Team / ManagedBy (4종) | + Owner (5종) | ✅ 병합 |

## 3. 로깅 · 탐지

| # | 항목 | AS-IS | TO-BE | 현재 |
|---:|---|---|---|:---:|
| 13 | CloudTrail | 다중리전 + 로그검증 + KMS | 동일 | ✅ |
| 14 | VPC Flow Logs | CloudWatch 전송 | 동일 | ✅ |
| 15 | AWS Config | 규칙 4개 | 동일 | ✅ |
| 16 | GuardDuty / Inspector / Security Hub | 활성화 | 동일 | ✅ |
| 17 | 자동조치 (SOAR) | Lambda 2 + SSM + EventBridge | 동일 (가이드 범위 밖, 차별점) | ✅ |

## 4. 형상관리 · State

| # | 항목 | AS-IS | TO-BE | 현재 |
|---:|---|---|---|:---:|
| 18 | `.gitignore` — state/tfvars/tfplan | 있음 | 동일 | ✅ |
| 19 | `.gitignore` | `*.pem`·`*.key` 있음, `*.tfplan`·`*.ppk` 없음 | 전부 포함 | ✅ 병합 |
| 20 | `.terraform.lock.hcl` | ignore 중 (가이드와 반대) | 커밋 대상 | ✅ 병합 |
| 21 | State 위치 | 로컬 | S3 + DynamoDB 잠금 | ⚠️ `bootstrap/` apply 필요 |

## 5. 제출물

| # | 항목 | AS-IS | TO-BE | 현재 |
|---:|---|---|---|:---:|
| 22 | 비용 예측 / 승인 기록 | 없음 | `docs/비용예측.md` | ✅ 양식 |
| 23 | 증적 12개 항목 | 없음 | `docs/증적양식.md` + VULN-001~004 | ✅ apply 전까지 |
| 24 | 제출 체크리스트 | 없음 | `docs/체크리스트.md` | ✅ |
| 25 | 차단/기능 검증 스크립트 | 없음 | `demo/verify-controls.sh` | ✅ 병합 |

## 6. 아키텍처 (B안에서 의도적으로 미변경)

| # | 항목 | AS-IS | 가이드 TO-BE | 판단 |
|---:|---|---|---|---|
| 26 | EC2 구성 | 5대 (DVWA/DB/Docker/대시보드/공격자) | 3대 (K3s/Flask/MySQL) | 미변경 |
| 27 | 진입점 | ALB 80→443 리다이렉트 (옵션) | NLB TCP 80·443 → NodePort | 미변경 |
| 28 | TLS 종료 | ALB (ACM 인증서 필요) | K3s Nginx (self-signed) | 미변경 |

> SOAR 시나리오가 DVWA 공격 탐지에 묶여 있어 아키텍처를 바꾸면 프로젝트 정체성이 사라집니다.
> 가이드의 평가 축은 아키텍처 모양이 아니라 "발견 → 증적 → 수정 → 재검증"이므로 현 구조로 충족 가능.
> 26~28은 **잔여 위험으로 발표에서 먼저 공개**합니다.

---

## 요약

| 구분 | 개수 |
|---|---:|
| ✅ 코드 완료 | 23 |
| ⚠️ 본인 실행 필요 | 2 |
| ⚠️ 미충족 · 잔여 위험 | 1 + 아키텍처 3 |

**남은 2건은 코드로 끝낼 수 없습니다**
- #21 원격 backend — `bootstrap/` apply 가 선행. `backend.hcl.example` 까지만 준비됨
- #23 증적 실제 값 — `apply` 출력이 있어야 채워집니다

**끝까지 남길 것**: HTTPS 미적용(#7), 아키텍처 차이(#26~28)
