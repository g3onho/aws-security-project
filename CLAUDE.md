# CLAUDE.md — 이 저장소에서 작업하는 규칙

Claude Code가 매 세션 자동으로 읽는 지침. 저장소 루트에 두고 커밋한다.
팀 전원(주협·건호·본인)이 같은 규칙으로 작업한다.

- 프로젝트: AWS 기반 SOAR / SIEM / NMS 보안 대시보드 (2팀, 2차 클라우드 보안 프로젝트)
- 저장소: `github.com/juhyeop/aws-security-project` (비공개 유지)
- Terraform 루트: `aws-soar-terraform/` · 대시보드: `dashboard/backend`, `dashboard/frontend`
- 최종 갱신: 2026-09-22 (저장소 스냅샷 코드 대조 반영)

---

## 0. 정본 우선순위 (충돌하면 이 순서)

1. **이 저장소의 코드** — 직전 문서와 코드가 다르면 **코드가 맞다.**
2. 2팀 기본기획서(2026-09-17) — 성공 기준·기능명의 근거
3. 설계문서 `README.md`(저장소 루트) 직전 버전
4. 그날 대화에서 지시한 내용

- 직전 문서 서술을 그대로 옮기지 않는다. 코드를 직접 읽어 확인한 뒤 쓴다.
- 리소스 선언만 있고 호출 분기가 없으면 "구현됨"이 아니다.

---

## 1. 실행 안전 규칙 (가장 먼저 지킨다)

- `terraform apply` / `destroy`, AWS **변경** 명령(`authorize-*`, `revoke-*`, `delete-*`, `put-*`, `update-*`, `create-*`, `start-automation-execution`, `send-command`, `lambda invoke` 등)은 **실행 전 반드시 사용자 확인**을 받는다. 조회(`describe-*`, `get-*`, `list-*`)는 바로 실행해도 된다.
- 실행 전 `aws sts get-caller-identity` 로 계정 ID를 출력해 사용자에게 보여준다. 계정이 바뀌었을 수 있다.
- Terraform 버전은 CI 고정값 **1.9.8**. 다른 버전으로 state를 건드리지 않는다(팀 공용 S3 state 버전이 올라감).
- 공격·키 시뮬레이션은 팀 소유 격리 계정/VPC(`10.0.0.0/16`) 안에서만.
- 커밋 금지: `.env`, AWS access key, `*.tfstate*`, `*.tfvars`(example 제외), `backend.hcl`, `plan.txt`/`tfplan`(계정ID·공인IP 포함). `.gitignore`에 이미 있음 — 우회하지 않는다.
- 키·시크릿 값은 코드·문서·커밋 메시지·PR 본문에 쓰지 않는다.

---

## 2. 작업 방식

- 코드 변경은 **브랜치 → 푸시 → PR**. main 직접 푸시 금지.
- 브랜치명: `fix/…`, `feat/…`, `docs/…` (예: `fix/asr-trigger-iam-arn`)
- PR 하나에 목적 하나. PR 본문에 **변경 이유 · 영향 파일 · 검증 방법(명령과 결과)** 을 쓴다.
- 코드 수정 시 같은 사실을 서술한 문서(`README.md`, `aws-soar-terraform/docs/*.md`)도 같은 PR에서 고친다.
- 로컬 확인 순서: `terraform fmt -recursive` → `terraform validate` → `terraform plan`(apply는 사용자 확인 후).
- Lambda 테스트: `aws-soar-terraform/modules/soar/lambda_src/test_parse_finding.py`
- 대시보드 테스트: `dashboard/backend/tests/` (pytest)

---

## 3. 설계문서 = 저장소 루트 `README.md` (파일명 고정)

- 파일명은 **`README.md` 하나로 고정**. v12, v13 파일을 새로 만들지 않는다.
- 버전은 파일 안 제목으로: `# AWS 기반 SOAR/SIEM/NMS 보안 대시보드 — 아키텍처 설계안 (v11)`
- 현재: 설계문서 **v11** · 인프라 **v3.2**(커밋 `ea57b3e`) · 대시보드 **v2.2.2**

### 버전 올리는 절차 (v11 → v12 …)

1. 직전 버전 작성 이후 커밋·diff 확인 (`git log`, `git diff <기준커밋>..HEAD`)
2. 직전 문서 서술 중 **지금 코드와 어긋나는 부분** 찾기 — 매 회차 핵심
3. 그 회차 변경사항 반영
4. 한 번에 완성본으로 교체 (부분 편집 반복 금지)

### 고정 목차 (번호 체계 변경 금지, 내용 없으면 "변동 없음" 한 줄)

`0 · 0-1 · 0-2 · 0-3 · 0-4 · 1 ~ 14 · 참고 자료`

| 장 | 제목 |
|---|---|
| 0 | 프로젝트 목표 |
| 0-1 | 확정된 방향 (유지) |
| 0-2 | (직전) → (이번) As-Is / To-Be 전체 비교표 — **매 회차 핵심** |
| 0-3 | 정본 우선순위 |
| 0-4 | 실습 가이드와의 관계 |
| 1 | 네트워크 설계 |
| 2 | 보호 대상 인프라 & 시나리오 (SEC-01~10) |
| 3 | 탐지·분석 계층 (SIEM) |
| 4 | 상관분석 (correlator) |
| 5 | 자동조치·알림 흐름 (SOAR/NMS) |
| 6 | 대시보드 기능 |
| 7 | 아키텍처 다이어그램 구성 기준 |
| 8 | Terraform / AWS 서비스 체크리스트 |
| 9 | 기존 학습 자산과의 연결점 |
| 10 | 비용 유의사항 |
| 11 | 기획서 성공 기준 매핑 |
| 12 | 역할 분담 |
| 13 | 남은 결정사항 |
| 14 | Terraform 구성 (모듈·파일·리소스) |
| — | 참고 자료 |

- `0-2` 비교표 열: **영역 · 항목 · As-Is · To-Be · 변경 이유 · 영향 코드(파일 경로)**
- 직전 `[팀 결정 필요]` 중 해소된 것은 13장에서 빼고 0-2에 "확정"으로 남긴다.
- 수치(파일 수·리소스 수·비용·임계치)는 저장소에서 센 값. 직전 문서 수치 복사 금지.
- 저장소가 인정한 제약(미배선 등)은 그대로 올린다. 감추지 않는다.

### 표기 규칙 (장 제목 옆)

| 표기 | 의미 | 판정 기준 |
|---|---|---|
| `[코드 반영 완료]` | 코드 존재 + 배선됨 | 리소스 선언 **+** 호출 분기 둘 다 확인 |
| `[코드 반영 필요]` | 설계만 있음 | — |
| `[팀 결정 필요]` | 선택지 둘 이상 | 13장 체크박스 |
| `[팀 작업]` | 코드 밖 작업 | — |

### 버전 축 3개 (섞지 않는다)

| 축 | 위치 |
|---|---|
| 설계문서 | `README.md` 제목 |
| 인프라 코드 | 커밋 태그 / `README.md` 머리말 |
| 대시보드 | `dashboard/frontend/VERSION`, `VERSIONS.md` |

### 코드 대조 체크리스트

- 커밋 로그·diff (직전 문서 기준일 이후)
- `aws-soar-terraform/` tf 파일 수·줄 수, 리소스/변수/출력 개수, 모듈 의존 순서
- `variables.tf` `enable_*` **기본값**
- `modules/soar/lambda_src/*/handler.py` 분기 존재 여부
- `modules/soar/documents/*.yaml` 개수, Automation/Command 구분
- `modules/network/sg.tf`, `nacl.tf` SG 개수, `0.0.0.0/0` 위치, 태그
- `aws-soar-terraform/docs/*.md` 자체 정정 내용
- `.github/workflows/`, `backend.tf`, `bootstrap/`
- `dashboard/frontend/VERSION`, `VERSIONS.md`

---

## 4. 알려진 코드 사실 (2026-09-22 스냅샷 대조)

커밋으로 바뀌었을 수 있다. **작업 시작 시 해당 파일을 열어 재확인**하고, 고쳤으면 이 절도 같은 PR에서 갱신한다.

### 4-1. 버그 (PR 대상)

- ~~**SSM 실행 권한 ARN**~~ — `document/ASR-*` + `automation-execution/*` 두 리소스로 수정 (`fix/ssm-automation-arn`, 코드 대조 2026-09-22).
  - `modules/soar/lambda.tf` (asr_trigger `StartApprovedPlaybooks`) / `modules/compute/iam.tf` `local.asr_document_arns`(대시보드 실행 정책 `RunApprovedPlaybooksOnly`) 둘 다 반영.
  - 9/21 임시 인라인 정책(`document/ASR-*` + `automation-execution/*`)과 동일 조합. **apply 및 임시 인라인 정책 삭제는 PR 머지 후 실행 필요.**
  - `README.md` 5-2장·14장도 같은 PR에서 갱신.
- **demo Windows 경로** — `demo/trigger-auto-remediation.sh` 가 `/tmp/sh-event.json` 을 `fileb:///tmp/...` 로 넘김. Windows `aws.exe` 가 MINGW 경로 인식 못 함. `cygpath -w` 분기 필요. `python3` 호출도 Windows에선 `python` 일 수 있음(확인 필요). 스크립트는 `terraform output` 에 의존 → state 연결된 폴더에서만 동작.
- **demo 자동조치는 대시보드에 안 뜬다** — demo 가짜 finding에 `Id` 가 없어 `handler.py` 가 `finding_id="unknown"` 으로 기록. `dashboard/backend/app/adapters/live.py` `_actions()` 가 `unknown` 을 버린다. 화면 검증은 실 Security Hub finding 경로로.

### 4-2. 제약·미구현

- **`ASR-HardenNginx` 미배선** — `handler.py` 에 `DOC_NGINX_HARDEN` 환경변수만, 호출 분기 없음. Lambda 역할에 `ssm:SendCommand` 없음 → **자동 아님, 수동 실행.** 대시보드 `services/gates.py` 도 미배선으로 막음.
  - 수동 실행 전제: 문서가 443 SSL(self-signed) 설정을 쓰는데 docker-host `compose.yaml` 은 `80:80` 만 매핑 → `443:443` + `nginx/certs` 마운트 선행 필요(없으면 WARN만 출력).
- **Before/After 실제 값은 SSM 실행 결과에만 있다** — `handler.py` 는 DynamoDB에 `before_state="sg:<id> open"`, `after_state="revoke in progress"` 같은 **자리표시 문자열**만 기록하고 SSM 완료를 기다리지 않는다. 실제 전/후 규칙은 `aws ssm get-automation-execution` 의 Outputs(`before`/`after`/`revoked_count`).
- **`ASR-RevokeSecurityGroupIngress` 는 대상 SG의 `0.0.0.0/0`·`::/0` 인바운드를 포트 무관 전부 회수** — 정상 공개가 필요한 SG(ALB 80/443 등)에 `AutoRemediation=enabled` 태그를 붙이면 서비스 중단.
- **`AutoRemediation=enabled` 태그는 `db-auto-sg` 에만** 있다(`network/sg.tf`). 다른 SG(web-dvwa 등)에 규칙을 넣으면 asr-trigger는 `manual-notified`(대조군 취급).
- **Security Hub → asr-trigger 규칙이 넓다** — `soar/eventbridge.tf` `sh_to_asr` 가 FAILED/WARNING + ACTIVE 인 **모든** finding을 보냄. 화이트리스트 밖이면 매번 DynamoDB `manual-notified` 행 + SNS 발송 → 이메일 구독 시 알림 폭주, 조치 이력 테이블이 무관한 행으로 채워짐. 대시보드는 `scan Limit=100` 단일 페이지 조회(`live.py`, `MAX_ITEMS=100`).
- **GuardDuty finding ID 형식 불일치 가능** — correlator·asr-trigger는 `detail.id`(짧은 ID)로 기록, Security Hub의 GuardDuty finding `Id` 는 ARN 형식 → 대시보드 조인 불일치 가능(확인 필요).
- **자동조치 안전장치는 경로마다 다르다**
  - SG 회수(SEC-01·03): 화이트리스트 + SG 태그 + dry-run = **3중**
  - IAM 키 비활성화(SEC-05): 화이트리스트 + dry-run = **2중**
- **WAF에 Count 모드 없음** — `compute/alb.tf` 관리형 규칙 `override_action { none {} }` + Rate 규칙 `block`. `enable_waf=true` 즉시 차단. SEC-08 Before = `enable_waf=false`.
- **Config `iam-no-full-admin`** (IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS) 평가 대상은 `AWS::IAM::Policy` 인데 레코더 기록 타입(7개)에 없음 → 평가 대상 0건일 수 있음(확인 필요). 화이트리스트에도 없음.
- **Config 규칙 실제 이름은 접두사 포함**: `soar-sec-dev-restricted-ssh`, `soar-sec-dev-restricted-common-ports`(22·3306·3389·23), `soar-sec-dev-iam-no-full-admin`, `soar-sec-dev-cloudtrail-enabled`
- **CloudWatch 알람** — CPU·메모리 `period=300`, `evaluation_periods=2` → **10분 이상** 초과해야 ALARM. 메모리 알람엔 `ok_actions` 없음.

### 4-3. 인프라 상태·토글

- 기본값: `enable_nat_gateway=false`, `enable_alb=false`, `enable_waf=false`, `enable_dvwa_instance=true`, `enable_attacker_instance=false`, `enable_auto_remediation=true`, `alert_email=""`
- `alert_email` 비우면 SNS **구독 자체가 생성 안 됨**(`soar/sns.tf` count).
- VPC 인터페이스 엔드포인트: `ssm`, `ssmmessages`, `ec2messages`, `monitoring` + S3 게이트웨이. **`logs`·`secretsmanager`·ECR 엔드포인트 없음.**
  - NAT off면: CloudWatch Logs 전송(SEC-06) 불가, Secrets Manager 조회 불가, ECR pull 불가, apt·docker 설치 불가(attacker 도구, stress-ng 포함). **검증 중엔 NAT on.**
- DB: EC2 1대 + SG 2개(db-auto / db-manual). RDS 아님. MySQL `general_log=1` → `Access denied for user` 가 general.log에 기록 → 메트릭 필터 대상.
- docker-host: Private-App 서브넷. SG는 80/443을 ALB·`admin_cidr`에서만 허용 → attacker 인스턴스에서 직접 curl 불가. 점검은 **SSM 포트포워딩** 또는 ALB.
- Public NACL 인바운드는 80·443·임시포트만 → web-dvwa 22번은 SG를 열어도 NACL에서 막힘(nmap 판정 불가).
- attacker 인스턴스(옵션)는 Private-App, `db-manual-sg` 3306 접근 규칙이 함께 생김(SEC-06용).
- docker-host `compose.yaml`: nginx `1.27-bookworm` / web `${ecr_repository_url}:app-1.0.0` / db `mysql:8.4`, frontend·backend(internal) 분리 이미 반영. **web 이미지는 ECR push 선행 필요.** `/health` 는 현재 Nginx 정적 `return 200` (Flask·DB 상태 미반영).
- 대시보드 백엔드: `config.py` `USE_DEMO_DATA` 기본 **true** → 실모드는 `false` 명시. 로컬 실모드 런처 `dashboard/backend/awsrun.py`. EC2 `dashboard.env` 에는 `USE_DEMO_DATA` 가 안 들어감. `dashboard/backend/README.md` 의 "실 어댑터는 스텁(501)" 서술은 `live.py` 구현과 어긋남(확인 필요).

### 4-4. SEC 검증 시 판정 규칙

- **SEC-03 판정에 nmap 쓰지 않는다** — SG 2개가 한 인스턴스라 자동조치 후에도 open. 판정은 SG 규칙 문자열 · Config 준수 상태 · Security Hub finding 상태. 포트 스캔은 수동조치까지 끝난 뒤.
- GuardDuty 무차별 대입 finding은 SSH/RDP 대상. EC2 MySQL 실패는 CloudWatch 메트릭 필터가 1차 탐지.
- Inspector2 이미지 스캔은 ECR push 이미지 대상.

---

## 5. 산출물·출력 규칙

- HTML 산출물: **현대오토에버 스타일** — Hyundai Blue `#002C5F`, 보조 `#0073C7` / 서체 `Hyundai Sans` → `Pretendard`, `Noto Sans KR`, system-ui
- **한 번에 완성본.** 블로그 글처럼 조금씩 다시 편집하지 않는다.
- md 산출물은 저장소에 커밋하거나 다운로드 가능한 형태로.
- 설계문서 갱신 응답은 주요 변경 5~8줄만. 문서 내용을 다시 설명하지 않는다.

## 6. 말투

- 개조식. 서술형 존댓말·AI 티 나는 말투 금지.
- 근거 없는 단정 금지. 확인 못 한 건 "확인 필요".
- 과장 금지("완벽", "강력한", "혁신적" 금지).

## 7. 팀 역할

| 파트 | 담당 | 책임 |
|---|---|---|
| PM · 인프라/IaC | 주협(팀장) | network·compute 모듈, plan/apply, 비용 토글·정리 |
| 탐지 연동(SIEM·NMS) · 대시보드(정) | 건호 | security 모듈, CloudWatch Agent·알람·SNS, Flask 대시보드 |
| 자동조치(SOAR) · 대시보드(부) · 서비스·취약환경·공격재현·문서화 | 본인 | EventBridge, correlator·asr_trigger, SSM 플레이북, Docker 3-Tier, 공격 재현, 증거·문서 |

- `apply`·`destroy`·비용 토글 변경은 인프라 담당(주협)과 합의 후.

## 8. 참고 (프로젝트 지식, 저장소 밖)

- 버전업 절차 원본: `soar-architecture-버전업-프롬프트.md`
- 공격·검증 절차: `SEC-01-10_공격시뮬레이션_조치검증_가이드.md` (4장 사실과 어긋나는 부분 있음 — 4장 우선)
- 성공 기준: 2팀 기본기획서(2026-09-17)
