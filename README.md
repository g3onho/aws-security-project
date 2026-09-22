# AWS 기반 SOAR/SIEM/NMS 보안 대시보드 — 아키텍처 설계안 (v11)

> v11: **코드 정본을 GitHub 저장소(`juhyeop/aws-security-project`)로 이관**했습니다. v10까지는 설계문서가 코드를 규정했지만, 이제 코드가 먼저 움직이고 문서가 따라갑니다. 이번 회차에서 확인한 코드 상태는 **인프라 v3.2(커밋 `ea57b3e`) · 대시보드 v2.2.2** 입니다.
>
> v10 대비 큰 변화는 네 가지입니다. ① `terraform validate` / `fmt` 통과 — v10의 "레지스트리 막혀 검증 불가"가 해소됨 ② **GitHub Actions plan 자동화 + OIDC** 신설 ③ **원격 state(S3) 확정** — v10의 [팀 결정 필요] 해소 ④ 저장소 문서가 스스로 찾아낸 **구현 격차 3건**을 설계문서에도 반영.
>
> 표기: **[코드 반영 완료]** = 선언 + 배선 둘 다 확인됨 · **[코드 반영 필요]** = 다음 작업 · **[팀 결정 필요]** = 확정 안 됨 · **[팀 작업]** = 코드 밖 작업
>
> 주의: **리소스 선언만 있고 호출 분기가 없으면 [코드 반영 완료]가 아닙니다.** v11에서 이 기준으로 재판정한 항목이 2건 있습니다(5-1, 2-3).

**버전 축이 3개입니다** — 헷갈리지 않게 분리합니다.

| 축 | 위치 | 현재 |
|---|---|---|
| 설계문서 (본 문서) | 프로젝트 문서 | **v11** |
| 인프라 코드 | 저장소 커밋 | **v3.2** — 최신 커밋 `ea57b3e` (2026-09-21) |
| 대시보드 프론트엔드 | `dashboard/frontend/VERSION` | **v2.2.2** (2026-09-20) |

> 커밋 메시지 라벨이 `v3.1 → v3.2 → v3.3 → v3.2` 순으로 어긋나 있습니다. **문서·코드 기준 현재 버전은 v3.2** 입니다(`docs/구성설명.md` 헤더). 커밋 라벨 정리는 13장 참고.

**아키텍처 다이어그램**
- **발표용 인포그래픽**: [AWS 보안 관제 아키텍처 · 인포그래픽](https://claude.ai/artifact/VQhQdkic42wej9P7KnLRDU) — 7-3 기준 갱신 필요 **[팀 작업]**
- **상세 기술 버전** (SVG): [AWS 보안 관제 아키텍처](https://claude.ai/artifact/D7fEoGxcPepD4W3nwZxe58) — 동일 **[팀 작업]**
- **저장소 내 Mermaid 다이어그램 5종**: `aws-soar-terraform/docs/아키텍처.md` (탐지→조치 전체 / 네트워크 배치 / 상관분석 시퀀스 / 자동조치 게이트 / 자동·수동 대조군). 발표 때 코드 저장소에서 바로 열 수 있습니다.

---

## 0. 프로젝트 목표

1. AWS 인프라 로그·점검 결과를 한 화면에 모아 **취약점별 조치 방안을 제시하는 보안 대시보드** 구축
2. 자동/수동 **모니터링·개선 각 2개 이상** 구현 — 자동조치 기준: ⓐ조직 고유 정책값이 필요 없고 ⓑ잘못 실행돼도 되돌릴 수 있는 조치만 자동화
3. EC2 **CPU/메모리 임계치(80%) 초과** 시 CloudWatch + SNS 알림
4. 동일 조건 재점검으로 **Before/After 개선 효과 수치화**
5. 전체 인프라를 **Terraform 코드**로 재현 가능하게 관리(4개 모듈)

## 0-1. 확정된 방향 (유지)

| 항목 | 결정 |
|---|---|
| SIEM/SOAR 엔진 | AWS 네이티브 (GuardDuty·Security Hub·Inspector·Config·IAM Access Analyzer + EventBridge·Lambda·SSM Automation) |
| 대시보드 | 커스텀 Flask + Chart.js + Tailwind (v2.2.2, 프론트엔드 데모 단계) |
| 진행 방식 | 팀 프로젝트, 역할 분업(12장) |
| 인프라 프로비저닝 | Terraform 4개 모듈 + `bootstrap/` (14장) |
| 보호 대상 | Nginx–Flask–MySQL 3-Tier 컨테이너 서비스 + EC2 자원 |
| 형상관리 | **GitHub `juhyeop/aws-security-project` — 코드 정본** |

## 0-2. v10 → v11 As-Is / To-Be 전체 비교표

| 영역 | 항목 | As-Is (v10) | To-Be (v11) | 변경 이유 | 영향 코드 |
|---|---|---|---|---|---|
| **정본** | 코드 기준 | zip 배포본 (`aws-soar-terraform-v10.zip`) | **GitHub 저장소** | 팀 동시 작업·CI·이력 추적 | 저장소 전체 |
| 정본 | 문서-코드 관계 | 문서가 코드를 규정 | **코드가 정본, 문서가 추종** | 코드가 먼저 움직임 | 0-3장 |
| **검증** | `terraform validate` | ❌ 레지스트리 차단으로 미실행 | **✅ 통과** | 저장소 환경에서 실행됨 | 14장 |
| 검증 | `terraform fmt -recursive` | 미실행 | **✅ clean** | CI가 `-check` 로 강제 | CI |
| 검증 | 정적분석 | HCL 파싱·참조 검사 수준 | **+ checkov 실행** | 실패 항목은 실습 의도(DVWA·평문 HTTP) | 14장 |
| 검증 | 런타임 | 미검증 | **여전히 미검증** (apply 이후) | 팀 계정 apply 필요 | — |
| **CI/CD** | plan 자동화 | 없음 | **GitHub Actions `terraform plan`** (PR·main·수동) | 가이드 4.1 "plan 공유 → 승인 → apply" 앞 두 단계 자동화 | `.github/workflows/terraform-plan.yml` |
| CI/CD | 워크플로 위치 | — | **저장소 루트 1개로 통일** — `aws-soar-terraform/.github/workflows/` 중첩본(116줄) 삭제 | 같은 워크플로가 두 벌이라 중복 실행·혼선 | 커밋 `ea57b3e` |
| CI/CD | AWS 인증 | 로컬 자격증명 | **OIDC 역할 2개** — plan(ReadOnly) / apply(PowerUser+IAM) | 액세스 키를 Secrets 에 넣지 않음(가이드 5.2) | `bootstrap/github_oidc.tf` |
| CI/CD | plan 결과 공유 | 수동 | **PR 코멘트 자동 + tfplan 아티팩트 14일 보관** | 증적양식 10번 항목 | 워크플로 |
| CI/CD | 안전 가드 | 없음 | `ADMIN_CIDR` **빈 값·`0.0.0.0/0` 거부**, `concurrency` 큐 | 러너 IP 가 SG 에 들어가는 사고 방지 | 워크플로 |
| **State** | 위치 | **[팀 결정 필요]** 로컬 / S3 | **S3 확정** — `soar-sec-tfstate-455958489281` + DynamoDB `soar-sec-tflock` | 팀 동시 작업·CI 필수 | `backend.tf` |
| State | 설정 방식 | `backend.tf.example` + `backend.hcl` 부분 구성 | **`backend.tf` 직접 설정** (`.example` 삭제) | `backend.hcl` 은 CI 가 못 읽어 워크플로도 같이 고쳐야 함 | `backend.tf` |
| State | 계정 이전 절차 | 미기재 | **`backend.tf` 수정 후 `terraform init -reconfigure` 필수** | 그냥 `init` 하면 `Backend configuration changed` 로 막힘 | 14장 |
| State | 계정 | 미지정 | **455958489281** (구 112232725243 에서 이전) | 팀 계정 변경 | `backend.tf`, 워크플로 |
| **구현 격차** | 자동 개선 | **3개** 주장 | **설계 3 / 실제 2** — `ASR-HardenNginx` **미배선** | SSM 문서·Lambda 환경변수는 있으나 호출 분기 없음 | `lambda_src/asr_trigger/handler.py` |
| 구현 격차 | 안전장치 | **3중** 주장 | **SG 경로만 3중, IAM 키 경로 2중** | 게이트②(태그)가 SG 분기에만 적용 | 동일 |
| 구현 격차 | `enable_auto_remediation` | dry-run 스위치(기본 off 뉘앙스) | **기본값 `true`** | 실제 코드 확인 | `variables.tf` |
| **인프라** | Docker Host 배치 | **[팀 결정 필요]** Private / Public | **Private-App 확정** | ALB 또는 관리자 IP 경유만 허용 | `compute/main.tf` |
| 인프라 | 인스턴스 타입 | 단일 `t3.micro` 전제 | **3분화** — micro(dvwa·dashboard·attacker) / small(docker-host·db) | 컨테이너·MySQL 메모리 | `variables.tf` |
| 인프라 | IMDSv2 | `http_tokens = required` 만 | **+ `http_endpoint`·`http_put_response_hop_limit`** — 컨테이너에서 IMDS 호출 허용 | 홉 1이면 컨테이너가 IAM 역할 못 씀 | `compute/main.tf` |
| 인프라 | NAT 필요성 | "부트스트랩 때만" | **첫 부팅에 필수** — user_data 가 apt·PyPI·docker.com 사용 | 끄면 EC2 3대가 빈 깡통 | `network/main.tf` 주석 |
| 인프라 | NAT off 부작용 | 미기재 | **CloudWatch Agent 전송 중단** → 메모리 알람·SEC-06 미동작 | 엔드포인트 3종에 logs·monitoring 없음 | 7장 |
| 인프라 | 대시보드 IAM | 읽기/실행 분리 | **+ SNS Publish 권한** | user_data 가 토픽 ARN 을 쓰는데 권한이 없어 실패하던 것 보완 | `compute/iam.tf` |
| **코드 정리** | 미사용 변수 | 다수 전달 | **6건 제거** (`enable_dvwa_instance`→network, `log_retention_days`→security, `log_group_flowlogs`·`enable_config`·`enable_flow_logs`·`db_security_group_id`·`public_nacl_id`→soar) | 선언-전달 불일치 해소 | `main.tf`, 각 `variables.tf` |
| 코드 정리 | `security/outputs.tf` | 존재 | **삭제** — 루트에서 참조하지 않는 출력뿐 | 필요하면 루트 `outputs.tf` 에 추가 | `modules/security/` |
| 코드 정리 | 중복 파일 | v1·v2 잔재 공존 | **삭제** — `soar/functions/*`, `compute/userdata/*.sh`, `.build/*.zip`, `network/security_groups.tf`, `security/main.tf`, `soar/nms.tf` | 중복 선언 충돌 | 커밋 `7f11f04`·`250b9af` |
| 코드 정리 | `tfplan` 바이너리 | 저장소에 커밋됨 | **삭제 + .gitignore 차단** | plan 파일에 평문 값 포함 가능(VULN-003) | `.gitignore` |
| 코드 정리 | 수치 | tf 36파일·3,600줄 | **tf 35파일·3,522줄** (bootstrap 제외) / 리소스 **173**·변수 121·출력 49 | 실측, `구성설명.md` v3.2 와 일치 | 14장 |
| **문서** | 저장소 문서 | 없음 | **7종 신설** — `아키텍처`·`구성설명`·`AS-IS_TO-BE`·`비용예측`·`체크리스트`·`증적양식`·`병합내역` | 제출물 + 코드 옆 문서 | `docs/*.md` |
| 문서 | 다이어그램 | 외부 아티팩트 2개 | **+ Mermaid 5종** (저장소 내장) | 코드와 함께 버전 관리 | `docs/아키텍처.md` |
| 문서 | soar 흐름도 | Security Hub 단일 진입 | **correlator 는 GuardDuty 직접 수신** 으로 정정 | 실제 EventBridge 규칙 3개 구조 반영 | `구성설명.md` v3.2 |
| 문서 | 운영 주의사항 | 5개 | **7개** — CloudTrail·state 버킷 삭제 조건, 계정 이전 시 자격증명 확인, OIDC 레포 경로 | 계정 이전 중 실제로 부딪힐 함정 | `구성설명.md` v3.2 |
| **검증 스크립트** | demo | 3종 | **4종** — `verify-controls.sh` 추가(`--json` 증적) | 차단·기능 검증 자동화 | `demo/` |
| **비용** | 최소 시나리오 | 시간당 $0.1047 / 10일 $25.1 | **시간당 $0.1356 / 10일 $32.5** | t3.small 2대 반영 | `docs/비용예측.md` |
| 비용 | 총 예상 | $30~$40 | **$37~$45** | 동일 | 10장 |
| **대시보드** | 리전 | 5개 | **17개** + 글로벌/위치 미상 | 실사용 화면에 가깝게 | `static/js/data.js` |
| 대시보드 | 지도 | 평면 2.5D | **정사영 회전 지구본** (드래그·휠·키보드) | 관제 화면 요구 | `static/js/map.js` |
| 대시보드 | 공격선 | 직선 | **대권(최단 구면) 곡선** + 고도 리프트 | 입체 표현 | 동일 |
| 대시보드 | 공격 출발지 | 파리/뉴욕/시드니 고정 | **위협 행위국 8개국** (북한·중국·러시아·이란·베트남·파키스탄·인도·튀르키예) | 리전 좌표와 겹쳐 "리전이 리전을 공격" 문제 | `static/js/data.js` |
| 대시보드 | 국가 강조 | 없음 | **리전 선택 시 소속 국가 밝게** (point-in-polygon) | 참고 영상 재현 | `map.js`, `app.css` |
| 대시보드 | 지도 대비 | 육지·바다 대비 1.16:1 | **3.11:1** | 강조가 화면에서 안 보이던 근본 원인 | `app.css` |
| 대시보드 | 버그 | 공격선이 지구본 밖 최대 47px 돌출 | **수정 — 오버슈트 0** | 리프트 후 좌표를 가시성 판정에 미반영 | `map.js` |
| 대시보드 | 기본 화면 | 1.55배율 | **1.0배율 · 서울 정중앙** | 사용자 요청(테두리 노출은 의도) | `map.js` |
| 대시보드 | AWS 연동 | 미연동 | **여전히 미연동** — 항상 데모 | `store.js` 의 `api.load/execute/verify` 가 교체 지점 | 6장 |

## 0-3. 정본 우선순위 (v11에서 변경)

충돌 시 **① GitHub 저장소 코드 → ② 기본기획서(2026-09-17) → ③ 본 설계문서 → ④ 실습 가이드** 순으로 따릅니다.

v10까지는 설계문서가 코드를 규정했습니다. v11부터 뒤집습니다. 코드가 매일 움직이고 문서는 회차마다 따라가므로, 둘이 다르면 코드가 맞습니다. 다만 **기능명은 기획서 원문을 유지**해 성공기준 시트와 1:1 대조가 되게 합니다.

저장소 자체 문서(`aws-soar-terraform/docs/*.md`)는 코드와 같은 커밋에 들어 있어 본 설계문서보다 최신일 수 있습니다. 본 문서와 다르면 저장소 문서를 확인하세요. **본 v11은 `구성설명.md` v3.2 · `아키텍처.md` 전체를 대조해 반영한 상태입니다.**

## 0-4. 신규 실습 가이드와의 관계 (v10에서 변동 없음)

실습 가이드(`aws-nlb-k3s-flask-mysql-terraform`)는 **Windows PC에서 Terraform을 실행하는 절차 문서**로만 사용합니다. NLB + K3s 구성은 이 프로젝트의 기준선이 아닙니다.

| 가이드에서 채택 | 가이드에서 미채택 |
|---|---|
| 실행 절차(init→fmt→validate→plan→apply→destroy) | NLB(TCP 패스스루) → **ALB 유지**(WAF 요건) |
| Windows PowerShell 기준 명령 | K3s/Nginx Pod → **Docker Compose 3-Tier 유지** |
| 실행 PC 공인 IP 자동 감지(`detected_admin_cidr`) | 전부 Public 2서브넷 → **3계층 유지** |
| `templates/*.sh.tftpl` + user-data 로그 | 로컬 state 전제 → **S3 backend 확정** |
| Ubuntu 24.04 | .pem SSH 전제 → **SSM 전용** |

**미채택 핵심 이유**: WAFv2는 NLB에 연결할 수 없습니다(ALB·CloudFront·API Gateway만 가능). 가이드 구성으로 가면 SEC-08이 성립하지 않습니다.

---

## 1. 네트워크 설계 — 멀티 서브넷 [코드 반영 완료]

VPC `10.0.0.0/16`, 서브넷 4개.

| 서브넷 | CIDR | AZ | 성격 | 배치 자원 |
|---|---|---|---|---|
| Public-Web | 10.0.0.0/24 | primary | Public | ALB, web-dvwa, NAT GW |
| Public-Web-b | 10.0.3.0/24 | secondary | Public | ALB 2 AZ 요건 **전용**(평소 비어 있음, 무과금) |
| Private-DB | 10.0.1.0/24 | primary | Private | MySQL EC2 1대 |
| Private-App | 10.0.2.0/24 | primary | Private | **docker-host**, dashboard, attacker, VPC 엔드포인트 |

**v11 확정**: Docker Host는 Private-App 입니다. v10의 [팀 결정 필요]를 해소했습니다. 인터넷에 직접 노출되지 않고 ALB 또는 관리자 IP 경유로만 닿습니다.

**네트워크 구성 요소**
- **IGW**: Public-Web 인터넷 출입구
- **VPC 엔드포인트 (기본 on)**: 인터페이스 `ssm`·`ssmmessages`·`ec2messages` + 게이트웨이 `s3`(무료). NAT($0.059/h)보다 엔드포인트 3개($0.033/h)가 쌉니다.
- **NAT Gateway (기본 off)** — **첫 부팅에는 켜야 합니다.** user_data 가 `apt-get`·PyPI·`download.docker.com` 을 쓰므로 엔드포인트 3종으로는 못 덮습니다. NAT 없이 apply 하면 EC2 3대가 패키지 없는 빈 상태로 뜹니다.
- **NACL + Security Group** 이중 방어. Private NACL 규칙 번호 **1~99는 Deny 예약**(SEC-06 IP 차단), 100 이상이 Allow. NACL 은 번호 순으로 평가되므로 Deny 가 앞 번호여야 합니다. 현재 NACL 규칙 7개.
- **VPC Flow Logs** → CloudWatch Logs (SEC-09)

**보안그룹 8종** — 고정 IP 나열 대신 **앞 계층의 SG를 소스로 참조**합니다(가이드 6.1). 핵심은 DB용 2개(2-4장).

```
인터넷 ──80/443──▶ alb
                    └──▶ web_dvwa · docker_host
                                      └──3306──▶ db_auto / db_manual
VPC 내부 ──5000──▶ dashboard   (SSM 포트 포워딩 경유)
```

SSH 22 인바운드 규칙은 **어느 SG에도 없습니다**. 접속은 Session Manager 전용입니다. 대시보드 5000도 `var.vpc_cidr` 로만 열려 있어 인터넷에서는 닿지 않습니다.

**남은 위험**: `alb_http`·`alb_https` 인바운드가 `0.0.0.0/0` 입니다. 뒷단이 DVWA이므로 실습 중에는 `var.admin_cidr` 로 좁히는 편이 안전합니다(`modules/network/sg.tf` 2줄). 증적양식 VULN-002가 이 건이며, **고치기 전에 Before 증적을 먼저 남겨야 합니다.**

**AZ 주의**: 기본 `ap-northeast-2a/2c`. **팀 계정의 실제 AZ 이름 확인 필요** [팀 결정 필요].

---

## 2. 보호 대상 인프라 & 침해사례 시나리오

"공격 → 로그 생성 → 대시보드 알람 → 대응 → 재점검" 흐름. 전부 팀 소유의 격리된 계정/VPC에서만 실행하고, 시연 후 정리를 원칙으로 합니다.

### 2-1. 공격 경로 원칙 [팀 결정 필요: 공격 실행 위치]

Private 자원은 인터넷에서 직접 접근할 수 없습니다. 아래 중 하나로 시연합니다.

1. **웹서버 경유(pivot)** — Public web-dvwa 침투 후 내부 이동
2. **VPC 내부 공격용 인스턴스** — `enable_attacker_instance=true`(기본 off). nmap/hydra/sqlmap 등은 팀이 격리 환경에서 직접 설치

공격자를 VPC 안에 두면 "허가 없는 대상 스캔" 문제를 피하면서 GuardDuty·Flow Logs에 확실히 잡힙니다. 다이어그램에서 외부 → Private-DB 직접 화살표는 쓰지 않습니다.

### 2-2. 보안 시나리오 SEC-01 ~ SEC-10 (기획서 확정, v10에서 변동 없음)

| ID | 취약/위험 항목 | 근거 | 탐지 | 개선 |
|---|---|---|---|---|
| SEC-01 | Security Group 과다 공개(SSH 22 등) | SK쉴더스 가상리소스 3.1 | [자동] Config `restricted-ssh` → Security Hub / [수동] nmap | [자동] SSM 규칙 회수 |
| SEC-02 | HTTP 평문·보안 헤더 미흡 | SK쉴더스 운영관리 / OWASP Secure Headers | [수동] curl -I, ZAP, Wireshark | [수동] Nginx 보안 설정 — **v11 재분류** (5-1 참고) |
| SEC-03 | DB 포트(3306) 외부 노출 | SK쉴더스 3.1 / Docker #3·#6·#17 | [자동] Config·Security Hub + Flow Logs / [수동] nmap | [자동] db-auto-sg 회수, db-manual-sg 알림만 |
| SEC-04 | 취약 컨테이너 이미지 | CIS Docker Benchmark / Docker #21~23 | [수동] Trivy / [자동] Inspector2 | [수동] 이미지 교체·버전 고정·USER 지정 |
| SEC-05 | 과도한 IAM 권한·Access Key 노출 | SK쉴더스 계정·권한 관리 | [자동] Access Analyzer·GuardDuty·CloudTrail | [자동] 키 Inactive / [수동] 최소권한 재작성 |
| SEC-06 | DB 무차별 대입 로그인 | SK쉴더스 운영관리 / KISA 계정 잠금 | [자동] CloudWatch Logs 메트릭 필터 → Alarm (10회/5분) | [수동] NACL Deny(오탐 때문에 자동화 제외) |
| SEC-07 | DB 자격증명 하드코딩·.env 노출 | CWE-798 / Docker #9~12·#18·#24 | [수동] 코드 리뷰, trivy fs secret | [수동] Secrets Manager, 앱 전용 계정 |
| SEC-08 | 웹 애플리케이션 공격(SQLi, DVWA) | OWASP A03 / KISA 웹 점검 | [수동] ZAP·SQLMap / [자동] WAF 룰 매치 | [수동] WAF 관리형 규칙·Rate Limit |
| SEC-09 | 로깅·감사 추적 미흡 | SK쉴더스 운영관리 | [자동] Security Hub·Config / [수동] 컨테이너 로그 | [기본] CloudTrail(+S3·KMS)·Flow Logs |
| SEC-10 | 리소스 과부하(CPU·메모리 80%) | 교재 Monitoring Hands-on | [자동] CloudWatch Alarm / [수동] JMeter | [수동] SNS 수신 후 담당자 조치 |

**탐지 관련 주의 (유지)**
- GuardDuty 무차별 대입 finding은 **SSH/RDP 대상**입니다. EC2에 직접 설치한 MySQL 로그인 실패는 못 잡으므로 SEC-06 1차 탐지는 **CloudWatch Logs 메트릭 필터**입니다. **[팀 결정 필요: Hydra 대상을 MySQL 유지 vs SSH 변경]**
- nmap 내부 스캔은 GuardDuty finding이 안 뜰 수 있으므로 SEC-03 1차 탐지는 **Config 규칙**입니다.
- Inspector2 이미지 스캔은 **ECR push 이미지** 대상이라 SEC-04는 ECR 업로드 단계를 포함합니다.
- **NAT를 끄면 SEC-06 탐지가 동작하지 않습니다.** CloudWatch Agent 로그 전송이 끊기기 때문입니다. `secretsmanager`·`logs`·`monitoring` 엔드포인트를 추가하면 살릴 수 있으나 월 약 $28 추가입니다.

발표 당일 라이브 공격이 불안정할 수 있으니 안전망으로 **GuardDuty `create-sample-findings`** 를 준비합니다.

### 2-3. 수동/자동 판단 기준 [팀 결정 필요: 분류 정의]

자동조치 기준은 **① 조직 고유 정책값이 필요 없고 ② 잘못 실행돼도 되돌릴 수 있는 경우**입니다. 적용 단위는 DB가 아니라 **finding 유형**입니다.

**v11 실측 — 게이트가 경로마다 다릅니다.**

| 경로 | 게이트① 화이트리스트 | 게이트② SG 태그 | 게이트③ dry-run | 실제 |
|---|:---:|:---:|:---:|---|
| SG 인바운드 회수 | ✅ | ✅ | ✅ | **3중** |
| IAM 키 비활성화 | ✅ | — | ✅ | **2중** |

`asr_trigger/handler.py` 의 게이트②(`_sg_has_auto_tag`)는 SG 분기에서만 호출됩니다. 코드 독스트링의 "안전장치 3중"은 SG 경로에만 해당합니다. 발표 때 "3중"으로 뭉뚱그리면 코드와 어긋납니다.

`enable_auto_remediation` 기본값은 **`true`** 입니다. dry-run으로 두려면 명시적으로 `false`를 넣어야 합니다.

> **기획서 분류 충돌 (미해소)**: 기획서는 "Nginx 보안 설정 일괄 적용"을 *버튼/승인 후 실행*으로 적고도 **자동 개선**으로 분류했습니다. v11 코드 기준 이 항목은 **수동**입니다(5-1). 발표 전 한 가지 정의로 통일하세요.

### 2-4. MySQL 대수 — 1대 + SG 2개 [코드 반영 완료]

DB EC2는 **1대**입니다. 대조군 시연은 보안그룹 2개로 구현합니다.

| SG | 태그 | 결과 |
|---|---|---|
| `db-auto-sg` | `AutoRemediation=enabled` | Config 위반 탐지 시 SSM 자동 회수 |
| `db-manual-sg` | 없음 | SNS 알림만, 대시보드 승인 후 조치(대조군) |

AWS Config는 EC2가 아니라 **보안그룹 단위로 평가**하므로, 같은 위반(3306/0.0.0.0/0)을 두 SG에 넣으면 "같은 위반인데 태그 하나로 결과가 갈린다"를 한 인스턴스로 보여줄 수 있습니다.

**이 시연의 탐지 주체는 AWS Config 입니다.** GuardDuty는 SG 설정 위반을 잡지 않습니다. 다이어그램에서 Config를 빠뜨리면 이 흐름이 설명되지 않습니다.

**docker-host 의 MySQL 컨테이너와 db 인스턴스는 별개입니다.** 전자는 보호 대상 서비스의 DB, 후자는 탐지·조치 대상입니다.

**MySQL을 RDS가 아니라 EC2에 두는 이유** — 탐지 커버리지 때문입니다.

| 항목 | EC2 MySQL | RDS였다면 |
|---|---|---|
| Inspector2 CVE 스캔 | ✅ | ❌ 대상 아님 |
| GuardDuty EBS 멀웨어 스캔 | ✅ | ❌ |
| correlator 상관분석 | ✅ | ❌ finding 구조가 달라 제외 |
| SSM Run Command 점검 | ✅ `SCAN-*` 실행 가능 | ❌ OS 접근 불가 |
| SG 2개 대조군 | ✅ | ✅ |
| 로그 수집 | ⚠️ CloudWatch Agent 필요 → NAT 의존 | ✅ 네이티브 |

RDS의 이점은 NAT 의존이 줄어드는 것 하나입니다.

---

## 3. 탐지·분석 계층 (SIEM) [코드 반영 완료]

### 자동 모니터링 3개 / 수동 모니터링 2개

| 구분 | 기능 | 구현 |
|---|---|---|
| 자동 ① | AWS 보안 설정 자동 점검(CSPM) | Config 규칙 4개 + Security Hub + Access Analyzer |
| 자동 ② | 위협·취약점 상관분석 | GuardDuty×Inspector → `correlator` → DynamoDB (4장) |
| 자동 ③ | 인프라 임계치 알림(NMS) | CloudWatch 알람 CPU·메모리 80% → SNS (5-3) |
| 수동 ① | 외부 포트·웹 점검 | `SCAN-PortAndWeb`(nmap·curl) → S3 |
| 수동 ② | 컨테이너 이미지 점검 | `SCAN-ContainerImage`(Trivy) → S3 |

### 로그 소스 → 탐지 서비스 연결

| 로그/소스 | 받는 서비스 | 비고 |
|---|---|---|
| VPC Flow Logs | GuardDuty (+CloudWatch Logs 보관) | Flow Logs는 로그를 **만드는** 쪽 |
| CloudTrail | GuardDuty, S3+KMS 저장 | 포렌식 조회 |
| EC2 OS/MySQL/Nginx 로그 | CloudWatch Agent → CloudWatch Logs | 메트릭 필터 → Alarm. **NAT 필요** |
| 리소스 설정(SG 등) | AWS Config 규칙 | SEC-01/03 1차 탐지 |
| EC2·ECR 이미지 | Inspector2 | CVE 스캔(SEC-04) |
| 리소스 기반 정책 | IAM Access Analyzer | 외부 접근(SEC-05) |
| 위 탐지 서비스 전부 | Security Hub | finding 집계 |

EC2 → Security Hub 직접 경로는 없습니다. finding은 반드시 탐지 서비스를 거칩니다.

### 서비스별 설명
- **AWS Config** — SG·보안 설정의 "값"을 규칙으로 평가. 비용 절감으로 7개 리소스 타입만 기록. 규칙 4개: `restricted-ssh`, `restricted-common-ports`(22·3306·3389·23), `iam-no-full-admin`, `cloudtrail-enabled`. 이 규칙들이 SOAR 자동조치의 **트리거 근거**입니다.
- **IAM Access Analyzer** — 리소스 기반 정책의 "의미"를 분석. 외부 접근 분석기는 무료.
- **GuardDuty** — ML 기반 이상탐지. `aws_guardduty_detector_feature` 로 기능 토글. `AI_PROTECTION` 기본 off. **`RDS_LOGIN_EVENTS` 가 켜져 있으나 RDS가 없어 탐지 대상 없음(과금 0)** — 정리 대상 [코드 반영 필요].
- **Shield Standard** — ALB 사용 시 자동 적용. 다이어그램에서는 경유 지점이 아니라 방어 계층.
- **WAFv2** — ALB에 연결. "ALB(WAFv2 연결)" 하나로 표시(SEC-08).
- **CloudTrail** — 다중 리전 + 로그 파일 검증 + KMS 암호화 + S3 퍼블릭 차단. 가이드 8장 요구사항 충족.

> `modules/security` 에는 **`outputs.tf` 가 없습니다.** 루트에서 참조하지 않는 출력뿐이라 삭제했습니다. 탐지 서비스 활성 상태를 `terraform output` 으로 뽑아야 하면 루트 `outputs.tf` 에 블록을 추가하면 됩니다.

---

## 4. GuardDuty + Inspector 상관분석 (correlator) [코드 반영 완료]

**흐름**: GuardDuty finding → EventBridge(`gd-correlator`) → Lambda(`correlator`) ↔ Inspector2 조회 → DynamoDB ← Flask 대시보드(boto3)

1. 이벤트에서 대상 리소스(`resource.instanceDetails.instanceId`) 추출
2. `inspector2:ListFindings` 로 같은 리소스의 CVE(`PACKAGE_VULNERABILITY`) 목록 조회
3. "행위 기반 이상탐지 + 취약점 존재"를 한 레코드로 합쳐 기록 — **둘 다 있으면 심각도 한 단계 상향** (`LOW→MEDIUM→HIGH→CRITICAL`, CRITICAL에서 정지)

합친 결과는 `correlated_findings_table` 에 적재하고 대시보드가 boto3로 읽습니다.

**correlator 는 Security Hub 를 거치지 않고 GuardDuty finding 을 직접 받습니다.** Config·Inspector·Access Analyzer 결과는 Security Hub 로 모여 `asr_trigger` 쪽으로만 갑니다. EventBridge 규칙이 3개(`gd-correlator`·`gd-asr`·`sh-asr`)로 나뉘어 있는 이유입니다. 마지막 소비자는 SSM이 아니라 **Flask 대시보드**입니다.

**이 경로는 EC2를 전제로 합니다.** instanceId 로 Inspector를 조회하므로, DB가 EC2여야 DB도 상관분석 대상이 됩니다(2-4 참고). GuardDuty finding 발행 주기는 15분입니다.

---

## 5. 자동조치·알림 흐름 (SOAR / NMS)

### 5-1. 자동 개선 — 설계 3 / 실제 2 [코드 반영 필요]

| # | 플레이북 | 유형 | 경로 | 되돌릴 수 있는가 | 배선 상태 |
|---|---|---|---|---|---|
| ① | `ASR-RevokeSecurityGroupIngress` | Automation | Security Hub → EventBridge(sh-asr) → asr_trigger → SSM | 예(규칙 재추가) | **✅ 배선됨** |
| ② | `ASR-DisableExposedAccessKey` | Automation | GuardDuty → EventBridge(gd-asr) → asr_trigger → SSM | 예(재활성화) | **✅ 배선됨** |
| ③ | `ASR-HardenNginx` | Command | (설계) asr_trigger → SSM Run Command | 예(원복본 백업) | **❌ 호출 분기 없음** |

**③의 실제 상태**: SSM 문서(`documents/ASR-HardenNginx.yaml`)는 등록돼 있고 Lambda 환경변수 `DOC_NGINX_HARDEN` 도 주입돼 있습니다. 그러나 `asr_trigger/handler.py` 에 이 변수를 사용하는 분기가 없습니다. finding 유형 분기는 (A) SG, (B) IAM 키 둘뿐이고, 나머지는 `"no handler"` 로 SNS 알림만 갑니다.

**영향**: 기획서 성공 기준 "자동 개선 2개 이상"은 ①②로 **충족합니다.** 다만 "자동 3개"라고 발표하면 코드와 어긋납니다. 선택지는 둘입니다.

- (a) `asr_trigger` 에 Nginx 분기를 추가해 배선 — 자동 3개 [코드 반영 필요]
- (b) `ASR-HardenNginx` 를 **수동 개선**으로 재분류 — 자동 2 / 수동 4 (기획서 분류와 어긋남을 발표에서 밝힘)

**[팀 결정 필요]** 입니다. 본 문서 2-2의 SEC-02는 잠정적으로 (b) 기준으로 적었습니다.

### 5-2. 수동 개선 3개 [코드 반영 완료]

| # | 플레이북/절차 | 유형 | 내용 |
|---|---|---|---|
| ① | `ASR-BlockIpWithNacl` | Automation | 무차별 대입 출발지 IP를 Private NACL Deny(1~99)로 차단. 승인 후 실행 |
| ② | `ASR-RotateDbSecret` | Automation | Secrets Manager 앱 계정 비밀번호 로테이션, DB 반영은 Run Command |
| ③ | 취약 이미지 교체 절차 | — | Trivy 비교 → 최저 위험 이미지로 버전 고정, Dockerfile `USER` 지정, ECR push |

수동 경로: asr_trigger 조건 불충족 → SNS 담당자 알림 → 대시보드에서 요청→승인→실행 → 대시보드 EC2의 **실행 전용 정책**(`document/ASR-*` + `automation-execution/*`)으로 SSM 실행.

**v11 보완**: 대시보드 EC2 역할에 `sns:Publish` 권한이 추가됐습니다(v3.0). user_data 가 토픽 ARN 을 받는데 권한이 없어 발행이 실패하던 것을 막습니다.

### 5-3. 모니터링 (NMS) [코드 반영 완료]

| 항목 | 기준 | 경로 |
|---|---|---|
| CPU | > 80% · 5분 × 2회 | `AWS/EC2 CPUUtilization` → SNS |
| 메모리 | > 80% · 5분 × 2회 | CloudWatch Agent 커스텀 지표 → SNS |
| MySQL 인증 실패 | ≥ 10회 / 5분 | `"Access denied for user"` 메트릭 필터 → SNS |
| GuardDuty 발행 주기 | 15분 | EventBridge → Lambda |
| 상관분석 승급 | +1 단계 | GuardDuty finding + 같은 인스턴스 CVE |

**메모리 알람과 MySQL 인증 실패 알람은 CloudWatch Agent 전송에 의존합니다.** NAT가 꺼져 있으면 동작하지 않습니다(1장, 7장).

### 5-4. Before / After 보장 [코드 반영 완료]

자동 조치는 대시보드를 거치지 않으므로 `asr_trigger` 가 판정 결과를 **`remediation_actions_table` 에 직접 기록**합니다. 자동 실행이든 SNS 알림만이든 **어느 쪽으로 갈라져도 항상 기록**됩니다. 레코드에 `before_state`/`after_state`/`decision`(auto-executed / manual-notified / dry-run)/`ssm_execution_id` 가 들어가 Before-After 증적이 됩니다. 대시보드는 이 테이블을 읽어 "전후 비교" 화면을 그립니다.

---

## 6. 대시보드 기능 — v2.2.2 [코드 반영 완료 (프론트) / 코드 반영 필요 (백엔드 연동)]

`dashboard/frontend/` 에 Flask + Chart.js + Tailwind 로 구현돼 있습니다. **현재는 프론트엔드 데모이며 실제 AWS 연결은 없습니다.**

### 구현된 화면

| 화면 | 내용 |
|---|---|
| 통합 관제 | 17개 리전 회전 지구본, 우측 상세, 시간 구간, CPU·메모리·해결률, 탐지 소스, 위험도, 최근 이벤트, 승인 대기 |
| 보안 이벤트 | 근거·자원·권장 조치·시나리오 전체 목록 |
| 취약점 점검 | 현재 필터의 Trivy·Inspector 항목 |
| 인프라 모니터링 | 선택 리전 CPU·메모리 + **80% 임계선**, Nginx→Flask→MySQL 상태 |
| 대응 이력 | 승인 대기/실행 이력, 실행 결과, 재검증 결과 |

### v11 시점의 지도 기능 (v2.0 → v2.2.2)

- **17개 리전** + 글로벌/위치 미상 가상 항목. 서울 기본 선택
- **정사영 회전 지구본** — 트랙볼 드래그, 휠 줌(1~3.2배), 방향키. 기본 1.0배율·서울 정중앙
- **대권(최단 구면) 공격선** — 40구간 보간 + 고도 리프트. 뒷면 클리핑
- **위협 행위국 8개국** 데이터(대표 그룹·목적·주요 타겟·전술). 개별 이벤트의 실제 귀속(attribution)이 아니라는 문구 병기
- **리전 선택 시 소속 국가 강조** — point-in-polygon 판정. 한 국가에 리전이 여럿이면(미국 4·일본 2) 국가 단위로 동일 처리
- 위치 미상·사설 IP에는 선을 그리지 않고 이유를 표시

### 대응 시연 흐름 (실제 AWS 작업 없음)

승인 → 취소 가능 → 실행 → **재검증 대기**(아직 해결 아님) → 동일 기준 재검증 → 통과/실패. `EVT-0004` 는 12개 → 2개 잔존으로 **재검증 실패** 사례입니다. "실행 성공 ≠ 해결"을 화면으로 보여주는 구조입니다.

### 실제 API 연결 지점 [코드 반영 필요 — 팀 대시보드 파트]

`static/js/store.js` 의 `api.load` / `api.execute` / `api.verify` 가 교체 지점입니다. 권장 인터페이스(현재 미구현):

- `GET /api/events` · `GET /api/metrics?region=&resource=&from=&to=`
- `POST /api/events/:id/approve` · `/execute` · `/verify`

서버가 인증·권한 확인, 감사 기록, 중복 실행 방지, 작업 상태를 관리해야 합니다. **AWS 자격증명을 프론트엔드에 넣지 않습니다.** `DEMO_MODE=false` 환경값만으로 실제 AWS에 연결되지는 않습니다.

대시보드는 관제 도구이지 MySQL을 쓰는 서비스가 아닙니다. 다이어그램에서 대시보드 → MySQL 화살표는 쓰지 않습니다.

### 검증 상태

- Chrome 1440×900 / 1920×1080 / 390×844 확인. 키보드·포커스 제한·Escape·`prefers-reduced-motion` 지원
- 테스트 5종(`browser-check.cjs`, `v2-check.cjs`, `v2.1-projection-check.mjs`, `v2.1-data-check.mjs`, `v2.2-country-highlight-check.mjs`) 통과
- **문서 드리프트**: `dashboard/frontend/README.md` 가 아직 "현재 버전 v2.0"으로 적혀 있습니다. `VERSION` 은 2.2.2 입니다 **[팀 작업: README 갱신]**

---

## 7. 아키텍처 다이어그램 구성 기준

### 7-1. 구역 구성

| 구역 | 제목 | 담당 모듈 | 들어갈 요소 |
|---|---|---|---|
| ① | IaC / CI | `bootstrap/`, `.github/workflows/` | Windows PC, GitHub Actions(plan), OIDC 역할 2개, S3 backend + DynamoDB Lock |
| ② | 보호 대상 인프라 | `network`, `compute` | VPC, IGW, NAT(옵션), 서브넷 4개, NACL, SG(**db-auto/db-manual**), ALB(WAFv2), EC2 5대, Secrets Manager, ECR, IAM Roles |
| ③ | 탐지·수집 (SIEM) | `security` | Flow Logs, CloudTrail, GuardDuty, Inspector2, Config, Access Analyzer, Security Hub |
| ④ | 자동조치·대시보드 (SOAR) | `soar` | EventBridge 3규칙, Lambda 2개, SSM Automation 4·Command 3, DynamoDB 2, SNS, CloudWatch, Flask 대시보드 |

**v11 신설**: 구역 ①에 **CI 경로**가 들어갑니다. v10에는 없던 요소입니다.

### 7-2. 그려야 할 화살표

| 흐름 | 경로 |
|---|---|
| 정상/공격 트래픽 | Attacker → (Shield Standard) → ALB(WAFv2) → Nginx(docker-host) |
| 내부 공격 | web-dvwa(pivot) 또는 attacker EC2 → MySQL |
| 로그 수집 | VPC → Flow Logs → GuardDuty / SG 설정 → Config |
| finding 집계 | GuardDuty·Inspector2·Config·Access Analyzer → Security Hub |
| **상관분석** | GuardDuty → EventBridge(`gd-correlator`) → correlator ↔ Inspector2 → DynamoDB ← 대시보드 |
| 자동 조치 | Security Hub → EventBridge(`sh-asr`) + GuardDuty → EventBridge(`gd-asr`) → asr_trigger → **SSM** → SG/IAM |
| 수동 조치 | asr_trigger → SNS → 담당자 → 대시보드 승인 → SSM |
| 모니터링 | EC2(CloudWatch Agent) → CloudWatch Alarm → SNS |
| **CI (신설)** | PR/push → GitHub Actions → OIDC → `terraform plan` → PR 코멘트 + 아티팩트 |

**Lambda는 직접 조치하지 않습니다.** 판정만 하고 실행은 SSM Automation 문서에 넘깁니다. 그래서 Lambda 권한이 `ASR-*` 문서 범위로 묶입니다. 화살표를 Lambda → SG 로 그리면 이 설계 의도가 사라집니다.

**correlator 로 가는 화살표는 Security Hub 를 거치지 않습니다.** GuardDuty 에서 바로 들어갑니다.

### 7-3. 팀 이미지에서 고칠 것 [팀 작업]

v10의 항목에 더해 v11 추가분입니다.

1. **CI 구역 추가** — GitHub Actions → OIDC → plan (구역 ①)
2. **S3 backend + DynamoDB Lock** 을 구역 ①에 표시(로컬 state 아님)
3. **docker-host 를 Private-App 으로** 이동 (Public 아님)
4. DB는 1대로 그리되 **SG 2개(db-auto/db-manual)를 인스턴스에 나란히** 표시
5. **Config → Security Hub 화살표 필수** — 자동/수동 대조군 시연의 탐지 주체
6. **correlator 는 GuardDuty 직접 연결** — Security Hub 경유로 그리면 틀림
7. `ASR-HardenNginx` 는 **점선 또는 "미배선" 표기** (5-1)
8. NLB·K3s는 그리지 않습니다

---

## 8. Terraform / AWS 서비스 체크리스트

| 분류 | 서비스 |
|---|---|
| 네트워크 | VPC, IGW, NAT(옵션), Route Table, Security Group 8종, NACL(규칙 7), VPC Flow Logs, VPC 엔드포인트 4(인터페이스 3+게이트웨이 1), Shield Standard(자동) |
| 컴퓨팅 | EC2 5대(docker-host·db·dashboard·web-dvwa·attacker), ALB + WAFv2(옵션), Secrets Manager, ECR |
| 탐지/SIEM | GuardDuty(+feature), Inspector2, AWS Config+규칙 4개, IAM Access Analyzer, Security Hub(FSBP), CloudTrail(+S3, KMS) |
| 자동조치/SOAR | EventBridge 3규칙, Lambda 2개, SSM Automation 4종·Command 3종, DynamoDB 2개, SNS, S3(스캔 결과) |
| 모니터링/NMS | CloudWatch(Agent/Logs 메트릭 필터/Alarm 3/Dashboard), SNS |
| IAM/거버넌스 | IAM Role 12개(읽기/실행 분리, Lambda·SSM·Config·EC2), KMS |
| IaC/운영 | Terraform 4모듈 + `bootstrap/`(S3 backend + DynamoDB Lock + **GitHub OIDC 역할 2종**) |
| **CI (신설)** | GitHub Actions `terraform plan`(저장소 루트 1개), OIDC 공급자, plan/apply 역할 |

---

## 9. 기존 학습 자산과의 연결점 (v10에서 변동 없음)

| 필요한 것 | 자산 |
|---|---|
| 멀티 서브넷 네트워크 설계 | `aws-network-firewall-lab.md`, `palo-alto-vmseries-aws-lab.md` |
| AWS 서비스 개념(Shield/WAF 포함) | `aws_services_summary.md` |
| CPU/Mem→SNS, GuardDuty/Inspector/Security Hub | 2-advanced.pdf |
| 공격·점검 도구(ZAP, nmap, Trivy) | 1-aws-security-tools.pdf |
| Docker 3-Tier 구성·체크리스트 | RAPA02~05, Docker_3Tier_보안_체크결과.csv |
| DVWA 웹 취약점 환경 | 기존 학습 환경 |
| 보안 시나리오 근거 | 2024SK쉴더스클라우드보안가이드.pdf |
| 대시보드 UX, 자동조치 판단 기준 | KISA/ISMS 대시보드 프로젝트 |

---

## 10. 비용 유의사항 (v11 재산정)

인스턴스 타입이 3분화돼 v10 추정치가 낮았습니다. `docs/비용예측.md` 기준으로 정정합니다.

| 변수 | 기본값 | 적용 대상 |
|---|---|---|
| `instance_type` | `t3.micro` | web_dvwa, dashboard, attacker |
| `docker_host_instance_type` | `t3.small` | docker_host |
| `db_instance_type` | `t3.small` | db |

| 항목 | 시간당(추정) | 비고 |
|---|---:|---|
| EC2 t3.micro × 2 (web_dvwa, dashboard) | $0.0288 | |
| EC2 t3.small × 2 (docker_host, db) | $0.0576 | micro의 2배 단가 |
| EBS gp3 90GB (30+20+20+20) | $0.0112 | docker_host만 30GB |
| 퍼블릭 IPv4 × 1 (web_dvwa) | $0.0050 | 2024년부터 유료 |
| VPC 인터페이스 엔드포인트 × 3 | $0.0330 | **기본 on** |
| **소계 — 항상 켜짐** | **$0.1356** | **약 하루 $3.25** |

| 시나리오 | 10일 합계(추정) |
|---|---|
| 최소 (토글 전부 off, 24h) | 약 **$32.5** |
| + NAT (부트스트랩 6h) | + 약 $0.4 |
| + ALB·WAF (시연 2일) | + 약 $1.5 |
| + 탐지 서비스 사용량 | + $2 ~ $10 (변동 큼) |
| **합계** | **약 $37 ~ $45** |

- 야간 중지 시 EC2 컴퓨팅·퍼블릭 IPv4(약 65%)가 빠집니다. 남는 것은 엔드포인트 $0.0330 + EBS $0.0112 = 시간당 약 $0.044.
- `enable_nat_gateway`/`enable_alb`/`enable_waf`/`enable_attacker_instance` 는 **기본 false**. `enable_vpc_endpoints`/`enable_dvwa_instance` 및 탐지 6종은 **기본 true**.
- **NAT와 엔드포인트를 둘 다 켜면 비용이 겹칩니다.** 첫 부팅 후 NAT는 끄세요.
- AWS Config는 7개 리소스 타입만 기록. Access Analyzer(외부 접근)는 무료.
- 정리: `demo/cleanup.sh` → `terraform destroy` → 탐지 서비스 비활성화 확인 → **CloudTrail S3·KMS 수동 삭제** (14장 종료 절차 참고).
- **기준 단가 확인일·팀 예산 한도·승인 기록이 비어 있습니다** [팀 작업] — `docs/비용예측.md` 3장.

---

## 11. 기획서 성공 기준 매핑

| 평가 항목 | 성공 기준 | 확인 방법 | v11 구현 |
|---|---|---|---|
| 자동 모니터링 | 2개 이상(기획 3개) | Security Hub finding, DynamoDB 레코드, SNS 메일 | ✅ Config·correlator·CloudWatch |
| 수동 모니터링 | 2개 이상(기획 2개) | ZAP·nmap·Trivy 결과, 체크리스트 | ✅ SCAN-PortAndWeb, SCAN-ContainerImage |
| 자동 개선 | 2개 이상(기획 3개) | SSM 실행 이력(Before/After), Lambda 로그 | **⚠️ 실제 2개** — RevokeSG, DisableKey (HardenNginx 미배선) |
| 수동 개선 | 2개 이상(기획 3개) | 변경 전후 diff, 승인 기록 | ✅ BlockIpWithNacl, RotateDbSecret, 이미지 교체 |
| 재검증 | 동일 조건 Before/After | 취약 항목·CVE 수·보안 점수 비교 | ✅ `remediation_actions_table` + SSM before/after |
| 서비스 안정성 | 개선 후 정상 유지 | /health 200, 자동조치 중단 0건 | ✅ 되돌릴 수 있는 조치만 자동화 |
| 문서화 | 설계·결과·증거 | 기획서·구성도·리포트 | ✅ 본 문서 + 저장소 `docs/` 7종 + `README` |
| AI(선택) | 개선안 도출·승인 | AI 제안 기록 | 선택안함 |

**기준 충족 여부**: 자동 개선 2개로 "2개 이상"은 충족합니다. 다만 기획서 기능명 3개와 대조하면 1개가 비므로, 5-1의 (a)/(b) 중 하나를 택해 발표 전에 정리해야 합니다.

---

## 12. 역할 분담 (5개 파트) [팀 결정 필요: 이름 배정]

| 파트 | 주요 책임 | 발표/시연 |
|---|---|---|
| PM · 인프라/IaC | 일정·산출물, network·compute 모듈, **CI 워크플로·OIDC·state**, 비용 토글·정리 | 개요, 아키텍처·Terraform·CI 설명 |
| 탐지 연동(SIEM·NMS) | security 모듈, CloudWatch Agent·알람·SNS | 탐지 finding·임계치 알림 |
| 자동조치 로직(SOAR) | EventBridge, correlator·asr_trigger, SSM 플레이북, **HardenNginx 배선 결정** | 자동조치 Before/After(자동 vs 대조군) |
| 보안 대시보드 | Flask 대시보드(v2.2.2), **실제 API 연동**, 침해사례 탭, 승인 워크플로우 | 대시보드 데모 |
| 서비스·공격·문서화 | Docker 3-Tier·체크리스트, 공격 재현, **증적 12개 항목**·Before/After·발표자료 | 공격 재현, 점검→개선 발표 |

인원이 적으면 1+2, 3+4 겸임.

---

## 13. 남은 결정사항

**v11에서 해소된 것** (13장에서 제외)
- ~~state 로컬 / S3~~ → **S3 확정** (`backend.tf`)
- ~~Docker Host 배치~~ → **Private-App 확정**
- ~~`terraform plan` 1회 실행해 provider 스키마 검증~~ → **validate 통과, CI가 매 PR 실행**
- ~~리소스 수 172 vs 173 불일치~~ → **173 확정** (`구성설명.md` v3.2 정정)

**남은 것**

- [ ] **`ASR-HardenNginx` 처리** — (a) asr_trigger 분기 추가해 자동 3개 / (b) 수동으로 재분류 (5-1) ← **우선순위 1**
- [ ] **자동/수동 분류 기준** — 기획서(도구 실행=자동) vs 코드(무개입=자동). 위 항목과 함께 정리 (2-3)
- [ ] **HTTPS** — 자체서명 ACM 임포트 / ALB HTTP만 두고 SEC-02 탐지 대상 (코드는 `acm_certificate_arn` 준비됨)
- [ ] **ALB `0.0.0.0/0`** — `admin_cidr` 로 좁힐지. **Before 증적 먼저** (VULN-002)
- [ ] **Hydra 대상** — MySQL 3306 유지 / SSH 22 변경 (2-2 탐지 주의)
- [ ] **공격 실행 위치** — attacker EC2 / web-dvwa pivot / 로컬 PC (2-1)
- [ ] **NAT 운용 방침** — 첫 부팅만 켜기 / 실습 내내 켜기(메모리·SEC-06 알람 유지, 비용 증가) / `secretsmanager`·`logs`·`monitoring` 엔드포인트 추가(월 +$28)
- [ ] **팀 계정 AZ 이름** 확인 (`az_primary`/`az_secondary`)
- [ ] `auto_remediable_patterns` 화이트리스트 팀 합의
- [ ] `enable_auto_remediation` 을 시연 전까지 `false` 로 둘지
- [ ] GuardDuty `RDS_LOGIN_EVENTS` 비활성화 (RDS 없음)
- [ ] **web-dvwa 의 IMDS hop limit 이 2** — 컨테이너를 돌리지 않는 인스턴스라 1이면 충분. 완화 검토 (14장)
- [ ] 역할분담 이름 배정 (12장)
- [ ] 팀 이미지 다이어그램 7-3 기준 수정 **[팀 작업]**
- [ ] `team_name`·`owner` 변수를 본인 값으로 (제출 전)
- [ ] `docs/비용예측.md` 단가 확인일·예산 한도·승인 기록 채우기
- [ ] 증적 10·11·12번 (`apply` 출력 필요)

**문서 드리프트 정리 [팀 작업]**
- [ ] **커밋 라벨 혼선** — `v3.1 → v3.2 → v3.3 → v3.2` 순으로 어긋남. 태그를 붙이거나 다음 커밋부터 단조 증가로
- [ ] 저장소 루트 `README.md` 가 "# Autoever-Aws-security / 2차 프로젝트" 두 줄뿐 — 프로젝트 개요·구조 필요
- [ ] `aws-soar-terraform/README.md` 제목이 "Terraform v10" — v3.2 기준으로 갱신
- [ ] `docs/구성설명.md` 의 "5대가 모두 이 값을 참조합니다" — `http_put_response_hop_limit` 은 docker-host 만 `local` 참조, 나머지 4대는 값을 직접 씀 (14장)
- [ ] `docs/체크리스트.md` 발표 화면 ③이 `modules/network/security_groups.tf` 를 가리킴 — 삭제된 파일. `sg.tf` 로 수정
- [ ] `dashboard/frontend/README.md` 가 "현재 버전 v2.0" — `VERSION` 은 2.2.2

---

## 14. Terraform 구성 (모듈·파일·리소스) — 코드 v3.2 [코드 반영 완료]

저장소 `aws-soar-terraform/` 기준 실측입니다. (커밋 `ea57b3e`)

| 항목 | 수치 |
|---|---:|
| tf 파일 (bootstrap 제외) | **35개 / 약 3,522줄** |
| tf 파일 (bootstrap 포함) | 37개 / 약 3,820줄 |
| 리소스 선언 | **173개** |
| 변수 선언 | **121개** |
| 출력 | **49개** |
| Lambda | 2개 / 258줄 (`asr_trigger` 178 + `correlator` 80) |
| SSM 문서 | **7종** — Automation 4 + Command 3 |
| user_data 템플릿 | 5종 (`templates/*.sh.tftpl`) |
| 데모 스크립트 | **4종** (v10 3종 + `verify-controls.sh`) |
| 저장소 문서 | **7종** (`docs/*.md`) |

`count`/`for_each` 때문에 실제 생성 개수는 토글에 따라 달라집니다.

### 모듈 구조

| 모듈 | 구역 | 주요 리소스 |
|---|---|---|
| `bootstrap/` | ① | state용 S3 + DynamoDB Lock + **GitHub OIDC 공급자·역할 2종** |
| `modules/network` | ② | VPC, 서브넷 4, 라우팅, NAT(옵션), SG 8종, NACL 규칙 7, Flow Logs, VPC 엔드포인트 4 |
| `modules/compute` | ② | EC2 5대, ALB+WAFv2(옵션), IAM(읽기/실행 분리 + SNS Publish), Secrets Manager, ECR, user_data 5종 |
| `modules/security` | ③ | GuardDuty(+feature), Inspector2, Config+규칙 4, Access Analyzer, Security Hub, CloudTrail+KMS+S3. **`outputs.tf` 없음** |
| `modules/soar` | ④ | EventBridge 3, Lambda 2, SSM 문서 7, DynamoDB 2, SNS, S3, CloudWatch 알람 3·메트릭 필터·대시보드 |

### 의존 순서와 순환 참조 방지

`network → compute → security → soar`. `soar` 가 마지막인 이유는 `compute` 가 만든 인스턴스 ID를 알람 차원(dimension)으로 받아야 하기 때문입니다.

모듈이 공유하는 리소스(로그 그룹·DynamoDB·S3·SSM 역할·SNS 토픽 ARN)의 **이름은 루트 `locals` 에서 먼저 확정**하고 생성만 각 모듈이 맡습니다. SNS 토픽 ARN은 이름으로 조립해 compute → soar 순환을 끊습니다. **순환 참조 없음.**

### 공통 설정 — 태그와 IMDSv2

**공통 태그**는 `providers.tf` 의 `default_tags` 5종입니다. 리소스마다 붙이지 않아 빠뜨릴 여지가 없습니다.

```hcl
Project = var.project   Environment = var.env   Team = var.team_name
Owner   = var.owner     ManagedBy   = "terraform"
```

**IMDSv2** 는 `compute/main.tf` 의 `local.common_metadata` 입니다.

```hcl
common_metadata = {
  http_endpoint               = "enabled"
  http_tokens                 = "required" # IMDSv2 강제
  http_put_response_hop_limit = 2          # 컨테이너에서의 호출 허용
}
```

hop limit 이 2인 이유는 **컨테이너 안에서 IMDS 를 호출하려면 홉이 하나 더 필요**하기 때문입니다. 기본값 1이면 docker-host 의 컨테이너가 IAM 역할 자격증명을 못 가져옵니다.

**실측 — 인스턴스별로 값이 다릅니다.**

| 인스턴스 | hop limit | 비고 |
|---|:---:|---|
| docker-host | 2 (`local` 참조) | 컨테이너 호출 필요 |
| web-dvwa | **2** (직접 지정) | 컨테이너를 돌리지 않음 — 1로 줄이는 것 검토(13장) |
| db · dashboard · attacker | 1 (직접 지정) | 컨테이너 없음 |

`http_endpoint`·`http_tokens` 는 5대 모두 `local.common_metadata` 를 참조하지만, **hop limit 은 docker-host 만 참조**하고 나머지는 값을 직접 씁니다. `구성설명.md` 의 "5대가 모두 이 값을 참조합니다"는 hop limit 에 한해 정확하지 않습니다.

EBS는 전부 `gp3` + `encrypted = true` 입니다.

### CI / 원격 state [v11 신설]

| 항목 | 값 |
|---|---|
| state 버킷 | `soar-sec-tfstate-455958489281` (S3, 버저닝) |
| 잠금 테이블 | `soar-sec-tflock` (DynamoDB) |
| 설정 위치 | **`backend.tf` 직접 설정** (`backend.tf.example` 삭제) |
| CI 워크플로 | `.github/workflows/terraform-plan.yml` — **저장소 루트 1개** (중첩본 삭제) |
| 트리거 | `pull_request` · `push:main` · `workflow_dispatch` |
| 단계 | init → `fmt -check -recursive` → validate → `plan -out=tfplan` |
| 인증 | OIDC. `github-actions-terraform-plan` (ReadOnlyAccess + state 접근) |
| apply 역할 | `github-actions-terraform-apply` (PowerUserAccess + IAM 쓰기, **main 브랜치만**) — 워크플로에서는 미사용, apply 는 사람이 로컬 실행 |
| 안전 가드 | `ADMIN_CIDR` 빈 값·`0.0.0.0/0` 이면 실패 / `concurrency` 로 동시 실행 큐잉 |
| 증적 | PR 코멘트(60,000자 절단) + `tfplan`·`plan.txt` 아티팩트 14일 보관 |
| Terraform | 1.9.8 / provider `~> 6.0` |

**`backend.hcl` 대신 `backend.tf` 를 쓰는 이유**: `backend.hcl` 은 저장소 밖에 두는 방식이라 CI 러너가 그 파일을 읽지 못합니다. 워크플로까지 같이 고쳐야 해서, 지금은 코드에 직접 두는 쪽을 택했습니다. `backend.hcl.example` 은 대안 예시로만 남아 있습니다.

**계정을 옮길 때** — 버킷 이름에 계정 ID가 박혀 있어 `backend.tf` 를 함께 고쳐야 하고, 고친 뒤에는 **`terraform init -reconfigure`** 가 필요합니다. 그냥 `init` 만 하면 `Backend configuration changed` 로 막힙니다.

**OIDC 신뢰 정책은 `sub` 클레임과 문자 그대로 비교**하므로 `github_repo` 는 대소문자까지 정확해야 합니다(기본값 `juhyeop/aws-security-project`). 다르면 CI 가 `Not authorized to perform sts:AssumeRoleWithWebIdentity` 로 막히고, 레포 이름을 바꿨다면 **`bootstrap` 을 다시 apply** 해야 합니다.

### 설계가 코드로 드러나는 지점 (발표 포인트)

1. **Lambda 는 조치하지 않는다** — 판정만 하고 실행은 SSM Automation 에 위임. Lambda 권한이 `ASR-*` 문서 범위로 묶임
2. **읽기/실행 권한 분리** — 대시보드 EC2 역할에 읽기 전용 정책과 `document/ASR-*` + `automation-execution/*` 실행 전용 정책을 분리. 대시보드에 버그가 있어도 조회 화면 때문에 조치가 실행되지 않음
3. **DB 1대 + SG 2개** — Config 가 SG 단위로 평가하는 점을 이용해 EC2 절감하면서 자동/수동 대조군 시연
4. **되돌릴 수 있는 조치만 자동화** — SG 회수·키 비활성화. 판정 결과는 분기와 무관하게 항상 DynamoDB 기록
5. **액세스 키 없는 CI** — OIDC 단기 토큰. plan 은 ReadOnly, apply 는 main 전용 역할로 분리

### 검증 상태 [v11에서 격상]

| 검사 | v10 | v11 |
|---|---|---|
| `terraform init -backend=false` | ❌ | ✅ |
| `terraform validate` | ❌ 레지스트리 차단 | **✅ Success** |
| `terraform fmt -recursive -check` | 미실행 | **✅ clean** |
| `checkov -d . --framework terraform` | 미실행 | **실행** — 실패 항목 대부분 실습 의도 |
| HCL 파싱 / 참조 / 순환 | ✅ 정적 검사 | ✅ 유지 |
| **런타임 (apply 이후)** | ❌ | **❌ 여전히 미검증** |

checkov 실패는 대부분 의도된 선택입니다 — DVWA 의도적 취약점, `force_destroy`, ALB 평문 HTTP, NACL 개방.

**팀 계정에서 반드시 확인할 것**

- **apply 전 자격증명 확인** — `aws sts get-caller-identity`. bootstrap 의 버킷 이름은 `data.aws_caller_identity` 로 만들어지므로, 프로파일이 잘못 잡혀 있으면 엉뚱한 계정에 그대로 생성됩니다. Terraform 은 `--profile` 옵션이 없고 환경변수 `AWS_PROFILE` 만 봅니다. 비어 있으면 `default` 프로파일입니다
- 실제 AZ 이름 (`az_primary`/`az_secondary`)
- AWS Config·Security Hub·GuardDuty 기존 활성화 여부 (중복 활성화 충돌)
- ECR 이미지(`app-1.0.0`) push 선행 — 없으면 docker-host 의 compose 가 web 컨테이너를 못 올림
- **첫 apply 는 `enable_nat_gateway = true`** 로 (user_data 인터넷 필요)
- `terraform.tfvars` 는 커밋되지 않습니다. 팀 공유는 `terraform.tfvars.example` 로
- `apply -auto-approve` 금지. `-/+ replace` 가 `aws_instance.db` 에 보이면 **데이터가 사라집니다**
- 콘솔에서 직접 고치면 드리프트가 생깁니다. 긴급이 아니면 코드를 고쳐 apply

**종료 절차**

`terraform plan -destroy` 로 먼저 확인하고 destroy 합니다. destroy 후에도 콘솔에서 확인할 것:

- **CloudTrail 버킷은 `force_destroy = false`** — 객체가 남아 있으면 삭제가 실패합니다
- **state 버킷은 버저닝이 켜져 있어 버전까지 지워야** 비워집니다
- KMS 키(삭제 대기), CloudWatch 로그 그룹, Elastic IP, Inspector/GuardDuty 활성화 상태

---

## 참고 자료

- 코드 저장소: [juhyeop/aws-security-project](https://github.com/juhyeop/aws-security-project)
- 저장소 내 문서: `aws-soar-terraform/docs/` — `아키텍처.md`(Mermaid 5종) · `구성설명.md`(v3.2) · `AS-IS_TO-BE.md` · `비용예측.md` · `체크리스트.md` · `증적양식.md` · `병합내역.md`
- [Automated Security Response on AWS — Solution overview](https://docs.aws.amazon.com/solutions/latest/automated-security-response-on-aws/solution-overview.html)
- [Using EventBridge for automated response and remediation — AWS Security Hub](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cloudwatch-events)
- [AWS WAF는 ALB·CloudFront·API Gateway에 연결](https://docs.aws.amazon.com/waf/latest/developerguide/how-aws-waf-works.html)
- [aws:executeScript 지원 런타임](https://docs.aws.amazon.com/systems-manager/latest/userguide/automation-action-executeScript.html)
- [GitHub Actions OIDC — AWS 자격증명 구성](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services)
- [EC2 IMDS hop limit 과 컨테이너](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-options.html)
- 지난 기수 레퍼런스: [\[프로젝트\] AWS 기반 서비스 보안 구축 프로젝트](https://k-giraffe.tistory.com/84)
- 아키텍처 다이어그램: [인포그래픽](https://claude.ai/artifact/VQhQdkic42wej9P7KnLRDU) · [SVG](https://claude.ai/artifact/D7fEoGxcPepD4W3nwZxe58)
