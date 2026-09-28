# 구현·검증 추적표

## 문서 정보

| 항목 | 내용 |
|---|---|
| 목적 | 요구사항과 설계 문서, 실제 코드 경로, 구현 연결 상태와 검증 증거를 추적한다. |
| 적용 범위 | 프로젝트 전체 코드·자료와 이 문서 체계 |
| 책임 역할 | 기능 담당자는 자신의 코드·검증 근거를 갱신하고, 설계 책임자는 ID·상태·문서 간 연결을 검토한다. |
| 실제 프로젝트 기준 경로 | C:\Users\user\aws-security-project |
| 확인 시점 | 2026-09-26 읽기 전용 정적 조사. 2026-09-28 공격·대응 실습(DRILL-01~04, v22·v22.1), EC2 교체 이력 조회 변경 및 v22.3 실환경 검증 반영 |
| 관련 문서 | [전체 설계](../README.md), [Dashboard](../dashboard/dashboard-design.md), [Terraform](../terraform/infrastructure-design.md), [허니팟](../honeypot/honeypot-design.md), [보안 시나리오](security-scenarios.md), [공통 용어](glossary.md), [결정 기록](decisions.md) |
| 갱신을 유발하는 변경 | 요구사항·코드 경로·호출 관계·구성 토글·데이터 계약·검증 증거·편차 상태 변경 |

## 1. 판정 방법과 조사 한계

코드 경로는 모두 위 실제 프로젝트 기준 경로에 상대적이다. 다음 상태는 소스 코드와 문서에서 확인한 범위만 설명한다.

- **완료**: 이 행의 범위에 필요한 소스 선언과 호출·이벤트·저장 연결을 확인했다. 배포·동작·성능·보안 효력까지 입증했다는 뜻은 아니다.
- **부분 구현**: 일부 코드나 선언은 있으나 목표 경로가 비활성·미연결·범위 제한·계약 편차 등으로 완성되지 않았다.
- **미구현**: 조사한 코드 및 파일 검색에서 구현 경로를 찾지 못했다. 기존 제안 문서만으로 구현이 있다고 판단하지 않는다.
- **미실행**: 이번 조사에서 해당 검증을 수행하지 않았고, 적용 가능한 명시적 실행 결과를 근거 자료에서 확인하지 못했다.
- **통합 검증**: 환경을 연결해 구성요소 간 흐름을 실제로 확인한 기록이 있을 때만 사용한다.
- **실환경 검증**: AWS 계정의 배포 자원에서 점검한 절차·환경·결과 증거가 있을 때만 사용한다.

“완료” 구현 상태와 검증 상태는 독립적이다. 코드에 테스트가 있어도 실행 결과가 없으면 검증은 미실행이다. 기존 테스트·시나리오 스크립트·검증 문서가 존재한다는 사실도 통과 기록이 아니다. 2026-09-26 초기 정적 조사에서는 코드 실행, 테스트, 의존성 설치, 서버 구동, Terraform, AWS API 호출을 수행하지 않았다. 이후 실행 결과는 아래에 별도로 기록한다.

DRILL-01~04는 예외로, 2026-09-28 작업에서 로컬 단위 테스트를 실제 실행했다(백엔드 pytest 66건, 프런트 node --test 77건 통과). 이는 단위·계약 수준 확인이며 통합·실환경 검증은 아니므로 각 행의 검증 상태는 미실행으로 둔다.

2026-09-28 인프라 지표 연속 조회 변경은 `dashboard/backend`의 로컬 pytest 71건과 `dashboard/frontend`의 Node 테스트 77건을 통과했다. CloudTrail의 실제 종료·실행 이벤트에는 이전 EC2 ID와 인스턴스 프로필이 들어 있음을 읽기 전용 조회로 확인했다. v22.3(`049ff4f`)을 기존 대시보드 EC2 `i-02779834499df9e6c`에 Terraform apply 없이 배포했다(SSM 명령 `46fdd3dd-98e5-4753-98dc-1c25c74b0475`, 성공). 배포 후 실제 AWS 공급자 조회에서 운영 서버 4대의 교체 이력과 옛 인스턴스 지표를 확인했고(SSM `9367dc35-f472-46d4-a64a-b10b0fa109cc`, 성공), 대시보드 서버의 7일·300초 조회에서 현재 인스턴스 39개와 직전 인스턴스 24개의 지표를 받았다(SSM `ff4a5960-ca53-4191-8ad7-19bd2398690c`, 성공). 로컬 자료 디렉터리가 남아 있고 ALB 대상 상태는 `healthy`였다. 인증된 브라우저에서 그래프와 취약점 화면 표시를 직접 확인한 기록은 없다.

대시보드의 dashboard/backend/docs/VERIFICATION.md는 2026-09-23 변경 기준으로 일부 검증 범위를 열거하지만 실제 데이터 수집, 원격 조치, 운영 부하 검증은 포함하지 않는다고 명시한다. 저장소에서 해당 검사별 통과 출력이나 AWS 실환경 결과를 확인하지 못했으므로, 이 표의 검증 상태는 확인 가능한 증거가 없는 항목을 모두 미실행으로 둔다.

## 2. 프로젝트·인프라·보호 대상

| 요구 ID | 출처·요구사항 | 설계 위치 | 실제 코드 경로와 정적 근거 | 구현 | 검증 |
|---|---|---|---|---|---|
| SYS-01 | README.md의 4계층 구조, 보호 대상과 관제 시스템 경계 | [README.md §1–3](../README.md) | terraform/main.tf에서 network, security, compute, soar 모듈을 선언. dashboard와 보호 대상은 별도 compute·서비스 자원으로 구성 | 완료 | 미실행 |
| TF-01 | GOAL-01: Terraform 4개 책임 모듈 | [infrastructure-design.md](../terraform/infrastructure-design.md) | terraform/main.tf → modules/network, modules/compute, modules/security, modules/soar | 완료 | 미실행 |
| TF-02 | 원격 상태와 잠금 | [infrastructure-design.md](../terraform/infrastructure-design.md) | terraform/backend.tf에 S3 backend 및 DynamoDB lock table 선언. bootstrap/main.tf에 S3 버전 관리·암호화·공개 차단 및 잠금 테이블 선언 | 완료 | 미실행 |
| TF-03 | CI plan, 사람의 apply 책임 | [README.md §1·8](../README.md), [infrastructure-design.md](../terraform/infrastructure-design.md) | .github/workflows/terraform-plan.yml에 OIDC, Terraform 1.9.8, init, fmt check, validate, plan, 결과 보관 선언. `versions.tf`는 `>=1.6.0` 호환 범위. apply 단계는 workflow에 없고 사람이 담당한다고 주석·PR 결과에 명시 | 완료 | 미실행 |
| NET-01 | 서브넷·보안 경계·관리 접속 | [README.md §3](../README.md), [infrastructure-design.md](../terraform/infrastructure-design.md) | terraform/modules/network/main.tf에 VPC, public/private subnet, SSM·SSM Messages·EC2 Messages·monitoring VPC endpoint 선언. sg.tf에 Dashboard 8080 경로, DB SG, NACL 선언. SSM 사용·SSH 미개방은 주석과 규칙에서 확인 | 완료 | 미실행 |
| APP-01 | 보호 대상 Nginx–Flask–MySQL 컨테이너 서비스 | [README.md §1·3](../README.md), [infrastructure-design.md](../terraform/infrastructure-design.md) | terraform/modules/compute/templates/docker-host.sh.tftpl에 Compose·Nginx·Flask·서비스 DB 구성 및 CloudWatch Agent 설정 | 완료 | 미실행 |
| APP-02 | 별도 Private-DB 시연 MySQL EC2와 자동/수동 대조군 | [README.md §1](../README.md), [security-scenarios.md §5–6](security-scenarios.md) | terraform/modules/compute/templates/mysql-db.sh.tftpl에 MySQL 설치·로그 수집. modules/network/sg.tf에 db-auto/db-manual SG와 3306 규칙 | 완료 | 미실행 |
| APP-03 | 별도 DVWA 공격 시험 자산 | DEC-004, [README.md §1](../README.md), [security-scenarios.md §6](security-scenarios.md) | terraform/modules/compute/templates/web-dvwa.sh.tftpl, modules/compute/alb.tf의 선택적 DVWA listener 8081, modules/network/sg.tf의 admin_cidr 제한 | 완료 | 미실행 |
| OPS-IAC-01 | 비용·토글·격리 구성 | [infrastructure-design.md](../terraform/infrastructure-design.md) | terraform/variables.tf, modules/compute/variables.tf와 docs/비용예측.md에 선택 리소스·비용 자료. 실제 예산 알림·청구 검증은 이 경로들만으로 확인되지 않음 | 부분 구현 | 미실행 |

## 3. 대시보드·저장소·API

| 요구 ID | 출처·요구사항 | 설계 위치 | 실제 코드 경로와 정적 근거 | 구현 | 검증 |
|---|---|---|---|---|---|
| DASH-01 | DEC-002: Terraform 선언 접근 경로 채택 | [dashboard-design.md §인증·인가](../dashboard/dashboard-design.md), [infrastructure-design.md](../terraform/infrastructure-design.md) | terraform/modules/compute/alb.tf에 조건부 ALB 8080→dashboard target 5000, modules/network/sg.tf에 CIDR ingress, modules/compute/templates/dashboard.sh.tftpl에 port 5000 설정. SSM 포트 포워딩 SG·VPC endpoint 구성도 있음. CIDR 기본값 0.0.0.0/0은 운영 허가가 아님 | 완료 | 미실행 |
| DASH-02 | 대시보드 화면·Store·Flask API 계층 | [dashboard-design.md](../dashboard/dashboard-design.md) | dashboard/frontend/static/js/store.js와 store·ui 모듈, backend/soar/standard_api.py·contracts.py가 표준 API와 `{data, meta}` 응답을 연결. 프런트엔드는 서명 cursor 페이지를 끝까지 조회하고, `/api/legacy/*` 경로는 제거됨. backend/tests/test_disconnected.py에 legacy 경로 404 확인이 있으나 실행 결과는 확인하지 않음 | 완료 | 미실행 |
| DASH-03 | 실제 데이터 공급자 및 실패 상태 | [dashboard-design.md §데이터 원본·실패](../dashboard/dashboard-design.md), [glossary.md](glossary.md) | dashboard/backend/soar/settings.py 기본값은 `DATA_PROVIDER=none`; soar/__init__.py는 이때 UnconfiguredProvider를 선택하고 provider.py가 503 `DATA_SOURCE_NOT_CONFIGURED`를 반환. `aws` 선택 시 AwsProvider와 integrations/aws의 Security Hub·Inspector·EC2·CloudWatch·DynamoDB 어댑터를 사용하며 Terraform dashboard.sh.tftpl은 `DATA_PROVIDER=aws`를 설정. 생성형 관측 자료 fallback은 두지 않음 | 부분 구현 | 미실행 |
| DASH-04 | Finding·취약점 동기화 자료를 대시보드에서 조회 | [dashboard-design.md §데이터 원본](../dashboard/dashboard-design.md), [infrastructure-design.md](../terraform/infrastructure-design.md) | terraform/modules/soar/finding_sync.tf에서 Security Hub·Inspector 이벤트와 주기 대조가 Lambda로 연결됨. lambda_src/finding_sync/handler.py가 Findings/Vulnerabilities DynamoDB 테이블을 갱신. dashboard/backend/soar/provider.py·integrations/aws/stored.py가 적재 자료를 읽도록 연결 | 완료 | 미실행 |
| DASH-05 | 작업·승인·감사 목표 저장소 DynamoDB | DEC-003, [dashboard-design.md](../dashboard/dashboard-design.md), [decisions.md](decisions.md) | dashboard/backend/soar/settings.py가 `instance/dashboard.sqlite3`를 기본 DB로 지정하고 soar/store.py에 users/events/jobs/requests/audit SQLite 테이블, workflow.py와 worker.py에 승인·작업 상태 전이가 있음. DynamoDB는 자동조치 이력 및 finding 조회에는 쓰이나 이 사용자 작업 저장소를 대체하지 않음. 설계 목표 DynamoDB와 구현 SQLite가 다름. 2026-09-23 DB 교체 기록에는 기존 계정 정보는 유지하고 운영 이벤트·조치·작업 이력은 이관하지 않았다고 적혀 있음; 현재 DB 내용은 별도 확인하지 않음 | 부분 구현 | 미실행 |
| DASH-06 | 승인·취소·실행·재검증 API와 실제 AWS 작업 | [dashboard-design.md §API·SOAR](../dashboard/dashboard-design.md), [glossary.md](glossary.md) | dashboard/backend/contracts/openapi.yaml과 backend/soar/workflow.py에 API·상태 전이, backend/soar/worker.py에 공급자 작업 호출. settings.py 기본값은 `WRITE_ENABLED=false`이나 Terraform의 `dashboard.sh.tftpl`은 이를 `true`로 덮어 API write-disabled 검사를 통과시킴. AwsProvider.execution_result 및 measure는 `ACTION_PROVIDER_DISABLED`를 반환하므로 실제 AWS 조치·재검증은 연결되지 않음 | 부분 구현 | 미실행 |
| DASH-07 | 사용자 인증·인가·세션과 운영 정책 | [dashboard-design.md §인증·인가](../dashboard/dashboard-design.md), [decisions.md §OPEN-001](decisions.md) | dashboard/backend/soar/auth.py, workflow.py, store.py에 로그인·역할·범위·권한·CSRF 관련 코드. settings.py 기본 세션 쿠키는 `soar_session`; store.py의 기본 계정 범위는 계정 목록이 빈 값이다. 2026-09-23 DB 교체 기록은 범위를 빈 목록으로 초기화했고 쿠키명 변경으로 재로그인이 필요하다고 적음; 현재 사용자·세션 상태는 별도 확인하지 않음. 운영 인증 공급자·MFA·계정 수명주기 확정 근거 없음 | 부분 구현 | 미실행 |
| DASH-08 | 화면·API·조치 상태 계약의 결측·실패 표현 | [dashboard-design.md §UI·오류](../dashboard/dashboard-design.md), [glossary.md](glossary.md) | dashboard/backend/contracts/openapi.yaml에 partial, warnings, healthy/degraded/unhealthy/unknown, ActionState enum. frontend/tests와 backend/tests에 disconnected·workflow·provider 테스트 파일 존재; 결과는 이번 조사에서 실행하지 않음 | 완료 | 미실행 |
| DRILL-01 | DEC-012: 공격·대응 실습 페이지(1차 관측·구조) | [dashboard-design.md §API·UI](../dashboard/dashboard-design.md), [decisions.md §DEC-012](decisions.md) | dashboard/frontend/static/js/ui/pages/drills.js, app.js(refresh의 drills 분기·render 분기), ui/router.js·templates/index.html(메뉴·라우트), store/actions.js·store/api/endpoints.js·ui/context.js. 실행 유형·대상·시나리오 선택과 유형별 정보·실행 가능 여부 표시. '시작'은 비활성이며 실제 실행 요청을 만들지 않는다. 미연결에서도 카탈로그로 렌더 | 부분 구현 | 미실행 |
| DRILL-02 | DEC-012: 실습 조회 API(조회 전용) | [openapi.yaml](../dashboard/backend/contracts/openapi.yaml), [dashboard-design.md](../dashboard/dashboard-design.md) | dashboard/backend/soar/drills.py(DrillService·정적 카탈로그·DrillRuns), standard_api.py의 GET /api/drills/catalog·/api/drills·/api/drills/{runId}, __init__.py의 drill_service 등록. provider 불필요(미연결에서도 200). 변경·실행 경로 없음 | 완료 | 미실행 |
| DRILL-03 | DEC-013: 실습 실행 이력 저장 어댑터 | [decisions.md §DEC-013](decisions.md) | dashboard/backend/soar/store.py의 drills 테이블(SQLite), drills.py DrillRuns.list/get. 목표 DynamoDB와의 편차(DEC-003 정합). 실행 경로가 없어 이력은 비어 있음 | 부분 구현 | 미실행 |
| DRILL-04 | 실제 공격·부하·재검증 실행 | [decisions.md §OPEN-015·016·017](decisions.md) | SSM 부하/ZAP 실행, 실행 공급자, 실행 접수·중단·타임라인·재검증 API를 코드에서 찾지 못함. AwsProvider.execution_result/measure는 ACTION_PROVIDER_DISABLED. dashboard IAM에 ssm:SendCommand 없음 | 미구현 | 미실행 |

## 4. 탐지·SOAR·기록

| 요구 ID | 출처·요구사항 | 설계 위치 | 실제 코드 경로와 정적 근거 | 구현 | 검증 |
|---|---|---|---|---|---|
| DET-01 | Config, GuardDuty, Inspector, Security Hub, CloudTrail, Access Analyzer 활성화 경로 | [README.md §1·3](../README.md), [infrastructure-design.md](../terraform/infrastructure-design.md) | terraform/modules/security/config.tf, guardduty.tf, inspector.tf, securityhub.tf, cloudtrail.tf, access_analyzer.tf에 리소스 선언. 기능 토글에 따라 조건부 생성되며 계정에서 활성 상태인지는 확인하지 않음 | 완료 | 미실행 |
| DET-02 | GuardDuty 상관분석과 Inspector 조회 | [README.md §3](../README.md), [infrastructure-design.md](../terraform/infrastructure-design.md) | terraform/modules/soar/eventbridge.tf의 gd_to_correlator 규칙·Lambda target; lambda_src/correlator/handler.py에서 Inspector 조회와 correlated DynamoDB 테이블 쓰기 | 완료 | 미실행 |
| DET-03 | Finding·취약점 적재, 재대조와 실패 경보 | [dashboard-design.md §데이터 원본](../dashboard/dashboard-design.md), [infrastructure-design.md](../terraform/infrastructure-design.md) | terraform/modules/soar/finding_sync.tf에서 Security Hub·Inspector·schedule→finding_sync, 재시도 설정·SQS DLQ·CloudWatch 오류/DLQ alarm. lambda_src/finding_sync/handler.py에서 조건부 적재·대조 | 완료 | 미실행 |
| DET-04 | MySQL 인증 실패와 CloudWatch 관측 경로 | DEC-005, [security-scenarios.md §6.6A](security-scenarios.md), [infrastructure-design.md](../terraform/infrastructure-design.md) | terraform/modules/compute/templates/mysql-db.sh.tftpl의 error/general log CloudWatch 전달. modules/soar/cloudwatch.tf의 Access denied for user metric filter→MySQLAuthFailure→alarm→SNS. 코드 기본 threshold 10, 300초 기간은 승인 정책이 아님. MySQL alarm에서 ASR로 이어지는 연결은 확인되지 않음 | 완료 | 미실행 |
| DET-05 | 운영 CPU·메모리 CloudWatch 경보 | README.md GOAL-03, [infrastructure-design.md](../terraform/infrastructure-design.md) | terraform/modules/soar/cloudwatch.tf의 EC2 CPU·Agent MemoryUsedPercent alarm 및 SNS. root variables.tf 기본값 80, 300초 기간·2회 평가는 코드 설정이며 사용자 확정 기준으로 승격하지 않음 | 완료 | 미실행 |
| DET-06 | SSH 공격 탐지·상관 경로와 SOAR 필터의 경계 | DEC-005, [security-scenarios.md §6.6B](security-scenarios.md), [decisions.md §GAP-003](decisions.md) | modules/security/guardduty.tf와 modules/soar/eventbridge.tf에서 GuardDuty finding→correlator는 연결. gd_to_asr 필터는 UnauthorizedAccess:IAMUser, CredentialAccess:IAMUser, Discovery:IAMUser 유형이며 SSH Hydra 행위 유형을 자동 조치에 연결한다고 확인되지 않음 | 부분 구현 | 미실행 |
| SOAR-01 | 보안 finding 기반 허용된 자동 조치 | [README.md §3·6](../README.md), [infrastructure-design.md](../terraform/infrastructure-design.md) | terraform/modules/soar/eventbridge.tf의 Security Hub 및 제한된 GuardDuty→asr_trigger; lambda_src/asr_trigger/handler.py에서 whitelist·ENABLE_AUTO 검사. SG branch에는 AutoRemediation=enabled 태그 검사가 추가되고 IAM key branch에는 이 태그 검사가 없음. 직접 SSM 실행 코드 존재 | 부분 구현 | 미실행 |
| SOAR-02 | 자동조치 이력과 SSM 결과 추적 | [README.md §6](../README.md), [glossary.md](glossary.md) | modules/soar/storage.tf의 remediation action 테이블, lambda_src/asr_trigger/handler.py의 기록·SSM 실행 ID, eventbridge.tf의 SSM terminal event→같은 handler 연결. _safe_record가 저장 실패를 기록만 하고 실행/알림을 계속할 수 있음. 자동 실행마다 SSM ID별 새 행을 생성해 동일 이벤트 중복 실행은 별도 억제되지 않음 | 부분 구현 | 미실행 |
| SOAR-03 | IP 차단 NACL 수동 SSM 경로 | DEC-007·DEC-008, [honeypot-design.md](../honeypot/honeypot-design.md), [security-scenarios.md §4](security-scenarios.md) | modules/soar/ssm.tf에 ASR-BlockIpWithNacl 등록, documents/ASR-BlockIpWithNacl.yaml에 담당자 승인 절차, IPv4 /32, 규칙 1–99, 최대 10개 검사. asr_trigger handler에서 해당 문서를 호출하는 분기는 확인되지 않았고 만료 자동 해제도 확인되지 않음 | 부분 구현 | 미실행 |
| SOAR-04 | 수동 Nginx 강화·DB 비밀 회전 문서 | DEC-006, [honeypot-design.md](../honeypot/honeypot-design.md), [security-scenarios.md §6.2](security-scenarios.md) | modules/soar/ssm.tf에서 ASR-HardenNginx Command와 ASR-RotateDbSecret Automation 등록. lambda.tf가 Nginx 문서 이름을 환경변수로 전달하지만 asr_trigger handler에서 Nginx 호출 분기는 없음. docker-host Compose는 80 포트 연결이며 Nginx 문서는 443 및 인증서 mount 부재 경고를 출력 | 부분 구현 | 미실행 |
| SOAR-05 | 재검증을 실행 성공과 분리 | [dashboard-design.md §수동 조치](../dashboard/dashboard-design.md), [glossary.md](glossary.md) | EventBridge 문서 주석은 SSM terminal 결과가 실행 이력이며 동일 조건 재검증은 아님을 명시. dashboard worker/provider는 별도 verify 작업을 표현하지만 실제 measure 공급자는 비활성 | 부분 구현 | 미실행 |

## 5. SEC-01~SEC-10 시나리오 추적

요구 출처는 기존 자료인 ../../honeypot/SEC-01-10_공격시뮬레이션_조치검증_가이드.md와 사용자 확정 DEC-004~DEC-006을 포함한다. 코드 경로가 있다는 뜻과 시나리오가 실제 실행·통과되었다는 뜻을 구분한다.

| 요구 ID | 출처·요구사항 | 설계 위치 | 실제 코드 경로와 정적 근거 | 구현 | 검증 |
|---|---|---|---|---|---|
| SC-SEC-01 | SSH 공개 구성 평가와 GuardDuty 행동 탐지를 혼합하지 않음 | [security-scenarios.md §6.1](security-scenarios.md) | modules/security/config.tf의 restricted_ssh 및 restricted_common_ports 규칙; Security Hub 연동. GuardDuty 공격 행동은 별도 SC-SEC-06B 참조 | 완료 | 미실행 |
| SC-SEC-02 | Nginx HTTP·헤더·TLS 강화는 수동 경로 | [security-scenarios.md §6.2](security-scenarios.md), DEC-006 | modules/soar/documents/ASR-HardenNginx.yaml 및 modules/compute/templates/docker-host.sh.tftpl. SSM command는 등록되나 trigger 연결·컨테이너 443 mount 미완성 | 부분 구현 | 미실행 |
| SC-SEC-03 | 시연 MySQL 3306 자동/수동 SG 대조 | [security-scenarios.md §6.3](security-scenarios.md), DEC-004 | modules/network/sg.tf의 db_auto/db_manual 및 conditional attacker ingress, modules/security/config.tf, modules/soar/eventbridge.tf, lambda_src/asr_trigger/handler.py, documents/ASR-RevokeSecurityGroupIngress.yaml | 완료 | 미실행 |
| SC-SEC-04 | Inspector/ECR/Trivy 이미지 취약점 확인 | [security-scenarios.md §6.4](security-scenarios.md) | modules/security/inspector.tf, modules/compute/ecr.tf, modules/soar/documents/SCAN-ContainerImage.yaml, demo/run-manual-scan.sh. Inspector→finding_sync/DynamoDB는 연결; Trivy 결과의 대시보드·자동 처리 연결은 확인되지 않음 | 부분 구현 | 미실행 |
| SC-SEC-05 | IAM 자격 증명 finding의 조건부 키 비활성화 | [security-scenarios.md §6.5](security-scenarios.md) | modules/security/access_analyzer.tf·guardduty.tf, modules/soar/eventbridge.tf의 IAM finding 필터, lambda_src/asr_trigger/handler.py의 key branch, documents/ASR-DisableExposedAccessKey.yaml | 완료 | 미실행 |
| SC-SEC-06A | DEC-005: MySQL Hydra 인증 실패는 CloudWatch로 검증 | [security-scenarios.md §6.6A](security-scenarios.md) | modules/compute/templates/mysql-db.sh.tftpl → modules/soar/cloudwatch.tf 로그 그룹/metric filter/alarm/SNS 경로. Hydra 실행·실제 로그 도착은 미검증 | 완료 | 미실행 |
| SC-SEC-06B | DEC-005: SSH Hydra 공격은 GuardDuty로 검증 | [security-scenarios.md §6.6B](security-scenarios.md) | modules/security/guardduty.tf, modules/soar/eventbridge.tf의 전체 GuardDuty→correlator 경로. 특정 Hydra finding 실발생과 ASR 전달은 확인되지 않음; IAM-only gd_to_asr 필터 확인 | 부분 구현 | 미실행 |
| SC-SEC-07 | 비밀정보 노출 확인과 안전한 회전 | [security-scenarios.md §6.5·7](security-scenarios.md) | modules/compute/secrets.tf와 modules/soar/documents/ASR-RotateDbSecret.yaml, ssm.tf 등록. 명시적 소스 비밀 스캔과 trigger handler 호출 연결은 확인되지 않음 | 부분 구현 | 미실행 |
| SC-SEC-08 | DVWA SQLi/ZAP 및 WAF 반응 | [security-scenarios.md §6.8](security-scenarios.md), DEC-004 | modules/compute/alb.tf의 DVWA :8081과 WAF SQLi 규칙, modules/soar/cloudwatch.tf WAF alarm, eventbridge.tf waf_alarm_to_finding, lambda_src/waf_finding/handler.py. 공격·차단 결과 실증 없음 | 완료 | 미실행 |
| SC-SEC-09 | CloudTrail·Config·VPC Flow Logs·서비스 로그 수집 | [security-scenarios.md §6.9](security-scenarios.md) | modules/security/cloudtrail.tf·config.tf, modules/network/flowlogs.tf, compute templates의 CloudWatch Agent 구성. 조건 토글 및 AWS 전달 상태 미검증 | 완료 | 미실행 |
| SC-SEC-10 | CPU·메모리·WAF 지표와 알림 | [security-scenarios.md §6.10](security-scenarios.md) | modules/soar/cloudwatch.tf의 CPU·MemoryUsedPercent·WAF alarms와 SNS 연결, compute templates의 Agent 설치/설정. 실제 metric·SNS 수신 미검증 | 완료 | 미실행 |

## 6. AI 허니팟·운영·검증·문서

| 요구 ID | 출처·요구사항 | 설계 위치 | 실제 코드 경로와 정적 근거 | 구현 | 검증 |
|---|---|---|---|---|---|
| HNY-01 | DEC-008: AI 허니팟 목표 범위, 세부 기술과 자동 차단 미결정 | [honeypot-design.md](../honeypot/honeypot-design.md), [decisions.md §DEC-008·OPEN-011](decisions.md) | 실제 프로젝트의 파일 목록·내용 검색에서 honeypot, decoy, Beelzebub 등 구현 경로를 찾지 못함. 기존 공격 검증 가이드는 시뮬레이션 자료이지 허니팟 구현 증거가 아님 | 미구현 | 미실행 |
| OPS-01 | 로그·finding·작업·감사 보존 및 만료 정책 | [README.md §6](../README.md), [decisions.md §OPEN-008·014](decisions.md) | modules/soar/variables.tf에 finding/action history TTL 기본 30일, finding_sync.tf DLQ 14일, cloudwatch.tf의 로그 보존 변수가 있음. 설정값은 기존 코드 기본값이며 승인된 보존 정책은 아님 | 부분 구현 | 미실행 |
| OPS-02 | 비용 추정·비용 운영 | [infrastructure-design.md](../terraform/infrastructure-design.md), [README.md §6](../README.md) | terraform/docs/비용예측.md와 기능 토글·비용 리소스 구성 확인. 실제 예산·청구·장기 비용 검증 기록은 확인되지 않음 | 부분 구현 | 미실행 |
| TEST-01 | 설계 계약과 검증 기준의 자동·수동 시험 | [dashboard-design.md §검증](../dashboard/dashboard-design.md), [security-scenarios.md §7](security-scenarios.md) | dashboard/backend/tests, dashboard/frontend/tests 및 modules/soar/lambda_src/test_*.py 파일 존재. dashboard/backend/docs/VERIFICATION.md는 커버 범위와 AWS 미포함 제한을 명시. 이번 검토에서 test 명령을 실행하지 않음 | 부분 구현 | 미실행 |
| TEST-02 | 시나리오 실행·정리 보조 스크립트 신뢰도 | [security-scenarios.md §7](security-scenarios.md) | terraform/demo/trigger-auto-remediation.sh는 SG 3306/0.0.0.0/0 변경 후 Security Hub 형식 payload를 Lambda에 직접 전달해 EventBridge 실연결을 우회. demo/verify-controls.sh는 연결 실패·HTTP 코드만으로 PASS가 될 수 있고 curl -k 사용. demo/cleanup.sh는 해당 규칙만 회수 시도 | 부분 구현 | 미실행 |
| EVID-01 | 요구·행위·조치·재검증 증거의 연결 | [README.md §8](../README.md), [security-scenarios.md §7](security-scenarios.md), [glossary.md §7](glossary.md) | terraform/docs/증적양식.md, modules/soar action-history DynamoDB, EventBridge SSM terminal result, dashboard/backend history contracts 확인. 자동 이력 write는 실패해도 조치가 계속될 수 있고 실환경 증거 없음 | 부분 구현 | 미실행 |
| DOC-01 | 문서 구조·링크·버전 추적 | [README.md §7–8](../README.md), [agents.md](../agents.md), [decisions.md](decisions.md) | 설계 문서는 루트와 기능별 폴더에 배치되고, AI 지침은 루트와 `.github/`에 있다. 이전 정적 링크 점검 이후 README 파일명 변경에 대한 링크 검증은 별도 수행한다. 커밋 SHA는 실제 커밋이 확인될 때에만 기록 | 완료 | 미실행 |

## 7. 주요 편차와 후속 작업 우선순위

| 우선순위 | 편차·결정 참조 | 확인된 영향 | 다음 추적 기준 |
|---|---|---|---|
| 높음 | DASH-05, DEC-003 | 승인·job·audit 저장소가 SQLite이며 목표 DynamoDB 저장과 다름 | DynamoDB 모델, 조건부 상태 갱신·멱등성·복구·마이그레이션이 연결되고 해당 통합 검증 증거가 생길 때 갱신 |
| 높음 | DASH-06, SOAR-05 | 대시보드 수동 실행·재검증 API는 있으나 실 AWS 실행·측정 Provider가 비활성 | 지원 문서·매개변수·권한·비밀 보호·원격 상태 조정과 동일 조건 재검증 연결을 확인 |
| 높음 | SOAR-01, SOAR-02, DEC-007 | SG와 IAM 자동 경로의 가드 차이, 실행 중복 가능성, 기록 실패 시 best-effort 동작 | 신규 확인 단계가 아니라 사용자 결정에 맞는 정책·대상·멱등성·감사 내구성 설계 완료 및 증거 |
| 높음 | HNY-01, DEC-008 | AI 허니팟 소스 미발견; 과거 프롬프트의 즉시 NACL 차단은 미결정 | 기술·데이터 처리·격리·차단·원복 정책 승인 및 새 코드 경로·실행 증거 |
| 중간 | DASH-01, OPEN-002 | Terraform dashboard ingress 기본 CIDR이 0.0.0.0/0이고 ALB listener는 HTTP | 실제 배포 변수, 사용자 인증, 네트워크 범위 및 외부 접속 확인 |
| 중간 | SC-SEC-06B, DEC-005 | SSH Hydra의 GuardDuty 탐지 경로 선택은 됐으나 finding 생성 결과가 없고 자동 ASR은 IAM finding으로 제한 | GuardDuty finding type·리소스·이벤트 조회·화면 연결 증거. 자동 대응 추가는 별도 결정 |
| 중간 | SC-SEC-02, SOAR-04, DEC-006 | Nginx 문서는 TLS·헤더를 구성하지만 443 port/cert mount 연결과 handler 호출이 미완성 | 수동 설정 후 서비스 응답·포트·인증서·헤더·원복 확인. HTTPS 전달 위치 결정 |
| 중간 | OPS-01, OPEN-008·009 | 코드의 기본 TTL·로그 보존·동기화 간격은 존재하지만 승인 정책이 아님 | 원천별 보존·신선도 기준과 소유자 결정, 설정 반영 및 삭제·장애 복구 증거 |

편차 우선순위는 설계·코드의 정적 위험을 기반으로 한 추적 순서이며, 실제 운영 심각도 평가가 아니다. DEC-003, DEC-007, DEC-008의 승인 내용은 그대로 유지한다. 자동조치 확인 단계를 추가하거나 AI 허니팟 자동 차단을 활성화하는 권한으로 해석하지 않는다.

## 8. 갱신 절차와 완료 조건

기능 변경을 완료할 때 담당자는 다음을 이 추적표에서 확인한다.

1. 기존 요구 ID 또는 새 ID에 출처와 결정 상태를 연결한다.
2. README.md 또는 기능 설계 문서의 정확한 절·계약 위치를 적는다.
3. 실제 코드 경로를 확인하고 각 요소가 선언만 되어 있는지, 호출·이벤트·데이터 연결까지 있는지 구분한다.
4. 구현 상태를 미구현·부분 구현·완료 중 하나로 갱신하고, 변경 대상이면 decisions.md의 구현 수정 대상·설계 갱신 대상·임시 예외 분류와 연결한다.
5. 검증 상태는 통합 또는 AWS 실환경 결과의 실제 증거가 있을 때만 승격한다. 실행하지 않은 테스트·배포·AWS 조치는 미실행으로 둔다.
6. API·데이터 계약, 상태 전이, 실패·복구, 보안 시나리오, 비용·운영 영향, 관련 링크를 점검한다.
7. 구현·검증 근거와 변경 설명을 실제 버전명 및 커밋 SHA에 연결한다. 제목은 DEC-009의 vN 또는 vN.M 형식만 사용한다.
8. 본문 내용이나 증거가 바뀌었을 때 확인 시점을 갱신한다. 날짜만 새로 쓰지 않는다.

현재 기준표의 모든 검증 상태는 미실행이다. 이는 코드 경로가 없다는 뜻이 아니라 이 기준 작성 시점에 동작 검증 근거를 확인하지 못했다는 뜻이다.
