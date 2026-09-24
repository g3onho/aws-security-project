# 보안 관제 백엔드

Flask·Waitress와 SQLite를 사용합니다. 패키지는 `soar`입니다. 인증, CSRF, 역할 검사, API 계약, 저장소 및 조치 상태 전이 구조를 유지합니다.

## 현재 연결 상태

기본 `DATA_PROVIDER=none`에서는 `UnconfiguredProvider`가 데이터 조회와 조치 요청을 503으로 거부합니다. `DATA_PROVIDER=aws`로 설정하면 `AwsProvider`가 STS 자격 증명을 확인하고 Security Hub, EC2, CloudWatch CPU, Inspector 결과를 읽기 전용으로 조회합니다. 앱 시작 시 운영 데이터를 생성하거나 적재하지 않습니다.

- `/health`: 프로세스 생존 상태와 `dataSourceConnected: false`
- `/api/auth/*`: 계정 로그인·로그아웃·세션·CSRF
- 표준 데이터 API와 화면 데이터 API: 연결 전 503
- `DATA_PROVIDER=aws`: `AWS_REGION`에서 AWS 보안·자원·지표 결과를 읽기 전용 조회
- `EVENT_SOURCE`(`securityhub`|`dynamodb`)·`VULNERABILITY_SOURCE`(`inspector`|`dynamodb`)·`FINDINGS_TABLE`·`VULNERABILITIES_TABLE` (v21): 탐지·취약점을 AWS에서 직접 조회할지, `modules/soar` finding_sync Lambda가 적재한 DynamoDB에서 읽을지. 기본값은 직접 조회. `dynamodb`를 고르면 해당 테이블 이름이 필수(없으면 기동 실패). 적재에서 읽을 때 `meta.asOf`는 마지막 대조 시각, 20분 넘은 지연·실패·건수 불일치는 `meta.warnings`. 배포(Terraform)는 `dynamodb`가 기본
- `REMEDIATION_ACTIONS_TABLE`·`CORRELATED_FINDINGS_TABLE`: Terraform `modules/soar`의 DynamoDB 테이블. 자동조치 판정 기록을 `/api/history`(source=automatic)에, 상관분석 위험도 상향을 이벤트에 붙인다. 없으면 `meta.warnings`로 알림
- 쓰기는 기본 비활성화. 환경변수만 켜도 공급자 없이 실행할 수 없음

`standard_api.py`는 HTTP 경계, `contracts.py`는 조회 계약·집계, `integrations/aws/`는 boto3 호출·페이지 처리·캐시, `repositories/`는 AWS 원본을 도메인 자료로 바꾸는 변환, `provider.py`는 이 둘을 조립하는 공급자, `workflow.py`는 승인·멱등성·작업 접수, `worker.py`는 공급자 결과를 저장하는 처리 구조입니다. `scope.py`의 계정·리전·자원 접근 범위 판정을 모든 표준 API에 적용합니다. 실제 조치·재검증 공급자 구현은 후속 작업입니다.

## 설치·실행

[프로젝트 안내](../README.md)를 따릅니다. `start-dashboard.cmd` 또는 `../frontend/start-dashboard.cmd`로 실행합니다. 별도 워커 명령은 공급자 연결 전 오류로 종료합니다.

| 설정 | 기본값 |
|---|---|
| `DASHBOARD_INSTANCE` | 이 폴더의 `instance/` |
| DB 파일 | `dashboard.sqlite3` |
| `DATA_PROVIDER` | `none` |
| `AWS_REGION` | `ap-northeast-2` |
| `WRITE_ENABLED` | `false` |
| `FLASK_SECRET_KEY` | 로컬 `session.key` |
| 포트 | 5051 |

현재 계정은 유지했으며 운영 데이터는 비어 있습니다. 새 계정의 계정 접근 범위는 빈 목록입니다. 실제 데이터 연결 시 접근 범위를 명시적으로 설정해야 합니다.

## 검증

`python tools/check.py`는 Python 검사와 프런트엔드 Store 계약 검사를 실행합니다. Python 검사는 미연결 오류, 무적재 시작, 권한·CSRF·로그아웃, 조치 차단과 정적 자산 제공을 확인합니다. 테스트 입력은 운영 DB에 적재하지 않습니다.

Terraform 작업과 서버 배포 직전 확인 항목은 프로젝트 루트의 `DEPLOYMENT_CHECKLIST.md`를 참고하세요.
