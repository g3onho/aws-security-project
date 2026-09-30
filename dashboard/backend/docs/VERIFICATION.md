# 검증 범위

2026-09-23 변경 기준입니다.

- 시작·재시작 시 운영 데이터가 자동 적재되지 않음
- 공급자 미연결 조회가 명시적인 503을 반환함
- 연결 없이 조치·워커 실행 불가
- 계정 로그인·CSRF·로그아웃·인증 없는 API 차단
- 실제 프런트엔드 파일과 Store 제공
- 화면 미연결 안내, 이전 내용 유지, 비동기 응답 순서 처리
- DOM·지도·다운로드·작업 감시 회귀 검사

2026-09-28 v23 변경(화면 개편·탐지 설명·자동 조치 표시) 추가 검사:

- 탐지 설명표 항목 완결성, 규칙 ID·GuardDuty 유형 추출, AWS 조치 링크 https 한정 (`tests/test_guidance.py`)
- 자동 조치 판정 예상이 asr_trigger·lambda.tf·eventbridge.tf 목록과 일치, 설정이 없으면 `unknown` (`tests/test_guidance.py`)
- 조치 이력의 판정 이유·SSM 보고값(전/후, `verification=NOT_RUN`)·요청당 SSM 조회 제한·GuardDuty 짧은 ID 연결·`NO_CHANGE` (`tests/test_detail_views.py`)
- 인프라 3계층 `unknown`, 경보 `noData`·범위 필터·읽기 실패 경고, 통합 관제 자동 대응 요약 (`tests/test_detail_views.py`)
- DynamoDB 적재 조회와 AWS 직접 조회의 설명·조치 필드 동등성 (`tests/test_stored_sources.py`)
- 화면: 탐지 상세·조치 이력·인프라·취약점·통합 관제 (`frontend/tests/detail-*.test.mjs`, `history.test.mjs`)


2026-09-29 v25 변경(허니팟 화면·차단 IP 관리) 추가 검사:

- 세션 로그 해석: 형식 위반·위조 세션 ID 건너뛰기, 문자열 길이·허용 값 제한, 비밀번호 비집계, 그래프 상한 (`tests/test_honeypot.py`)
- 동작 상태 판정(ok·waiting·partial·unknown·not_deployed), 읽지 못한 원천은 unknown, 범위 제한 계정 차단 (`tests/test_honeypot.py`)
- 차단 목록: 표와 NACL 대조(불일치 4종·기록 없음·적용 중), NACL 읽기 실패 경고, CSV 수식 주입 방지 (`tests/test_honeypot.py`)
- 해제·기간·예외: 권한(operator만)·`WRITE_ENABLED`·CSRF·`Idempotency-Key`·`expectedVersion`, 재시도·응답 유실 재시도, SSM 시작 실패 되돌림, 동시 변경, 잘못된 IP·본문 (`tests/test_honeypot.py`)
- openapi.yaml 과 실제 라우트 8개의 일치 (`tests/test_honeypot.py`)
- 화면: 정상 흐름(차트 6·그래프·재생·해제·기간·예외·보고서), 악성 입력 이스케이프, 읽기 전용 계정, 부분 실패, 미배포 (`frontend/tests/honeypot*.test.mjs`)
- Lambda·SSM 문서: `test_block_expiry.py`, `test_auto_remediation.py`(차단 기록·오탐 예외), `test_asr_documents.py`(ASR-UnblockIpWithNacl)

2026-09-29~30 v26~v37 변경(AI 도우미·원클릭 조치·3계층 상태·전부 실행·허니팟 AI) 테스트 파일이 다루는 범위입니다. 이 문서 작성 시 실행 결과는 확인하지 않았습니다.

- AI 도우미: 도구가 읽기 전용, 알 수 없는 도구·쓰기 도구 호출 거부, 비밀 필드 제거, 공격자 문자열은 신뢰할 수 없는 데이터로 전달, 도구 호출·출력 상한, 잘못된 메시지는 모델 호출 전에 거부 (`tests/test_assistant.py`)
- 화면별 AI 보고서: 숫자를 서버가 집계, 조회 범위·31일 창, 비밀번호 비포함, 모르는 화면 400, 비활성 503, TTL 안 캐시 (`tests/test_report.py`)
- 원클릭 조치: 서버가 계획 생성, viewer 실행 불가, `WRITE_ENABLED` 차단, 멱등 재시도, 이미 충족은 미실행, SSM 성공만으로 해결 처리하지 않음, 재검증 읽기 실패는 통과가 아님, 태그 없는 SG·다른 리전 차단, 진행 중 중복 실행 거부 (`tests/test_remediation.py`)
- 3계층 상태: 오래됐거나 읽지 못한 행은 `unknown`이며 정상으로 표시하지 않음, 읽기 실패 경고에 내부 오류 비노출 (`tests/test_tier_status.py`)
- 전부 실행: 항목별 실행 분배, 지리 설정 없음·미끼 미탐색 시 건너뜀, 이전 실행이 진행 중이면 거부하고 끝났거나 방치되면 허용, 응답 없는 실행 시간 초과 표기, 허니팟 접속 시연의 출발지·대상 (`tests/test_drills_run_all.py`)
- 허니팟 AI: 성공·실패·기록 없음에 따른 카드 판정, 악성 필드 정리, `converse` 호출과 실패 시 오류 클래스만 기록, 셸이 아닌 문장은 FALLBACK, 분석 JSON 재시도 후 규칙 판정, 명령 없는 세션은 Bedrock 미호출 (`tests/test_honeypot_ai_card.py`, `tests/test_honeypot_ai_client.py`)

실제 데이터 수집·원격 조치·운영 부하 검증은 포함하지 않습니다.
