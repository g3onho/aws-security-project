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

실제 데이터 수집·원격 조치·운영 부하 검증은 포함하지 않습니다.
