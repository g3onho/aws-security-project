# 보안 관제 화면

`../backend/`가 HTML과 정적 자산을 제공합니다. `static/js/store.js`는 표준 API(`/api/events`, `/api/summary`, `/api/metrics`, `/api/vulnerabilities`, `/api/infra/status`, `/api/history`)를 호출합니다. 인증은 `/api/auth/*`를 사용합니다. Store가 `{data, meta}` 응답, UTC ISO 시각, 커서 페이지네이션을 처리합니다.

Store 구조(v20.3, 설계 2.1·2.2): 화면(`app.js`)은 `store.actions`·`store.selectors`만 사용합니다.

- `store/api/client.js`: fetch·CSRF·시간 제한 30초. **GET만** 429·502·503·504·네트워크 오류를 최대 3회 지수 백오프+지터로 재시도, 변경 요청은 재시도하지 않음
- `store/api/endpoints.js`·`validators.js`: API 경로, 응답 계약 검증(해석할 수 없는 응답은 빈 목록으로 바꾸지 않고 오류)
- `store/adapters/`: DTO → 화면 모델(순수 함수). 잘못된 행만 빼고 건수를 경고로, 모르는 심각도는 UNKNOWN
- `store/state.js`·`selectors.js`·`actions.js`: 상태, 읽기, 요청·필터 변경(`setFilters`)
- `store/polling.js`: 자동 새로고침 타이머 하나, 탭이 숨으면 정지

화면 구조(v20.4, 설계 2.1): `static/js/` 바로 아래에는 시작점 `app.js`와 Store 입구 `store.js`만 둡니다.

- `ui/context.js`: Store 연결(화면 모듈 중 유일하게 `store.js`를 불러옴), 화면 전용 상태, `render`·`refresh` 연결
- `ui/pages/`: 통합 관제·이벤트·취약점·인프라·대응 이력·로그인(설계 지침 2장 화면 목록)
- `ui/components/`: 서식·배지·패널·상세 창·상태 바로가기·CSV·레이아웃 애니메이션 등 공통 부품
- `ui/charts/charts.js`: Chart.js 생성·갱신·제거
- `ui/map/`: 지구본 계산(`globe.js`)·조작(`interaction.js`)·관제 지도 화면(`view.js`)
- `ui/router.js`: 주소창 ↔ 필터·열린 이벤트

`static/js/ui/constants.js`에는 리전 지리 좌표와 화면용 열거값만 있습니다. 이벤트, 자원 ID, 공격 출발지, 취약점, 지표는 API에서 받아야 합니다.

현재 데이터 소스는 미연결 상태입니다. 로그인 후 오류 안내와 재시도 버튼을 표시하고 가상의 탐지 건수·지표·조치 성공 결과를 만들지 않습니다.

이벤트 상세는 표준 목록 응답이 제공하는 필드만 보여줍니다. 조치 공급자는 비활성화되어 화면은 읽기 전용입니다.

## 실행

[프로젝트 설치 안내](../README.md)를 따른 뒤 `start-dashboard.cmd`를 실행합니다. 접속 주소는 http://127.0.0.1:5051 입니다.

## 검사

```powershell
node --test tests/*.test.mjs tests/v2.1-projection-check.mjs
```

DOM 검사에는 jsdom이 필요합니다. 테스트의 고정 입력과 네트워크 대역은 회귀 검사 전용입니다. 실제 서버가 읽거나 배포 자산으로 제공하지 않습니다.

지도 경계 자료는 Natural Earth, 차트는 Chart.js를 사용합니다. 라이선스는 `static/vendor/`에 보존합니다.
