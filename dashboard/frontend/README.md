# 보안 관제 화면

`../backend/`가 HTML과 정적 자산을 제공합니다. `static/js/store.js`는 표준 API(`/api/events`, `/api/summary`, `/api/metrics`, `/api/vulnerabilities`, `/api/infra/status`, `/api/history`)를 호출합니다. 인증은 `/api/auth/*`를 사용합니다. Store가 `{data, meta}` 응답, UTC ISO 시각, 커서 페이지네이션을 처리합니다.

`static/js/data.js`에는 리전 지리 좌표와 화면용 열거값만 있습니다. 이벤트, 자원 ID, 공격 출발지, 취약점, 지표는 API에서 받아야 합니다.

현재 데이터 소스는 미연결 상태입니다. 로그인 후 오류 안내와 재시도 버튼을 표시하고 가상의 탐지 건수·지표·조치 성공 결과를 만들지 않습니다.

침해사례 탭은 실제 이벤트를 시나리오별로 묶어 보여줍니다. 시나리오 배선·공격 재현 절차·조치 계획 등 표준 API에 없는 정보는 표시하지 않습니다. 이벤트 상세는 표준 목록 응답이 제공하는 필드만 보여줍니다. 조치 공급자는 비활성화되어 화면은 읽기 전용입니다.

## 실행

[프로젝트 설치 안내](../README.md)를 따른 뒤 `start-dashboard.cmd`를 실행합니다. 접속 주소는 http://127.0.0.1:5051 입니다.

## 검사

```powershell
node --test tests/*.test.mjs tests/v2.1-projection-check.mjs
```

DOM 검사에는 jsdom이 필요합니다. 테스트의 고정 입력과 네트워크 대역은 회귀 검사 전용입니다. 실제 서버가 읽거나 배포 자산으로 제공하지 않습니다.

지도 경계 자료는 Natural Earth, 차트는 Chart.js를 사용합니다. 라이선스는 `static/vendor/`에 보존합니다.
