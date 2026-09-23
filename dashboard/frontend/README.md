# 보안 관제 화면

`../backend/`가 HTML과 정적 자산을 제공합니다. `static/js/store.js`는 서버 API를 호출하는 단일 클라이언트이며, 화면 호출을 `/api/legacy/*`에 연결합니다. 인증은 `/api/auth/*`를 사용합니다.

`static/js/data.js`에는 리전 지리 좌표와 화면용 열거값만 있습니다. 이벤트, 자원 ID, 공격 출발지, 취약점, 지표는 API에서 받아야 합니다.

현재 데이터 소스는 미연결 상태입니다. 로그인 후 오류 안내와 재시도 버튼을 표시하고 가상의 탐지 건수·지표·조치 성공 결과를 만들지 않습니다.

## 실행

[프로젝트 설치 안내](../README.md)를 따른 뒤 `start-dashboard.cmd`를 실행합니다. 접속 주소는 http://127.0.0.1:5051 입니다.

## 검사

```powershell
node --test tests/*.test.mjs tests/v2.1-projection-check.mjs
```

DOM 검사에는 jsdom이 필요합니다. 테스트의 고정 입력과 네트워크 대역은 회귀 검사 전용입니다. 실제 서버가 읽거나 배포 자산으로 제공하지 않습니다.

지도 경계 자료는 Natural Earth, 차트는 Chart.js를 사용합니다. 라이선스는 `static/vendor/`에 보존합니다.
