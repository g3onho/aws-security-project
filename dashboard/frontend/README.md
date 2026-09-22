# AWS Security Operations — 프론트엔드 데모

**현재 버전: v2.6.0.** 기존 차콜·민트 디자인을 유지하고 17개 리전, 공격 IP 연결선, 지도 드래그·휠 확대/축소, 약한 입체 표현을 구현했습니다. v2.3.0 에서 인프라 모니터링의 시간축·3계층 연동·표 내 조치 동선을 보완했고, v2.4.0 에서 침해사례 탭을, v2.5.0 에서 취약점 점검 실데이터화와 인프라 전체 서버 표시를 추가했습니다. [버전 정의](VERSIONS.md) 및 [v2.0 검증 기록](VERIFICATION-v2.md)을 참조하세요. 이전 v1.0 소스는 `../releases/v1.0-source.zip`에 보관했습니다.

## v2.0 지도 사용법

- 서울이 기본 선택입니다. 상단 리전 메뉴에서 17개 리전 또는 전체/글로벌을 선택합니다.
- 지도 위에서 휠로 1~4배 확대·축소하고, 확대 후 드래그 또는 방향키로 이동합니다. 초기화 버튼은 전체 지도 위치와 1배 배율로 돌아갑니다.
- 지도 위의 ‘전체 공격 흐름’ 메뉴로 특정 IP/이벤트를 선택합니다. 선 또는 출발 위치를 클릭하거나 키보드로 선택하면 이벤트 상세가 열립니다.
- 연결선은 현재 지역·환경·시간·검색·위험도·상태·탐지 소스 필터를 따릅니다. 상단 검색에서 출발 IP도 검색할 수 있습니다.
- 주황색 방향선은 **공격 출발 IP → 대상 AWS 리전** 관계입니다. 실제 인터넷 라우팅 경로를 표현하지 않습니다. 예시 IP와 도시 좌표는 모두 모의 데이터입니다.
- 위치 미상·사설 IP에는 선을 그리지 않고 건수 및 이벤트 상세에 그 이유를 표시합니다. 글로벌 이벤트에는 임의 좌표를 부여하지 않습니다.
- 지도는 국가 경계·마커·연결선 끝점을 같은 곡면 투영에 배치하고 음영을 더한 2.5D 표현입니다. 회전형 3D 지구본은 아닙니다.
- 색상 비교 샘플 A~G는 참고 자료로만 보존했습니다. 실행 화면에는 적용하지 않았습니다.

시연: 기본 화면의 `EVT-0005`는 위치가 있는 공격, `EVT-0013`은 위치 미상 공격입니다. 7일 범위에서 `10.0.0.8`을 검색하면 사설 IP 예시를 확인할 수 있습니다.

사진의 지도 중심 구도, 차콜 패널, 청록색 원형 파동과 영상의 지도 이동·지역 패널 전환을 재현한 관제 화면입니다. 기존 Terraform의 `run.py` 진입점과 Flask 방향에 맞춰 별도 앱으로 작성했습니다. Terraform과 실제 AWS 설정은 변경하지 않았습니다.

## 실행

> **서버 코드는 `../backend/` 로 옮겼습니다.** 이 폴더에는 화면 자산(templates / static / tests)만 남습니다.
> `start-dashboard.cmd` 와 `requirements.txt` 는 기존 절차를 깨지 않도록 backend 쪽으로 위임하는 포인터로 남겨두었습니다.

이 Windows PC에서는 **`start-dashboard.cmd`를 더블클릭**하면 설치된 Codex Python 실행 환경을 찾아 로컬 서버를 시작합니다. 실행 창을 닫으면 서버가 종료됩니다. 이미 미리보기가 실행 중이면 아래 브라우저 주소로 바로 접속하세요.

Python 3.10 이상에서 실행합니다.

```powershell
cd ..\backend
python -m pip install -r requirements.txt
python run.py
```

이 폴더에서 `python -m pip install -r requirements.txt` 를 실행해도 backend 의 의존성이 설치됩니다.

브라우저: http://127.0.0.1:5000

포트 변경: `python run.py --port 5050`

Flask가 설치되지 않았으면 같은 명령이 Python 내장 서버로 프론트엔드를 표시합니다. 내장 서버는 로컬 UI 확인용이며 `/health` 라우트는 Flask 실행 시에만 제공합니다. 서버는 로컬 주소에만 바인딩합니다. 별도 Node 빌드, 외부 CDN, 지도 API 키 없이 실행됩니다. HTML 파일을 더블클릭하는 방식은 모듈과 지도 fetch 때문에 지원하지 않습니다.

## 화면과 조작

- 통합 관제: 리전 지도, 우측 상세, 시간 구간, CPU·메모리·해결률, 탐지 소스, 위험도, 최근 이벤트와 승인 대기.
- 보안 이벤트: 근거, 자원, 권장 조치와 시나리오를 확인하는 전체 목록.
- 취약점 점검: 현재 필터에 포함된 Trivy·Inspector 항목.
- 인프라 모니터링: 선택한 리전의 CPU·메모리와 80% 임계선, Nginx → Flask → MySQL 데모 상태.
- 대응 이력: 승인 대기 또는 실행 이력이 있는 이벤트, 실행 결과와 재검증 결과.

지역·환경·검색·위험도·상태·탐지 소스·시간 조건이 집계와 이벤트에 함께 적용됩니다. 지도는 지역 비교를 위해 현재 지역 조건만 제외한 나머지 동일 필터로 모든 리전을 표시합니다. 우측 패널과 하단 집계는 선택 지역을 사용합니다. 글로벌 IAM 이벤트에는 좌표를 부여하지 않습니다.

CPU·메모리는 보안 이벤트 개수가 아닌 자원 시계열이므로, 리전·환경·시간에 연결되며 이벤트의 위험도·상태·소스 검색에 따라 바뀌지 않습니다. 전체 리전 또는 글로벌을 선택하면 임의 평균을 만들지 않고 EC2 데이터 없음을 표시합니다. 게이지는 선택 구간 종료 시점의 지표입니다.

시간 프리셋은 구간 길이를, 슬라이더는 구간의 종료 시각을 변경합니다. 재현 가능한 고정 기준 시각은 **2026-09-18 15:00 KST**입니다. 새로고침은 현재 데모 상태를 다시 표시하며, 브라우저 페이지 새로고침 시 원본 데모 데이터로 복원됩니다. 조치 이력은 메모리에만 보관하며 실제 수행 시각을 기록합니다.

## 대응 시연

1. 기본 서울 / Production / 24시간 상태에서 `EVT-0003`을 검색합니다.
2. MySQL 이벤트를 열고 **조치 검토 및 승인**을 선택합니다.
3. **취소**하면 상태가 그대로 유지됩니다.
4. 승인 후 실행이 끝나면 **재검증 대기**가 됩니다. 아직 해결이 아닙니다.
5. **동일 기준 재검증**을 누르면 통과 및 해결로 바뀝니다.
6. `EVT-0004`의 Trivy 항목을 같은 순서로 실행하면 12개 → 2개가 남아 **재검증 실패**가 됩니다.

자동 대응 이벤트도 실제 AWS 작업 없이 버튼으로 상태 전이를 시연합니다. 실서비스의 자동 실행 스케줄러는 포함하지 않습니다. 데모에서는 Inspector 등 일부 원본 탐지 항목의 예시를 정규화해 표현했습니다. 모든 숫자는 실제 AWS 측정값이 아닙니다.

## 파일 구성

| 파일 | 역할 |
|---|---|
| `../backend/run.py` | Flask 앱 팩토리, HTML 라우트, health, 로컬 미리보기 fallback |
| `../backend/app/` | API 블루프린트, 시나리오 카탈로그, 데모·실 AWS 어댑터, 게이트 |
| `start-dashboard.cmd` | `../backend/start-dashboard.cmd` 로 위임하는 런처 |
| `templates/index.html` | 공통 페이지와 접근성 레이블 |
| `static/css/app.css` | 반응형 스타일과 지도·패널 모션 |
| `static/css/tailwind.css` | 미리 생성한 Tailwind CSS |
| `static/js/data.js` | 고정 이벤트, 리전 위치, 데모 자원 시계열 |
| `static/js/store.js` | 공통 필터, 데이터 어댑터, 대응 상태 전이, CSV 직렬화 |
| `static/js/app.js` | 지도 SVG, Chart.js, 메뉴·상세·필터 상호작용 |
| `static/js/map.js` | 공통 곡면 투영, 입체 음영, 공격 곡선, 드래그·휠·키보드 지도 조작 |
| `static/data/countries.geojson` | 로컬 국가 경계 지도 |
| `static/vendor/` | 버전 고정 라이브러리와 라이선스 |
| `tests/browser-check.cjs` | 실제 브라우저 기능·반응형 검증 |
| `screenshots/` | 화면 크기별 캡처와 검증 결과 |

## 실제 API 연결 지점

`static/js/store.js`의 `api.load`, `api.execute`, `api.verify`가 교체 지점입니다. **프론트엔드는 아직 실제 API 요청을 하지 않습니다.**

다만 백엔드는 이미 붙어 있습니다. `../backend/` 가 `/api/*` 를 제공하고, 데모 모드에서는 `data.js` 와 **이벤트 단위로 동일한 데이터**를 냅니다(`backend/tests/test_demo_parity.py` 가 Node 로 대조). 명세는 `docs/backend/03-api-spec.yaml`, 필드 대응은 `docs/backend/01-frontend-as-is.md` §3 에 있습니다.

주의: API 는 상태·위험도·대응 방식을 **영문 enum**으로 내려줍니다(`NEW`, `CRITICAL`, `AUTO` …). 화면 국문 문자열로의 변환은 프론트 어댑터가 맡습니다. CSV 는 국문 그대로입니다.

아래는 프론트가 소비해야 할 엔드포인트입니다:

v2.0 추가 데이터 필드: `sourceIp`(문자열 또는 null), `sourceLocation`({city, lon, lat, provenance} 또는 null), `geoStatus`. 위치 데이터는 백엔드에서 정규화해 전달해야 하며, 프론트엔드는 실제 GeoIP 서비스를 호출하지 않습니다. 국가 경계·리전·연결선의 좌표 변환은 `map.js`의 `project`를 공통 사용합니다.

- `GET /api/events`: 탐지 이벤트, 처리 상태, 근거, 조치·재검증 이력.
- `GET /api/metrics?region=...&resource=...&from=...&to=...`: 실제 CPU·메모리 시계열.
- `POST /api/events/:id/approve`: 서버 측 권한 및 변경 대상 검증 후 승인.
- `POST /api/events/:id/execute`: 작업 ID 반환, 완료 상태 조회.
- `POST /api/events/:id/verify`: 동일 자원·검사 기준의 재검증 결과.

실행 성공은 해결 조건이 아니며, `execution`과 `verification`은 분리해야 합니다. 실제 연결 시 인증·권한 확인, 감사 기록, 중복 실행 방지와 작업 상태는 서버가 관리해야 합니다. AWS 자격 증명을 프론트엔드에 넣지 않습니다. 기존 Terraform의 `DEMO_MODE=false` 환경값만으로 이 앱이 실제 AWS에 연결되지는 않습니다. 현재 앱은 항상 데모입니다.

## 검증 및 제약

Chrome에서 1440×900, 1920×1080, 390×844를 확인했습니다. 상세 검증 결과는 `screenshots/verification.json`, 시각 검증 기록은 `VERIFICATION.md`에 있습니다. 화면은 키보드, native dialog의 포커스 제한·Escape 닫기, 텍스트 차트 요약, `prefers-reduced-motion`을 지원합니다.

테스트에는 Node.js, Playwright와 Chrome이 필요합니다. 이 작업 환경의 기본 경로를 테스트 파일에 명시해 두었으며, 다른 환경에서는 `PLAYWRIGHT_MODULE`, `CHROME_PATH` 환경변수를 설정하면 됩니다. 앱 서버를 먼저 실행한 뒤 `node tests/browser-check.cjs`로 검증합니다. 테스트 코드는 앱 실행에 필요하지 않습니다.

Tailwind 4.1.3의 로컬 컴파일 결과를 배포했으므로 브라우저에서 Tailwind 컴파일러를 실행하지 않습니다. 유틸리티 클래스를 추가했다면 앱 서버를 켠 상태로 `node tests/build-styles.cjs`를 실행해 CSS를 다시 생성할 수 있습니다.

현재 범위는 프론트엔드 데모입니다. 실제 탐지 수집, AWS 연결, 사용자 인증, 영속 저장, 실제 승인 권한 및 SOAR 실행은 미연동입니다. 인터넷 공개 배포는 수행하지 않았습니다.

## 출처 및 라이선스

- 지도: [Natural Earth 1:110m Admin 0 Countries](https://github.com/nvkelso/natural-earth-vector/blob/master/geojson/ne_110m_admin_0_countries.geojson), [Public domain 이용 조건](https://www.naturalearthdata.com/about/terms-of-use/). 다운로드한 원본을 로컬 보관하고 국가 경계만 SVG로 투영합니다. 경계는 관제 시각화용이며 법적 경계 판정 자료가 아닙니다.
- 차트: [Chart.js 4.4.8](https://www.chartjs.org/docs/latest/getting-started/integration), MIT, `static/vendor/Chart-LICENSE.md`.
- 스타일 유틸리티: [Tailwind CSS 4.1.3](https://github.com/tailwindlabs/tailwindcss/tree/v4.1.3), MIT, `static/vendor/Tailwind-LICENSE.txt`.
- 사진·영상: 사용자가 제공한 디자인 참고. 해당 이미지나 영상, 원본 로고를 앱 배경으로 포함하지 않았습니다.
