# 대시보드 백엔드

Flask API. 화면 자산은 옆 폴더 `../frontend/`(templates · static)를 그대로 쓴다.

계약(응답 필드·타입)의 정본은 코드다 — `app/adapters/demo.py` 의 이벤트 필드와
`tests/test_live_mapping.py` 의 검사가 그 역할을 한다. 설계 문서 `docs/backend/`
는 이 저장소에 없다.

---

## 실행

```powershell
cd dashboard\backend
python -m pip install -r requirements.txt
python run.py                  # http://127.0.0.1:5000
python run.py --port 5050
```

또는 `start-dashboard.cmd` 더블클릭. `..\frontend\start-dashboard.cmd` 도 이쪽으로 위임한다.

Flask 나 PyYAML 이 없으면 `run.py` 가 stdlib 내장 서버로 폴백해 화면만 띄운다. 그 경로에는 `/health` 도 `/api/*` 도 없다.

## 동작 모드

| 환경변수 | 기본 | 의미 |
|---|---|---|
| `USE_DEMO_DATA` | `true` | `false` 면 실 AWS 어댑터. 현재는 스텁이라 501 을 돌려준다 |
| `WRITE_ENABLED` | `false` | 승인·실행·재검증 허용 여부. 실 AWS 를 **읽기만** 하는 중간 단계를 위해 분리했다 |
| `ENFORCE_GATES` | `true` | 데모에서도 게이트를 강제한다. 미배선 플레이북이 화면에서 그대로 막힌다 |

기본값이 데모 + 읽기 전용인 이유: 발표 당일 AWS 계정이 불안정해도 화면은 뜬다. 실모드는 `dashboard.env`(user_data 가 만든다)에 명시해야 켜진다.

## 구조

```
backend/
├── run.py                  앱 팩토리 · /  · /health · 폴백 서버
├── app/
│   ├── config.py           환경변수 · 캐시 TTL · 조회 상한
│   ├── enums.py            API enum ↔ 화면 국문 매핑
│   ├── catalog/
│   │   ├── scenarios.yaml  SEC-01~10 + 데모 4종. criterion · playbook · wired · verify
│   │   └── loader.py
│   ├── api/                블루프린트 12개 엔드포인트 · RFC 9457 오류
│   ├── adapters/
│   │   ├── demo.py         data.js 생성기의 파이썬 포팅
│   │   └── live.py         실 AWS (스텁 — 어떤 호출이 들어갈지 명시)
│   └── services/
│       ├── filters.py      store.js selectEvents() 재현 + 커서 페이지네이션
│       ├── csv_export.py   store.js toCSV() 와 바이트 단위 동일
│       ├── gates.py        asr_trigger 의 3중 게이트 + 가역성 게이트
│       ├── scenarios.py    SEC 커버리지 집계
│       └── evidence.py     증적양식 12항목 조립
└── tests/                  pytest 51개 + Node 대조 스크립트
```

## 테스트

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest tests -q
python tests\flask-check.py
```

AWS 계정이 필요한 테스트는 하나도 없다.

`test_demo_parity.py` 와 `test_csv_export.py` 는 **Node 로 `../frontend/static/js/` 원본을 실행해** 대조한다. Node 가 없으면 자동으로 skip 한다. `data.js` 나 `store.js` 를 고치면 이 두 테스트가 먼저 깨진다 — 의도한 동작이다.

## 알아둘 것

- **응답 시각은 전부 epoch ms 정수다.** 프론트가 `new Date(ms)` 와 산술 비교를 직접 하므로 ISO 문자열을 주면 필터가 깨진다.
- **상태·위험도·대응 방식은 영문 enum.** 화면 국문 변환은 프론트가 한다. 단 CSV 는 국문이 계약이다.
- **SEC-02 는 실행이 422 로 막힌다.** `ASR-HardenNginx` 는 SSM 문서와 Lambda 환경변수는 있으나 `asr_trigger` 에 호출 분기가 없다(README:303). 막는 게 정확한 동작이다.
- **조치 이력은 `finding_id` 로 조인한다.** `asr_trigger` 가 판정할 때마다 `remediation_actions` 에 `finding_id` 를 함께 기록하므로, live 어댑터가 이 값으로 이벤트에 이력을 붙인다. DynamoDB 는 스키마리스라 `aws_dynamodb_table` 정의는 바꾸지 않았다 — 키가 아닌 속성이기 때문이다. 조회량이 늘면 그때 GSI 를 판다.
