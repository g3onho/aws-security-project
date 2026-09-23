# 보안 관제 대시보드

실제 데이터만 사용하는 대시보드입니다. 현재 실데이터 수집·조회 공급자는 연결되지 않았습니다. 로그인과 화면 자산은 제공하지만 데이터 API는 `503 DATA_SOURCE_NOT_CONFIGURED`를 반환하며 조치는 비활성 상태입니다. 미연결을 정상 0건으로 표시하지 않습니다.

## 구조

- `backend/soar/`: 인증, API, 저장소, 조회·조치 계약, 공급자 경계
- `frontend/`: 화면과 API 클라이언트
- `backend/contracts/openapi.yaml`: 표준 API 계약
- `backend/docs/DASHBOARD_DESIGN_STANDARD.md`: 설계 기준

## 실행

이 폴더에서 PowerShell로 실행합니다.

```powershell
python -m venv backend/.venv
./backend/.venv/Scripts/python.exe -m pip install -r backend/requirements.lock
# 계정이 없는 최초 설치에서만:
./backend/.venv/Scripts/python.exe backend/run.py --init-admin
./frontend/start-dashboard.cmd
```

실제 AWS 조회를 켜려면 `DATA_PROVIDER=aws`와 `AWS_REGION`을 설정합니다. Security Hub, EC2, CloudWatch CPU, Inspector 결과를 읽기 전용으로 제공하며 변경·실행 API는 비활성화되어 있습니다.

Terraform 담당 작업과 대시보드 배포 전 점검은 [DEPLOYMENT_CHECKLIST.md](DEPLOYMENT_CHECKLIST.md)에 구분해 정리했습니다.

접속: http://127.0.0.1:5051 . 계정과 저장소 파일은 `backend/instance/dashboard.sqlite3`입니다. 최초 계정 안내는 `backend/instance/initial-login.txt`에 있습니다.

## 검증

```powershell
./backend/.venv/Scripts/python.exe -m pip install -r backend/requirements-dev.lock
./backend/.venv/Scripts/python.exe backend/tools/check.py
npm.cmd --prefix frontend install --no-save --package-lock=false jsdom@27.0.1 --no-audit --no-fund
node --test frontend/tests/*.test.mjs frontend/tests/v2.1-projection-check.mjs
```

테스트용 입력은 테스트 폴더 안에서만 사용하며 서버에 적재하거나 화면 데이터로 제공하지 않습니다. 실행 환경·계정·DB·캐시는 Git에 포함하지 않습니다.
