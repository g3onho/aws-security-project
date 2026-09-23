# 대시보드 배포 전 작업 구분

이 저장소는 애플리케이션 코드와 배포 전 점검만 담당합니다. Terraform 저장소, AWS 콘솔, IAM 정책은 이 작업 범위에 포함하지 않습니다.

## Terraform·인프라 담당자가 할 일

- EC2 또는 ECS 등 실행 환경과 네트워크 구성
- 대시보드 서버의 IAM 역할 연결
- 다음 읽기 권한 부여
  - `sts:GetCallerIdentity`
  - `securityhub:GetFindings`
  - `ec2:DescribeInstances`
  - `cloudwatch:GetMetricData`
  - `inspector2:ListFindings`
- Security Hub와 Inspector2를 대상 리전에서 활성화
- HTTPS 종료, 보안 그룹, DNS, 로그 수집, 백업 구성
- 애플리케이션 환경변수 주입과 영속 디스크 연결

## 대시보드 담당자가 할 일

- AWS 계정에서 읽기 전용 스모크 테스트 수행
- `DATA_PROVIDER=aws`, `AWS_REGION`, `FLASK_SECRET_KEY` 설정
- HTTPS 환경에서 `SESSION_COOKIE_SECURE=true` 설정
- `WRITE_ENABLED=false` 유지
- `DASHBOARD_INSTANCE`를 영속 디스크 경로로 지정
- 관리자 계정 생성 및 초기 비밀번호 전달 경로 확인
- `/health`, 로그인, 이벤트·자원·지표·취약점 조회 확인
- 권한 부족·서비스 미활성화가 정상 오류로 표시되는지 확인

## 서버에 배포하기 직전 명령

```powershell
$env:DATA_PROVIDER="aws"
$env:AWS_REGION="ap-northeast-2"
$env:WRITE_ENABLED="false"
$env:SESSION_COOKIE_SECURE="true"
$env:DASHBOARD_HOST="127.0.0.1"
$env:DASHBOARD_PORT="5051"
$env:DASHBOARD_INSTANCE="D:\dashboard-data"
$env:FLASK_SECRET_KEY="<secret-manager에서 주입>"
./backend/.venv/Scripts/python.exe backend/tools/check.py
./backend/.venv/Scripts/python.exe backend/run.py --no-worker
```

리버스 프록시가 없는 단독 서버에서 직접 접근할 때만 `DASHBOARD_HOST=0.0.0.0`으로 설정합니다. 기본값은 외부에 직접 노출되지 않는 `127.0.0.1`입니다.

현재 애플리케이션은 AWS 리소스를 변경하지 않으며 실행·검증 API도 비활성화되어 있습니다. 실제 배포 전에는 계정의 샘플 finding, EC2 인스턴스, CloudWatch 지표, Inspector finding으로 조회 결과를 확인해야 합니다.
