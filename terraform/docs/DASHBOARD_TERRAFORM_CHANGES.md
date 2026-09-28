# 대시보드 Terraform 연동 변경 내역

## 목적

대시보드를 실제 AWS 데이터 공급자와 조치 실행 환경에서 시작하도록 Terraform의 EC2 user-data와 systemd 설정을 정리했습니다. Terraform apply는 별도로 실행해야 합니다.

## 변경 전·후

### 환경변수

기존에는 `AWS_REGION`과 `USE_DEMO_DATA=false`만 전달했습니다. 변경 후에는 다음 값을 전달합니다.

```bash
DATA_PROVIDER=aws
AWS_REGION=${region}
WRITE_ENABLED=true
DASHBOARD_HOST=0.0.0.0
DASHBOARD_PORT=5000
DASHBOARD_INSTANCE=/opt/dashboard/instance
```

- `DATA_PROVIDER=aws`: Security Hub, EC2, CloudWatch, Inspector 조회 공급자 선택
- `WRITE_ENABLED=true`: 승인·실행·검증 API를 조치 활성화 기준으로 시작
- `DASHBOARD_HOST`·`DASHBOARD_PORT`: ALB와 헬스체크가 접속할 주소·포트
- `DASHBOARD_INSTANCE`: DB·세션 키·조치 이력의 영속 경로
- `USE_DEMO_DATA`: 현재 백엔드에서 사용하지 않아 제거

v23(2026-09-28)에서 다음 값을 더 전달합니다. 모두 기존 Terraform 변수에서 만들며 새 비밀값은 없습니다.

```bash
NAME_PREFIX=${project}                                  # CloudWatch 알람 이름 접두어(인프라 경보 표시)·메모리 지표 네임스페이스
AUTO_REMEDIABLE_PATTERNS=${auto_remediable_patterns}    # asr_trigger 와 같은 화이트리스트(쉼표 구분)
AUTO_REMEDIABLE_CONTROLS=${auto_remediable_controls}    # 규칙 ID 자동 조치 목록 + SEC-06A·SEC-06B
ENABLE_AUTO_REMEDIATION=${enable_auto_remediation}      # 전체 dry-run 스위치
```

- 대시보드는 이 세 값으로 탐지 상세의 "자동 조치 여부"를 예상해 보여줍니다. 셋 중 하나라도 없으면 `확인 불가`로 표시합니다.
- user_data 가 바뀌므로(`user_data_replace_on_change = true`) apply 때 대시보드 인스턴스가 새로 뜹니다. 대시보드 코드가 바뀌어도 같은 동작이므로 추가 영향은 없습니다. SQLite(로그인 계정·세션)는 인스턴스와 함께 새로 만들어집니다.
- 조회 권한은 기존 정책(`cloudwatch:DescribeAlarms`, `ssm:GetAutomationExecution`)으로 충분해 IAM 변경은 없습니다.

### systemd 실행 명령

기존:

```ini
ExecStart=/opt/dashboard/venv/bin/python run.py --port 5000 --lan
```

변경:

```ini
ExecStart=/opt/dashboard/venv/bin/python run.py --host 0.0.0.0 --port 5000
```

`--lan`은 현재 `run.py`가 지원하지 않는 옵션입니다. `--no-worker`는 사용하지 않아 AWS 공급자 연결 시 조치 작업 워커가 함께 시작될 수 있도록 했습니다.

## IAM 권한

`modules/compute/iam.tf`의 다음 리소스는 유지합니다.

```hcl
aws_iam_policy.dashboard_execute
aws_iam_role_policy_attachment.dashboard_execute
```

이 정책은 SSM Automation 실행·상태 조회, 제한된 `iam:PassRole`, 조치 이력 DynamoDB 기록, SNS 알림에 사용됩니다. Terraform에서 실행 권한을 제거하지 않고 백엔드의 승인 흐름과 함께 사용합니다.

## 적용 전 확인

```powershell
cd C:\Users\user\aws-security-project\terraform
terraform fmt -recursive
terraform init
terraform validate
terraform plan -out=tfplan
```

plan에서 dashboard user-data, IAM 실행 정책, S3 배포 zip 경로, 보안 그룹 변경을 확인한 뒤 별도로 `terraform apply tfplan`을 실행합니다.

현재 백엔드의 조치 공급자 구현이 실제 AWS API와 연결되어 있어야 실행 요청이 성공합니다. Terraform 변경만으로 AWS 조치가 자동 실행되는 것은 아닙니다.