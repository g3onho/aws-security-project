"""실 AWS 어댑터 — B2/B3 단계에서 구현한다.

지금은 **의도적인 스텁**이다. USE_DEMO_DATA=false 로 기동하면 서버는 뜨지만
각 엔드포인트가 501 을 돌려주고, 어떤 AWS 호출이 들어갈 자리인지 알려준다.
이렇게 두는 이유: 프론트가 실모드 전환 경로(어댑터 선택, 에러 처리)를
AWS 계정 없이도 미리 검증할 수 있게 하기 위해서다.

구현 시 참조
  04-backend-design.md §1.2  필드 × 조회 경로
  04-backend-design.md §2.2  DynamoDB To-Be 키/GSI (apply 전에 반영해야 함)
  04-backend-design.md §3    상태 머신 · 게이트 · 멱등성 · 재검증
"""
from __future__ import annotations

from ..api.errors import ApiProblem

PLAN = {
    "list_events": "dynamodb:Query(correlated GSI1 region_status) + securityhub:GetFindings",
    "get_event": "dynamodb:GetItem + dynamodb:Query(actions PK=finding_id) + ssm:GetAutomationExecution",
    "metrics": "cloudwatch:GetMetricData (AWS/EC2 CPUUtilization, <prefix>/host MemoryUsedPercent)",
    "vulnerabilities": "inspector2:ListFindings + s3:GetObject(Trivy 리포트)",
    "scenarios": "카탈로그 + dynamodb:Query 집계",
    "evidence": "위 전부 + s3:GetObject",
    "approve": "dynamodb:PutItem(actions, decision=approved)",
    "execute": "게이트 판정 → ssm:StartAutomationExecution + iam:PassRole → dynamodb:PutItem",
    "execution_status": "ssm:GetAutomationExecution + ssm:DescribeAutomationStepExecutions",
    "verify": "verify.type 별 재검사 (04 §3.4)",
}


class LiveAdapter:
    mode = "live"

    def __init__(self, config) -> None:
        self.config = config

    def _todo(self, name: str):
        raise ApiProblem(
            501, "실 AWS 연동이 아직 구현되지 않았습니다.", code="NOT_IMPLEMENTED",
            detail=f"{name}: {PLAN.get(name, '')}",
        )

    def list_events(self, q):
        self._todo("list_events")

    def get_event(self, event_id):
        self._todo("get_event")

    def metrics(self, q):
        self._todo("metrics")

    def vulnerabilities(self, q):
        self._todo("vulnerabilities")

    def scenarios(self, q):
        self._todo("scenarios")

    def evidence(self, event_id):
        self._todo("evidence")

    def approve(self, event_id, body, actor, key):
        self._todo("approve")

    def execute(self, event_id, body, actor, key):
        self._todo("execute")

    def execution_status(self, event_id, execution_id):
        self._todo("execution_status")

    def verify(self, event_id, body, actor, key):
        self._todo("verify")

    def health_checks(self) -> dict:
        """실모드에서 어떤 상류가 살아 있는지 알려준다.

        예외 메시지를 그대로 노출하지 않는다 — 권한 오류 본문에 ARN 이 섞인다
        (04-backend-design.md §4.3).
        """
        checks = {}
        try:
            import boto3  # noqa: PLC0415
        except ImportError:
            return {k: "skipped" for k in ("dynamodb", "cloudwatch", "securityhub", "ssm")}

        probes = {
            "dynamodb": lambda: boto3.client("dynamodb").describe_table(
                TableName=self.config.CORRELATED_FINDINGS_TABLE),
            "cloudwatch": lambda: boto3.client("cloudwatch").describe_alarms(MaxRecords=1),
            "securityhub": lambda: boto3.client("securityhub").describe_hub(),
            "ssm": lambda: boto3.client("ssm").describe_automation_executions(MaxResults=1),
        }
        for name, probe in probes.items():
            try:
                probe()
                checks[name] = "ok"
            except Exception:  # noqa: BLE001 — 상세는 서버 로그에만
                checks[name] = "error"
        return checks
