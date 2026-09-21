"""증적 12항목 조립 — aws-soar-terraform/docs/증적양식.md:17-28.

source 필드가 "manual" 인 항목은 사람이 채워야 한다. 자동으로 채울 수 있는 것과
없는 것을 화면에서 구분해 보여주기 위해 표시한다.
"""
from __future__ import annotations

from .. import enums
from ..catalog import loader

LABELS = [
    "자산명 / 자산 ID",
    "점검 항목 · 기준 ID",
    "현재 설정",
    "점검 명령 · 화면 경로",
    "원본 점검 결과",
    "취약 여부 / 위험도",
    "판정 근거와 영향",
    "개선 방법 · 담당자",
    "Terraform·설정 변경",
    "Plan·Apply 결과",
    "동일 조건 재점검",
    "정상 기능 · 롤백 확인",
]

VERIFY_COMMAND = {
    "sg_ingress_count": "aws ec2 describe-security-group-rules --filters Name=group-id,Values={resource}",
    "iam_key_status": "aws iam list-access-keys --user-name <user>",
    "config_compliance": "aws configservice get-compliance-details-by-config-rule --config-rule-name <rule>",
    "inspector_cve_count": "aws inspector2 list-findings --filter-criteria '{{\"resourceId\":[{{\"comparison\":\"EQUALS\",\"value\":\"{resource}\"}}]}}'",
    "trivy_report_diff": "aws ssm send-command --document-name SCAN-ContainerImage --instance-ids <id>",
    "cloudwatch_metric": "aws cloudwatch get-metric-statistics --namespace <ns> --metric-name <metric>",
    "http_headers": "curl -I http://<target>/",
}


def build_evidence(event: dict, ssm_execution_ids: list[str] | None = None) -> dict:
    spec = loader.get(event["scenario"]) or {}
    verify = spec.get("verify") or {}
    remediation = spec.get("remediation") or {}
    command = VERIFY_COMMAND.get(verify.get("type", ""), "")
    if command:
        command = command.format(resource=event.get("resource", "<resource>"))

    before, after = event.get("before") or {}, event.get("after") or {}

    values = [
        (event.get("resource"), "aws"),
        (f"{event['scenario']} · {spec.get('title', event.get('title'))}", "catalog"),
        (before.get("label"), "dynamodb"),
        (command or None, "catalog"),
        (event.get("evidence"), "aws"),
        (f"{'취약' if event['verification'] != 'PASSED' else '양호'} · "
         f"{enums.severity_display(event['severity'])}", "aws"),
        (event.get("evidence"), "aws"),
        (f"{event.get('recommendation', '')}"
         + (f" · 담당 {event['approver']}" if event.get("approver") else ""), "manual"),
        (remediation.get("playbook") and f"SSM 문서 {remediation['playbook']}", "manual"),
        (None, "manual"),
        (f"{event.get('criterion', '')} → {after.get('label') or '미실행'}", "dynamodb"),
        (None, "manual"),
    ]

    items = []
    for index, (label, (value, source)) in enumerate(zip(LABELS, values), start=1):
        items.append({
            "no": index,
            "label": label,
            "value": value if value else None,
            "raw": event.get("evidence") if index == 5 else None,
            "source": source,
        })

    return {
        "eventId": event["id"],
        "items": items,
        "ssmExecutionIds": ssm_execution_ids or [],
        "scanReportKeys": [],
    }
