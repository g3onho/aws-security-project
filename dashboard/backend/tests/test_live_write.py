"""실 AWS 쓰기 경로. AWS 는 부르지 않는다 — _call 을 가짜로 바꾼다.

여기서 지키는 계약.
  1. 게이트가 막으면 SSM 을 부르지 않는다
  2. 같은 Idempotency-Key 는 SSM 을 두 번 부르지 않는다
  3. 조치 이력에 finding_id 가 들어간다 (없으면 이벤트와 조인 불가)
  4. 재검증 결과가 0 이 아니면 RESOLVED 로 만들지 않는다
"""
import pytest

from app.adapters.live import LiveAdapter
from app.api.errors import ApiProblem
from app.config import Config

SG_FINDING = {
    "Id": "sh-sg-1",
    "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/EC2.13",
    "Title": "SSH open to the world",
    "Severity": {"Label": "HIGH"},
    "UpdatedAt": "2026-09-21T03:00:00Z",
    "Resources": [{"Id": "arn:aws:ec2:ap-northeast-2:1:security-group/sg-0abc"}],
    "ProductFields": {"aws/securityhub/ProductName": "Security Hub"},
}


def build(monkeypatch, calls, overrides=None):
    """쓰기가 켜진 어댑터. calls 리스트에 호출 기록이 쌓인다."""
    overrides = overrides or {}
    monkeypatch.setattr(Config, "WRITE_ENABLED", True, raising=False)
    monkeypatch.setattr(Config, "ENFORCE_GATES", True, raising=False)
    monkeypatch.setattr(Config, "NAME_PREFIX", "soar-sec-dev", raising=False)
    monkeypatch.setattr(Config, "CORRELATED_FINDINGS_TABLE", "", raising=False)
    monkeypatch.setattr(Config, "REMEDIATION_ACTIONS_TABLE", "actions", raising=False)
    live = LiveAdapter(Config)

    def fake_call(service, op, **kwargs):
        calls.append((service, op, kwargs))
        key = (service, op)
        if key in overrides:
            return overrides[key]
        if key == ("securityhub", "get_findings"):
            return {"Findings": [SG_FINDING]}
        if key == ("cloudwatch", "describe_alarms"):
            return {"MetricAlarms": []}
        if key == ("sts", "get_caller_identity"):
            return {"Account": "455958489281"}
        if key == ("ssm", "start_automation_execution"):
            return {"AutomationExecutionId": "exec-1"}
        if key == ("dynamodb", "put_item"):
            return {}
        if key == ("dynamodb", "scan"):
            return {"Items": []}
        if key == ("ec2", "describe_security_groups"):
            return {"SecurityGroups": [{"Tags": [
                {"Key": "AutoRemediation", "Value": "true"}], "IpPermissions": []}]}
        raise AssertionError("예상하지 못한 호출: %s.%s" % (service, op))

    monkeypatch.setattr(live, "_call", fake_call)
    return live


def test_execute_starts_ssm_with_role_and_params(monkeypatch):
    calls = []
    live = build(monkeypatch, calls)
    result = live.execute("sh-sg-1", {}, "operator", "key-1")

    assert result["execution"]["executionId"] == "exec-1"
    assert result["event"]["status"] == "EXECUTING"

    start = next(c for c in calls if c[1] == "start_automation_execution")
    assert start[2]["DocumentName"] == "ASR-RevokeSecurityGroupIngress"
    params = start[2]["Parameters"]
    assert params["SecurityGroupId"] == ["sg-0abc"]          # ARN 이 아니라 ID
    assert params["AutomationAssumeRole"] == [
        "arn:aws:iam::455958489281:role/soar-sec-dev-ssm-automation-role"]


def test_action_record_has_finding_id(monkeypatch):
    """finding_id 가 없으면 이벤트와 조치 이력을 조인할 수 없다."""
    calls = []
    build(monkeypatch, calls).execute("sh-sg-1", {}, "operator", "key-2")
    put = next(c for c in calls if c[1] == "put_item")
    item = put[2]["Item"]
    assert item["finding_id"]["S"] == "sh-sg-1"
    assert item["decision"]["S"] == "auto-executed"
    assert item["ssm_execution_id"]["S"] == "exec-1"
    assert item["actor"]["S"] == "operator"


def test_idempotency_does_not_call_ssm_twice(monkeypatch):
    calls = []
    live = build(monkeypatch, calls)
    first = live.execute("sh-sg-1", {}, "operator", "same-key")
    second = live.execute("sh-sg-1", {}, "operator", "same-key")
    assert first is second
    assert sum(1 for c in calls if c[1] == "start_automation_execution") == 1


def test_dry_run_skips_ssm(monkeypatch):
    calls = []
    live = build(monkeypatch, calls)
    result = live.execute("sh-sg-1", {"dry_run": True}, "operator", "key-3")
    assert result["execution"] is None
    assert not any(c[1] == "start_automation_execution" for c in calls)


def test_gate_blocks_unwired_playbook(monkeypatch):
    """ASR-HardenNginx(SEC-02)는 호출 분기가 없어 승인으로도 못 푼다."""
    calls = []
    live = build(monkeypatch, calls)
    event = live._require("sh-sg-1")
    event["scenario"] = "SEC-02"
    event["approver"] = "operator"

    with pytest.raises(ApiProblem) as caught:
        live.execute("sh-sg-1", {}, "operator", "key-4")
    assert caught.value.status == 422
    assert not any(c[1] == "start_automation_execution" for c in calls)


def test_verify_failure_is_not_resolved(monkeypatch):
    """규칙이 남아 있으면 RESOLVED 로 만들지 않는다."""
    calls = []
    live = build(monkeypatch, calls, {("ec2", "describe_security_groups"): {
        "SecurityGroups": [{"Tags": [], "IpPermissions": [
            {"FromPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]}})
    result = live.verify("sh-sg-1", {}, "operator", "key-5")
    event = result["event"]
    assert event["afterValue"] == 1
    assert event["verification"] == "FAILED"
    assert event["status"] == "VERIFICATION_FAILED"


def test_verify_success_sets_resolved(monkeypatch):
    calls = []
    live = build(monkeypatch, calls, {("ec2", "describe_security_groups"): {
        "SecurityGroups": [{"Tags": [], "IpPermissions": []}]}})
    event = live.verify("sh-sg-1", {}, "operator", "key-6")["event"]
    assert event["afterValue"] == 0
    assert event["verification"] == "PASSED"
    assert event["status"] == "RESOLVED"
    assert isinstance(event["afterAt"], int)


def test_cancel_still_unsupported(monkeypatch):
    """대시보드 역할에 ssm:StopAutomationExecution 이 없다."""
    live = build(monkeypatch, [])
    with pytest.raises(ApiProblem) as caught:
        live.cancel("sh-sg-1", {}, "operator", "key-7")
    assert caught.value.status == 501
