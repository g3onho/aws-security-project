"""실 AWS 어댑터의 매핑 검증. AWS 호출은 하지 않는다 — _call 을 가짜로 바꾼다.

여기서 지키는 계약은 두 가지다.
  1. 모든 시각이 epoch ms 정수여야 한다. ISO 문자열이 새어나가면 프론트 필터가 깨진다.
  2. live 이벤트의 필드 집합이 demo 와 같아야 한다. 프론트가 같은 코드로 그린다.
"""
from app.adapters.demo import _build_events as demo_events
from app.adapters.live import LiveAdapter, _ms
from app.catalog import loader
from app.config import Config

FINDING = {
    "Id": "arn:aws:securityhub:ap-northeast-2:1:finding/abc",
    "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/EC2.13",
    "Title": "Security groups should not allow ingress from 0.0.0.0/0 to port 22",
    "Description": "SSH 가 전체 공개되어 있습니다.",
    "Severity": {"Label": "HIGH"},
    "CreatedAt": "2026-09-21T01:00:00.000Z",
    "UpdatedAt": "2026-09-21T02:00:00.000Z",
    "Resources": [{"Id": "arn:aws:ec2:ap-northeast-2:1:security-group/sg-123"}],
    "ProductFields": {"aws/securityhub/ProductName": "Security Hub"},
}

ACTIONS = {"Items": [
    {"action_id": {"S": "asr-1"}, "created_at": {"S": "2026-09-21T00:40:00Z"},
     "finding_id": {"S": "gd-1"}, "decision": {"S": "manual-notified"},
     "before_state": {"S": "key:AKIA... Active"}, "after_state": {"S": "pending"},
     "ssm_execution_id": {"S": "n/a"}},
    {"action_id": {"S": "asr-2"}, "created_at": {"S": "2026-09-21T00:50:00Z"},
     "finding_id": {"S": "gd-1"}, "decision": {"S": "auto-executed"},
     "before_state": {"S": "key:AKIA... Active"}, "after_state": {"S": "Inactive in progress"},
     "ssm_execution_id": {"S": "exec-9"}},
    # finding_id 가 없던 옛 행은 조인할 수 없으므로 버려야 한다.
    {"action_id": {"S": "asr-old"}, "created_at": {"S": "2026-09-20T00:00:00Z"},
     "finding_id": {"S": "unknown"}, "decision": {"S": "auto-executed"}},
]}

CORRELATED = {"Items": [{
    "finding_id": {"S": "gd-1"},
    "instance_id": {"S": "i-0abc"},
    "guardduty_type": {"S": "UnauthorizedAccess:IAMUser/MaliciousIPCaller"},
    "final_severity": {"S": "CRITICAL"},
    "severity_bumped": {"BOOL": True},
    "cve_ids": {"L": [{"S": "CVE-2024-1"}]},
    "created_at": {"S": "2026-09-21T00:30:00Z"},
}]}


def adapter(monkeypatch):
    live = LiveAdapter(Config)
    monkeypatch.setattr(Config, "CORRELATED_FINDINGS_TABLE", "correlated", raising=False)
    monkeypatch.setattr(Config, "REMEDIATION_ACTIONS_TABLE", "actions", raising=False)

    def fake_call(service, op, **kwargs):
        if (service, op) == ("dynamodb", "scan"):
            return {"correlated": CORRELATED, "actions": ACTIONS}[kwargs["TableName"]]
        if (service, op) == ("securityhub", "get_findings"):
            return {"Findings": [FINDING]}
        raise AssertionError(f"예상하지 못한 호출: {service}.{op}")

    monkeypatch.setattr(live, "_call", fake_call)
    return live


def test_epoch_ms_only(monkeypatch):
    """시각 필드가 전부 정수여야 한다."""
    for event in adapter(monkeypatch)._events():
        for field in ("at", "beforeAt"):
            assert isinstance(event[field], int), (event["id"], field)
        assert event["afterAt"] is None or isinstance(event["afterAt"], int)
        for entry in event["history"]:
            assert isinstance(entry["at"], int)


def test_field_set_matches_demo(monkeypatch):
    """live 이벤트가 demo 의 필드를 전부 갖는다. historyNote 만 실모드 전용."""
    demo_fields = set(demo_events()[0])
    for event in adapter(monkeypatch)._events():
        assert demo_fields <= set(event), demo_fields - set(event)
        assert set(event) - demo_fields == {"historyNote"}


def test_classification_and_correlation(monkeypatch):
    events = {e["id"]: e for e in adapter(monkeypatch)._events()}

    sg = events["arn:aws:securityhub:ap-northeast-2:1:finding/abc"]
    assert sg["scenario"] == "SEC-01"          # generator 에 EC2.13 이 들어 있다
    assert sg["playbook"] == "ASR-RevokeSecurityGroupIngress"
    assert sg["mode"] == "AUTO"                # 카탈로그 wired=true
    assert sg["at"] == _ms("2026-09-21T02:00:00.000Z")   # UpdatedAt 우선

    gd = events["gd-1"]
    assert gd["scenario"] == "SEC-05"          # guardduty_type_prefix 매칭
    assert gd["severity"] == "CRITICAL"        # correlator 가 올린 값
    assert gd["severityBumped"] is True
    assert gd["cveIds"] == ["CVE-2024-1"]


def test_action_history_join(monkeypatch):
    """remediation_actions 가 finding_id 로 붙어 상태와 이력을 만든다."""
    events = {e["id"]: e for e in adapter(monkeypatch)._events()}

    gd = events["gd-1"]
    texts = [h["text"] for h in gd["history"]]
    assert texts[0] == "탐지 근거 수집"
    assert "수동 조치 알림" in texts[1]                  # 오래된 판정이 먼저
    assert "자동 조치 실행" in texts[2]
    assert "Inactive in progress" in texts[2]            # after_state 가 붙는다
    assert gd["status"] == "PENDING_VERIFICATION"        # 마지막 판정 기준
    assert gd["execution"] == "SUCCEEDED"
    assert gd["afterAt"] == _ms("2026-09-21T00:50:00Z")
    assert gd["historyNote"] is None                     # 테이블이 있으면 안내 불필요

    # 조치가 없는 finding 은 탐지 항목만 남고 미조치 상태를 지킨다.
    sg = events["arn:aws:securityhub:ap-northeast-2:1:finding/abc"]
    assert len(sg["history"]) == 1
    assert sg["afterAt"] is None
    assert sg["execution"] == "NOT_RUN"


def test_actions_table_unset_explains_itself(monkeypatch):
    """테이블이 없으면 조인을 건너뛰고 historyNote 로 이유를 밝힌다."""
    monkeypatch.setattr(Config, "REMEDIATION_ACTIONS_TABLE", "", raising=False)
    live = LiveAdapter(Config)
    event = live._event(
        event_id="x", scenario="SEC-01", title="t", severity="HIGH",
        source="Security Hub", region="ap-northeast-2", resource="r",
        at=1, evidence="", recommendation="", extra=None,
    )
    assert event["historyNote"]
    assert live._actions() == {}


def test_unwired_scenario_is_manual(monkeypatch):
    """배선 안 된 플레이북은 자동으로 분류되지 않는다 (ASR-HardenNginx)."""
    assert loader.is_wired("SEC-02") is False
    live = LiveAdapter(Config)
    event = live._event(
        event_id="x", scenario="SEC-02", title="t", severity="MEDIUM",
        source="Security Hub", region="ap-northeast-2", resource="r",
        at=1, evidence="", recommendation="", extra=None,
    )
    assert event["mode"] == "MANUAL"
    assert event["status"] == "PENDING_APPROVAL"


def test_ms_handles_every_shape():
    assert _ms("2026-09-21T00:00:00Z") == 1789948800000
    assert _ms(1789948800000) == 1789948800000
    assert _ms(1789948800) == 1789948800000      # 초 단위는 ms 로 올린다
    assert _ms(None) is None
    assert _ms("깨진 값") is None


def test_writes_are_blocked():
    """쓰기는 아직 501 이다. run.py 가 실모드에서 WRITE_ENABLED 를 끈다."""
    import pytest
    from app.api.errors import ApiProblem
    live = LiveAdapter(Config)
    for name in ("approve", "execute", "verify", "cancel"):
        with pytest.raises(ApiProblem) as caught:
            getattr(live, name)("e", {}, "actor", "key")
        assert caught.value.status == 501
