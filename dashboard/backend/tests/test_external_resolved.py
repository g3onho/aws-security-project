"""'외부 해결(추정)': 열린 탐지에서 사라졌는데 대시보드·자동 조치 기록이 없는 것만. 확정 표현·오탐 방지."""
from types import SimpleNamespace

from botocore.exceptions import ClientError

from soar import create_app
from soar.contracts import StandardService
from soar.remediation_service import _definite
from soar.store import now_ms

DAY = 86400 * 1000


def build(tmp_path):
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "e.sqlite3"), "SECRET_KEY": "unit-test-only",
                      "DATA_PROVIDER": "demo"})
    return app.extensions["store"]


def ev(i, **extra):
    return {"id": f"EVT-{i}", "title": f"t{i}", "resource": f"r{i}", "severity": "HIGH", "source": "Security Hub",
            "region": "ap-northeast-2", "accountId": "000000000000", "controlId": "EC2.19",
            "externalFindingId": f"arn:finding/{i}", **extra}


def test_ledger_marks_gone_and_clears_when_it_returns(tmp_path):
    store = build(tmp_path)
    now = now_ms()
    store.observe_events([ev(1), ev(2)], now - 3000, 30 * DAY)
    store.observe_events([ev(1)], now - 2000, 30 * DAY)                    # 2 가 사라짐
    assert [g["id"] for g in store.gone_events(now - 5000, now)] == ["EVT-2"]
    store.observe_events([ev(1), ev(2)], now - 1000, 30 * DAY)             # 돌아오면 사라짐 기록 해제
    assert store.gone_events(now - 5000, now) == []


def test_ledger_prunes_old_gone_rows(tmp_path):
    store = build(tmp_path)
    now = now_ms()
    store.observe_events([ev(1)], now - 40 * DAY, 30 * DAY)
    store.observe_events([], now - 39 * DAY, 30 * DAY)
    store.observe_events([], now, 30 * DAY)
    assert store.gone_events(0, now + 1) == []


def service(store, records=None, partial=False, connected=True):
    def records_fn(principal, notes, finding_ids=None):
        if partial:
            notes["partial"] = True
            return []
        return records or []
    svc = SimpleNamespace(store=store, provider=SimpleNamespace(connected=connected), _automation_records=records_fn,
                          _event_sync_warning=lambda: None)
    return svc


def external(svc, now):
    return StandardService._external_resolved(svc, {"from": now - DAY, "to": now + 1000}, {"accounts": None, "regions": None, "resources": None},
                                              {"warnings": [], "partial": False})


def test_external_only_without_any_of_our_records(tmp_path):
    store = build(tmp_path)
    now = now_ms()
    store.observe_events([ev(1), ev(2), ev(3), ev(4)], now - 2000, 30 * DAY)
    store.observe_events([], now - 1000, 30 * DAY)                          # 넷 다 사라짐
    with store.connect(write=True) as db:                                   # 3: 대시보드 조치 기록, 4: 감사 기록
        db.execute("INSERT INTO remediations(id,event_id,actor,request_key,state,payload,created_at,updated_at) VALUES "
                   "('r','EVT-3','a','k','VERIFIED','{}',1,1)")
        store.audit(db, "a", "EVT-4", "approve", {})
    svc = service(store, records=[])
    got = [x["eventId"] for x in external(svc, now)]
    assert sorted(got) == ["EVT-1", "EVT-2"]
    filtered = StandardService._external_resolved(svc, {"from": now - DAY, "to": now + 1000, "eventId": "EVT-1"},
                                                  {"accounts": None, "regions": None, "resources": None},
                                                  {"warnings": [], "partial": False})
    assert [x["eventId"] for x in filtered] == ["EVT-1"]
    svc = service(store, records=[{"decision": "auto-executed"}])           # 자동 조치 기록이 있으면 외부가 아니다
    assert external(svc, now) == []


def test_unreadable_auto_records_are_not_claimed_external(tmp_path):
    store = build(tmp_path)
    now = now_ms()
    store.observe_events([ev(1)], now - 2000, 30 * DAY)
    store.observe_events([], now - 1000, 30 * DAY)
    notes = {"warnings": [], "partial": False}
    got = StandardService._external_resolved(service(store, partial=True), {"from": now - DAY, "to": now + 1000},
                                             {"accounts": None, "regions": None, "resources": None}, notes)
    assert got == [] and notes["partial"] and notes["warnings"]


def test_demo_provider_has_no_external_rows(tmp_path):
    store = build(tmp_path)
    assert external(service(store, connected=False), now_ms()) == []


def test_stale_sync_does_not_claim_external_resolution(tmp_path):
    store = build(tmp_path)
    now = now_ms()
    store.observe_events([ev(1)], now - 2000, 30 * DAY)
    store.observe_events([], now - 1000, 30 * DAY)
    svc = service(store)
    svc._event_sync_warning = lambda: "탐지 동기화가 불완전합니다."
    notes = {"warnings": [], "partial": False}
    assert StandardService._external_resolved(svc, {"from": now - DAY, "to": now + 1000},
                                              {"accounts": None, "regions": None, "resources": None}, notes) == []
    assert notes["partial"] and notes["warnings"]


def test_server_error_does_not_prove_ssm_start_was_rejected():
    def error(status):
        return ClientError({"Error": {"Code": "InternalServerError" if status == 500 else "AccessDeniedException"},
                            "ResponseMetadata": {"HTTPStatusCode": status}}, "StartAutomationExecution")
    assert _definite(error(500)) is False
    assert _definite(error(403)) is True
