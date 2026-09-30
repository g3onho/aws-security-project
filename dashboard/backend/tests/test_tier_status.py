"""3계층(Nginx·Flask·MySQL) 상태: tier_check 가 저장한 점검 결과만 읽고, 없음·오래됨·읽기 실패는 정상으로 보이지 않는다."""
from datetime import datetime, timedelta, timezone

from soar.repositories.tiers import evaluate
from soar.store import now_ms
from tests.test_action_history import client_for
from tests.test_detail_views import DetailProvider

TIER = {"id": "tier/web", "name": "Nginx", "role": "웹"}
NOW = now_ms()


def stamp(seconds_ago):
    moment = datetime.fromtimestamp(NOW / 1000, timezone.utc) - timedelta(seconds=seconds_ago)
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def row(status="healthy", seconds_ago=60, **extra):
    return {"tier_id": "tier/web", "status": status, "detail": "컨테이너 실행 중", "checked_at": stamp(seconds_ago),
            "source": "ssm:TIER-Check", "stale_after_seconds": 900, **extra}


def test_fresh_result_is_shown_as_stored():
    got = evaluate(TIER, row("degraded", detail="응답 없음"), NOW)
    assert got["status"] == "degraded" and got["detail"] == "응답 없음" and got["source"] == "ssm:TIER-Check"
    assert got["observedAt"] == NOW - 60_000 and got["name"] == "Nginx"


def test_missing_or_unreadable_rows_are_unknown_not_healthy():
    assert evaluate(TIER, None, NOW)["status"] == "unknown"
    for bad in (row(status="ok"), row(checked_at="어제"), row(checked_at=None)):
        got = evaluate(TIER, bad, NOW)
        assert got["status"] == "unknown" and got["observedAt"] is None
    for stale_after in (None, 0, -5, "900", True):
        got = evaluate(TIER, row(stale_after_seconds=stale_after), NOW)
        assert got["status"] == "unknown" and "기준" in got["detail"]


def test_stale_and_future_results_are_unknown_even_if_last_state_was_healthy():
    got = evaluate(TIER, row("healthy", seconds_ago=901), NOW)
    assert got["status"] == "unknown" and "오래된" in got["detail"] and "healthy" in got["detail"]
    assert got["observedAt"] == NOW - 901_000
    assert evaluate(TIER, row("healthy", seconds_ago=900), NOW)["status"] == "healthy"  # 기준 시간 이내
    assert evaluate(TIER, row("healthy", seconds_ago=-30), NOW)["status"] == "unknown"


def test_stored_unknown_keeps_the_reason_from_the_checker():
    got = evaluate(TIER, row("unknown", detail="점검 명령이 성공하지 못했습니다(Failed)"), NOW)
    assert got["status"] == "unknown" and "Failed" in got["detail"]


class TierProvider(DetailProvider):
    """저장된 3계층 행을 돌려주는 공급자. rows=None 이면 저장소 미설정, fail=True 면 읽기 실패."""
    def __init__(self, rows=None, fail=False, **kw):
        super().__init__(**kw)
        self.rows, self.fail = rows, fail

    def tiers(self):
        if self.fail:
            raise RuntimeError("AccessDeniedException: internal detail")
        if self.rows is None:
            return {"configured": False, "items": []}
        return {"configured": True, "items": self.rows, "truncated": False}


def infra(tmp_path, **kw):
    client = client_for(tmp_path, TierProvider(**kw))
    body = client.get("/api/infra/status").json
    return body["data"]["tiers"], body["meta"]


def stored(tier, status, seconds_ago=60, detail="ok"):
    return {**row(status, seconds_ago, detail=detail), "tier_id": f"tier/{tier}"}


def test_infra_status_reports_stored_tier_results(tmp_path):
    tiers, meta = infra(tmp_path, rows=[stored("web", "healthy"), stored("app", "degraded", detail="5000 무응답"),
                                        stored("db", "unhealthy", detail="healthcheck 실패")])
    assert [(t["name"], t["status"]) for t in tiers] == [("Nginx", "healthy"), ("Flask", "degraded"), ("MySQL", "unhealthy")]
    assert all(t["observedAt"].endswith("Z") for t in tiers) and tiers[1]["detail"] == "5000 무응답"
    assert meta["warnings"] == []


def test_missing_tier_row_stays_unknown_while_others_show(tmp_path):
    tiers, _ = infra(tmp_path, rows=[stored("web", "healthy"), stored("db", "healthy")])
    assert [t["status"] for t in tiers] == ["healthy", "unknown", "healthy"]
    assert tiers[1]["detail"] == "점검 결과 없음" and tiers[1]["observedAt"] is None


def test_stale_rows_are_not_shown_as_healthy(tmp_path):
    tiers, _ = infra(tmp_path, rows=[stored(t, "healthy", seconds_ago=3600) for t in ("web", "app", "db")])
    assert all(t["status"] == "unknown" and "오래된" in t["detail"] for t in tiers)


def test_table_not_configured_is_unknown_with_reason(tmp_path):
    tiers, meta = infra(tmp_path, rows=None)
    assert all(t["status"] == "unknown" and "TIER_STATUS_TABLE" in t["detail"] for t in tiers)
    assert meta["warnings"] == []


def test_read_failure_warns_and_does_not_leak_internal_error(tmp_path):
    tiers, meta = infra(tmp_path, fail=True)
    assert all(t["status"] == "unknown" and t["detail"] == "점검 결과 조회 실패" for t in tiers)
    assert any("3계층" in w for w in meta["warnings"]) and "AccessDenied" not in str(meta) + str(tiers)
