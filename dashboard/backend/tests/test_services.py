"""인프라 모니터링 보완분 — 지표 시간 정합성, 호스트 선택, 3계층 상태."""
from types import SimpleNamespace

from app.adapters.demo import DEMO_NOW, breaches_of, metrics_for, period_seconds
from app.adapters.live import LiveAdapter


def _q(client, path):
    response = client.get(path)
    assert response.status_code == 200, response.json
    return response.json


# ── 지표 ─────────────────────────────────────────────────
def test_short_window_is_not_flat():
    """1시간 구간이 직선으로 나오던 회귀. 곡선이 시각을 따라가야 한다."""
    points = metrics_for("ap-northeast-2", 1.0)["points"]
    assert len({p["cpu"] for p in points}) > 3


def test_quarter_hour_window_has_usable_resolution():
    """화면 기간 프리셋이 15분·1시간·1일·1주일로 바뀌었다. 15분이 표본 3개면 못 쓴다."""
    data = metrics_for("ap-northeast-2", 0.25)
    assert data["period"] == 60
    assert len(data["points"]) == 16


def test_same_instant_has_same_value_in_every_window():
    """기간을 바꿔도 같은 시각의 값은 같아야 한다 — 시간축이 진짜 시간이라는 뜻."""
    wide = {p["at"]: p["cpu"] for p in metrics_for("ap-northeast-2", 24.0)["points"]}
    narrow = metrics_for("ap-northeast-2", 6.0)["points"]
    shared = [p for p in narrow if p["at"] in wide]
    assert shared, "두 구간이 겹치는 표본이 있어야 한다"
    assert all(wide[p["at"]] == p["cpu"] for p in shared)


def test_period_grows_with_range_and_points_stay_bounded():
    # 15분 구간은 1분 간격이어야 의미가 있다(5분이면 표본 3개).
    assert period_seconds(15 * 60 * 1000) == 60
    assert period_seconds(24 * 3600 * 1000) == 900
    previous = 0
    for hours in (0.25, 1, 6, 24, 168, 744):
        data = metrics_for("ap-northeast-2", float(hours))
        assert data["period"] >= previous
        previous = data["period"]
        assert 2 <= len(data["points"]) <= 121


def test_window_ends_at_requested_time():
    data = metrics_for("ap-northeast-2", 6.0, 3.0)
    assert data["points"][-1]["at"] == data["at"] == DEMO_NOW - 3 * 3600000
    assert data["window"]["from"] == data["points"][0]["at"]


def test_breaches_group_contiguous_samples():
    points = [{"at": 0, "cpu": 81, "memory": 10}, {"at": 1, "cpu": 92, "memory": 10},
              {"at": 2, "cpu": 40, "memory": 10}, {"at": 3, "cpu": 85, "memory": 10}]
    runs = breaches_of(points, {"cpu": 80, "memory": 80})
    assert [(r["from"], r["to"], r["peak"], r["samples"]) for r in runs] == \
           [(0, 1, 92, 2), (3, 3, 85, 1)]


def test_hosts_are_selectable_and_differ(client):
    listing = _q(client, "/api/resources?region=ap-northeast-2")["items"]
    ids = [item["id"] for item in listing]
    assert "i-seoul-db-01" in ids and len(ids) == 5
    assert all(item["role"] for item in listing)
    app_host = _q(client, f"/api/metrics?region=ap-northeast-2&resource={ids[0]}")
    db_host = _q(client, "/api/metrics?region=ap-northeast-2&resource=i-seoul-db-01")
    assert app_host["cpu"] != db_host["cpu"]
    assert db_host["host"]["name"] == "db"


def test_metrics_default_to_first_host_when_resource_absent(client):
    data = _q(client, "/api/metrics?region=ap-northeast-2")
    assert data["resource"] == "i-seoul-app-01"
    assert data["summary"]["samples"] == len(data["points"])


# ── 3계층 서비스 ──────────────────────────────────────────
def test_services_returns_three_wired_tiers(client):
    data = _q(client, "/api/services?region=ap-northeast-2")
    assert [item["id"] for item in data["items"]] == ["nginx", "flask", "mysql"]
    assert data["overall"] in ("UP", "DEGRADED", "DOWN")
    for item in data["items"]:
        # 하드코딩 '미연동' 을 대체한 자리다. 상태와 근거가 반드시 함께 와야 한다.
        assert item["status"] in ("UP", "DEGRADED", "DOWN", "UNKNOWN")
        assert item["detail"] and item["target"] and item["probe"]
        assert item["checkedAt"] == data["checkedAt"]


def test_services_reflect_open_events(client):
    data = _q(client, "/api/services?region=ap-northeast-2")
    mysql = next(item for item in data["items"] if item["id"] == "mysql")
    # 데모 데이터에는 SEC-03(3306 과다 공개) 미해결 건이 있다.
    assert mysql["status"] == "DEGRADED"
    assert mysql["blockers"]


def test_services_without_host_are_unknown(client):
    data = _q(client, "/api/services?region=global")
    assert data["overall"] == "UNKNOWN" and data["items"] == [] and data["note"]


# ── 실모드 ───────────────────────────────────────────────
def _live():
    return LiveAdapter(SimpleNamespace(AWS_REGION="ap-northeast-2", NAME_PREFIX="soar-sec-dev",
                                       CACHE_TTL={"metrics": 30}))


def test_live_services_read_alb_and_alarms():
    live = _live()

    def call(service, operation, **kwargs):
        if operation == "describe_target_groups":
            return {"TargetGroups": [{"TargetGroupArn": "arn:tg"}]}
        if operation == "describe_target_health":
            return {"TargetHealthDescriptions": [{"TargetHealth": {"State": "healthy"}},
                                                 {"TargetHealth": {"State": "unhealthy"}}]}
        if operation == "get_metric_data":
            return {"MetricDataResults": [{"Id": "rt", "Values": [0.12]},
                                          {"Id": "e5", "Values": [2]},
                                          {"Id": "req", "Values": [100]}]}
        if operation == "describe_alarms":
            return {"MetricAlarms": [{"AlarmName": "soar-sec-mysql-auth-failures",
                                      "StateValue": "ALARM"}]}
        if operation == "filter_log_events":
            return {"events": []}
        raise AssertionError(operation)

    live._call = call
    data = live.services({"region": "ap-northeast-2", "from": 0, "to": 3600000})
    by_id = {item["id"]: item for item in data["items"]}
    assert by_id["nginx"]["status"] == "DEGRADED" and "1 / 2" in by_id["nginx"]["detail"]
    assert by_id["flask"]["status"] == "DEGRADED" and by_id["flask"]["latencyMs"] == 120.0
    assert by_id["mysql"]["status"] == "DEGRADED"
    assert data["overall"] == "DEGRADED"


def test_live_services_degrade_gracefully_without_alb():
    live = _live()

    def call(service, operation, **kwargs):
        from app.api.errors import ApiProblem
        raise ApiProblem(502, "no", code="UPSTREAM_ERROR")

    live._call = call
    data = live.services({"region": "ap-northeast-2", "from": 0, "to": 3600000})
    assert data["overall"] == "UNKNOWN" and data["note"]
    assert len(data["items"]) == 3


def test_live_services_fall_back_to_logs_without_alb():
    """ALB(enable_alb) 가 꺼진 배포에서도 3계층이 UNKNOWN 으로만 남지 않아야 한다."""
    live = _live()
    seen = []

    def call(service, operation, **kwargs):
        from app.api.errors import ApiProblem
        seen.append((operation, kwargs.get("logGroupName"), kwargs.get("filterPattern")))
        if operation == "describe_target_groups":
            return {"TargetGroups": []}          # ALB 없음
        if operation == "describe_alarms":
            return {"MetricAlarms": [{"AlarmName": "soar-sec-dev-mysql-bruteforce",
                                      "StateValue": "OK"}]}
        if operation == "filter_log_events":
            group, pattern = kwargs["logGroupName"], kwargs.get("filterPattern")
            if group.endswith("/web/nginx"):
                if pattern is None:
                    return {"events": [{"message": 'GET / 200'}] * 12}
                return {"events": []}            # error 로그 없음
            return {"events": []}                # mysql 오류 없음
        raise ApiProblem(502, "unexpected " + operation, code="UPSTREAM_ERROR")

    live._call = call
    data = live.services({"region": "ap-northeast-2", "from": 0, "to": 3600000})
    by_id = {item["id"]: item for item in data["items"]}
    assert by_id["nginx"]["status"] == "UP" and "12건" in by_id["nginx"]["detail"]
    assert by_id["flask"]["status"] == "UP" and "프록시 정상" in by_id["flask"]["detail"]
    assert by_id["mysql"]["status"] == "UP"
    assert data["overall"] == "UP"
    # NAME_PREFIX 에서 Terraform 의 로그 그룹 이름을 유도해야 한다.
    groups = {group for _, group, _ in seen if group}
    assert groups == {"/soar-sec/dev/web/nginx", "/soar-sec/dev/db/mysql"}
    assert "enable_alb=true" in data["note"]


def test_live_services_detect_upstream_failure_as_flask_down():
    live = _live()

    def call(service, operation, **kwargs):
        if operation == "describe_target_groups":
            return {"TargetGroups": []}
        if operation == "describe_alarms":
            return {"MetricAlarms": []}
        if operation == "filter_log_events":
            group, pattern = kwargs["logGroupName"], kwargs.get("filterPattern")
            if group.endswith("/web/nginx"):
                if pattern is None:
                    return {"events": [{"message": "GET / 502"}] * 6}
                return {"events": [{"message": "connect() failed ... upstream: http://127.0.0.1:5000/"}] * 6}
            return {"events": []}
        raise AssertionError(operation)

    live._call = call
    by_id = {i["id"]: i for i in live.services({"region": "ap-northeast-2", "from": 0, "to": 3600000})["items"]}
    assert by_id["nginx"]["status"] == "DEGRADED"
    assert by_id["flask"]["status"] == "DOWN"


def test_live_services_unknown_when_nothing_readable():
    live = _live()

    def call(service, operation, **kwargs):
        from app.api.errors import ApiProblem
        raise ApiProblem(502, "no", code="UPSTREAM_ERROR")

    live._call = call
    data = live.services({"region": "ap-northeast-2", "from": 0, "to": 3600000})
    assert data["overall"] == "UNKNOWN" and "CloudWatch Agent" in data["note"]


def test_scope_all_returns_every_running_host(client):
    """인프라 화면이 운영 중인 서버를 전부 보여줘야 한다(이전에는 1대씩만)."""
    data = _q(client, "/api/metrics?region=ap-northeast-2&scope=all")
    ids = [s["resource"] for s in data["series"]]
    assert ids == [h["id"] for h in data["hosts"]]
    assert len(ids) == 5
    for series in data["series"]:
        assert series["host"]["name"] and series["points"] and series["summary"]
    # 호스트마다 값이 달라야 한다 — 전부 같으면 시드가 안 먹은 것이다.
    assert len({s["cpu"] for s in data["series"]}) > 1


def test_scope_one_is_the_default(client):
    assert "series" not in _q(client, "/api/metrics?region=ap-northeast-2")
