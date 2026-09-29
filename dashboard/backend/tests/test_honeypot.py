"""허니팟 화면·차단 IP 관리(v25, DEC-021) — 로그 해석, 상태 판정, 목록 대조, 해제·기간 변경, 권한, 공격자 입력."""
import json

import pytest

from soar import create_app
from soar.auth import create_user
from soar.blocklist_service import BlocklistService
from soar.honeypot_service import HoneypotService
from soar.repositories import honeypot as hp
from soar.repositories.blocklist import merge, normalize
from soar.store import now_ms

NOW = now_ms()
SETTINGS = {"WRITE_ENABLED": True, "AUTO_REMEDIABLE_CONTROLS": "EC2.2,SEC-06A,HONEYPOT",
            "ENABLE_AUTO_REMEDIATION": "true", "IP_BLOCK_TTL_HOURS": 24}
NACL = "acl-0123456789abcdef0"
ALL = {"accounts": None, "regions": None, "resources": None}


def log(ts, **body):
    return {"timestamp": ts, "logStreamName": "s", "message": json.dumps(body, ensure_ascii=False)}


def session_events(sid, ip, start, commands=(), analysis=None, users=(("root", "hunter2"),), end=True):
    rows = [log(start, event="connect", src_ip=ip, src_port=51000, session_id=sid)]
    for i, (user, password) in enumerate(users):
        rows.append(log(start + 1 + i, event="auth", src_ip=ip, session_id=sid, user=user, password=password))
    for i, (command, response) in enumerate(commands):
        rows.append(log(start + 100 + i * 10, event="command", src_ip=ip, session_id=sid, command=command))
        rows.append(log(start + 101 + i * 10, event="response", src_ip=ip, session_id=sid, response=response))
    if end:
        rows.append(log(start + 900, event="session_end", src_ip=ip, session_id=sid, command_count=len(commands),
                        analysis=analysis or {"summary": "미끼서버 접속 · 명령 %d회(AI 분석 미적용)" % len(commands),
                                              "iocs": [], "intent": "unknown", "severity": "low"}))
    return rows


AI = {"summary": "공격자가 계정 정보를 훑어봤다.", "iocs": ["cat /etc/passwd"], "intent": "recon", "severity": "medium"}


class FakeSources:
    log_group, alarm_name = "/honeypot/soar-sec-dev", "soar-sec-dev-honeypot"

    def __init__(self, rows=(), instances=None, alarm="OK", fail_logs=False):
        self.rows, self.fail_logs = list(rows), fail_logs
        self._instances = instances if instances is not None else [
            {"id": "i-0abc", "state": "running", "privateIp": "10.0.1.50", "launchedAt": NOW - 3_600_000}]
        self._alarm = alarm
        self.transitions = []

    def events(self, start, end):
        if self.fail_logs:
            raise RuntimeError("AccessDenied")
        return [r for r in self.rows if start <= r["timestamp"] <= end], False

    def instances(self):
        return self._instances

    def alarm(self):
        return None if self._alarm is None else {"name": self.alarm_name, "state": self._alarm, "updatedAt": NOW - 60_000,
                                                 "actionsEnabled": True}

    def alarm_transitions(self, start, end):
        return self.transitions


class FakeGateway:
    nacl_id = NACL

    def __init__(self, rows=(), denies=None):
        self.table = {r["ip"]: dict(r) for r in rows}
        self.denies, self.started, self.actions = dict(denies or {}), [], []
        self.fail_start = self.fail_nacl = False

    def rows(self):
        return [dict(r) for r in self.table.values()]

    def row(self, ip):
        return dict(self.table[ip]) if ip in self.table else None

    def nacl_denies(self):
        if self.fail_nacl:
            raise RuntimeError("Throttling")
        return dict(self.denies)

    def update(self, ip, sets, remove=(), condition=None):
        row = self.table[ip]
        if condition:
            expression, names, values = condition
            for clause in expression.split(" AND "):
                left, right = [x.strip() for x in clause.split("=")]
                if row.get(names[left]) != values[right]:
                    return False
        row.update(sets)
        for attr in remove:
            row.pop(attr, None)
        row["version"] = row.get("version", 0) + 1
        return True

    def create_unrecorded(self, ip, sets):
        if ip in self.table:
            return False
        self.table[ip] = {"ip": ip, "version": 1, **sets}
        return True

    def start_unblock(self, ip, nacl_id, rule, seed):
        if self.fail_start:
            raise RuntimeError("AccessDenied")
        self.started.append({"ip": ip, "nacl": nacl_id, "rule": rule, "seed": seed})
        return f"exec-{len(self.started)}"

    def record_action(self, *args):
        self.actions.append(args)


class FakeProvider:
    connected, account_id, region = True, "123456789012", "ap-northeast-2"

    def __init__(self, sources, gateway, actions=(), executions=None):
        self.honeypot, self.blocklist = sources, gateway
        self._actions, self.executions = list(actions), executions or {}

    def require_ready(self):
        pass

    def actions(self):
        return {"configured": True, "items": self._actions, "truncated": False}

    def execution(self, execution_id, fetch=True):
        status = self.executions.get(execution_id)
        return True, ({"status": status, "startedAt": NOW - 5000, "endedAt": NOW - 1000} if status else None)


def row(ip="10.0.2.55", **over):
    base = {"ip": ip, "status": "ACTIVE", "rule_number": 3, "nacl_id": NACL, "source": "HONEYPOT", "version": 1,
            "blocked_at": "2026-09-29T02:00:00.000Z", "expires_at": NOW // 1000 + 3600, "allowlisted": False,
            "ssm_execution_id": "exec-b1", "evidence": {"hits": 4, "alarm": "soar-sec-dev-honeypot"}}
    base.update(over)
    return base


def build(tmp_path, rows=(), gateway=None, provider=None, sources=None, **settings):
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "d.sqlite3"), "SECRET_KEY": "unit-test-only",
                      "WRITE_ENABLED": settings.get("WRITE_ENABLED", True)})
    store = app.extensions["store"]
    for name, role, scope in (("op", "operator", ALL), ("view", "viewer", ALL), ("appr", "approver", ALL),
                              ("scoped", "operator", {"accounts": ["999999999999"], "regions": None, "resources": None})):
        create_user(store, name, "test-password-123", role, scope=scope)
    sources = sources if sources is not None else FakeSources(rows)
    gateway = gateway if gateway is not None else FakeGateway()
    provider = provider or FakeProvider(sources, gateway)
    merged = {**SETTINGS, **settings}
    honeypot = HoneypotService(provider, app.extensions["workflow"], merged)
    app.extensions.update(honeypot_service=honeypot,
                          blocklist_service=BlocklistService(provider, app.extensions["workflow"], store, honeypot, merged))
    return app, provider, gateway


def login(app, name="op"):
    client = app.test_client()
    token = client.get("/api/auth/session").json["csrfToken"]
    response = client.post("/api/auth/login", json={"username": name, "password": "test-password-123"},
                           headers={"X-CSRF-Token": token})
    assert response.status_code == 200
    client.environ_base["HTTP_X_CSRF_TOKEN"] = response.json["csrfToken"]
    return client


def post(client, url, body, key="k-1", method="post"):
    return getattr(client, method)(url, json=body, headers={"Idempotency-Key": key})


# ---------------------------------------------------------------------------------------------
# 로그 해석 — 공격자가 조종하는 값
# ---------------------------------------------------------------------------------------------

def test_sessions_pair_commands_with_responses_and_read_the_analysis():
    events, skipped = hp.parse(session_events("a1b2c3d4e5f6", "10.0.2.55", NOW - 5000,
                                              commands=[("whoami", "root"), ("ls", "backup.sql data")], analysis=AI))
    session = hp.sessions(events)["a1b2c3d4e5f6"]
    assert skipped == 0 and session["srcIp"] == "10.0.2.55" and session["srcPort"] == 51000
    assert [(c["command"], c["response"]) for c in session["commands"]] == [("whoami", "root"), ("ls", "backup.sql data")]
    assert session["analysis"]["aiApplied"] is True and session["analysis"]["intent"] == "recon"
    assert hp.summary(session)["commandCount"] == 2


def test_rule_based_fallback_summary_is_marked_as_not_ai():
    events, _ = hp.parse(session_events("a1b2c3d4e5f6", "10.0.2.55", NOW - 5000, commands=[("id", "uid=0")]))
    assert hp.sessions(events)["a1b2c3d4e5f6"]["analysis"]["aiApplied"] is False


def test_malformed_or_forged_log_lines_are_skipped_not_trusted():
    rows = [{"timestamp": NOW, "message": "not json"},
            log(NOW, event="connect", src_ip="10.0.2.55", session_id="../../etc/passwd"),      # 세션 ID 형식 위반
            log(NOW, event=7, src_ip="10.0.2.55", session_id="a1b2c3d4e5f6"),                    # 이벤트 형식 위반
            {"timestamp": NOW, "message": json.dumps(["list"])}]
    events, skipped = hp.parse(rows)
    assert events == [] and skipped == 4


def test_untrusted_strings_are_truncated_and_constrained():
    huge = "A" * 100_000
    rows = session_events("a1b2c3d4e5f6", "10.0.2.55", NOW - 5000, commands=[(huge, huge)],
                          users=((huge, huge),),
                          analysis={"summary": huge, "iocs": [huge] * 50, "intent": "<script>alert(1)</script>",
                                    "severity": "catastrophic"})
    session = hp.sessions(hp.parse(rows)[0])["a1b2c3d4e5f6"]
    assert len(session["commands"][0]["command"]) == hp.LIMITS["command"]
    assert len(session["commands"][0]["response"]) == hp.LIMITS["response"]
    assert len(session["authAttempts"][0]["password"]) == hp.LIMITS["password"]
    analysis = session["analysis"]
    assert len(analysis["summary"]) == hp.LIMITS["summary"] and len(analysis["iocs"]) == hp.MAX_IOCS
    assert analysis["intent"] == "unknown" and analysis["severity"] is None      # 집합 밖 값은 버린다


def test_invalid_source_address_is_dropped():
    rows = session_events("a1b2c3d4e5f6", "not-an-ip", NOW - 5000)
    assert hp.sessions(hp.parse(rows)[0])["a1b2c3d4e5f6"]["srcIp"] is None


def test_stats_and_graph_summarize_by_ip_command_intent_and_never_count_passwords():
    rows = (session_events("a00000000001", "10.0.2.55", NOW - 60_000, [("whoami", "root"), ("ls", "x")], AI)
            + session_events("a00000000002", "10.0.2.55", NOW - 50_000, [("whoami", "root")], AI)
            + session_events("a00000000003", "10.0.2.77", NOW - 40_000, [], None, users=(("admin", "p"),)))
    by_id = hp.sessions(hp.parse(rows)[0])
    stats = hp.stats(by_id, NOW - 3_600_000, NOW)
    assert stats["totals"] == {"sessions": 3, "commands": 3, "uniqueIps": 2, "unanalyzed": 0}
    assert stats["topIps"][0]["ip"] == "10.0.2.55" and stats["topIps"][0]["sessions"] == 2
    assert stats["topCommands"][0] == {"key": "whoami", "count": 2}
    assert {u["key"] for u in stats["topUsers"]} == {"root", "admin"}
    assert "password" not in json.dumps(stats)
    assert sum(b["sessions"] for b in stats["timeline"]) == 3
    graph = hp.graph(by_id)
    kinds = {n["type"] for n in graph["nodes"]}
    assert kinds == {"ip", "session", "command"} and all(l["source"] and l["target"] for l in graph["links"])
    assert {n["id"] for n in graph["nodes"]} >= {"ip:10.0.2.55", "s:a00000000001", "c:whoami"}


def test_graph_limits_report_what_was_hidden():
    rows = []
    for n in range(20):
        rows += session_events(f"{n:012x}", f"10.0.3.{n + 1}", NOW - 10_000, [(f"cmd-{n}", "x")], AI)
    graph = hp.graph(hp.sessions(hp.parse(rows)[0]))
    assert sum(1 for n in graph["nodes"] if n["type"] == "ip") == hp.GRAPH_LIMITS["ips"]
    assert graph["hidden"]["ips"] == 5 and graph["hidden"]["commands"] >= 0


def test_csv_cells_cannot_inject_formulas():
    assert hp.csv_safe("=HYPERLINK(\"http://x\")").startswith("'=") and hp.csv_safe("+1+1") == "'+1+1"
    assert hp.csv_safe("@SUM(A1)") == "'@SUM(A1)" and hp.csv_safe("-2+3") == "'-2+3" and hp.csv_safe("ls -la") == "ls -la"


# ---------------------------------------------------------------------------------------------
# ① 동작 상태
# ---------------------------------------------------------------------------------------------

def status(client):
    response = client.get("/api/honeypot/status")
    assert response.status_code == 200, response.json
    return response.json["data"]


def healthy_rows():
    return session_events("a00000000001", "10.0.2.55", NOW - 600_000, [("whoami", "root")], AI)


def test_status_ok_when_everything_has_been_observed(tmp_path):
    action = {"actionId": "ssm-x", "createdAt": NOW - 1000, "status": "SUCCESS", "controlId": "HONEYPOT",
              "reason": "미끼 접속 4회", "resource": f"{NACL} ← 10.0.2.55/32"}
    app, *_ = build(tmp_path, healthy_rows(), provider=None)
    app.extensions["honeypot_service"].provider._actions.append(action)
    data = status(login(app))
    assert data["verdict"]["state"] == "ok" and data["verdict"]["label"] == "정상 동작"
    assert {k: v["state"] for k, v in data["cards"].items()} == {
        "instance": "ok", "logs": "ok", "ai": "ok", "alarm": "ok", "block": "ok"}
    assert data["canWrite"] is True


def test_status_partial_names_what_is_missing(tmp_path):
    rows = session_events("a00000000001", "10.0.2.55", NOW - 600_000, [("whoami", "root")])   # AI 미적용 분석
    app, *_ = build(tmp_path, rows, sources=FakeSources(rows, instances=[{"id": "i-1", "state": "stopped",
                                                                       "privateIp": None, "launchedAt": None}]),
                    AUTO_REMEDIABLE_CONTROLS="EC2.2")
    data = status(login(app))
    assert data["verdict"]["state"] == "partial"
    reasons = " ".join(data["verdict"]["reasons"])
    assert "stopped" in reasons and "AI 분석이 적용되지 않음" in reasons and "HONEYPOT 자동 차단이 꺼져 있음" in reasons
    assert data["cards"]["ai"]["state"] == "warn" and data["cards"]["block"]["state"] == "warn"


def test_status_is_waiting_not_ok_when_nothing_was_observed_yet(tmp_path):
    app, *_ = build(tmp_path, [])
    data = status(login(app))
    assert data["verdict"]["state"] == "waiting" and data["cards"]["logs"]["state"] == "info"


def test_unreadable_logs_are_unknown_never_healthy(tmp_path):
    app, *_ = build(tmp_path, sources=FakeSources(fail_logs=True))
    data = status(login(app))
    assert data["verdict"]["state"] == "unknown"
    assert data["cards"]["logs"]["state"] == "unknown" and data["cards"]["ai"]["state"] == "unknown"


def test_status_when_honeypot_is_not_deployed(tmp_path):
    class Empty(FakeSources):
        log_group = None
    app, *_ = build(tmp_path, sources=Empty())
    client = login(app)
    assert status(client)["deployed"] is False and status(client)["verdict"]["state"] == "not_deployed"
    for url in ("/api/honeypot/stats", "/api/honeypot/sessions", "/api/honeypot/timeline?ip=10.0.2.55"):
        response = client.get(url)
        assert response.status_code == 409 and response.json["error"]["code"] == "HONEYPOT_NOT_DEPLOYED"


def test_missing_alarm_and_last_failed_block_are_reported(tmp_path):
    action = {"actionId": "ssm-x", "createdAt": NOW - 1000, "status": "FAILED", "controlId": "HONEYPOT", "reason": "r",
              "resource": None}
    app, provider, _ = build(tmp_path, healthy_rows(), sources=FakeSources(healthy_rows(), alarm=None))
    provider._actions.append(action)
    data = status(login(app))
    assert data["cards"]["alarm"]["state"] == "bad" and data["cards"]["block"]["state"] == "bad"
    assert data["verdict"]["state"] == "partial"


def test_scoped_account_cannot_see_honeypot_data(tmp_path):
    app, *_ = build(tmp_path, healthy_rows())
    response = login(app, "scoped").get("/api/honeypot/status")
    assert response.status_code == 403 and response.json["error"]["code"] == "FORBIDDEN"


# ---------------------------------------------------------------------------------------------
# ⑤ 세션 목록·상세
# ---------------------------------------------------------------------------------------------

def many_rows():
    rows = []
    for n in range(12):
        rows += session_events(f"{n:012x}", "10.0.2.55" if n % 2 else "10.0.2.77", NOW - 600_000 + n * 1000,
                               [("whoami", "root")], AI if n % 3 == 0 else None)
    return rows


def test_session_list_filters_and_paginates_with_a_bound_cursor(tmp_path):
    app, *_ = build(tmp_path, many_rows())
    client = login(app)
    page = client.get("/api/honeypot/sessions?limit=5").json["data"]
    assert page["total"] == 12 and len(page["items"]) == 5 and page["nextCursor"]
    starts = [i["startedAt"] for i in page["items"]]
    assert starts == sorted(starts, reverse=True)
    second = client.get("/api/honeypot/sessions?limit=5&cursor=" + page["nextCursor"]).json["data"]
    assert not {i["sessionId"] for i in page["items"]} & {i["sessionId"] for i in second["items"]}
    changed = client.get("/api/honeypot/sessions?limit=5&ip=10.0.2.55&cursor=" + page["nextCursor"])
    assert changed.status_code == 400 and changed.json["error"]["code"] == "INVALID_CURSOR"
    only = client.get("/api/honeypot/sessions?ip=10.0.2.55&limit=200").json["data"]
    assert only["total"] == 6 and {i["srcIp"] for i in only["items"]} == {"10.0.2.55"}
    assert client.get("/api/honeypot/sessions?intent=recon&limit=200").json["data"]["total"] == 4
    assert client.get("/api/honeypot/sessions?limit=0").status_code == 400
    assert client.get("/api/honeypot/sessions?intent=%3Cscript%3E").status_code == 400
    assert client.get("/api/honeypot/sessions?bogus=1").status_code == 400


def test_session_detail_masks_passwords_unless_an_operator_reveals_them(tmp_path):
    rows = session_events("a00000000001", "10.0.2.55", NOW - 600_000, [("cat /etc/passwd", "root:x:0:0")], AI,
                          users=(("root", "S3cret!"),))
    app, *_ = build(tmp_path, rows)
    url = "/api/honeypot/sessions/a00000000001"
    detail = login(app).get(url).json["data"]
    assert detail["authAttempts"] == [{"at": detail["authAttempts"][0]["at"], "user": "root", "passwordLength": 7, "password": None}]
    assert "S3cret!" not in json.dumps(detail) and detail["commands"][0]["response"] == "root:x:0:0"
    revealed = login(app).get(url + "?revealPasswords=true").json["data"]
    assert revealed["authAttempts"][0]["password"] == "S3cret!"
    with app.extensions["store"].connect() as db:
        audits = [r["action"] for r in db.execute("SELECT action FROM audit")]
    assert "honeypot-reveal-passwords" in audits
    denied = login(app, "view").get(url + "?revealPasswords=true")
    assert denied.status_code == 403
    assert login(app, "view").get(url).status_code == 200                       # 마스킹된 조회는 조회 전용 계정도 가능
    assert login(app).get("/api/honeypot/sessions/zzzz").status_code == 404
    assert login(app).get("/api/honeypot/sessions/ffffffffffff").json["error"]["code"] == "SESSION_NOT_FOUND"


def test_hostile_session_content_is_returned_as_plain_json_data(tmp_path):
    payload = "<img src=x onerror=alert(1)>"
    rows = session_events("a00000000001", "10.0.2.55", NOW - 600_000, [(payload, payload)],
                          {"summary": payload, "iocs": [payload], "intent": "recon", "severity": "high"},
                          users=((payload, payload),))
    app, *_ = build(tmp_path, rows)
    response = login(app).get("/api/honeypot/sessions/a00000000001")
    assert response.mimetype == "application/json" and response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.json["data"]["commands"][0]["command"] == payload           # 원문 그대로. 화면이 텍스트로만 그린다


def test_partial_when_log_lines_were_skipped(tmp_path):
    app, *_ = build(tmp_path, healthy_rows() + [{"timestamp": NOW - 1000, "message": "garbage"}])
    body = login(app).get("/api/honeypot/stats").json
    assert body["meta"]["partial"] is True and any("건너뛰었습니다" in w for w in body["meta"]["warnings"])


def test_stats_endpoint_returns_charts_and_graph(tmp_path):
    app, *_ = build(tmp_path, many_rows())
    data = login(app).get("/api/honeypot/stats").json["data"]
    assert data["totals"]["sessions"] == 12 and data["graph"]["nodes"] and data["timeline"]
    assert login(app).get("/api/honeypot/stats?from=2026-01-01T00:00:00Z").status_code == 400


# ---------------------------------------------------------------------------------------------
# ② 타임라인
# ---------------------------------------------------------------------------------------------

def test_timeline_shows_each_stage_and_marks_missing_ones_as_missing(tmp_path):
    rows = session_events("a00000000001", "10.0.2.55", NOW - 600_000, [("whoami", "root")], AI)
    action = {"actionId": "ssm-exec-b1", "createdAt": NOW - 500_000, "status": "SUCCESS", "decision": "auto-executed",
              "controlId": "HONEYPOT", "reason": "미끼 접속 1회", "resource": f"{NACL} ← 10.0.2.55/32",
              "executionId": "exec-b1"}
    gateway = FakeGateway([row()], {"10.0.2.55": 3})
    sources = FakeSources(rows)
    sources.transitions = [{"at": NOW - 540_000, "to": "ALARM"}]
    app, *_ = build(tmp_path, gateway=gateway, sources=sources,
                    provider=FakeProvider(sources, gateway, [action], {"exec-b1": "Success"}))
    data = login(app).get("/api/honeypot/timeline?ip=10.0.2.55").json["data"]
    assert [(s["key"], s["state"]) for s in data["steps"]] == [
        ("connect", "done"), ("auth", "done"), ("command", "done"), ("analysis", "done"), ("alarm", "done"),
        ("judge", "done"), ("ssm", "done"), ("nacl", "done")]
    empty = login(app).get("/api/honeypot/timeline?ip=10.0.9.9").json["data"]
    assert empty["steps"][0]["state"] == "missing"


def test_timeline_distinguishes_unreadable_from_missing(tmp_path):
    rows = session_events("a00000000001", "10.0.2.55", NOW - 600_000, [], None)
    gateway = FakeGateway()
    gateway.fail_nacl = True

    class Broken(FakeSources):
        def alarm_transitions(self, start, end):
            raise RuntimeError("AccessDenied")
    sources = Broken(rows)
    app, *_ = build(tmp_path, gateway=gateway, sources=sources)
    steps = {s["key"]: s for s in login(app).get("/api/honeypot/timeline?ip=10.0.2.55").json["data"]["steps"]}
    assert steps["alarm"]["state"] == "unknown" and steps["nacl"]["state"] == "unknown"
    assert steps["judge"]["state"] == "missing" and steps["command"]["state"] == "missing"
    assert login(app).get("/api/honeypot/timeline?ip=nope").status_code == 400


# ---------------------------------------------------------------------------------------------
# ⑥ 차단 IP 목록
# ---------------------------------------------------------------------------------------------

def listing(client, query=""):
    response = client.get("/api/blocklist" + query)
    assert response.status_code == 200, response.json
    return response.json


def test_list_compares_the_table_with_the_real_nacl(tmp_path):
    gateway = FakeGateway(
        [row("10.0.2.55"), row("10.0.2.56", rule_number=4, expires_at=NOW // 1000 - 60),
         row("10.0.2.57", rule_number=5, ssm_execution_id="exec-gone"),
         row("10.0.2.58", status="RELEASED", rule_number=6), row("10.0.2.59", status="FAILED", rule_number=7)],
        {"10.0.2.55": 3, "10.0.2.56": 4, "10.0.2.58": 6, "10.0.2.99": 8})
    app, *_ = build(tmp_path, healthy_rows(), gateway=gateway)
    body = listing(login(app))
    states = {i["ip"]: (i["state"], i["mismatch"]) for i in body["data"]["items"]}
    assert states == {"10.0.2.55": ("blocked", None), "10.0.2.56": ("expiring", None),
                      "10.0.2.57": ("mismatch", "nacl-missing"), "10.0.2.58": ("released", "nacl-still-blocked"),
                      "10.0.2.59": ("failed", None), "10.0.2.99": ("unrecorded", "record-missing")}
    counts = body["data"]["counts"]
    assert counts["blocked"] == 1 and counts["expiring"] == 1 and counts["mismatch"] == 3 and counts["unrecorded"] == 1
    assert body["data"]["canWrite"] is True and body["data"]["durations"][-1] == {"hours": 0, "label": "영구"}
    first = next(i for i in body["data"]["items"] if i["ip"] == "10.0.2.55")
    assert first["sessions"]["sessionCount"] == 1 and first["sessions"]["topCommands"][0]["key"] == "whoami"


def test_running_block_is_applying_not_a_mismatch(tmp_path):
    gateway = FakeGateway([row("10.0.2.57", rule_number=5, ssm_execution_id="exec-run")], {})
    app, provider, _ = build(tmp_path, gateway=gateway)
    provider.executions["exec-run"] = "InProgress"
    assert listing(login(app))["data"]["items"][0]["state"] == "applying"


def test_unreadable_nacl_shows_table_state_with_a_warning_not_a_guess(tmp_path):
    gateway = FakeGateway([row()], {"10.0.2.55": 3})
    gateway.fail_nacl = True
    app, *_ = build(tmp_path, gateway=gateway)
    body = listing(login(app))
    item = body["data"]["items"][0]
    assert item["inNacl"] is None and item["mismatch"] is None
    assert body["meta"]["partial"] is True and any("NACL 을 읽지 못해" in w for w in body["meta"]["warnings"])


def test_unreadable_honeypot_logs_leave_evidence_empty_with_a_warning(tmp_path):
    gateway = FakeGateway([row()], {"10.0.2.55": 3})
    app, *_ = build(tmp_path, gateway=gateway, sources=FakeSources(fail_logs=True))
    body = listing(login(app))
    assert body["data"]["items"][0]["sessions"] is None and body["meta"]["partial"] is True


def test_csv_and_json_reports_are_downloads_and_safe(tmp_path):
    hostile = session_events("a00000000001", "10.0.2.55", NOW - 600_000, [("=cmd|' /C calc'!A0", "x")], AI)
    gateway = FakeGateway([row()], {"10.0.2.55": 3})
    app, *_ = build(tmp_path, hostile, gateway=gateway)
    client = login(app)
    csv_response = client.get("/api/blocklist?format=csv")
    assert csv_response.mimetype == "text/csv" and "attachment" in csv_response.headers["Content-Disposition"]
    text = csv_response.get_data(as_text=True)
    assert text.startswith("﻿ip,state,source") and "\r\n10.0.2.55,blocked,HONEYPOT,3," in text
    assert "'=cmd" in text and ",=cmd" not in text                                   # 수식 주입 방지
    json_response = client.get("/api/blocklist?format=download")
    assert "attachment" in json_response.headers["Content-Disposition"] and json_response.json["data"]["items"]
    assert client.get("/api/blocklist?format=xml").status_code == 400


def test_list_needs_configuration_and_scope(tmp_path):
    app, provider, _ = build(tmp_path)
    provider.blocklist = None
    app.extensions["blocklist_service"].gateway = None
    assert login(app).get("/api/blocklist").json["error"]["code"] == "BLOCKLIST_NOT_CONFIGURED"
    app, *_ = build(tmp_path / "b")
    assert login(app, "scoped").get("/api/blocklist").status_code == 403


# --- 오탐 해제 ---------------------------------------------------------------------------------

def release_body(**over):
    return {"reason": "사내 보안 점검 도구의 정상 접속", "expectedVersion": 1, **over}


def test_release_starts_the_unblock_playbook_and_records_everything(tmp_path):
    gateway = FakeGateway([row()], {"10.0.2.55": 3})
    app, *_ = build(tmp_path, gateway=gateway)
    response = post(login(app), "/api/blocklist/10.0.2.55/release", release_body(allowlist=True))
    assert response.status_code == 202, response.json
    data = response.json["data"]
    assert data["state"] == "releasing" and data["executionId"] == "exec-1"
    assert gateway.started == [{"ip": "10.0.2.55", "nacl": NACL, "rule": 3, "seed": "10.0.2.55|k-1"}]
    saved = gateway.table["10.0.2.55"]
    assert saved["status"] == "RELEASING" and saved["allowlisted"] is True and saved["released_by"] == "op"
    assert saved["release_kind"] == "manual" and saved["unblock_execution_id"] == "exec-1"
    assert gateway.actions[0][:4] == ("10.0.2.55", NACL, 3, "exec-1") and gateway.actions[0][-1] == "UNBLOCK-MANUAL"
    with app.extensions["store"].connect() as db:
        audit = db.execute("SELECT actor,action,detail FROM audit WHERE action='blocklist-release'").fetchone()
    assert audit["actor"] == "op" and "exec-1" in audit["detail"] and "10.0.2.55" in audit["detail"]


def test_release_retry_with_the_same_key_does_not_start_a_second_execution(tmp_path):
    gateway = FakeGateway([row()], {"10.0.2.55": 3})
    app, *_ = build(tmp_path, gateway=gateway)
    client = login(app)
    first = post(client, "/api/blocklist/10.0.2.55/release", release_body())
    again = post(client, "/api/blocklist/10.0.2.55/release", release_body())
    assert again.status_code == first.status_code and again.json["data"] == first.json["data"]
    assert len(gateway.started) == 1
    other = post(client, "/api/blocklist/10.0.2.55/release", release_body(reason="다른 사유"))
    assert other.status_code == 409 and other.json["error"]["code"] == "IDEMPOTENCY_CONFLICT"
    third = post(client, "/api/blocklist/10.0.2.55/release", release_body(expectedVersion=3), key="k-2")
    assert third.status_code == 409 and third.json["error"]["code"] == "RELEASE_IN_PROGRESS"
    assert len(gateway.started) == 1


def test_lost_response_retry_finds_the_release_already_started(tmp_path):
    gateway = FakeGateway([row()], {"10.0.2.55": 3})
    app, *_ = build(tmp_path, gateway=gateway)
    client = login(app)
    post(client, "/api/blocklist/10.0.2.55/release", release_body())
    with app.extensions["store"].connect(write=True) as db:                    # 응답을 잃은 상황: 캐시가 없다
        db.execute("DELETE FROM requests")
    retry = post(client, "/api/blocklist/10.0.2.55/release", release_body())
    assert retry.status_code == 202 and retry.json["data"]["executionId"] == "exec-1" and len(gateway.started) == 1


def test_release_needs_the_operator_role_write_mode_and_fresh_version(tmp_path):
    gateway = FakeGateway([row()], {"10.0.2.55": 3})
    app, *_ = build(tmp_path, gateway=gateway)
    assert post(login(app, "view"), "/api/blocklist/10.0.2.55/release", release_body()).status_code == 403
    assert post(login(app, "appr"), "/api/blocklist/10.0.2.55/release", release_body()).json["error"]["code"] == "FORBIDDEN"
    assert post(login(app, "scoped"), "/api/blocklist/10.0.2.55/release", release_body()).status_code == 403
    stale = post(login(app), "/api/blocklist/10.0.2.55/release", release_body(expectedVersion=9))
    assert stale.status_code == 409 and stale.json["error"]["code"] == "VERSION_CONFLICT" and not gateway.started
    app, *_ = build(tmp_path / "ro", gateway=FakeGateway([row()], {"10.0.2.55": 3}), WRITE_ENABLED=False)
    assert post(login(app), "/api/blocklist/10.0.2.55/release", release_body()).json["error"]["code"] == "WRITE_DISABLED"


def test_release_without_csrf_or_key_or_json_is_refused(tmp_path):
    app, *_ = build(tmp_path, gateway=FakeGateway([row()], {"10.0.2.55": 3}))
    client = login(app)
    assert client.post("/api/blocklist/10.0.2.55/release", json=release_body()).json["error"]["code"] == "INVALID_IDEMPOTENCY_KEY"
    assert client.post("/api/blocklist/10.0.2.55/release", data="x", headers={"Idempotency-Key": "k"}).status_code == 400
    bare = app.test_client()
    bare.get("/api/auth/session")
    assert bare.post("/api/blocklist/10.0.2.55/release", json=release_body(), headers={"Idempotency-Key": "k"}).status_code == 401
    client.environ_base["HTTP_X_CSRF_TOKEN"] = "wrong"
    assert post(client, "/api/blocklist/10.0.2.55/release", release_body()).json["error"]["code"] == "CSRF_INVALID"


@pytest.mark.parametrize("ip", ["10.0.2.55%2F32", "999.1.1.1", "0.0.0.0", "10.0.2", "127.0.0.1", "224.0.0.1", "abc"])
def test_release_rejects_addresses_that_are_not_single_ipv4_hosts(tmp_path, ip):
    gateway = FakeGateway([row()], {"10.0.2.55": 3})
    app, *_ = build(tmp_path, gateway=gateway)
    assert post(login(app), f"/api/blocklist/{ip}/release", release_body()).status_code in {400, 404}
    assert not gateway.started


def test_write_roles_are_configurable_but_viewer_can_never_write(tmp_path):
    gateway = FakeGateway([row()], {"10.0.2.55": 3})
    app, *_ = build(tmp_path, gateway=gateway, BLOCKLIST_WRITE_ROLES=frozenset({"operator", "approver"}))
    listed = login(app, "appr").get("/api/blocklist").json["data"]
    assert listed["canWrite"] is True and login(app, "view").get("/api/blocklist").json["data"]["canWrite"] is False
    assert post(login(app, "appr"), "/api/blocklist/10.0.2.55/release", release_body()).status_code == 202
    assert post(login(app, "view"), "/api/blocklist/10.0.2.55/release", release_body(), "k-9").status_code == 403
    assert login(app, "appr").get("/api/honeypot/sessions/ffffffffffff?revealPasswords=true").status_code != 403
    for bad in ("viewer", "operator,viewer", "admin", ""):
        with pytest.raises(ValueError):
            create_app({"TESTING": True, "DATABASE": str(tmp_path / "x.sqlite3"), "SECRET_KEY": "s",
                        "BLOCKLIST_WRITE_ROLES": bad})


def test_release_body_is_validated(tmp_path):
    app, *_ = build(tmp_path, gateway=FakeGateway([row()], {"10.0.2.55": 3}))
    client = login(app)
    for body in ({}, {"reason": "", "expectedVersion": 1}, {"reason": "x" * 501, "expectedVersion": 1},
                 {"reason": "ok", "expectedVersion": "1"}, {"reason": "ok", "expectedVersion": 1, "extra": 1},
                 {"reason": "ok", "expectedVersion": 1, "allowlist": "yes"}, ["list"]):
        assert post(client, "/api/blocklist/10.0.2.55/release", body).status_code == 400, body


def test_release_when_nacl_rule_is_already_gone_only_finishes_the_record(tmp_path):
    gateway = FakeGateway([row()], {})
    app, *_ = build(tmp_path, gateway=gateway)
    response = post(login(app), "/api/blocklist/10.0.2.55/release", release_body())
    assert response.status_code == 200 and response.json["data"]["state"] == "released" and not gateway.started
    assert gateway.table["10.0.2.55"]["status"] == "RELEASED" and "이미 Deny 없음" in gateway.table["10.0.2.55"]["release_reason"]
    again = post(login(app), "/api/blocklist/10.0.2.55/release", release_body(expectedVersion=2), key="k-2")
    assert again.status_code == 409 and again.json["error"]["code"] == "ALREADY_RELEASED"


def test_release_of_a_manual_block_without_a_record_creates_one(tmp_path):
    gateway = FakeGateway([], {"10.0.2.99": 8})
    app, *_ = build(tmp_path, gateway=gateway)
    response = post(login(app), "/api/blocklist/10.0.2.99/release", release_body(expectedVersion=0))
    assert response.status_code == 202 and gateway.started[0]["rule"] == 8
    saved = gateway.table["10.0.2.99"]
    assert saved["status"] == "RELEASING" and saved["source"] == "MANUAL" and saved["nacl_id"] == NACL
    unknown = post(login(app), "/api/blocklist/10.0.2.98/release", release_body(expectedVersion=0), key="k-2")
    assert unknown.status_code == 404 and unknown.json["error"]["code"] == "IP_NOT_FOUND"


def test_release_reverts_and_keeps_the_block_when_ssm_cannot_start(tmp_path):
    gateway = FakeGateway([row()], {"10.0.2.55": 3})
    gateway.fail_start = True
    app, *_ = build(tmp_path, gateway=gateway)
    response = post(login(app), "/api/blocklist/10.0.2.55/release", release_body(allowlist=True))
    assert response.status_code == 502 and response.json["error"]["code"] == "UNBLOCK_START_FAILED"
    saved = gateway.table["10.0.2.55"]
    assert saved["status"] == "ACTIVE" and saved["allowlisted"] is False and "해제 시작 실패" in saved["last_error"]
    assert "10.0.2.55" in gateway.denies


def test_release_is_finished_by_the_next_listing_when_ssm_succeeds(tmp_path):
    gateway = FakeGateway([row()], {"10.0.2.55": 3})
    app, provider, _ = build(tmp_path, gateway=gateway)
    client = login(app)
    post(client, "/api/blocklist/10.0.2.55/release", release_body())
    provider.executions["exec-1"] = "InProgress"
    assert listing(client)["data"]["items"][0]["state"] == "releasing"
    provider.executions["exec-1"] = "Success"
    gateway.denies.clear()
    item = listing(client)["data"]["items"][0]
    assert item["state"] == "released" and gateway.table["10.0.2.55"]["status"] == "RELEASED" and item["mismatch"] is None


def test_failed_unblock_returns_the_row_to_blocked_and_says_why(tmp_path):
    gateway = FakeGateway([row()], {"10.0.2.55": 3})
    app, provider, _ = build(tmp_path, gateway=gateway)
    client = login(app)
    post(client, "/api/blocklist/10.0.2.55/release", release_body())
    provider.executions["exec-1"] = "Failed"
    item = listing(client)["data"]["items"][0]
    assert item["state"] == "blocked" and "Failed" in item["lastError"]


def test_release_stuck_without_an_execution_id_is_returned_to_blocked(tmp_path):
    stuck = row(status="RELEASING", release_request_key="k", updated_at="2026-01-01T00:00:00.000Z")
    stuck["updated_at"] = "2026-01-01T00:00:00.000Z"
    gateway = FakeGateway([stuck], {"10.0.2.55": 3})
    app, *_ = build(tmp_path, gateway=gateway)
    item = listing(login(app))["data"]["items"][0]
    assert item["state"] == "blocked" and "되돌림" in item["lastError"]


# --- 차단 기간·예외 등록 -------------------------------------------------------------------------

def patch(client, ip, body, key="p-1"):
    return post(client, f"/api/blocklist/{ip}", body, key, method="patch")


def test_changing_the_block_period_sets_or_clears_the_expiry(tmp_path):
    gateway = FakeGateway([row()], {"10.0.2.55": 3})
    app, *_ = build(tmp_path, gateway=gateway)
    client = login(app)
    before = now_ms() // 1000
    assert patch(client, "10.0.2.55", {"reason": "연장", "expectedVersion": 1, "durationHours": 168}).status_code == 200
    saved = gateway.table["10.0.2.55"]
    assert 168 * 3600 - 5 <= saved["expires_at"] - before <= 168 * 3600 + 5 and saved["expiry_changed_by"] == "op"
    assert patch(client, "10.0.2.55", {"reason": "영구", "expectedVersion": 2, "durationHours": 0}, "p-2").status_code == 200
    assert "expires_at" not in gateway.table["10.0.2.55"]
    item = listing(client)["data"]["items"][0]
    assert item["permanent"] is True and item["expiresAt"] is None


def test_allowlist_toggle_and_validation(tmp_path):
    gateway = FakeGateway([row(), row("10.0.2.58", status="RELEASED", rule_number=6)], {"10.0.2.55": 3})
    app, *_ = build(tmp_path, gateway=gateway)
    client = login(app)
    assert patch(client, "10.0.2.58", {"reason": "사내 도구", "expectedVersion": 1, "allowlisted": True}).status_code == 200
    assert gateway.table["10.0.2.58"]["allowlisted"] is True
    listed = {i["ip"]: i for i in listing(client)["data"]["items"]}
    assert listed["10.0.2.58"]["allowlisted"] is True and listed["10.0.2.58"]["state"] == "released"
    duration_on_released = patch(client, "10.0.2.58", {"reason": "x", "expectedVersion": 2, "durationHours": 24}, "p-2")
    assert duration_on_released.status_code == 409
    for body in ({"reason": "x", "expectedVersion": 1}, {"reason": "x", "expectedVersion": 1, "durationHours": 5},
                 {"reason": "x", "expectedVersion": 1, "durationHours": True},
                 {"reason": "x", "expectedVersion": 1, "allowlisted": "true"}):
        assert patch(client, "10.0.2.55", body, "p-3").status_code == 400, body
    assert patch(client, "10.0.2.77", {"reason": "x", "expectedVersion": 1, "allowlisted": True}, "p-4").status_code == 404
    stale = patch(client, "10.0.2.55", {"reason": "x", "expectedVersion": 7, "durationHours": 1}, "p-5")
    assert stale.status_code == 409 and stale.json["error"]["code"] == "VERSION_CONFLICT"
    assert patch(login(app, "view"), "10.0.2.55", {"reason": "x", "expectedVersion": 1, "durationHours": 1}).status_code == 403


def test_expiry_change_loses_to_a_concurrent_state_change(tmp_path):
    """만료 Lambda 가 먼저 RELEASING 으로 바꿨다면(버전·상태 변경) 기간 변경은 적용되지 않는다."""
    gateway = FakeGateway([row()], {"10.0.2.55": 3})
    app, *_ = build(tmp_path, gateway=gateway)
    real = gateway.row

    def racing(ip):
        found = real(ip)
        gateway.table[ip].update(status="RELEASING", version=2)       # 읽은 직후 다른 쪽이 갱신
        return found
    gateway.row = racing
    response = patch(login(app), "10.0.2.55", {"reason": "연장", "expectedVersion": 1, "durationHours": 24})
    assert response.status_code == 409 and gateway.table["10.0.2.55"]["status"] == "RELEASING"


# --- 병합 규칙 단위 ------------------------------------------------------------------------------

def test_merge_orders_recent_first_and_flags_rule_number_drift():
    rows = [normalize(row("10.0.2.55", blocked_at="2026-09-29T01:00:00Z")),
            normalize(row("10.0.2.56", blocked_at="2026-09-29T03:00:00Z", rule_number=4))]
    items = merge(rows, {"10.0.2.55": 9, "10.0.2.56": 4}, NOW)
    assert [i["ip"] for i in items] == ["10.0.2.56", "10.0.2.55"]
    assert items[1]["state"] == "mismatch" and items[1]["mismatch"] == "rule-changed"


def test_openapi_lists_exactly_the_honeypot_and_blocklist_routes(tmp_path):
    import re
    from pathlib import Path

    import yaml
    spec = yaml.safe_load((Path(__file__).resolve().parents[1] / "contracts" / "openapi.yaml").read_text(encoding="utf-8"))
    documented = {(re.sub(r"\{(\w+)\}", r"<\1>", path), method.upper()) for path, item in spec["paths"].items()
                  if path.startswith(("/api/honeypot", "/api/blocklist")) for method in item}
    app, *_ = build(tmp_path)
    implemented = {(re.sub(r"<(?:string:)?(\w+)>", r"<\1>", rule.rule), method)
                   for rule in app.url_map.iter_rules() if rule.rule.startswith(("/api/honeypot", "/api/blocklist"))
                   for method in rule.methods - {"HEAD", "OPTIONS"}}
    documented = {(re.sub(r"<\w+>", "<x>", p), m) for p, m in documented}
    implemented = {(re.sub(r"<\w+>", "<x>", p), m) for p, m in implemented}
    assert documented == implemented and len(implemented) == 8
