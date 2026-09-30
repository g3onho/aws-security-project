"""전부 실행(start_all) 오케스트레이션 자가 점검.

가짜 provider 로 SEC-02/07(docker-host) + SEC-08(geo) + SEC-10(파리 EC2 전부, 대시보드 제외)
팬아웃과 SEC 라벨 표기, 그리고 중복 실행 방지(_active_run_all)를 검증한다.
실제 AWS·SSM 은 호출하지 않는다.
"""
import tempfile, os
import pytest
from soar.drills import DrillService, _step_label
from soar.errors import Problem
from soar.store import Store, now_ms


class FakeProvider:
    region = "ap-northeast-2"
    name_prefix = "proj"

    def __init__(self):
        self.sent = []
        self.sg_drills = []

    def discover_attackers(self, regions):
        return [{"regionLabel": "tokyo", "instanceId": "i-atk", "regionCode": "ap-northeast-1"}]

    def run_web_attack(self, targets, parameters):
        return [{"regionLabel": t["regionLabel"], "regionCode": t["regionCode"],
                 "instanceId": t["instanceId"], "commandId": "c-geo",
                 "runToken": f"tok-{t['regionLabel']}"} for t in targets]

    def merged_report(self, commands, bucket):
        # tokyo 는 "이미 올라간 것"처럼, 나머지는 아직 없는 것처럼 흉내낸다.
        out = {}
        for c in commands:
            if c["regionLabel"] == "tokyo":
                out[c["regionLabel"]] = {"ready": True, "analysisPrompt": "p", "steps": [{"step": "nmap", "output": "ok"}]}
            else:
                out[c["regionLabel"]] = {"ready": False, "reason": "아직 업로드 안 됨"}
        return out

    def discover_host_by_role(self, region, role, region_label="paris"):
        found = {"service-3tier": {"instanceId": "i-docker"},
                 "attack-simulation": {"instanceId": "i-atk-local"},
                 "database": {"instanceId": "i-db", "privateIp": "10.0.2.50"},
                 "honeypot-decoy": {"instanceId": "i-decoy", "privateIp": "10.0.1.115"}}.get(role)
        return {"regionLabel": "paris", "regionCode": region, **found} if found else None

    def discover_load_targets(self, region):
        # 대시보드는 이미 제외된 채로 온다(provider 가 Role=soar-dashboard 를 거른다).
        return [{"regionLabel": "docker-host", "regionCode": region, "instanceId": "i-docker"},
                {"regionLabel": "attacker", "regionCode": region, "instanceId": "i-atk-local"}]

    def send_commands(self, target, steps):
        out = []
        for s in steps:
            self.sent.append((target["instanceId"], s["documentName"], s["sec"], s.get("parameters")))
            out.append({"sec": s["sec"], "regionLabel": target["regionLabel"],
                        "regionCode": target["regionCode"], "instanceId": target["instanceId"],
                        "commandId": f"c-{s['sec']}"})
        return out

    def attack_command_status(self, commands):
        status = getattr(self, "status_override", "Success")
        return [{"regionLabel": c["regionLabel"], "status": status, "output": "ok"} for c in commands]

    def discover_sg_by_name(self, region, group_name):
        return {"proj-sec01-ssh-demo-sg": "sg-sec01",
                "proj-db-auto-sg": "sg-auto",
                "proj-db-manual-sg": "sg-manual"}.get(group_name)

    def run_sg_violation_drill(self, region, sg_id, port, sec, title, expect_revoked, region_label="paris"):
        self.sg_drills.append((sg_id, port, sec, region_label, expect_revoked))
        status = getattr(self, "sg_status_override", "Success")
        return {"sec": sec, "regionLabel": region_label, "status": status,
                "output": f"{sg_id} 0.0.0.0/0:{port} 재현 -> asr_trigger 호출"}

    def check_audit_sources(self, region):
        status = getattr(self, "audit_status_override", "Success")
        return {"sec": "SEC-09", "regionLabel": "paris", "status": status, "output": "ok"}


def _service(store, provider=None):
    cfg = {"documentName": "proj-ATK-WebAttack", "targetIp": "1.2.3.4",
           "webUrl": "http://alb:8081", "scanBucket": "bkt",
           "regions": ["ap-northeast-1"], "homeRegion": "ap-northeast-2"}
    return DrillService(store, provider or FakeProvider(), attack_config=cfg)


def test_start_all_fans_out_all_secs():
    with tempfile.TemporaryDirectory() as d:
        svc = _service(Store(os.path.join(d, "t.sqlite3")))
        result = svc.start_all({}, actor="tester")
        secs = {c["sec"] for c in result["launched"]}
        assert secs == {"SEC-01", "SEC-02", "SEC-03", "SEC-04", "SEC-06A", "SEC-07", "SEC-08",
                        "SEC-09", "SEC-10", "HONEYPOT"}, secs
        # SEC-03 은 db-auto-sg(자동) · db-manual-sg(대조군)로 팬아웃 → 2건.
        sec03 = [c for c in result["launched"] if c["sec"] == "SEC-03"]
        assert len(sec03) == 2, sec03
        # SEC-10 은 파리 EC2(대시보드 제외) 전부로 팬아웃 → 2건.
        sec10 = [c for c in result["launched"] if c["sec"] == "SEC-10"]
        assert len(sec10) == 2, sec10
        assert not result["skipped"], result["skipped"]


def test_all_status_labels_use_sec_not_region():
    with tempfile.TemporaryDirectory() as d:
        svc = _service(Store(os.path.join(d, "t.sqlite3")))
        run = svc.start_all({}, actor="tester")
        status = svc.all_status(run["runId"])
        labels = {row["label"] for row in status["items"]}
        assert "SEC-02" in labels and "SEC-07" in labels
        assert "SEC-08 · 도쿄" in labels          # geo: 출발 지역
        assert "SEC-10 · docker-host" in labels    # 부하: 대상 EC2
        assert all(row["status"] == "Success" for row in status["items"])


def test_skips_geo_when_not_configured():
    with tempfile.TemporaryDirectory() as d:
        svc = _service(Store(os.path.join(d, "t.sqlite3")))
        svc.attack_config["regions"] = []  # geo 미설정
        result = svc.start_all({}, actor="tester")
        assert all(c["sec"] != "SEC-08" for c in result["launched"])
        assert any("SEC-08" in s for s in result["skipped"])


def test_step_label():
    assert _step_label({"sec": "SEC-07"}) == "SEC-07"
    assert _step_label({"sec": "SEC-08", "regionLabel": "singapore"}) == "SEC-08 · 싱가포르"
    assert _step_label({"sec": "SEC-10", "regionLabel": "db"}) == "SEC-10 · db"
    assert _step_label({"sec": "SEC-03", "regionLabel": "auto"}) == "SEC-03 · auto"
    assert _step_label({"sec": "SEC-03", "regionLabel": "manual"}) == "SEC-03 · manual"


def test_mysql_bruteforce_runs_from_inner_attacker_to_db_private_ip():
    with tempfile.TemporaryDirectory() as d:
        svc = _service(Store(os.path.join(d, "t.sqlite3")))
        svc.start_all({}, actor="tester")
        runs = [s for s in svc.provider.sent if s[2] == "SEC-06A"]
        assert len(runs) == 1
        instance, document, _, params = runs[0]
        assert instance == "i-atk-local" and document == "ATK-MysqlBruteForce"  # 파리(홈 리전) VPC 안 공격자에서 실행
        assert params["DbHost"] == "10.0.2.50"                                  # DB 사설 IP 를 런타임 탐색


def test_mysql_bruteforce_skipped_without_db():
    with tempfile.TemporaryDirectory() as d:
        svc = _service(Store(os.path.join(d, "t.sqlite3")))
        orig = svc.provider.discover_host_by_role
        svc.provider.discover_host_by_role = lambda r, role, region_label="paris": \
            None if role == "database" else orig(r, role, region_label)
        result = svc.start_all({}, actor="tester")
        assert all(c["sec"] != "SEC-06A" for c in result["launched"])
        assert any("SEC-06A" in s for s in result["skipped"])


def test_sec01_reproduces_violation_on_dedicated_sg():
    with tempfile.TemporaryDirectory() as d:
        svc = _service(Store(os.path.join(d, "t.sqlite3")))
        svc.start_all({}, actor="tester")
        runs = [c for c in svc.provider.sg_drills if c[2] == "SEC-01"]
        assert len(runs) == 1
        sg_id, port, _, region_label, expect_revoked = runs[0]
        assert sg_id == "sg-sec01" and port == 22 and expect_revoked is True and region_label == "paris"


def test_sec01_skipped_without_demo_sg():
    with tempfile.TemporaryDirectory() as d:
        svc = _service(Store(os.path.join(d, "t.sqlite3")))
        orig = svc.provider.discover_sg_by_name
        svc.provider.discover_sg_by_name = lambda r, name: None if "sec01" in name else orig(r, name)
        result = svc.start_all({}, actor="tester")
        assert all(c["sec"] != "SEC-01" for c in result["launched"])
        assert any("SEC-01" in s for s in result["skipped"])


def test_sec03_compares_auto_and_manual_sg():
    with tempfile.TemporaryDirectory() as d:
        svc = _service(Store(os.path.join(d, "t.sqlite3")))
        svc.start_all({}, actor="tester")
        runs = {(c[0], c[3]): c[4] for c in svc.provider.sg_drills if c[2] == "SEC-03"}
        assert runs[("sg-auto", "auto")] is True      # 자동 회수 대상 — 회수돼야 성공
        assert runs[("sg-manual", "manual")] is False  # 대조군 — 남아 있어야 성공


def test_sec03_skipped_without_db_sgs():
    with tempfile.TemporaryDirectory() as d:
        svc = _service(Store(os.path.join(d, "t.sqlite3")))
        orig = svc.provider.discover_sg_by_name
        svc.provider.discover_sg_by_name = lambda r, name: None if "db-" in name else orig(r, name)
        result = svc.start_all({}, actor="tester")
        assert all(c["sec"] != "SEC-03" for c in result["launched"])
        assert any("SEC-03" in s for s in result["skipped"])


def test_sec09_checks_audit_sources():
    with tempfile.TemporaryDirectory() as d:
        svc = _service(Store(os.path.join(d, "t.sqlite3")))
        result = svc.start_all({}, actor="tester")
        sec09 = [c for c in result["launched"] if c["sec"] == "SEC-09"]
        assert len(sec09) == 1 and sec09[0]["status"] == "Success"


def test_honeypot_probe_runs_from_inner_attacker_to_decoy_private_ip():
    with tempfile.TemporaryDirectory() as d:
        svc = _service(Store(os.path.join(d, "t.sqlite3")))
        svc.start_all({}, actor="tester")
        probes = [s for s in svc.provider.sent if s[2] == "HONEYPOT"]
        assert len(probes) == 1
        instance, document, _, params = probes[0]
        assert instance == "i-atk-local" and document == "ATK-HoneypotProbe"  # 파리(홈 리전) VPC 안 공격자에서 실행
        assert params["HoneypotHost"] == "10.0.1.115"                          # 미끼 사설 IP 를 런타임 탐색


def test_honeypot_probe_skipped_without_decoy():
    with tempfile.TemporaryDirectory() as d:
        svc = _service(Store(os.path.join(d, "t.sqlite3")))
        orig = svc.provider.discover_host_by_role
        svc.provider.discover_host_by_role = lambda r, role, region_label="paris": \
            None if role == "honeypot-decoy" else orig(r, role, region_label)
        result = svc.start_all({}, actor="tester")
        assert all(c["sec"] != "HONEYPOT" for c in result["launched"])
        assert any("HONEYPOT" in s for s in result["skipped"])


def test_honeypot_label():
    assert _step_label({"sec": "HONEYPOT", "regionLabel": "paris"}) == "HONEYPOT · 내부 침투"


# --- 중복 실행 방지(2026-09-29 뭄바이·도쿄 SSM 에이전트 다운 사고 재발 방지) ---------------

def test_start_all_rejects_while_previous_run_still_in_progress():
    with tempfile.TemporaryDirectory() as d:
        provider = FakeProvider()
        svc = _service(Store(os.path.join(d, "t.sqlite3")), provider=provider)
        provider.status_override = "InProgress"
        svc.start_all({}, actor="tester")  # 1회차: 아직 안 끝난 채로 남는다
        with pytest.raises(Problem) as exc:
            svc.start_all({}, actor="tester")  # 2회차: 막혀야 한다
        assert exc.value.status == 409
        assert exc.value.code == "RUN_ALREADY_ACTIVE"


def test_start_all_allows_new_run_once_previous_one_terminates():
    with tempfile.TemporaryDirectory() as d:
        provider = FakeProvider()
        svc = _service(Store(os.path.join(d, "t.sqlite3")), provider=provider)
        provider.status_override = "InProgress"
        svc.start_all({}, actor="tester")
        provider.status_override = "Success"  # 이제 다 끝났다고 가정
        result = svc.start_all({}, actor="tester")  # 막히지 않아야 한다
        assert result["launched"]


def test_start_all_allows_new_run_when_previous_one_is_stale():
    with tempfile.TemporaryDirectory() as d:
        provider = FakeProvider()
        svc = _service(Store(os.path.join(d, "t.sqlite3")), provider=provider)
        # DrillRuns.save 는 insert-only 라 start_all 을 두 번 부르는 대신 방치된 이전 실행을 직접 심는다.
        svc.runs.save({"runId": "stale-run", "type": "run-all", "actor": "tester",
                       "startedAt": now_ms() - 41 * 60 * 1000,  # 40분 방치 기준을 넘김
                       "secs": ["SEC-10"], "skipped": [],
                       "commands": [{"sec": "SEC-10", "regionLabel": "db", "instanceId": "i-x"}]})
        provider.status_override = "InProgress"  # 살아있었다면 여전히 안 끝난 것처럼 보일 상태
        result = svc.start_all({}, actor="tester")  # 방치된 것으로 보고 막지 않아야 한다
        assert result["launched"]


def test_all_status_marks_stale_run_as_timed_out():
    """에이전트가 죽어 InProgress 에 묶인 실행은 40분 뒤 시간초과로 표기한다."""
    with tempfile.TemporaryDirectory() as d:
        provider = FakeProvider()
        svc = _service(Store(os.path.join(d, "t.sqlite3")), provider=provider)
        svc.runs.save({"runId": "stale-run", "type": "run-all", "actor": "tester",
                       "startedAt": now_ms() - 41 * 60 * 1000,
                       "secs": ["SEC-08"], "skipped": [],
                       "commands": [{"sec": "SEC-08", "regionLabel": "tokyo", "instanceId": "i-x"}]})
        provider.status_override = "InProgress"
        row = svc.all_status("stale-run")["items"][0]
        assert row["label"] == "SEC-08 · 도쿄"
        assert row["status"] == "TimedOut", row
        assert row["staleFrom"] == "InProgress"


def test_all_status_keeps_fresh_run_running():
    """아직 40분이 안 됐으면 건드리지 않는다(정상 실행을 시간초과로 위장하지 않는다)."""
    with tempfile.TemporaryDirectory() as d:
        provider = FakeProvider()
        svc = _service(Store(os.path.join(d, "t.sqlite3")), provider=provider)
        provider.status_override = "InProgress"
        run = svc.start_all({}, actor="tester")
        rows = svc.all_status(run["runId"])["items"]
        assert all(row["status"] == "InProgress" for row in rows), rows


# --- 보고서(merged_report) — 출력 파싱이 아니라 runToken 으로 S3 키를 바로 안다 -------------

def test_report_merges_regions_by_run_token():
    with tempfile.TemporaryDirectory() as d:
        svc = _service(Store(os.path.join(d, "t.sqlite3")))
        run = svc.start_all({}, actor="tester")
        report = svc.report(run["runId"])
        assert report["regions"]["tokyo"]["ready"] is True
        assert report["regions"]["tokyo"]["steps"][0]["step"] == "nmap"


def test_report_empty_when_no_sec08():
    with tempfile.TemporaryDirectory() as d:
        svc = _service(Store(os.path.join(d, "t.sqlite3")))
        svc.attack_config["regions"] = []  # geo 미설정 → SEC-08 없음
        run = svc.start_all({}, actor="tester")
        report = svc.report(run["runId"])
        assert report["regions"] == {}
