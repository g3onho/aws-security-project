"""전부 실행(start_all) 오케스트레이션 자가 점검.

가짜 provider 로 SEC-02/07(docker-host) + SEC-08(geo) + SEC-10(서울 EC2 전부, 대시보드 제외)
팬아웃과 SEC 라벨 표기를 검증한다. 실제 AWS·SSM 은 호출하지 않는다.
"""
import tempfile, os
from soar.drills import DrillService, _step_label
from soar.store import Store


class FakeProvider:
    region = "ap-northeast-2"

    def __init__(self):
        self.sent = []

    def discover_attackers(self, regions):
        return [{"regionLabel": "tokyo", "instanceId": "i-atk", "regionCode": "ap-northeast-1"}]

    def run_web_attack(self, targets, parameters):
        return [{"regionLabel": t["regionLabel"], "regionCode": t["regionCode"],
                 "instanceId": t["instanceId"], "commandId": "c-geo"} for t in targets]

    def discover_host_by_role(self, region, role, region_label="seoul"):
        found = {"service-3tier": {"instanceId": "i-docker"},
                 "attack-simulation": {"instanceId": "i-atk-local"},
                 "honeypot-decoy": {"instanceId": "i-decoy", "privateIp": "10.0.1.115"}}.get(role)
        return {"regionLabel": "seoul", "regionCode": region, **found} if found else None

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
        return [{"regionLabel": c["regionLabel"], "status": "Success", "output": "ok"} for c in commands]


def _service(store):
    cfg = {"documentName": "proj-ATK-WebAttack", "targetIp": "1.2.3.4",
           "webUrl": "http://alb:8081", "scanBucket": "bkt",
           "regions": ["ap-northeast-1"], "homeRegion": "ap-northeast-2"}
    return DrillService(store, FakeProvider(), attack_config=cfg)


def test_start_all_fans_out_all_secs():
    with tempfile.TemporaryDirectory() as d:
        svc = _service(Store(os.path.join(d, "t.sqlite3")))
        result = svc.start_all({}, actor="tester")
        secs = {c["sec"] for c in result["launched"]}
        assert secs == {"SEC-02", "SEC-04", "SEC-07", "SEC-08", "SEC-10", "HONEYPOT"}, secs
        # SEC-10 은 서울 EC2(대시보드 제외) 전부로 팬아웃 → 2건.
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


def test_honeypot_probe_runs_from_inner_attacker_to_decoy_private_ip():
    with tempfile.TemporaryDirectory() as d:
        svc = _service(Store(os.path.join(d, "t.sqlite3")))
        svc.start_all({}, actor="tester")
        probes = [s for s in svc.provider.sent if s[2] == "HONEYPOT"]
        assert len(probes) == 1
        instance, document, _, params = probes[0]
        assert instance == "i-atk-local" and document == "ATK-HoneypotProbe"  # 서울 VPC 안 공격자에서 실행
        assert params["HoneypotHost"] == "10.0.1.115"                          # 미끼 사설 IP 를 런타임 탐색


def test_honeypot_probe_skipped_without_decoy():
    with tempfile.TemporaryDirectory() as d:
        svc = _service(Store(os.path.join(d, "t.sqlite3")))
        orig = svc.provider.discover_host_by_role
        svc.provider.discover_host_by_role = lambda r, role, region_label="seoul": \
            None if role == "honeypot-decoy" else orig(r, role, region_label)
        result = svc.start_all({}, actor="tester")
        assert all(c["sec"] != "HONEYPOT" for c in result["launched"])
        assert any("HONEYPOT" in s for s in result["skipped"])


def test_honeypot_label():
    assert _step_label({"sec": "HONEYPOT", "regionLabel": "seoul"}) == "HONEYPOT · 내부 침투"
