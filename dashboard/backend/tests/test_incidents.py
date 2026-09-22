"""침해사례 보드 — 설계안 12장 대시보드 파트의 '침해사례 탭'."""
from app.catalog import loader


def _get(client, path):
    response = client.get(path)
    assert response.status_code == 200, response.json
    return response.json


def test_every_catalog_scenario_has_a_case(client):
    data = _get(client, "/api/incidents")
    assert [i["scenario"] for i in data["items"]] == loader.ids()
    for item in data["items"]:
        # 서술이 비면 발표 화면이 빈칸으로 남는다. 카탈로그 누락을 여기서 잡는다.
        assert item["summary"], item["scenario"]
        assert item["attack"] and item["trace"], item["scenario"]
        assert item["impact"] and item["control"] and item["basis"], item["scenario"]


def test_stages_are_five_in_order(client):
    for item in _get(client, "/api/incidents")["items"]:
        assert [s["key"] for s in item["stages"]] == \
               ["attack", "detect", "approve", "execute", "verify"]


def test_attack_stage_never_auto_completes(client):
    """카탈로그에 절차가 적혀 있다고 '공격 재현'이 완료로 켜지면 안 된다."""
    for item in _get(client, "/api/incidents")["items"]:
        assert item["stages"][0]["done"] is False


def test_detect_stage_follows_real_events(client):
    for item in _get(client, "/api/incidents")["items"]:
        detect = next(s for s in item["stages"] if s["key"] == "detect")
        assert detect["done"] == bool(item["counts"]["total"])
        if detect["done"]:
            assert detect["at"] is not None


def test_unwired_playbook_is_visible(client):
    """ASR-HardenNginx 미배선이 화면 데이터에 그대로 드러나야 한다(README 5-1)."""
    item = next(i for i in _get(client, "/api/incidents")["items"] if i["scenario"] == "SEC-02")
    assert item["remediation"]["wired"] is False
    assert item["remediation"]["plannedMode"] == "AUTO"
    assert item["remediation"]["mode"] == "MANUAL"
    # 기획서는 자동으로 분류했지만 코드 기준은 수동이다. 이 차이가 화면 데이터에 남아야
    # 발표에서 "자동 3개"라고 말하지 않게 된다.
    assert item["remediation"]["plannedMode"] != item["remediation"]["mode"]


def test_unexecuted_unwired_playbook_says_so(client):
    """실행 이력이 없는 미배선 시나리오는 '미배선'을 이유로 내놔야 한다."""
    from app.adapters.demo import DEMO_NOW
    data = _get(client, f"/api/incidents?from={DEMO_NOW - 3600000}&to={DEMO_NOW}")
    unwired = [i for i in data["items"]
               if not i["remediation"]["wired"]
               and not next(s for s in i["stages"] if s["key"] == "execute")["done"]]
    assert unwired, "미배선이면서 미실행인 시나리오가 하나는 있어야 한다"
    for item in unwired:
        execute = next(s for s in item["stages"] if s["key"] == "execute")
        assert "미배선" in execute["detail"], item["scenario"]


def test_irreversible_playbook_is_flagged(client):
    item = next(i for i in _get(client, "/api/incidents")["items"] if i["scenario"] == "SEC-07")
    assert item["remediation"]["reversible"] is False


def test_time_filter_narrows_cases(client):
    from app.adapters.demo import DEMO_NOW
    wide = _get(client, f"/api/incidents?from={DEMO_NOW - 168 * 3600000}&to={DEMO_NOW}")
    narrow = _get(client, f"/api/incidents?from={DEMO_NOW - 3600000}&to={DEMO_NOW}")
    total = lambda d: sum(i["counts"]["total"] for i in d["items"])  # noqa: E731
    assert total(narrow) < total(wide)


def test_catalog_is_separate_from_behaviour_catalog():
    """서술 카탈로그를 고쳐도 탐지 분류는 바뀌지 않아야 한다."""
    assert loader.load_incidents()["incidents"].keys() <= set(loader.load()["scenarios"])
    assert loader.classify(config_rule="restricted-ssh") == "SEC-01"


# ── SEC-06 차단 계획 (NACL) ───────────────────────────────
def test_nacl_list_suggests_a_free_deny_rule_number(client):
    """화면이 acl-xxxx 와 빈 규칙 번호를 손으로 찾지 않게 서버가 제안한다."""
    data = _get(client, "/api/nacls")
    assert data["denyRuleRange"] == [1, 99]
    item = data["items"][0]
    assert item["id"] and item["suggestedRuleNumber"] not in item["usedDenyRuleNumbers"]
    assert 1 <= item["suggestedRuleNumber"] <= 99


def test_live_nacl_list_skips_used_numbers_and_defers_default_acl():
    from types import SimpleNamespace
    from app.adapters.live import LiveAdapter

    live = LiveAdapter(SimpleNamespace(AWS_REGION="ap-northeast-2", NAME_PREFIX="soar-sec-dev",
                                       CACHE_TTL={"metrics": 30}))
    live._call = lambda service, op, **kw: {"NetworkAcls": [
        {"NetworkAclId": "acl-default", "VpcId": "vpc-1", "IsDefault": True,
         "Associations": [], "Entries": [], "Tags": []},
        {"NetworkAclId": "acl-private", "VpcId": "vpc-1", "IsDefault": False,
         "Associations": [{"SubnetId": "subnet-app"}],
         "Tags": [{"Key": "Name", "Value": "private"}],
         "Entries": [{"RuleNumber": 1, "Egress": False}, {"RuleNumber": 2, "Egress": False},
                     {"RuleNumber": 100, "Egress": False}, {"RuleNumber": 1, "Egress": True}]},
    ]}
    items = live.nacls({})["items"]
    assert [i["id"] for i in items] == ["acl-private", "acl-default"], "기본 NACL 은 뒤로"
    private = items[0]
    assert private["usedDenyRuleNumbers"] == [1, 2], "100 번은 Allow 구간이라 제외"
    assert private["suggestedRuleNumber"] == 3
    assert private["name"] == "private" and private["subnets"] == ["subnet-app"]


def test_plan_is_rejected_in_demo_mode(client):
    """계획 설정은 실 AWS 검증이 필요하다. 데모에서는 명확히 막혀야 한다."""
    import uuid
    # 데모 이벤트에는 SEC-06 이 없다. 계획 설정이 모드로 막히는지만 본다.
    event = next(e for e in client.get("/api/snapshot").json["items"] if e.get("actionable"))
    response = client.post(
        f"/api/events/{event['id']}/plan",
        json={"expected_status": event["status"], "plan_hash": event["planHash"],
              "parameters": {"networkAclId": "acl-demo-private", "sourceIp": "203.0.113.45",
                             "ruleNumber": 3, "sourceEvidence": "데모"}},
        headers={"Idempotency-Key": str(uuid.uuid4())})
    assert response.status_code == 409
    assert response.json["code"] == "WRITE_DISABLED"


# ── 알림 발송 이력 (대시보드는 보내지 않는다) ─────────────
def test_dashboard_has_no_send_endpoint(demo_app):
    """설계안 5-2·5-3 기준 SNS 발행 주체는 CloudWatch 알람과 asr_trigger 다.
    대시보드에 발송 경로가 있으면 설계와 어긋난다."""
    rules = {str(r) for r in demo_app.url_map.iter_rules()}
    assert not [r for r in rules if "notify" in r or "notification" in r]


def test_events_carry_notification_history(client):
    items = client.get("/api/snapshot").json["items"]
    assert all("notification" in e for e in items)
    sent = [e for e in items if e["notification"]]
    assert sent, "알림이 발행된 이벤트가 하나는 있어야 한다"
    for event in sent:
        note = event["notification"]
        assert note["channel"] == "SNS"
        assert note["source"] in ("cloudwatch-alarm", "asr_trigger")
        assert note["at"] and note["reason"] and note["count"] >= 1


def test_cloudwatch_events_are_always_notified(client):
    """알람이 떴다는 것은 alarm_actions 가 이미 SNS 로 발행했다는 뜻이다."""
    items = client.get("/api/snapshot").json["items"]
    cw = [e for e in items if e["source"] == "CloudWatch"]
    assert cw and all(e["notification"]["source"] == "cloudwatch-alarm" for e in cw)


def test_resolved_auto_events_have_no_manual_notification(client):
    items = client.get("/api/snapshot").json["items"]
    auto_new = [e for e in items
                if e["mode"] == "AUTO" and e["source"] != "CloudWatch" and e["status"] == "NEW"]
    assert auto_new and all(e["notification"] is None for e in auto_new)
