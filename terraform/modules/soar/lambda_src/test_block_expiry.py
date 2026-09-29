"""block_expiry 검증 (v25 · DEC-021) — 만료된 차단만 해제하고, 실패·충돌·NACL 불일치에서 안전한지 확인한다.

lambda_src/ 바로 아래에 둡니다(archive_file 은 block_expiry/ 하위만 압축하므로 Lambda zip 에 들어가지 않습니다).
다른 Lambda 테스트와 모듈 이름(handler)이 겹치므로 파일별로 실행합니다.

    AWS_DEFAULT_REGION=ap-northeast-2 python modules/soar/lambda_src/test_block_expiry.py
"""
import os
import sys
import time
from pathlib import Path

from botocore.exceptions import ClientError

os.environ.setdefault("AWS_REGION", "ap-northeast-2")
os.environ.setdefault("AWS_DEFAULT_REGION", "ap-northeast-2")
os.environ.update(IP_BLOCKLIST_TABLE="bl", REMEDIATION_ACTIONS_TABLE="actions", DOC_UNBLOCK_IP="ASR-UnblockIpWithNacl",
                  AUTOMATION_ROLE_ARN="arn:aws:iam::111122223333:role/auto", SNS_TOPIC_ARN="arn:aws:sns:x:1:t")

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parent / "block_expiry"))
sys.modules.pop("handler", None)
import handler  # noqa: E402

NOW = int(time.time())
NACL = "acl-0123456789abcdef0"


class FakeTable:
    """이 함수가 쓰는 식(SET·REMOVE·if_not_exists 버전 증가·'#s = :x AND version = :v' 조건)만 해석한다."""
    def __init__(self, rows=None):
        self.rows = {r["ip"]: dict(r) for r in (rows or [])}
        self.puts = []

    def scan(self, **kw):
        return {"Items": [dict(r) for r in self.rows.values()]}

    def put_item(self, Item):
        self.puts.append(Item)

    def update_item(self, Key, UpdateExpression, ExpressionAttributeValues, ExpressionAttributeNames=None,
                    ConditionExpression=None):
        row = self.rows[Key["ip"]]
        names, values = ExpressionAttributeNames or {}, ExpressionAttributeValues
        resolve = lambda n: names.get(n, n)
        if ConditionExpression:
            for clause in ConditionExpression.split(" AND "):
                left, right = [x.strip() for x in clause.split("=")]
                if row.get(resolve(left)) != values[right]:
                    raise ClientError({"Error": {"Code": "ConditionalCheckFailedException"}}, "UpdateItem")
        set_part, _, remove_part = UpdateExpression.partition(" REMOVE ")
        assert set_part.startswith("SET ")
        for assignment in set_part[4:].replace("if_not_exists(version, :zero)", "IFNE").split(", "):
            left, right = [x.strip() for x in assignment.split(" = ", 1)]
            row[resolve(left)] = (row.get("version", values[":zero"]) + values[":one"]) if right.startswith("IFNE") \
                else values[right]
        for name in [x.strip() for x in remove_part.split(",")] if remove_part else []:
            row.pop(resolve(name), None)


class Fakes:
    def __init__(self, rows, nacl_entries=None, ssm_status="Success", fail_start=False):
        self.table, self.started, self.sent = FakeTable(rows), [], []
        fakes = self
        handler.dynamodb = type("D", (), {"Table": lambda _s, name: fakes.table})()
        handler.sns = type("S", (), {"publish": lambda _s, **kw: fakes.sent.append(kw)})()
        entries = nacl_entries if nacl_entries is not None else [
            {"RuleNumber": 3, "RuleAction": "deny", "Egress": False, "CidrBlock": "10.0.2.55/32"},
            {"RuleNumber": 100, "RuleAction": "allow", "Egress": False, "CidrBlock": "10.0.0.0/16"}]
        handler.ec2 = type("E", (), {"describe_network_acls": lambda _s, **kw: {"NetworkAcls": [{"Entries": entries}]}})()

        def start(_s, **kw):
            if fail_start:
                raise RuntimeError("AccessDenied")
            fakes.started.append(kw)
            return {"AutomationExecutionId": f"exec-{len(fakes.started)}"}
        handler.ssm = type("M", (), {
            "start_automation_execution": start,
            "get_automation_execution": lambda _s, AutomationExecutionId: {
                "AutomationExecution": {"AutomationExecutionStatus": ssm_status}}})()


def row(ip="10.0.2.55", **kw):
    base = {"ip": ip, "status": "ACTIVE", "rule_number": 3, "nacl_id": NACL, "source": "HONEYPOT", "version": 1,
            "expires_at": NOW - 60, "allowlisted": False}
    base.update(kw)
    return base


def test_expired_active_row_starts_unblock_and_becomes_releasing():
    f = Fakes([row()])
    out = handler.handler({}, None)
    assert out["released"][0]["result"] == "releasing"
    p = f.started[0]
    assert p["DocumentName"] == "ASR-UnblockIpWithNacl"
    assert p["Parameters"]["AttackerCidr"] == ["10.0.2.55/32"] and p["Parameters"]["RuleNumber"] == ["3"]
    assert p["Parameters"]["NetworkAclId"] == [NACL]
    saved = f.table.rows["10.0.2.55"]
    assert saved["status"] == "RELEASING" and saved["unblock_execution_id"] == "exec-1" and saved["release_kind"] == "expiry"
    assert saved["release_attempts"] == 1 and saved["version"] == 2
    audit = f.table.puts[0]
    assert audit["action_id"] == "ssm-exec-1" and audit["control_id"] == "UNBLOCK-EXPIRY" and audit["status"] == "IN_PROGRESS"


def test_not_yet_expired_and_permanent_rows_are_left_alone():
    permanent = row("10.0.2.56")
    del permanent["expires_at"]
    f = Fakes([row("10.0.2.55", expires_at=NOW + 600), permanent])
    handler.handler({}, None)
    assert not f.started and {r["status"] for r in f.table.rows.values()} == {"ACTIVE"}


def test_only_active_rows_expire():
    f = Fakes([row(status="RELEASED"), row("10.0.2.56", status="FAILED"), row("10.0.2.57", status="EXPIRED")])
    handler.handler({}, None)
    assert not f.started


def test_rule_already_gone_from_nacl_is_finished_without_calling_ssm():
    f = Fakes([row()], nacl_entries=[{"RuleNumber": 100, "RuleAction": "allow", "Egress": False, "CidrBlock": "10.0.0.0/16"}])
    out = handler.handler({}, None)
    assert out["released"][0]["result"] == "expired-no-rule" and not f.started
    saved = f.table.rows["10.0.2.55"]
    assert saved["status"] == "EXPIRED" and "이미 없음" in saved["release_reason"]


def test_reused_rule_number_for_another_ip_is_never_deleted():
    other = [{"RuleNumber": 3, "RuleAction": "deny", "Egress": False, "CidrBlock": "10.0.9.9/32"}]
    f = Fakes([row()], nacl_entries=other)
    out = handler.handler({}, None)
    assert out["released"][0]["result"] == "expired-no-rule" and not f.started


def test_releasing_row_finishes_as_expired_or_released():
    f = Fakes([row(status="RELEASING", unblock_execution_id="exec-9", release_kind="expiry"),
               row("10.0.2.56", status="RELEASING", unblock_execution_id="exec-8", release_kind="manual")])
    handler.handler({}, None)
    assert f.table.rows["10.0.2.55"]["status"] == "EXPIRED" and f.table.rows["10.0.2.56"]["status"] == "RELEASED"
    assert "released_at" in f.table.rows["10.0.2.55"]


def test_failed_unblock_reverts_to_active_and_notifies():
    f = Fakes([row(status="RELEASING", unblock_execution_id="exec-9", release_kind="expiry", expires_at=NOW + 5)],
              ssm_status="Failed")
    out = handler.handler({}, None)
    saved = f.table.rows["10.0.2.55"]
    assert out["finished"][0]["result"] == "reverted" and saved["status"] == "ACTIVE" and "Failed" in saved["last_error"]
    assert f.sent and "해제 실패" in f.sent[0]["Subject"]


def test_in_progress_unblock_is_left_alone():
    f = Fakes([row(status="RELEASING", unblock_execution_id="exec-9", release_kind="expiry")], ssm_status="InProgress")
    out = handler.handler({}, None)
    assert out["finished"][0]["result"] == "in-progress" and f.table.rows["10.0.2.55"]["status"] == "RELEASING"


def test_repeated_failures_stop_after_max_attempts():
    f = Fakes([row(release_attempts=handler.MAX_ATTEMPTS)])
    out = handler.handler({}, None)
    assert out["released"][0]["result"] == "manual" and not f.started


def test_concurrent_change_wins_over_expiry():
    """대시보드가 먼저 버전을 올렸다면(예: 기간 연장) 이 함수의 조건부 갱신은 적용되지 않는다."""
    f = Fakes([row()])
    original = f.table.update_item

    def racing(**kw):
        f.table.rows["10.0.2.55"]["version"] = 5          # 스캔 뒤 다른 쪽이 갱신
        return original(**kw)
    f.table.update_item = racing
    out = handler.handler({}, None)
    assert out["released"][0]["result"] == "conflict" and f.table.rows["10.0.2.55"]["status"] == "ACTIVE"


def test_release_stuck_without_execution_id_is_returned_to_active_after_a_wait():
    old = "2026-01-01T00:00:00.000Z"
    recent = handler._now()
    f = Fakes([row(status="RELEASING", release_kind="manual", updated_at=old),
               row("10.0.2.56", status="RELEASING", release_kind="manual", updated_at=recent)])
    out = handler.handler({}, None)
    assert f.table.rows["10.0.2.55"]["status"] == "ACTIVE" and "되돌림" in f.table.rows["10.0.2.55"]["last_error"]
    assert f.table.rows["10.0.2.56"]["status"] == "RELEASING"     # 방금 시작한 해제는 기다린다
    assert {r["result"] for r in out["finished"]} == {"reverted", "skipped"}


def test_one_failing_row_does_not_stop_the_others():
    f = Fakes([row(), row("10.0.2.56", nacl_id=None)], fail_start=True)
    out = handler.handler({}, None)
    assert out["errors"] and out["released"][0]["result"] == "skipped"


if __name__ == "__main__":
    count = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            count += 1
    print(f"ok - block_expiry {count}건 통과")
