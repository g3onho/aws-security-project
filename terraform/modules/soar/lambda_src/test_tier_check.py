"""tier_check 검증 — 점검 출력 해석, 대상·SSM 실패 시 확인 불가 기록, 늦은 결과가 새 결과를 덮지 않는지 확인한다.

lambda_src/ 바로 아래에 둡니다(archive_file 은 tier_check/ 하위만 압축하므로 Lambda zip 에 들어가지 않습니다).
다른 Lambda 테스트와 모듈 이름(handler)이 겹치므로 파일별로 실행합니다.

    AWS_DEFAULT_REGION=ap-northeast-2 python modules/soar/lambda_src/test_tier_check.py
"""
import os
import sys
from pathlib import Path

from botocore.exceptions import ClientError

os.environ.setdefault("AWS_REGION", "ap-northeast-2")
os.environ.setdefault("AWS_DEFAULT_REGION", "ap-northeast-2")
os.environ.update(TIER_STATUS_TABLE="tier-status", TIER_CHECK_DOCUMENT="TIER-Check", TIER_STALE_AFTER_SECONDS="900")

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parent / "tier_check"))
sys.modules.pop("handler", None)
import handler  # noqa: E402

GOOD = ("TIER|web|healthy|컨테이너 실행 중, /health 응답 200\n"
        "TIER|app|degraded|5000 포트가 응답하지 않습니다\n"
        "TIER|db|unhealthy|healthcheck 실패\n")


def error(code):
    return ClientError({"Error": {"Code": code, "Message": "x"}}, "op")


class FakeEc2:
    def __init__(self, ids):
        self.ids = ids

    def get_paginator(self, name):
        outer = self

        class Paginator:
            def paginate(self, **kw):
                assert {"Name": "tag:Role", "Values": ["service-3tier"]} in kw["Filters"]
                assert {"Name": "instance-state-name", "Values": ["running"]} in kw["Filters"]
                return [{"Reservations": [{"Instances": [{"InstanceId": i} for i in outer.ids]}]}]
        return Paginator()


class FakeSsm:
    def __init__(self, invocations=None, send_error=None):
        self.invocations = list(invocations or [])
        self.send_error = send_error
        self.sent = []

    def send_command(self, **kw):
        if self.send_error:
            raise self.send_error
        self.sent.append(kw)
        return {"Command": {"CommandId": "cmd-1"}}

    def get_command_invocation(self, **kw):
        item = self.invocations.pop(0) if len(self.invocations) > 1 else self.invocations[0]
        if isinstance(item, Exception):
            raise item
        return item


class FakeTable:
    def __init__(self, existing=None):
        self.rows = dict(existing or {})

    def put_item(self, Item, ConditionExpression=None, ExpressionAttributeValues=None):
        old = self.rows.get(Item["tier_id"])
        if old and not old["checked_at"] <= ExpressionAttributeValues[":at"]:
            raise error("ConditionalCheckFailedException")
        self.rows[Item["tier_id"]] = Item


class FakeDynamo:
    def __init__(self, table):
        self.table = table

    def Table(self, name):
        assert name == "tier-status"
        return self.table


def setup(ids=("i-0aaa",), ssm=None, table=None):
    handler.ec2 = FakeEc2(ids)
    handler.ssm = ssm or FakeSsm([{"Status": "Success", "StandardOutputContent": GOOD}])
    handler.dynamodb = FakeDynamo(table or FakeTable())
    handler.time.sleep = lambda seconds: None
    return handler.dynamodb.table


def test_parse_output_keeps_only_valid_tier_lines():
    got = handler.parse_output(GOOD + "garbage\nTIER|cache|healthy|x\nTIER|web|fine|x\nTIER|db|healthy\n")
    assert got == {"web": ("healthy", "컨테이너 실행 중, /health 응답 200"), "app": ("degraded", "5000 포트가 응답하지 않습니다"),
                   "db": ("unhealthy", "healthcheck 실패")}
    assert handler.parse_output(None) == {}


def test_success_stores_three_rows_with_freshness_fields():
    table = setup()
    result = handler.handler({}, None)
    assert result["ok"] and result["saved"] == 3
    assert {k: v["status"] for k, v in table.rows.items()} == {"tier/web": "healthy", "tier/app": "degraded", "tier/db": "unhealthy"}
    row = table.rows["tier/web"]
    assert row["instance_id"] == "i-0aaa" and row["command_id"] == "cmd-1" and row["stale_after_seconds"] == 900
    assert row["source"] == "ssm:TIER-Check" and row["checked_at"].endswith("Z")
    assert handler.ssm.sent[0]["DocumentName"] == "TIER-Check" and handler.ssm.sent[0]["InstanceIds"] == ["i-0aaa"]


def test_missing_line_for_a_tier_is_unknown_not_healthy():
    setup(ssm=FakeSsm([{"Status": "Success", "StandardOutputContent": "TIER|web|healthy|ok\n"}]))
    table = handler.dynamodb.table
    handler.handler({}, None)
    assert table.rows["tier/web"]["status"] == "healthy"
    assert table.rows["tier/app"]["status"] == "unknown" and "결과가 없습니다" in table.rows["tier/app"]["detail"]


def test_no_or_ambiguous_target_records_unknown_without_running_anything():
    for ids, text in (((), "찾지 못했습니다"), (("i-1", "i-2"), "2대")):
        table = setup(ids=ids)
        result = handler.handler({}, None)
        assert not result["ok"] and handler.ssm.sent == []
        assert all(r["status"] == "unknown" and text in r["detail"] for r in table.rows.values()) and len(table.rows) == 3


def test_ssm_failures_are_unknown_not_healthy():
    cases = [(FakeSsm(send_error=error("InvalidInstanceId")), "InvalidInstanceId"),
             (FakeSsm([{"Status": "Failed"}]), "Failed"),
             (FakeSsm([error("AccessDeniedException")]), "AccessDeniedException")]
    for ssm, text in cases:
        table = setup(ssm=ssm)
        result = handler.handler({}, None)
        assert not result["ok"] and all(r["status"] == "unknown" and text in r["detail"] for r in table.rows.values())


def test_invocation_not_ready_yet_is_retried_until_success():
    table = setup(ssm=FakeSsm([error("InvocationDoesNotExist"), {"Status": "InProgress"},
                               {"Status": "Success", "StandardOutputContent": GOOD}]))
    assert handler.handler({}, None)["ok"] and table.rows["tier/db"]["status"] == "unhealthy"


def test_timeout_records_unknown():
    handler.WAIT_SECONDS = 0
    try:
        table = setup(ssm=FakeSsm([{"Status": "InProgress"}]))
        result = handler.handler({}, None)
        assert not result["ok"] and all(r["status"] == "unknown" and "받지 못했습니다" in r["detail"] for r in table.rows.values())
    finally:
        handler.WAIT_SECONDS = 60


def test_older_run_never_overwrites_newer_result():
    newer = {"tier/web": {"tier_id": "tier/web", "status": "healthy", "checked_at": "2999-01-01T00:00:00.000Z"}}
    table = setup(table=FakeTable(newer))
    result = handler.handler({}, None)
    assert result["saved"] == 2 and table.rows["tier/web"]["checked_at"].startswith("2999")


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    for name, fn in tests:
        fn()
        print("ok", name)
    print(f"{len(tests)} passed")
