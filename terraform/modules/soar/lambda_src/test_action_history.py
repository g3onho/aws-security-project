"""asr_trigger 조치 이력 기록 규칙 검증 (v20).

lambda_src/ 바로 아래에 둡니다. archive_file 은 asr_trigger/ 하위만 압축하므로 Lambda zip 에 들어가지 않습니다.

    python modules/soar/lambda_src/test_action_history.py
"""
import os
import sys
from pathlib import Path

os.environ.setdefault("AWS_REGION", "ap-northeast-2")
os.environ.setdefault("AWS_DEFAULT_REGION", "ap-northeast-2")
for k in ("ACCOUNT_ID", "REMEDIATION_ACTIONS_TABLE", "SNS_TOPIC_ARN",
          "DOC_REVOKE_SG", "DOC_DISABLE_KEY", "DOC_NGINX_HARDEN", "AUTOMATION_ROLE_ARN"):
    os.environ.setdefault(k, "test")
os.environ["AUTO_REMEDIABLE_PATTERNS"] = "EC2.19,MaliciousIPCaller"
os.environ["ENABLE_AUTO_REMEDIATION"] = "true"

sys.path.insert(0, str(Path(__file__).parent / "asr_trigger"))
import handler  # noqa: E402


class FakeTable:
    """action_id(해시)·created_at(정렬) 키만 흉내 낸다."""
    def __init__(self, fail=False):
        self.rows, self.fail = {}, fail

    def query(self, KeyConditionExpression, Limit=None):
        want = KeyConditionExpression.get_expression()["values"][1]
        return {"Items": [dict(r) for (a, _), r in sorted(self.rows.items()) if a == want][:Limit]}

    def put_item(self, Item):
        if self.fail:
            raise RuntimeError("AccessDenied")
        self.rows[(Item["action_id"], Item["created_at"])] = dict(Item)

    def update_item(self, Key, UpdateExpression, ExpressionAttributeValues, ExpressionAttributeNames=None):
        row = self.rows[(Key["action_id"], Key["created_at"])]
        v = ExpressionAttributeValues
        if "occurrence_count" in UpdateExpression:
            row["occurrence_count"] = row.get("occurrence_count", v[":first"]) + v[":one"]
            row.update(last_seen_at=v[":now"], updated_at=v[":now"], expires_at=v[":exp"])
        else:
            row.update(status=v[":s"], after_state=v[":a"], updated_at=v[":now"], completed_at=v[":now"])


class Fakes:
    def __init__(self, fail=False):
        self.table, self.sent, self.started = FakeTable(fail), [], []
        handler.dynamodb = type("D", (), {"Table": lambda _s, name: self.table})()
        handler.sns = type("S", (), {"publish": lambda _s, **kw: self.sent.append(kw)})()
        handler.ssm = type("M", (), {"start_automation_execution":
                                     lambda _s, **kw: self.started.append(kw) or {"AutomationExecutionId": "exec-1"}})()
        handler.ec2 = type("E", (), {"describe_security_groups": lambda _s, **kw: {"SecurityGroups": [
            {"Tags": [{"Key": "AutoRemediation", "Value": "enabled"}]}]}})()


def sh_event(fid, title="S3 buckets should require TLS", gen="x", resources=None):
    return {"source": "aws.securityhub", "region": "ap-northeast-2", "account": "111122223333", "detail": {"findings": [{
        "Id": fid, "Title": title, "GeneratorId": gen, "Region": "ap-northeast-2", "AwsAccountId": "111122223333",
        "Resources": resources or [{"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::b"}]}]}}


def test_repeated_notification_updates_one_row():
    f = Fakes()
    for _ in range(3):
        handler.handler(sh_event("arn:aws:securityhub:ap-northeast-2:111122223333:finding/a"), None)
    assert len(f.table.rows) == 1
    row = next(iter(f.table.rows.values()))
    assert row["occurrence_count"] == 3 and row["status"] == "NOTIFIED"
    assert row["region"] == "ap-northeast-2" and row["account_id"] == "111122223333"
    assert row["action_id"].startswith("fnd-") and row["expires_at"] > 0
    assert len(f.sent) == 3  # 알림은 매번 보낸다


def test_different_findings_or_decisions_are_separate_rows():
    f = Fakes()
    handler.handler(sh_event("f-1"), None)
    handler.handler(sh_event("f-2"), None)
    assert len(f.table.rows) == 2


def test_old_rows_without_count_are_treated_as_one():
    f = Fakes()
    aid = handler._action_id({"finding_id": "f-old"}, "manual-notified", None)
    f.table.rows[(aid, "2026-09-24T00:00:00Z")] = {"action_id": aid, "created_at": "2026-09-24T00:00:00Z"}
    handler.handler(sh_event("f-old"), None)
    assert f.table.rows[(aid, "2026-09-24T00:00:00Z")]["occurrence_count"] == 2


def test_auto_execution_gets_its_own_row_and_ssm_result_updates_it():
    f = Fakes()
    res = [{"Type": "AwsEc2SecurityGroup", "Id": "arn:aws:ec2:::security-group/sg-0abc"}]
    out = handler.handler(sh_event("f-sg", title="EC2.19 open port", gen="EC2.19", resources=res), None)
    assert out["decision"] == "auto-executed"
    row = f.table.rows[("ssm-exec-1", next(k[1] for k in f.table.rows))]
    assert row["status"] == "IN_PROGRESS" and row["playbook_id"] == "test" and row["ssm_execution_id"] == "exec-1"
    got = handler.handler({"source": "aws.ssm", "detail": {"ExecutionId": "exec-1", "Status": "Success",
                                                           "Definition": "ASR-RevokeSecurityGroupIngress"}}, None)
    assert got == {"updated": True, "status": "SUCCESS"}
    assert row is not None and f.table.rows[("ssm-exec-1", row["created_at"])]["after_state"] == "SSM Success"


def test_unknown_or_non_terminal_ssm_events_are_ignored():
    Fakes()
    assert handler.handler({"source": "aws.ssm", "detail": {"ExecutionId": "zzz", "Status": "Success"}}, None)["updated"] is False
    assert handler.handler({"source": "aws.ssm", "detail": {"ExecutionId": "exec-1", "Status": "InProgress"}}, None)["updated"] is False


def test_history_write_failure_does_not_block_notification():
    f = Fakes(fail=True)
    out = handler.handler(sh_event("f-x"), None)
    assert out["decision"] == "manual-notified" and len(f.sent) == 1


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
    print("ok - 조치 이력 기록 규칙 6건 통과")
