"""finding_sync 적재·대조 규칙 검증 (v21, PR-4).

lambda_src/ 바로 아래에 둡니다. archive_file 은 finding_sync/ 하위만 압축하므로 Lambda zip 에 들어가지 않습니다.
다른 Lambda 테스트와 모듈 이름(handler)이 겹치므로 파일별로 실행합니다.

    AWS_DEFAULT_REGION=ap-northeast-2 python -m pytest modules/soar/lambda_src/test_finding_sync.py
"""
import os
import sys
from pathlib import Path

from botocore.exceptions import ClientError

os.environ.setdefault("AWS_REGION", "ap-northeast-2")
os.environ.setdefault("AWS_DEFAULT_REGION", "ap-northeast-2")
os.environ["FINDINGS_TABLE"] = "findings"
os.environ["VULNERABILITIES_TABLE"] = "vulnerabilities"

# finding_sync/ 안에 __pycache__ 가 생기면 archive_file 이 Lambda zip 에 넣는다 — 바이트코드를 쓰지 않는다.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parent / "finding_sync"))
sys.modules.pop("handler", None)
import handler  # noqa: E402


def conditional_failed():
    return ClientError({"Error": {"Code": "ConditionalCheckFailedException"}}, "PutItem")


class FakeTable:
    """finding_sync 가 쓰는 조건식만 의미대로 흉내 낸다."""

    def __init__(self, key):
        self.key, self.rows, self.writes = key, {}, 0

    def put_item(self, Item, ConditionExpression=None, **_):
        old = self.rows.get(Item[self.key])
        if ConditionExpression and old is not None:
            newer = old["version"] < Item["version"]
            same = old["version"] == Item["version"]
            state_changed = old.get("view_state") != Item["view_state"]
            old_format = old.get("record_version", 0) < Item.get("record_version", 0)
            if not (newer or (same and (state_changed or old_format))):
                raise conditional_failed()
        self.rows[Item[self.key]] = dict(Item)
        self.writes += 1

    def update_item(self, Key, UpdateExpression, ExpressionAttributeValues, ConditionExpression=None,
                    ExpressionAttributeNames=None):
        v = ExpressionAttributeValues
        row = self.rows.setdefault(Key[self.key], {self.key: Key[self.key]})
        if ConditionExpression:
            if row.get("view_state") != v[":open"] or row.get("version") != v[":seen"]:
                raise conditional_failed()
            row.update(view_state=v[":closed"], closed_at=v[":now"], expires_at=v[":exp"])
        else:
            row.update(last_attempt_at=v[":now"], last_error=v[":e"])
        self.writes += 1

    def query(self, IndexName, ExpressionAttributeValues, Select=None, **_):
        rows = [r for r in self.rows.values() if r.get("view_state") == ExpressionAttributeValues[":s"]]
        if Select == "COUNT":
            return {"Count": len(rows)}
        return {"Items": [{self.key: r[self.key], "version": r["version"], "record_version": r.get("record_version")}
                          for r in rows]}


class Fakes:
    def __init__(self, sh=(), insp=(), sh_error=None):
        self.tables = {"findings": FakeTable("finding_id"), "vulnerabilities": FakeTable("finding_arn")}
        self.sh, self.insp = list(sh), list(insp)
        handler.dynamodb = type("D", (), {"Table": lambda _s, name: self.tables[name]})()
        outer = self

        class Pager:
            def __init__(self, rows, key, error=None):
                self.rows, self.key, self.error = rows, key, error

            def paginate(self, **_):
                if self.error:
                    raise self.error
                return [{self.key: outer_rows} for outer_rows in [self.rows]]

        handler.securityhub = type("S", (), {"get_paginator": lambda _s, op: Pager(outer.sh, "Findings", sh_error)})()
        handler.inspector = type("I", (), {"get_paginator": lambda _s, op: Pager(outer.insp, "findings")})()

    @property
    def findings(self):
        return {k: v for k, v in self.tables["findings"].rows.items() if k != handler.SYNC_KEY}

    @property
    def vulns(self):
        return {k: v for k, v in self.tables["vulnerabilities"].rows.items() if k != handler.SYNC_KEY}


def asff(fid, updated="2026-09-24T03:00:00Z", product="Security Hub", workflow="NEW", label="HIGH", state="ACTIVE"):
    return {"Id": fid, "ProductName": product, "Title": "t-" + fid, "Region": "ap-northeast-2",
            "AwsAccountId": "111122223333", "Severity": {"Label": label}, "UpdatedAt": updated,
            "CreatedAt": "2026-09-23T00:00:00Z", "RecordState": state, "Workflow": {"Status": workflow},
            "Resources": [{"Id": "i-1", "Type": "AwsEc2Instance", "Details": {"big": "x" * 100}}],
            "ProductFields": {"aws/guardduty/service/action/x/remoteIpDetails/ipAddressV4": "1.2.3.4", "other": "drop"}}


def insp(arn, last="2026-09-24T05:00:00Z", status="ACTIVE", score=7.5):
    return {"findingArn": arn, "awsAccountId": "111122223333", "severity": "HIGH", "status": status,
            "firstObservedAt": "2026-09-24T02:00:00Z", "lastObservedAt": last, "updatedAt": last,
            "resources": [{"id": "i-1", "type": "AWS_EC2_INSTANCE", "region": "ap-northeast-2", "tags": {"Name": "web"}}],
            "packageVulnerabilityDetails": {"vulnerabilityId": "CVE-1",
                                            "vulnerablePackages": [{"name": "openssl", "version": "1", "fixedInVersion": "2"}]},
            "inspectorScoreDetails": {"adjustedCvss": {"score": score}}}


def sh_event(*findings):
    return {"source": "aws.securityhub", "detail-type": "Security Hub Findings - Imported",
            "detail": {"findings": list(findings)}}


def test_time_formats_normalize_to_one_comparable_form():
    assert handler.iso("2026-09-24T03:00:00Z") == "2026-09-24T03:00:00.000Z"
    assert handler.iso("2026-09-24T03:00:00.123456+00:00") == "2026-09-24T03:00:00.123Z"
    assert handler.iso("Wed Sep 04 16:59:44.356 UTC 2024") == "2024-09-04T16:59:44.356Z"
    assert handler.iso(1790000000000) == handler.iso(1790000000)
    assert handler.iso("nonsense") is None


def test_securityhub_event_stores_only_needed_fields_and_skips_inspector():
    f = Fakes()
    result = handler.handler(sh_event(asff("a"), asff("cve", product="Inspector")), None)
    assert result == {"received": 2, "written": 1} and set(f.findings) == {"a"}
    row = f.findings["a"]
    assert row["view_state"] == "OPEN" and "expires_at" not in row
    assert row["raw"]["ProductFields"] == {"aws/guardduty/service/action/x/remoteIpDetails/ipAddressV4": "1.2.3.4"}
    assert "Details" not in row["raw"]["Resources"][0]


def test_older_event_does_not_overwrite_newer():
    f = Fakes()
    handler.handler(sh_event(asff("a", updated="2026-09-24T05:00:00Z", workflow="RESOLVED")), None)
    handler.handler(sh_event(asff("a", updated="2026-09-24T04:00:00Z")), None)  # 늦게 도착한 옛 정보
    row = f.findings["a"]
    assert row["view_state"] == "CLOSED" and row["updated_at"] == "2026-09-24T05:00:00.000Z" and row["expires_at"] > 0


def test_closed_states_follow_dashboard_filter():
    f = Fakes()
    handler.handler(sh_event(asff("info", label="INFORMATIONAL"), asff("sup", workflow="SUPPRESSED"),
                             asff("arch", state="ARCHIVED"), asff("open")), None)
    assert {k: v["view_state"] for k, v in f.findings.items()} == {
        "info": "CLOSED", "sup": "CLOSED", "arch": "CLOSED", "open": "OPEN"}


def test_sample_findings_are_closed_and_existing_sample_rows_close_on_reconcile():
    """GuardDuty create-sample-findings(ASFF Sample=true)는 시연용 — 대시보드 목록(OPEN)에 넣지 않는다."""
    f = Fakes()
    sample = asff("smp") | {"Sample": True}
    handler.handler(sh_event(sample, asff("real")), None)
    assert f.findings["smp"]["view_state"] == "CLOSED" and f.findings["smp"]["raw"]["Sample"] is True
    assert f.findings["real"]["view_state"] == "OPEN" and "Sample" not in f.findings["real"]["raw"]
    # v20.2 에서 OPEN 으로 저장된 샘플 행: 원본은 그대로(같은 UpdatedAt)여도 대조가 닫는다.
    f.tables["findings"].rows["smp"] |= {"view_state": "OPEN"}
    f.tables["findings"].rows["smp"].pop("expires_at", None)
    f.sh = [sample, asff("real")]
    result = handler.handler({"action": "reconcile"}, None)["findings"]
    assert f.findings["smp"]["view_state"] == "CLOSED" and f.findings["smp"]["expires_at"] > 0
    assert result["source_open"] == result["table_open"] == 1


def test_inspector_event_and_closed_status():
    f = Fakes()
    handler.handler({"source": "aws.inspector2", "region": "ap-northeast-2", "detail": insp("v1")}, None)
    row = f.vulns["v1"]
    assert row["view_state"] == "ACTIVE" and row["last_observed_at"] == "2026-09-24T05:00:00.000Z"
    assert str(row["raw"]["inspectorScoreDetails"]["adjustedCvss"]["score"]) == "7.5"
    handler.handler({"source": "aws.inspector2", "detail": insp("v1", last="2026-09-24T06:00:00Z", status="CLOSED")}, None)
    assert f.vulns["v1"]["view_state"] == "CLOSED" and f.vulns["v1"]["expires_at"] > 0


def test_reconcile_backfills_counts_and_writes_only_changes():
    f = Fakes(sh=[asff("a"), asff("b"), asff("info", label="INFORMATIONAL")], insp=[insp("v1"), insp("v2")])
    result = handler.handler({"action": "reconcile"}, None)
    assert set(f.findings) == {"a", "b"} and set(f.vulns) == {"v1", "v2"}  # 닫힌 원본은 새로 쓰지 않는다
    assert result["findings"]["corrected"] == 2 and result["findings"]["source_open"] == 2
    assert result["findings"]["table_open"] == 2 and result["vulnerabilities"]["table_open"] == 2
    writes = f.tables["vulnerabilities"].writes
    again = handler.handler({"source": "aws.events", "detail-type": "Scheduled Event"}, None)
    assert again["vulnerabilities"]["corrected"] == 0
    assert f.tables["vulnerabilities"].writes == writes + 1  # 동기화 상태 행만


def test_reconcile_corrects_missed_updates_and_closes_vanished():
    f = Fakes(sh=[asff("a")], insp=[insp("v1"), insp("v2")])
    handler.handler({"action": "reconcile"}, None)
    f.insp = [insp("v1", last="2026-09-24T09:00:00Z")]  # v1 재탐지(이벤트 못 받음), v2 사라짐(해결)
    result = handler.handler({"action": "reconcile"}, None)["vulnerabilities"]
    assert result["corrected"] == 1 and result["closed"] == 1 and result["table_open"] == 1
    assert f.vulns["v1"]["last_observed_at"] == "2026-09-24T09:00:00.000Z"
    assert f.vulns["v2"]["view_state"] == "CLOSED" and f.vulns["v2"]["expires_at"] > 0
    status = f.tables["vulnerabilities"].rows[handler.SYNC_KEY]
    assert status["source_open"] == status["table_open"] == 1 and "view_state" not in status


def test_empty_source_does_not_mass_close():
    f = Fakes(sh=[asff("a")], insp=[insp("v1")])
    handler.handler({"action": "reconcile"}, None)
    f.insp = []
    result = handler.handler({"action": "reconcile"}, None)["vulnerabilities"]
    assert result["close_skipped"] is True and f.vulns["v1"]["view_state"] == "ACTIVE"


def test_one_source_failure_still_reconciles_other_and_raises():
    f = Fakes(sh=[asff("a")], insp=[insp("v1")], sh_error=RuntimeError("TooManyRequests"))
    try:
        handler.handler({"action": "reconcile"}, None)
        raise AssertionError("실패를 올려야 재시도·DLQ·알람이 동작한다")
    except RuntimeError as error:
        assert "findings" in str(error)
    assert set(f.vulns) == {"v1"}
    assert "TooManyRequests" in f.tables["findings"].rows[handler.SYNC_KEY]["last_error"]


def test_v2_raw_keeps_explanation_fields():
    """DEC-015 — 대시보드 탐지 상세의 AWS 원문 설명·조치 안내·규칙 ID, 취약점 설명·업데이트 명령."""
    f = Fakes()
    control = asff("ctl") | {
        "Types": ["Software and Configuration Checks/Industry and Regulatory Standards", "b", "c", "d"],
        "Compliance": {"Status": "FAILED", "SecurityControlId": "EC2.2", "AssociatedStandards": [{"x": 1}]},
        "Remediation": {"Recommendation": {"Text": "For directions ... documentation.",
                                           "Url": "https://docs.aws.amazon.com/console/securityhub/EC2.2/remediation"}}}
    handler.handler(sh_event(control), None)
    raw = f.findings["ctl"]["raw"]
    assert raw["Compliance"] == {"Status": "FAILED", "SecurityControlId": "EC2.2"}
    assert raw["Remediation"]["Recommendation"]["Url"].endswith("/EC2.2/remediation") and len(raw["Types"]) == 3
    assert f.findings["ctl"]["record_version"] == handler.RECORD_VERSION
    legacy = asff("old") | {"ProductFields": {"ControlId": "EC2.19", "RecommendationUrl": "https://x", "other": "drop"}}
    handler.handler(sh_event(legacy), None)
    assert f.findings["old"]["raw"]["ProductFields"] == {"ControlId": "EC2.19", "RecommendationUrl": "https://x"}

    rich = insp("v9") | {"title": "CVE-2024-0001 - openssl", "description": "d" * 1500, "fixAvailable": "YES",
                         "exploitAvailable": "NO", "epss": {"score": 0.0123},
                         "remediation": {"recommendation": {"text": "None Provided"}}}
    rich["packageVulnerabilityDetails"]["vulnerablePackages"][0] |= {
        "remediation": "apt-get install --only-upgrade openssl", "packageManager": "OS"}
    rich["packageVulnerabilityDetails"]["sourceUrl"] = "https://ubuntu.com/security/CVE-2024-0001"
    rich["resources"][0]["details"] = {"awsEcrContainerImage": {"repositoryName": "app", "imageTags": ["app-1.0.0"]}}
    handler.handler({"source": "aws.inspector2", "region": "ap-northeast-2", "detail": rich}, None)
    raw = f.vulns["v9"]["raw"]
    package = raw["packageVulnerabilityDetails"]["vulnerablePackages"][0]
    assert package["remediation"].startswith("apt-get") and package["packageManager"] == "OS"
    assert raw["fixAvailable"] == "YES" and raw["exploitAvailable"] == "NO" and str(raw["epss"]["score"]) == "0.0123"
    assert len(raw["description"]) == 1000 and raw["title"].startswith("CVE-2024-0001")
    assert raw["resources"][0]["details"]["awsEcrContainerImage"] == {"repositoryName": "app", "imageTags": ["app-1.0.0"]}


def test_reconcile_rewrites_old_format_rows_once():
    f = Fakes(sh=[asff("a")], insp=[insp("v1")])
    handler.handler({"action": "reconcile"}, None)
    for table in f.tables.values():  # v1 형식으로 저장돼 있던 행(배포 전 적재분)을 흉내 낸다
        for key, row in table.rows.items():
            if key != handler.SYNC_KEY:
                row["record_version"] = 1
    result = handler.handler({"action": "reconcile"}, None)
    assert result["findings"]["corrected"] == 1 and result["vulnerabilities"]["corrected"] == 1
    assert f.findings["a"]["record_version"] == handler.RECORD_VERSION
    again = handler.handler({"action": "reconcile"}, None)
    assert again["findings"]["corrected"] == 0 and again["vulnerabilities"]["corrected"] == 0


def test_old_event_never_overwrites_newer_row_even_if_row_is_old_format():
    f = Fakes()
    handler.handler(sh_event(asff("a", updated="2026-09-24T05:00:00Z", workflow="RESOLVED")), None)
    f.tables["findings"].rows["a"]["record_version"] = 1
    handler.handler(sh_event(asff("a", updated="2026-09-24T04:00:00Z")), None)  # 늦게 도착한 옛 정보
    assert f.findings["a"]["view_state"] == "CLOSED" and f.findings["a"]["record_version"] == 1


def test_newer_event_during_reconcile_is_not_closed():
    f = Fakes(insp=[insp("v1")])
    handler.handler({"action": "reconcile"}, None)
    table = f.tables["vulnerabilities"]
    # 대조가 열린 행을 읽은 뒤 새 이벤트가 version 을 올렸다면 닫지 않는다.
    assert handler.close_if_unchanged(table, "finding_arn", "v1", "2000-01-01T00:00:00.000Z", "ACTIVE") is False
    assert f.vulns["v1"]["view_state"] == "ACTIVE"
