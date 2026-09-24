"""v21 (PR-4): 탐지·취약점을 DynamoDB 적재에서 읽어도 AWS 직접 조회와 같은 결과인지 검사한다.

적재 행은 실제 적재 Lambda(aws-soar-terraform/modules/soar/lambda_src/finding_sync)의 변환 함수로 만든다.
원본 → Lambda 행 → DynamoDB 형식 → 대시보드 연동 → repository 결과가 직접 조회 결과와 같아야 한다.
"""
import importlib.util
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from boto3.dynamodb.types import TypeSerializer

from soar import create_app
from soar.auth import create_user
from soar.provider import AwsProvider
from soar.settings import configure
from soar.store import now_ms
from tests.test_provider import FakeSession

LAMBDA = (Path(__file__).resolve().parents[3] / "aws-soar-terraform" / "modules" / "soar"
          / "lambda_src" / "finding_sync" / "handler.py")
ACCOUNT = "123456789012"


@pytest.fixture(scope="module")
def sync():
    if not LAMBDA.is_file():
        pytest.skip("적재 Lambda 소스가 없는 배포본")
    os.environ.setdefault("AWS_DEFAULT_REGION", "ap-northeast-2")
    os.environ.setdefault("FINDINGS_TABLE", "findings")
    os.environ.setdefault("VULNERABILITIES_TABLE", "vulnerabilities")
    spec = importlib.util.spec_from_file_location("finding_sync_handler", LAMBDA)
    module = importlib.util.module_from_spec(spec)
    # Lambda 폴더에 __pycache__ 가 생기면 archive_file 이 Lambda zip 에 넣는다 — 바이트코드를 쓰지 않는다.
    previous, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def asff(fid, **extra):
    base = {"Id": fid, "ProductArn": "arn:aws:securityhub:ap-northeast-2::product/aws/guardduty",
            "ProductName": "GuardDuty", "GeneratorId": "gd", "Title": "t-" + fid, "Description": "d",
            "Region": "ap-northeast-2", "AwsAccountId": ACCOUNT, "Severity": {"Label": "HIGH"},
            "UpdatedAt": "2026-09-24T03:14:31.645Z", "CreatedAt": "2026-09-23T01:00:00Z",
            "RecordState": "ACTIVE", "Workflow": {"Status": "NEW"},
            "Resources": [{"Id": "arn:aws:ec2:ap-northeast-2:1:instance/i-1", "Type": "AwsEc2Instance"}]}
    return {**base, **extra}


SH = [
    asff("gd-1", ProductFields={
        "aws/guardduty/service/action/networkConnectionAction/remoteIpDetails/ipAddressV4": "198.51.100.7",
        "aws/guardduty/service/action/networkConnectionAction/remoteIpDetails/country/countryName": "Korea",
        "aws/guardduty/service/action/networkConnectionAction/remoteIpDetails/geoLocation/lat": "37.5",
        "aws/guardduty/service/action/networkConnectionAction/remoteIpDetails/geoLocation/lon": "127.0"}),
    asff("cfg-1", ProductName="Config", Severity={"Label": "MEDIUM"}, UpdatedAt="2026-09-23T07:01:54.100Z"),
    asff("waf-1", ProductName="Default", GeneratorId="soar-waf-alarm", Severity={"Label": "CRITICAL"}),
]
CLOSED_SH = [asff("info", Severity={"Label": "INFORMATIONAL"}), asff("done", Workflow={"Status": "RESOLVED"})]


def inspector_finding(arn, severity="HIGH", last="2026-09-24T05:01:30.147Z", score=7.5, name="docker-host"):
    return {"findingArn": arn, "awsAccountId": ACCOUNT, "severity": severity, "status": "ACTIVE",
            "firstObservedAt": "2026-09-24T02:00:42.482Z", "lastObservedAt": last, "updatedAt": last,
            "resources": [{"id": "i-1", "type": "AWS_EC2_INSTANCE", "region": "ap-northeast-2", "tags": {"Name": name}}],
            "packageVulnerabilityDetails": {"vulnerabilityId": "CVE-" + arn[-1],
                                            "vulnerablePackages": [{"name": "openssl", "version": "3.0.2",
                                                                    "fixedInVersion": "3.0.13"}]},
            "inspectorScoreDetails": {"adjustedCvss": {"score": score}}}


INSPECTOR = [inspector_finding("arn:v1"), inspector_finding("arn:v2", severity="CRITICAL", score=9.8),
             inspector_finding("arn:v3", severity="LOW", score=None, name=None)]


class FakeDynamo:
    """query(인덱스, view_state) · get_item 만. 응답은 실제처럼 DynamoDB 형식."""

    def __init__(self, tables):
        self.tables, self.queries = tables, 0
        self._ser = TypeSerializer()

    def _wire(self, item):
        return {k: self._ser.serialize(v) for k, v in item.items()}

    def query(self, TableName, IndexName, ExpressionAttributeValues, **_):
        self.queries += 1
        state = ExpressionAttributeValues[":s"]["S"]
        return {"Items": [self._wire(i) for i in self.tables[TableName].values() if i.get("view_state") == state]}

    def get_item(self, TableName, Key):
        item = self.tables[TableName].get(next(iter(Key.values()))["S"])
        return {"Item": self._wire(item)} if item else {}


def sync_row(key, minutes_ago=3, source=None, table=None, error=None):
    at = datetime.fromtimestamp((now_ms() - minutes_ago * 60000) / 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return {key: "__sync__", "last_attempt_at": at, "last_success_at": at, "source_open": source,
            "table_open": table, "corrected": 0, "closed": 0, "last_error": error}


def tables(sync, sh=SH + CLOSED_SH, insp=INSPECTOR, finding_status=None, vuln_status=None):
    findings = {i["finding_id"]: i for i in (sync.finding_item(f) for f in sh)}
    vulns = {i["finding_arn"]: i for i in (sync.vulnerability_item(f) for f in insp)}
    open_f = sum(i["view_state"] == "OPEN" for i in findings.values())
    findings["__sync__"] = finding_status or sync_row("finding_id", source=open_f, table=open_f)
    vulns["__sync__"] = vuln_status or sync_row("finding_arn", source=len(vulns) - 0, table=len(vulns))
    if finding_status is False:
        del findings["__sync__"]
    return {"findings": findings, "vulnerabilities": vulns}


def direct_provider():
    session = FakeSession("ap-northeast-2")
    hub = type("Hub", (), {"get_findings": lambda self, **kw: {"Findings": SH}})()  # AWS 필터 통과분만
    inspector = type("Inspector", (), {"list_findings": lambda self, **kw: {"findings": [
        f for f in INSPECTOR if f["severity"] == kw["filterCriteria"]["severity"][0]["value"]]}})()
    session.client = lambda name, **kw: {"securityhub": hub, "inspector2": inspector}.get(name) or FakeSession.client(session, name)
    return AwsProvider("ap-northeast-2", session_factory=lambda region: session)


def stored_provider(data):
    session = FakeSession("ap-northeast-2")
    dynamo = FakeDynamo(data)
    session.client = lambda name, **kw: dynamo if name == "dynamodb" else FakeSession.client(session, name)
    provider = AwsProvider("ap-northeast-2", session_factory=lambda region: session,
                           findings_table="findings", vulnerabilities_table="vulnerabilities",
                           event_source="dynamodb", vulnerability_source="dynamodb")
    return provider, dynamo


def by_id(rows):
    return sorted(rows, key=lambda row: row["id"])


def test_events_from_dynamodb_match_security_hub(sync):
    direct = by_id(direct_provider().observations({}))
    stored = by_id(stored_provider(tables(sync))[0].observations({}))
    assert [r["id"] for r in stored] == [r["id"] for r in direct] and len(stored) == 3  # 닫힌 2건은 빠진다
    assert stored == direct
    assert next(r for r in stored if r["source"] == "WAF")["scenario"] == "SEC-08 웹 공격 차단"
    assert next(r for r in stored if r["sourceIp"])["sourceLocation"]["country"] == "Korea"


def test_event_period_and_region_filters_behave_the_same(sync):
    start = {"from": str(1790208000000)}  # 2026-09-24T00:00Z 이후 갱신만 → 09-23 갱신된 cfg-1 은 빠진다
    direct = by_id(direct_provider().observations(start))
    stored = by_id(stored_provider(tables(sync))[0].observations(start))
    assert stored == direct and "cfg-1" not in {r["externalFindingId"] for r in stored} and len(stored) == 2
    assert stored_provider(tables(sync))[0].observations({"region": "us-east-1"}) == []


def test_vulnerabilities_from_dynamodb_match_inspector(sync):
    direct = by_id(direct_provider().vulnerabilities({})["items"])
    stored = by_id(stored_provider(tables(sync))[0].vulnerabilities({})["items"])
    assert stored == direct and len(stored) == 3
    assert next(v for v in stored if v["cveId"] == "CVE-2")["cvss"] == 9.8


def test_stored_rows_are_cached_and_reused(sync):
    provider, dynamo = stored_provider(tables(sync))
    first = provider.vulnerabilities({})["items"]
    assert provider.vulnerabilities({})["items"] is first  # 가공 결과 재사용 유지
    provider.observations({})
    provider.observations({})
    assert dynamo.queries == 2  # 두 테이블 각 1회


def app_with(provider, tmp_path):
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "stored.sqlite3"),
                      "SECRET_KEY": "test", "WRITE_ENABLED": False})
    create_user(app.extensions["store"], "viewer", "test-password-123", "viewer",
                {"accounts": [ACCOUNT], "regions": None, "resources": None})
    app.extensions["provider"] = provider
    for name in ("standard_service", "workflow", "worker"):
        app.extensions[name].provider = provider
    client = app.test_client()
    token = client.get("/api/auth/session").json["csrfToken"]
    client.post("/api/auth/login", json={"username": "viewer", "password": "test-password-123"},
                headers={"X-CSRF-Token": token})
    return client


def window():
    return {"from": "2026-09-01T00:00:00Z", "to": "2026-09-25T00:00:00Z"}


def test_api_reports_sync_time_as_asof_without_warnings(sync, tmp_path):
    data = tables(sync)
    client = app_with(stored_provider(data)[0], tmp_path)
    response = client.get("/api/events", query_string=window()).json
    assert len(response["data"]["items"]) == 3
    assert response["meta"]["asOf"] == data["findings"]["__sync__"]["last_success_at"]
    assert response["meta"]["warnings"] == []
    vulns = client.get("/api/vulnerabilities", query_string=window()).json
    assert len(vulns["data"]["items"]) == 3 and vulns["meta"]["warnings"] == []


@pytest.mark.parametrize(("status", "expected"), [
    (False, "탐지 동기화 기록이 없습니다"),
    ({"minutes_ago": 45}, "탐지 동기화가 45분 동안 완료되지 않았습니다"),
    ({"source": 3, "table": 2}, "탐지 원본 3건과 저장 2건이 달랐습니다"),
])
def test_api_warns_when_sync_is_missing_stale_or_mismatched(sync, tmp_path, status, expected):
    row = status if status is False else sync_row("finding_id", **{"source": 3, "table": 3, **status})
    client = app_with(stored_provider(tables(sync, finding_status=row))[0], tmp_path)
    for path in ("/api/events", "/api/summary"):
        warnings = client.get(path, query_string=window()).json["meta"]["warnings"]
        assert any(expected in w for w in warnings), warnings


def test_api_warns_on_last_sync_failure(sync, tmp_path):
    row = sync_row("finding_arn", source=3, table=3, error="TooManyRequests")
    row["last_attempt_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    client = app_with(stored_provider(tables(sync, vuln_status=row))[0], tmp_path)
    warnings = client.get("/api/vulnerabilities", query_string=window()).json["meta"]["warnings"]
    assert warnings == ["최근 취약점 동기화가 실패했습니다."]  # 내부 오류 원문은 노출하지 않는다


def test_direct_sources_add_no_sync_warnings(tmp_path):
    client = app_with(direct_provider(), tmp_path)
    assert client.get("/api/events", query_string=window()).json["meta"]["warnings"] == []


@pytest.mark.parametrize(("env", "message"), [
    ({"EVENT_SOURCE": "dynamodb"}, "FINDINGS_TABLE"),
    ({"VULNERABILITY_SOURCE": "dynamodb"}, "VULNERABILITIES_TABLE"),
    ({"EVENT_SOURCE": "athena"}, "EVENT_SOURCE"),
])
def test_dynamodb_source_requires_its_table(monkeypatch, tmp_path, env, message):
    for key in ("FINDINGS_TABLE", "VULNERABILITIES_TABLE", "EVENT_SOURCE", "VULNERABILITY_SOURCE"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(ValueError, match=message):
        configure({"DATABASE": str(tmp_path / "x.sqlite3")})
