from soar.provider import AwsProvider, UnconfiguredProvider, remote_ip


class FakeSts:
    def __init__(self, error=None):
        self.error = error

    def get_caller_identity(self):
        if self.error:
            raise self.error
        return {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:role/test"}


class FakeSession:
    def __init__(self, region, error=None):
        self.region = region
        self.error = error

    def client(self, name, **kwargs):
        if name == "sts":
            return FakeSts(self.error)
        if name == "ec2":
            return type("EC2", (), {"describe_instances": lambda self: {"Reservations": [{"Instances": [{"InstanceId": "i-1", "State": {"Name": "running"}, "InstanceType": "t3.micro"}]}]}})()
        if name == "cloudwatch":
            return type("CloudWatch", (), {"get_metric_data": lambda self, **kwargs: {"MetricDataResults": [{"Timestamps": [], "Values": []}]}})()
        if name == "securityhub":
            return self.hub
        raise AssertionError(name)

    hub = None


class FakeSecurityHub:
    def __init__(self):
        self.calls = 0

    def get_findings(self, **kwargs):
        self.calls += 1
        # 실제 API 와 같은 규칙: UpdatedAt 필터는 Start/End 를 함께 요구한다.
        for f in kwargs.get("Filters", {}).get("UpdatedAt", []):
            assert "DateRange" in f or {"Start", "End"} <= f.keys(), f
        # 실제 ASFF 처럼 날짜는 문자열이다.
        return {"Findings": [
            {"Id": "new", "Title": "new", "UpdatedAt": "2026-09-23T02:00:00.000Z"},
            {"Id": "old", "Title": "old", "UpdatedAt": "2020-01-01T00:00:00Z"},
        ]}


def test_unconfigured_provider_has_no_data_fallback():
    provider = UnconfiguredProvider()
    assert provider.status()["state"] == "not_configured"


def test_aws_provider_verifies_identity_without_enabling_actions():
    provider = AwsProvider("ap-northeast-2", session_factory=lambda region: FakeSession(region))
    assert provider.connected is True
    assert provider.status()["state"] == "credentials_verified"
    assert provider.status()["region"] == "ap-northeast-2"
    try:
        provider.execution_result({})
    except Exception as error:
        assert getattr(error, "code", None) == "ACTION_PROVIDER_DISABLED"
    else:
        raise AssertionError("AWS action provider must remain disabled")


def test_aws_provider_does_not_hide_connection_failure():
    provider = AwsProvider("ap-northeast-2", session_factory=lambda region: FakeSession(region, RuntimeError("denied")))
    assert provider.connected is False
    assert provider.status()["state"] == "unavailable"
    try:
        provider.require_ready()
    except Exception as error:
        assert getattr(error, "code", None) == "DATA_SOURCE_UNAVAILABLE"
    else:
        raise AssertionError("unavailable provider must reject reads")


def test_aws_provider_reads_normalized_metrics_from_aws_clients():
    provider = AwsProvider("ap-northeast-2", session_factory=lambda region: FakeSession(region))
    result = provider.metrics({})
    assert result["dataMode"] == "live"
    assert result["hosts"][0]["id"] == "i-1"


def test_aws_provider_metrics_match_infrastructure_view_shape():
    from datetime import datetime, timezone
    ts = [datetime(2026, 9, 23, h, tzinfo=timezone.utc) for h in (3, 2, 1)]  # CloudWatch 는 최신순
    cw = type("CW", (), {"get_metric_data": lambda self, **kw: {"MetricDataResults": [
        {"Id": "cpu", "Timestamps": ts, "Values": [90.0, 95.0, 10.0]},
        {"Id": "memory", "Timestamps": ts[:1], "Values": [40.0]}]}})()
    session = FakeSession("ap-northeast-2")
    session.client = lambda name, **kw: cw if name == "cloudwatch" else FakeSession.client(session, name)
    m = AwsProvider("ap-northeast-2", session_factory=lambda region: session).metrics({"from": "0", "to": "9999999999999"})
    assert m["resource"] == "i-1" and m["host"]["name"] == "i-1"
    assert [p["cpu"] for p in m["points"]] == [10.0, 95.0, 90.0]  # 시간순 정렬
    assert m["cpu"] == 90.0 and m["memory"] == 40.0
    assert m["breaches"] == [{"metric": "cpu", "from": ts[1].timestamp() * 1000, "to": ts[0].timestamp() * 1000, "peak": 95.0, "samples": 2}]
    assert m["summary"]["cpu"] == {"max": 95.0, "avg": 65.0} and m["summary"]["samples"] == 3
    assert m["series"][0]["resource"] == "i-1"


def test_aws_provider_services_have_fields_the_view_reads():
    svc = AwsProvider("ap-northeast-2", session_factory=lambda region: FakeSession(region)).services({})
    assert svc["overall"] == "UP" and svc["intervalSec"] and svc["target"]
    for item in svc["items"]:
        for key in ("tier", "port", "latencyMs", "errorRate", "probe", "blockers", "detail", "source"):
            assert key in item, key
        assert item["blockers"] == []


def test_aws_provider_findings_are_cached_and_time_filtered():
    hub = FakeSecurityHub()
    session = FakeSession("ap-northeast-2")
    session.hub = hub
    provider = AwsProvider("ap-northeast-2", session_factory=lambda region: session)
    rows = provider.observations({"from": "1790000000000"})  # 2026-09-21
    assert [r["externalFindingId"] for r in rows] == ["new"]
    assert rows[0]["at"] == 1790128800000
    assert len(provider.observations({})) == 2
    assert hub.calls == 1  # 두 번 조회해도 Security Hub 호출은 한 번


def test_aws_provider_inspector_findings_are_active_only_and_cached():
    calls = []
    inspector = type("Inspector", (), {"list_findings": lambda self, **kw: calls.append(kw) or {"findings": [
        {"findingArn": "arn:f1", "severity": "HIGH", "resourceId": "i-1",
         "packageVulnerabilityDetails": {"vulnerabilityId": "CVE-1", "vulnerablePackages": [{"name": "openssl"}]}}]}})()
    session = FakeSession("ap-northeast-2")
    session.client = lambda name, **kw: inspector if name == "inspector2" else FakeSession.client(session, name)
    provider = AwsProvider("ap-northeast-2", session_factory=lambda region: session)
    assert provider.vulnerabilities({})["items"][0]["cveId"] == "CVE-1"
    provider.vulnerabilities({})  # 화면이 다음 페이지를 요청해도 AWS 는 다시 호출하지 않는다
    assert len(calls) == 1
    assert calls[0]["filterCriteria"]["findingStatus"][0]["value"] == "ACTIVE"


def test_remote_ip_reads_guardduty_slash_keys_for_map_arcs():
    base = "aws/guardduty/service/action/networkConnectionAction/remoteIpDetails/"
    got = remote_ip({base + "ipAddressV4": "198.51.100.7", base + "country/countryName": "Netherlands",
                     base + "geoLocation/lat": "52.37", base + "geoLocation/lon": "4.89"})
    assert got == {"sourceIp": "198.51.100.7", "geoStatus": "located",
                   "sourceLocation": {"lat": 52.37, "lon": 4.89, "country": "Netherlands", "city": "Netherlands"}}
    # 좌표가 없으면 지도에 선을 긋지 않는다(NaN 방지). IP 가 없으면 전부 비운다.
    assert remote_ip({base + "ipAddressV4": "198.51.100.7", base + "country/countryName": "NL"})["sourceLocation"] is None
    assert remote_ip({"aws/securityhub/ProductName": "Config"})["sourceIp"] is None
