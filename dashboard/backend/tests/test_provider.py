from soar.provider import AwsProvider, UnconfiguredProvider


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
