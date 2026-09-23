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
            return FakeSecurityHub()
        raise AssertionError(name)


class FakeSecurityHub:
    def get_findings(self, **kwargs):
        # 실제 API 와 같은 규칙: UpdatedAt 필터는 Start/End 를 함께 요구한다.
        for f in kwargs.get("Filters", {}).get("UpdatedAt", []):
            assert "DateRange" in f or {"Start", "End"} <= f.keys(), f
        return {"Findings": []}


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


def test_aws_provider_time_filter_is_accepted_by_security_hub():
    provider = AwsProvider("ap-northeast-2", session_factory=lambda region: FakeSession(region))
    assert provider.observations({"from": "1790000000000"}) == []
