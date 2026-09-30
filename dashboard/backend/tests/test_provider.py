from soar.provider import AwsProvider, UnconfiguredProvider, classify, remote_ip


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
            {"Id": "sample", "Title": "sample", "UpdatedAt": "2026-09-23T03:00:00.000Z", "Sample": True},
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
    host = provider.resources({})["items"][0]
    assert host["id"] == "i-1" and host["state"] == "running"
    assert provider.metric_for(host, {})["period"] == 300


def test_aws_provider_metrics_match_infrastructure_view_shape():
    from datetime import datetime, timezone
    ts = [datetime(2026, 9, 23, h, tzinfo=timezone.utc) for h in (3, 2, 1)]  # CloudWatch 는 최신순
    cw = type("CW", (), {"get_metric_data": lambda self, **kw: {"MetricDataResults": [
        {"Id": "cpu", "Timestamps": ts, "Values": [90.0, 95.0, 10.0]},
        {"Id": "memory", "Timestamps": ts[:1], "Values": [40.0]}]}})()
    session = FakeSession("ap-northeast-2")
    session.client = lambda name, **kw: cw if name == "cloudwatch" else FakeSession.client(session, name)
    provider = AwsProvider("ap-northeast-2", session_factory=lambda region: session)
    host = provider.resources({})["items"][0]
    m = provider.metric_for(host, {"from": "0", "to": "9999999999999"})
    assert [p["cpu"] for p in m["points"]] == [10.0, 95.0, 90.0]  # 시간순 정렬
    assert m["points"][-1]["memory"] == 40.0 and m["points"][0]["memory"] is None  # 같은 시각끼리 병합, 결측은 None


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
    assert "sourceSample" not in rows[0]  # 샘플 finding 은 목록에서 빠진다(아래 2건 = new·old)
    assert len(provider.observations({})) == 2
    assert hub.calls == 1  # 두 번 조회해도 Security Hub 호출은 한 번


def test_aws_provider_inspector_findings_are_active_only_and_cached():
    calls = []
    # 심각도별 병렬 조회 — 자기 심각도 묶음만 돌려준다(실제 API 의 severity 필터처럼).
    inspector = type("Inspector", (), {"list_findings": lambda self, **kw: calls.append(kw) or {"findings": [
        {"findingArn": "arn:f1", "severity": "HIGH", "resourceId": "i-1",
         "resources": [{"id": "i-1", "tags": {"Name": "docker-host"}}],
         "packageVulnerabilityDetails": {"vulnerabilityId": "CVE-1", "vulnerablePackages": [{"name": "openssl"}]}}]
        if kw["filterCriteria"]["severity"][0]["value"] == "HIGH" else []}})()
    session = FakeSession("ap-northeast-2")
    session.client = lambda name, **kw: inspector if name == "inspector2" else FakeSession.client(session, name)
    provider = AwsProvider("ap-northeast-2", session_factory=lambda region: session)
    items = provider.vulnerabilities({})["items"]
    assert [(v["cveId"], v["resourceName"]) for v in items] == [("CVE-1", "docker-host")]
    provider.vulnerabilities({})  # 화면이 다음 페이지를 요청해도 AWS 는 다시 호출하지 않는다
    assert sorted(c["filterCriteria"]["severity"][0]["value"] for c in calls) == sorted(AwsProvider.INSPECTOR_SEVERITIES)
    assert all(c["filterCriteria"]["findingStatus"][0]["value"] == "ACTIVE" for c in calls)


def test_remote_ip_reads_guardduty_slash_keys_for_map_arcs():
    base = "aws/guardduty/service/action/networkConnectionAction/remoteIpDetails/"
    got = remote_ip({base + "ipAddressV4": "198.51.100.7", base + "country/countryName": "Netherlands",
                     base + "geoLocation/lat": "52.37", base + "geoLocation/lon": "4.89"})
    assert got == {"sourceIp": "198.51.100.7", "geoStatus": "located",
                   "sourceLocation": {"lat": 52.37, "lon": 4.89, "country": "Netherlands", "city": "Netherlands"}}
    # 좌표가 없으면 지도에 선을 긋지 않는다(NaN 방지). IP 가 없으면 전부 비운다.
    assert remote_ip({base + "ipAddressV4": "198.51.100.7", base + "country/countryName": "NL"})["sourceLocation"] is None
    assert remote_ip({"aws/securityhub/ProductName": "Config"})["sourceIp"] is None


# --- 지리별 공격 명령 상태(2026-09-29 뭄바이·도쿄: 에이전트 다운으로 배달 실패) ---------------

class FakeSsm:
    """get_command_invocation 이 없는 명령. 명령 레벨 상태만 진실을 안다."""

    def __init__(self, command_status, invocation_error="InvocationDoesNotExist"):
        self.command_status = command_status
        self.invocation_error = invocation_error

    def get_command_invocation(self, **kwargs):
        error = Exception("no invocation")
        error.response = {"Error": {"Code": self.invocation_error}}
        raise error

    def list_commands(self, **kwargs):
        return {"Commands": [{"Status": self.command_status}] if self.command_status else []}


def _status_for(ssm):
    session = FakeSession("ap-northeast-2")
    session.client = lambda name, **kw: ssm if name == "ssm" else FakeSession.client(session, name)
    provider = AwsProvider("ap-northeast-2", session_factory=lambda region: session)
    return provider.attack_command_status(
        [{"regionCode": "ap-south-1", "instanceId": "i-x", "commandId": "c-1", "regionLabel": "mumbai"}])[0]


def test_undelivered_command_reports_failure_instead_of_waiting():
    # 에이전트가 죽어 배달되지 않은 명령 — 40분 방치 판정을 기다리지 않고 바로 실패로 보여야 한다.
    assert _status_for(FakeSsm("Failed"))["status"] == "Failed"


def test_just_registered_command_still_reports_pending():
    # 명령 레벨이 아직 진행 중이면 invocation 이 없는 건 "아직"이라는 뜻이다.
    assert _status_for(FakeSsm("InProgress"))["status"] == "InProgress"


def test_command_lookup_failure_keeps_pending():
    # 명령 조회조차 안 되면(권한 등) 기존 판정을 유지한다 — 실패로 단정하지 않는다.
    ssm = FakeSsm(None)
    ssm.list_commands = lambda **kw: (_ for _ in ()).throw(RuntimeError("denied"))
    assert _status_for(ssm)["status"] == "Pending"


def test_unexpected_error_is_failure_not_pending():
    # AccessDenied 같은 건 대기가 아니라 실패다(화면이 영영 '실행 중'에 묶이지 않도록).
    assert _status_for(FakeSsm("Success", invocation_error="AccessDeniedException"))["status"] == "Failed"


def test_classify_names_the_real_detector_instead_of_security_hub():
    assert classify({"ProductName": "GuardDuty"}) == {"source": "GuardDuty", "scenario": "위협 탐지"}
    assert classify({"ProductName": "Default", "GeneratorId": "soar-waf-alarm"})["scenario"] == "SEC-08 웹 공격 차단"
    assert classify({})["source"] == "Security Hub"
