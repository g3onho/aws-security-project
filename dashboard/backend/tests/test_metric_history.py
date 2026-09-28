"""EC2 교체 전후 지표를 같은 논리 서버에 잇는 계약."""
import json
from datetime import datetime, timezone

from soar.contracts import StandardService
from soar.integrations.aws.cloudtrail import replaced_instances
from soar.integrations.aws.cloudwatch import get_metric_data


def _event(name, *resources, profile=None):
    rows = [{"ResourceType": "AWS::EC2::Instance", "ResourceName": value} for value in resources]
    if profile:
        rows.insert(0, {"ResourceType": "AWS::IAM::InstanceProfile", "ResourceName": profile})
    return {"EventName": name, "Resources": rows, "CloudTrailEvent": json.dumps({})}


class TrailClient:
    def lookup_events(self, **kwargs):
        if kwargs["LookupAttributes"][0]["AttributeValue"] == "TerminateInstances":
            return {"Events": [_event("TerminateInstances", "i-aaaaaaaa", "i-bbbbbbbb")]}
        return {"Events": [_event("RunInstances", "i-aaaaaaaa", profile="server-db-profile"),
                           _event("RunInstances", "i-bbbbbbbb", profile="other-profile")]}


def test_cloudtrail_matches_only_verified_profile():
    session = type("Session", (), {"client": lambda self, name: TrailClient()})()
    start = datetime(2026, 9, 27, tzinfo=timezone.utc)
    end = datetime(2026, 9, 29, tzinfo=timezone.utc)
    history, incomplete = replaced_instances(session, start, end, {"server-db-profile"})
    assert history == {"server-db-profile": ["i-aaaaaaaa"]}
    assert incomplete is False  # 다른 역할은 식별하여 제외했으므로 부분 결과가 아님


def test_cloudtrail_orders_replacements_by_launch_time():
    class Trail:
        def lookup_events(self, **kwargs):
            if kwargs["LookupAttributes"][0]["AttributeValue"] == "TerminateInstances":
                return {"Events": [_event("TerminateInstances", "i-aaaaaaaa", "i-ffffffff")]}
            first = _event("RunInstances", "i-ffffffff", profile="server-db-profile")
            second = _event("RunInstances", "i-aaaaaaaa", profile="server-db-profile")
            first["EventTime"] = datetime(2026, 9, 26, tzinfo=timezone.utc)
            second["EventTime"] = datetime(2026, 9, 27, tzinfo=timezone.utc)
            return {"Events": [second, first]}

    session = type("Session", (), {"client": lambda self, name: Trail()})()
    history, incomplete = replaced_instances(session, datetime(2026, 9, 27, tzinfo=timezone.utc),
                                              datetime(2026, 9, 29, tzinfo=timezone.utc), {"server-db-profile"})
    assert history["server-db-profile"] == ["i-ffffffff", "i-aaaaaaaa"]
    assert incomplete is False


class Provider:
    def __init__(self):
        self.queried = []

    def resources(self, query):
        return {"items": [{"id": "i-cccccccc", "name": "db", "region": "ap-northeast-2", "accountId": "111"}]}

    def metric_history(self, resources, query):
        return {"byResource": {"i-cccccccc": ["i-aaaaaaaa"]}}

    def metric_for(self, resource, query):
        self.queried.append(resource["id"])
        values = {"i-aaaaaaaa": [(1000, 10), (2000, 20)], "i-cccccccc": [(2000, 30), (3000, 40)]}
        return {"period": 300, "points": [{"at": at, "cpu": value, "memory": None}
                                           for at, value in values[resource["id"]]]}


def _metrics(provider, resources=None):
    service = StandardService(None, None, provider, "test")
    principal = {"scope": {"accounts": ["111"], "regions": ["ap-northeast-2"], "resources": resources}}
    return service._metrics({"from": 1, "to": 4000, "periodSeconds": 300}, principal)


def test_metrics_stitch_old_and_new_instances_with_provenance():
    provider = Provider()
    result = _metrics(provider)
    cpu = next(row for row in result["series"] if row["metric"] == "cpu")
    assert [point["value"] for point in cpu["points"]] == [10, 30, 40]
    assert [point["instanceId"] for point in cpu["points"]] == ["i-aaaaaaaa", "i-cccccccc", "i-cccccccc"]
    assert cpu["resource"] == "i-cccccccc"
    assert cpu["instanceIds"] == ["i-aaaaaaaa", "i-cccccccc"]
    memory = next(row for row in result["series"] if row["metric"] == "memory")
    assert [point["value"] for point in memory["points"]] == [None, None, None]
    assert all(point["instanceId"] is None for point in memory["points"])


def test_resource_scope_does_not_authorize_old_instance_implicitly():
    provider = Provider()
    result = _metrics(provider, ["i-cccccccc"])
    cpu = next(row for row in result["series"] if row["metric"] == "cpu")
    assert provider.queried == ["i-cccccccc"]
    assert [point["value"] for point in cpu["points"]] == [30, 40]


def test_cloudwatch_collects_all_metric_pages():
    class CloudWatch:
        def get_metric_data(self, **kwargs):
            if "NextToken" not in kwargs:
                return {"NextToken": "next", "MetricDataResults": [
                    {"Id": "cpu", "StatusCode": "PartialData", "Timestamps": [1], "Values": [10]}]}
            return {"MetricDataResults": [
                {"Id": "cpu", "StatusCode": "Complete", "Timestamps": [2], "Values": [20]}]}

    session = type("Session", (), {"client": lambda self, name: CloudWatch()})()
    result = get_metric_data(session, [], datetime(2026, 9, 27, tzinfo=timezone.utc),
                             datetime(2026, 9, 28, tzinfo=timezone.utc))
    assert result["MetricDataResults"][0]["Values"] == [10, 20]
