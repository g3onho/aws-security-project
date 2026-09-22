"""Pagination, metric identity/alignment and conservative verification."""
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace

import pytest

from app.adapters.live import LiveAdapter
from app.api.errors import ApiProblem


def adapter():
    return LiveAdapter(SimpleNamespace(AWS_REGION='ap-northeast-2', NAME_PREFIX='test', CACHE_TTL={'metrics': 30}))


def test_pagination_reads_all_pages():
    live = adapter()
    calls = []
    def call(service, operation, **kwargs):
        calls.append(kwargs)
        if not kwargs.get('ExclusiveStartKey'):
            return {'Items': [1], 'LastEvaluatedKey': {'id': {'S': 'next'}}}
        return {'Items': [2]}
    live._call = call
    assert live._pages('dynamodb', 'scan', 'Items', token='ExclusiveStartKey') == [1, 2]
    assert calls[1]['ExclusiveStartKey'] == {'id': {'S': 'next'}}


def test_repeated_token_fails_instead_of_silently_truncating():
    live = adapter()
    live._call = lambda *a, **k: {'Items': [1], 'NextToken': 'same'}
    with pytest.raises(ApiProblem):
        live._pages('x', 'x', 'Items')


def test_metrics_use_requested_resource_and_align_timestamps():
    live = adapter()
    first = datetime(2026, 9, 22, tzinfo=timezone.utc)
    second = first + timedelta(minutes=5)
    calls = []
    def call(service, operation, **kwargs):
        calls.append(kwargs)
        if operation == 'describe_instances':
            return {'Reservations': [{'Instances': [{'InstanceId': 'i-a'}, {'InstanceId': 'i-b'}]}]}
        assert kwargs['MetricDataQueries'][0]['MetricStat']['Metric']['Dimensions'][0]['Value'] == 'i-b'
        assert kwargs['MetricDataQueries'][0]['MetricStat']['Period'] % 60 == 0
        return {'MetricDataResults': [
            {'Id': 'cpu', 'Timestamps': [first, second], 'Values': [10, 20]},
            {'Id': 'mem', 'Timestamps': [second], 'Values': [80]},
        ]}
    live._call = call
    data = live.metrics({'region': 'ap-northeast-2', 'resource': 'i-b', 'from': 0, 'to': 1234567})
    assert data['points'][0]['memory'] is None
    assert data['points'][1]['memory'] == 80
    assert data['resource'] == 'i-b'
    assert live.metrics({'region': 'us-east-1'})['resource'] is None


@pytest.mark.parametrize('permissions,count', [
    ([{'IpProtocol': '-1', 'Ipv6Ranges': [{'CidrIpv6': '::/0'}]}], 1),
    ([{'IpProtocol': 'tcp', 'FromPort': 1, 'ToPort': 65535, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}], 1),
    ([{'IpProtocol': 'udp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}], 0),
])
def test_sg_verification_covers_ranges_ipv6_and_protocol(permissions, count):
    live = adapter()
    live._call = lambda *a, **k: {'SecurityGroups': [{'IpPermissions': permissions}]}
    assert live._verify_sg_ingress({'resource': 'sg-x'}, {'port': 22, 'cidr': '0.0.0.0/0'}) == count


def test_iam_unknown_owner_does_not_pass():
    live = adapter()
    live._call = lambda *a, **k: {}
    with pytest.raises(ApiProblem):
        live._verify_iam_key({'resource': 'AKIA123'}, {})


def test_iam_queries_owner():
    live = adapter()
    def call(service, operation, **kwargs):
        if operation == 'get_access_key_last_used':
            return {'UserName': 'alice'}
        assert kwargs['UserName'] == 'alice'
        return {'AccessKeyMetadata': [{'AccessKeyId': 'AKIA123', 'Status': 'Inactive'}]}
    live._call = call
    assert live._verify_iam_key({'resource': 'AKIA123'}, {}) == 0
