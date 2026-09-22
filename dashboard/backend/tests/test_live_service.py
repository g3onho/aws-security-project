"""Offline contract tests for the production live service, not just the mapper."""
import copy
import uuid
from types import SimpleNamespace

import pytest

from app.adapters.live_service import LiveService
from app.api.errors import ApiProblem
from app.storage import migrate, connect
from run import create_app
from app.auth import create_user
from tests.conftest import login


@pytest.fixture
def service(tmp_path, monkeypatch):
    import socket
    monkeypatch.setattr(socket.socket, 'connect', lambda *a: pytest.fail('Tests must not access AWS/network'))
    path = str(tmp_path/'live.sqlite3')
    migrate(path)
    config = SimpleNamespace(WRITE_ENABLED=True, ENFORCE_GATES=True, AWS_REGION='ap-northeast-2',
                             NAME_PREFIX='soar-sec-dev', REMEDIATION_ACTIONS_TABLE='actions',
                             CORRELATED_FINDINGS_TABLE='', SCAN_RESULTS_BUCKET='', SNS_TOPIC_ARN='',
                             CACHE_TTL={'events': 15, 'metrics': 30, 'vulnerabilities': 120})
    live = LiveService(config, path)
    calls = []
    cloud = {'open': True, 'state': 'InProgress', 'timeout': False, 'ddb_error': False}

    def call(service, operation, **kwargs):
        calls.append((service, operation, kwargs))
        if operation == 'get_findings':
            return {'Findings': [{'Id': 'sg-finding', 'GeneratorId': 'EC2.13', 'Title': 'SSH open',
                                  'UpdatedAt': '2026-09-22T00:00:00Z', 'Severity': {'Label': 'HIGH'},
                                  'Resources': [{'Id': 'sg-123'}]}]}
        if operation == 'describe_document':
            return {'Document': {'DocumentVersion': '3'}}
        if operation == 'describe_alarms':
            return {'MetricAlarms': []}
        if operation == 'scan':
            return {'Items': []}
        if operation == 'put_item':
            if cloud['ddb_error']:
                raise ApiProblem(502, 'unavailable', code='UPSTREAM_ERROR')
            return {}
        if operation == 'get_caller_identity':
            return {'Account': '123456789012'}
        if operation == 'describe_security_groups':
            return {'SecurityGroups': [{'IpPermissions': [{'IpProtocol': 'tcp', 'FromPort': 1, 'ToPort': 65535,
                                                          'Ipv6Ranges': [{'CidrIpv6': '::/0'}]}] if cloud['open'] else []}]}
        if operation == 'start_automation_execution':
            if cloud['timeout']:
                raise ApiProblem(502, 'timeout', code='UPSTREAM_ERROR')
            return {'AutomationExecutionId': 'aws-run-1'}
        if operation == 'get_automation_execution':
            return {'AutomationExecution': {'AutomationExecutionStatus': cloud['state']}}
        raise AssertionError((service, operation, kwargs))

    live._call = call
    live.test_calls, live.test_cloud = calls, cloud
    return live


def change(live, action, event_id='sg-finding', **extra):
    e = live.get_event(event_id)
    return getattr(live, action)(event_id, {'expected_status': e['status'], 'plan_hash': e['planHash'], **extra},
                                 'operator', str(uuid.uuid4()))


def finish_execution(live):
    change(live, 'approve')
    result = change(live, 'execute')
    live.work_once()  # persist exact request and Before before submission
    live.work_once()
    live.test_cloud['state'] = 'Success'
    live.work_once()
    return result


def test_complete_flow_and_restart(service):
    result = finish_execution(service)
    assert service.get_event('sg-finding')['status'] == 'PENDING_VERIFICATION'
    assert service.get_event('sg-finding')['before']['value'] == 1
    service.test_cloud['open'] = False
    job = change(service, 'verify')['execution']
    service.work_once()
    restarted = LiveService(service.config, service.path)
    restarted._call = service._call
    e = restarted.get_event('sg-finding')
    assert e['status'] == 'RESOLVED' and e['after']['value'] == 0
    assert restarted.execution_status('sg-finding', job['executionId'])['execution']['kind'] == 'VERIFICATION'
    assert restarted.execution_status('other-finding', job['executionId']) is None
    assert restarted.evidence('sg-finding')['ssmExecutionIds'] == ['aws-run-1']
    assert service.test_calls.count(('ssm', 'get_automation_execution', {'AutomationExecutionId': 'aws-run-1'})) == 1


def test_request_replay_after_restart_without_aws(service):
    e = service.get_event('sg-finding')
    body = {'expected_status': e['status'], 'plan_hash': e['planHash']}
    result = service.approve(e['id'], body, 'operator', 'key')
    restarted = LiveService(service.config, service.path)
    restarted._call = lambda *a, **k: pytest.fail('Replay must not require AWS')
    assert restarted.approve(e['id'], body, 'operator', 'key') == result
    with pytest.raises(ApiProblem) as caught:
        restarted.approve(e['id'], body, 'different-actor', 'key')
    assert caught.value.status == 409


@pytest.mark.parametrize('action', ['execute', 'verify', 'cancel'])
def test_out_of_order_blocked(service, action):
    with pytest.raises(ApiProblem) as caught:
        change(service, action)
    assert caught.value.status == 409
    assert not any(op == 'start_automation_execution' for _, op, _ in service.test_calls)


def test_approval_cancel(service):
    change(service, 'approve')
    change(service, 'cancel')
    assert service.get_event('sg-finding')['approver'] is None
    with pytest.raises(ApiProblem):
        change(service, 'execute')


def test_tampered_plan(service):
    with pytest.raises(ApiProblem) as caught:
        service.approve('sg-finding', {'expected_status': 'NEW', 'plan_hash': 'tampered'}, 'operator', 'x')
    assert caught.value.status == 409


def test_submission_timeout_reuses_token(service):
    change(service, 'approve')
    job = change(service, 'execute')['execution']
    service.work_once()
    service.test_cloud['timeout'] = True
    service.work_once()
    assert service.execution_status('sg-finding', job['executionId'])['execution']['status'] == 'RUNNING'
    service.test_cloud['timeout'] = False
    restarted = LiveService(service.config, service.path)
    restarted._call = service._call
    restarted.work_once()
    tokens = [args['ClientToken'] for _, op, args in service.test_calls if op == 'start_automation_execution']
    assert tokens == [job['executionId'], job['executionId']]


def test_failure_is_not_success(service):
    change(service, 'approve')
    change(service, 'execute')
    service.work_once()
    service.work_once()
    service.test_cloud['state'] = 'Failed'
    service.work_once()
    assert service.get_event('sg-finding')['status'] == 'EXECUTION_FAILED'
    with pytest.raises(ApiProblem):
        change(service, 'verify')


def test_remaining_rules_fail_verification(service):
    finish_execution(service)
    change(service, 'verify')
    service.work_once()
    assert service.get_event('sg-finding')['verification'] == 'FAILED'


def test_outbox_survives_failure(service):
    change(service, 'approve')
    service.test_cloud['ddb_error'] = True
    service.flush_outbox()
    with connect(service.path) as db:
        assert db.execute('SELECT count(*) FROM live_outbox').fetchone()[0] == 1
    service.test_cloud['ddb_error'] = False
    service.flush_outbox()
    with connect(service.path) as db:
        assert db.execute('SELECT count(*) FROM live_outbox').fetchone()[0] == 0


def test_manual_evidence_is_explicit(service):
    e = service._event(event_id='manual', scenario='SEC-02', title='headers', severity='MEDIUM',
                       source='Security Hub', region='ap-northeast-2', resource='web-server',
                       at=1, evidence='', recommendation='', extra=None)
    service._cache['events'] = (__import__('time').time(), [e])
    change(service, 'approve', 'manual')
    with pytest.raises(ApiProblem):
        change(service, 'execute', 'manual')
    change(service, 'execute', 'manual', evidence={'note': '담당자가 설정 수정', 'reference': 'change-42'})
    e = service.get_event('manual')
    proof = {'resource': e['resource'], 'criterionVersion': e['criterionVersion'], 'value': 0,
             'observedAt': e['executedAt'], 'reference': 'curl-result-42'}
    change(service, 'verify', 'manual', evidence=proof)
    service.work_once()
    assert service.get_event('manual')['after']['source'] == 'operator-evidence'
    assert not any(op == 'start_automation_execution' for _, op, _ in service.test_calls)


def test_real_api_live_write_and_readonly(service, tmp_path):
    app = create_app({'TESTING': True, 'USE_DEMO_DATA': False, 'WRITE_ENABLED': True,
                      'DATABASE': str(tmp_path/'api.sqlite3')})
    app.extensions['dashboard_adapter'] = service
    create_user(app.config['DATABASE'], 'operator', 'test-password-123', 'operator')
    client = login(app)
    e = client.get('/api/events/sg-finding').json
    assert e['actionable'] and e['planHash']
    headers = {'Idempotency-Key': str(uuid.uuid4())}
    body = {'expected_status': e['status'], 'plan_hash': e['planHash']}
    assert client.post('/api/events/sg-finding/approve', json=body, headers=headers).status_code == 200
    app.config['WRITE_ENABLED'] = False
    assert client.post('/api/events/sg-finding/execute', json=body, headers=headers).status_code == 409


def test_submission_matches_installed_aws_sdk_schema(service):
    import botocore.session
    from botocore.validate import validate_parameters
    finish_execution(service)
    args = next(args for _, op, args in service.test_calls if op == 'start_automation_execution')
    shape = botocore.session.get_session().get_service_model('ssm').operation_model('StartAutomationExecution').input_shape
    validate_parameters(args, shape)
    assert args['DocumentVersion'] == '3'


def test_readonly_service_does_not_process_jobs(service):
    change(service, 'approve')
    change(service, 'execute')
    service.config.WRITE_ENABLED = False
    service.work_once()
    assert not any(op == 'start_automation_execution' for _, op, _ in service.test_calls)
