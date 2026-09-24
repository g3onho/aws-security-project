import json
from pathlib import Path

import pytest

from soar import create_app
from soar.errors import Problem


@pytest.mark.parametrize('route', [
    '/api/events', '/api/summary', '/api/metrics', '/api/vulnerabilities', '/api/infra/status', '/api/history',
])
def test_missing_source_is_not_reported_as_empty_or_success(client, route):
    response = client.get(route)
    assert response.status_code == 503
    assert response.json['error']['code'] == 'DATA_SOURCE_NOT_CONFIGURED'


def test_startup_and_restart_do_not_populate_operational_tables(app):
    restarted = create_app(dict(app.config))
    with restarted.extensions['store'].connect() as db:
        for table in ('events', 'jobs', 'requests', 'metadata'):
            assert db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] == 0
        assert db.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 1
        assert json.loads(db.execute('SELECT scope FROM users').fetchone()[0])['accounts'] == []


def test_disconnected_status_and_write_gate(client):
    for path in ('/api/legacy/config', '/api/legacy/health', '/api/legacy/events'):
        assert client.get(path).status_code == 404
    assert client.post('/execute', json={}).status_code == 403


def test_worker_cannot_fabricate_a_result(app):
    with pytest.raises(Problem) as error:
        app.extensions['worker'].run_once()
    assert error.value.status == 503
    assert app.extensions['store'].events() == []


def test_write_flag_cannot_enable_unconfigured_execution(app, client):
    app.config['WRITE_ENABLED'] = True
    response = client.post('/execute', json={})
    assert response.status_code == 503


def test_authentication_csrf_logout_and_assets(app, client):
    anonymous = app.test_client()
    assert anonymous.get('/').status_code == 302
    assert anonymous.get('/api/events').status_code == 401
    assert anonymous.post('/api/auth/login', json={}).status_code == 403
    assert client.get('/').status_code == 200
    root = Path(__file__).resolve().parents[2]
    assert client.get('/static/js/store.js').data == (root / 'frontend/static/js/store.js').read_bytes()
    assert client.get('/static/js/data.js').data == (root / 'frontend/static/js/data.js').read_bytes()
    assert client.post('/api/auth/logout', json={}).status_code == 200
    assert client.get('/api/events').status_code == 401


def test_health_distinguishes_process_from_data_readiness(client):
    response = client.get('/health')
    assert response.status_code == 200
    # 설계 3.3 #1·openapi HealthEnvelope: 생존 여부와 연결 여부만. 공급자 내부 구성은 노출하지 않는다.
    assert response.json['data'] == {'status': 'ok', 'dataSourceConnected': False}
