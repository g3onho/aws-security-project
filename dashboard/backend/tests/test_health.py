"""Health reports actual adapter checks, including partial AWS failures."""
import pytest


@pytest.mark.parametrize('checks,connected', [
    ({'cloudwatch': 'ok', 'securityhub': 'ok'}, True),
    ({'cloudwatch': 'ok', 'securityhub': 'error'}, False),
    ({'cloudwatch': 'skipped'}, False),
    ({}, False),
])
def test_live_health(demo_app, checks, connected):
    class Adapter:
        mode = 'live'

        def health_checks(self):
            return checks

    # The route captures the adapter at app creation.
    adapter = demo_app.extensions['dashboard_adapter']
    adapter.mode = Adapter.mode
    adapter.health_checks = Adapter().health_checks
    response = demo_app.test_client().get('/health')
    assert response.status_code == 200
    assert response.json['checks'] == checks
    assert response.json['aws_connected'] is connected
    assert response.json['status'] == ('ok' if connected else 'degraded')


def test_demo_health_never_claims_aws_connection(demo_app):
    demo_app.extensions['dashboard_adapter'].health_checks = lambda: {'worker': 'ok', 'database': 'ok'}
    result = demo_app.test_client().get('/health').json
    assert result['status'] == 'ok'
    assert result['aws_connected'] is False
