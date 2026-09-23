from pathlib import Path
import socket
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from soar import create_app
from soar.auth import create_user


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def reject(*args, **kwargs):
        raise AssertionError("A disconnected backend must not contact external services")
    monkeypatch.setattr(socket.socket, "connect", reject)


@pytest.fixture
def app(tmp_path):
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "dashboard.sqlite3"),
                      "SECRET_KEY": "unit-test-only", "WRITE_ENABLED": False})
    create_user(app.extensions["store"], "operator", "test-password-123", "operator")
    return app


@pytest.fixture
def client(app):
    client = app.test_client()
    token = client.get('/api/auth/session').json['csrfToken']
    response = client.post('/api/auth/login', json={"username": "operator", "password": "test-password-123"},
                           headers={"X-CSRF-Token": token})
    assert response.status_code == 200
    client.environ_base['HTTP_X_CSRF_TOKEN'] = response.json['csrfToken']
    return client
