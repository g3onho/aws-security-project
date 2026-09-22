from pathlib import Path
import sys
import pytest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from run import create_app
from app.auth import create_user

@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    """The backend suite is offline, including live-mode integration tests."""
    import socket
    monkeypatch.setattr(socket.socket, 'connect', lambda *args: pytest.fail('Network access is forbidden in backend tests'))

@pytest.fixture
def demo_app(tmp_path):
    app=create_app({'DATABASE':str(tmp_path/'db.sqlite3'),'TESTING':True,'USE_DEMO_DATA':True,'WRITE_ENABLED':True})
    create_user(app.config['DATABASE'],'operator','test-password-123','operator')
    create_user(app.config['DATABASE'],'reader','test-password-123','viewer')
    return app

def login(app,name='operator'):
    c=app.test_client();token=c.get('/api/auth/session').json['csrfToken']
    r=c.post('/api/auth/login',json={'username':name,'password':'test-password-123'},headers={'X-CSRF-Token':token})
    assert r.status_code==200
    c.environ_base['HTTP_X_CSRF_TOKEN']=r.json['csrfToken']
    return c

@pytest.fixture
def client(demo_app):return login(demo_app)

@pytest.fixture
def readonly_app(demo_app):
    demo_app.config['WRITE_ENABLED']=False
    return demo_app

@pytest.fixture
def live_app(tmp_path):return create_app({'DATABASE':str(tmp_path/'live.sqlite3'),'TESTING':True,'USE_DEMO_DATA':False})
