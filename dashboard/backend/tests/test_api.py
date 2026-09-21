import concurrent.futures
import csv
import io
import json
import uuid
import pytest
from tests.conftest import login
from run import create_app
from app.storage import connect,save
from app.adapters.demo import DEMO_NOW

ID='EVT-0003'
def event(c,id=ID):return c.get('/api/events/'+id).json
def change(c,action,id=ID,body=None,key=None):
    e=event(c,id)
    return c.post('/api/events/'+id+'/'+action,json=body if body is not None else {'expected_status':e['status'],'plan_hash':e['planHash']},headers={'Idempotency-Key':key or str(uuid.uuid4()),'X-Actor':'forged-admin'})
def work(app):app.extensions['dashboard_adapter'].work_once()

def test_pages_and_assets(client):
    assert client.get('/').status_code==200
    for name in ['js/app.js','js/store.js','js/login.js','css/app.css','data/countries.geojson']:
        assert client.get('/static/'+name).status_code==200

def test_auth_required(demo_app):
    c=demo_app.test_client()
    assert c.get('/').status_code==302
    assert c.get('/api/events').status_code==401
    assert c.post('/api/events/'+ID+'/verify',json={}).status_code==401

def test_csrf(client):
    r=client.post('/api/events/'+ID+'/approve',json={},headers={'X-CSRF-Token':'wrong'})
    assert r.status_code==403

def test_viewer(demo_app):
    c=login(demo_app,'reader');assert c.get('/api/events').status_code==200
    assert change(c,'approve').status_code==403

def test_actor_is_authenticated(client):
    r=change(client,'approve');assert r.status_code==200
    assert r.json['approver']=='operator'

def test_manual_requires_approval(client):assert change(client,'execute').status_code==409

def test_verify_before_execute_blocked(client):
    assert change(client,'verify').status_code==409
    assert event(client)['execution']=='NOT_RUN'

def test_missing_expected_status(client):assert change(client,'approve',body={}).status_code==409

def test_plan_hash_required(client):
    assert change(client,'approve',body={'expected_status':'PENDING_APPROVAL'}).status_code==409

def test_full_flow(client,demo_app):
    assert change(client,'approve').status_code==200
    r=change(client,'execute');assert r.status_code==202
    job=r.json['execution']['executionId'];assert event(client)['status']=='EXECUTING'
    work(demo_app);assert event(client)['status']=='PENDING_VERIFICATION'
    assert event(client)['verification']=='NOT_RUN'
    assert client.get('/api/events/'+ID+'/executions/'+job).json['execution']['status']=='SUCCEEDED'
    assert change(client,'verify').status_code==202
    work(demo_app);assert event(client)['status']=='RESOLVED'

def test_trivy_failure(client,demo_app):
    id='EVT-0004';assert change(client,'approve',id).status_code==200
    assert change(client,'execute',id).status_code==202;work(demo_app)
    assert change(client,'verify',id).status_code==202;work(demo_app)
    e=event(client,id);assert e['status']=='VERIFICATION_FAILED' and e['afterValue']==2

def test_cancel(client):
    change(client,'approve');assert change(client,'cancel').status_code==200
    assert event(client)['approver'] is None
    assert change(client,'execute').status_code==409

def test_cannot_cancel_running(client):
    change(client,'approve');change(client,'execute')
    assert change(client,'cancel').status_code==409

def test_dry_run_no_mutation(client,demo_app):
    change(client,'approve');e=event(client)
    r=change(client,'execute',body={'expected_status':e['status'],'plan_hash':e['planHash'],'dry_run':True})
    assert r.status_code==202 and r.json['dryRun']
    work(demo_app);assert event(client)['execution']=='NOT_RUN'

def test_identical_approval_replay(client):
    e=event(client);body={'expected_status':e['status'],'plan_hash':e['planHash']};key=str(uuid.uuid4())
    a=change(client,'approve',body=body,key=key);b=change(client,'approve',body=body,key=key)
    assert a.status_code==b.status_code==200 and a.json==b.json

def test_identical_execution_replay(client):
    change(client,'approve');e=event(client);body={'expected_status':e['status'],'plan_hash':e['planHash']};key=str(uuid.uuid4())
    a=change(client,'execute',body=body,key=key);b=change(client,'execute',body=body,key=key)
    assert a.status_code==b.status_code==202 and a.json==b.json

def test_key_bound_to_operation(client):
    key=str(uuid.uuid4());change(client,'approve',key=key)
    assert change(client,'execute',key=key).status_code==409

def test_key_bound_to_event(client):
    key=str(uuid.uuid4());change(client,'approve',key=key)
    assert change(client,'approve',id='EVT-0004',key=key).status_code==409

def test_duplicate_execution_different_keys(client):
    change(client,'approve');assert change(client,'execute').status_code==202
    assert change(client,'execute').status_code==409

def test_parallel_requests(demo_app,client):
    change(client,'approve');e=event(client);body={'expected_status':e['status'],'plan_hash':e['planHash']}
    def submit(_):return change(login(demo_app),'execute',body=body).status_code
    with concurrent.futures.ThreadPoolExecutor(2) as pool:results=list(pool.map(submit,range(2)))
    assert sorted(results)==[202,409]

def test_restart_persists_and_worker_resumes(client,demo_app):
    change(client,'approve');change(client,'execute')
    new=create_app({'DATABASE':demo_app.config['DATABASE'],'USE_DEMO_DATA':True,'TESTING':True})
    c=login(new);assert event(c)['approver']=='operator';assert event(c)['status']=='EXECUTING'
    work(new);assert event(c)['status']=='PENDING_VERIFICATION'

def test_changed_plan_invalidates_approval(client,demo_app):
    change(client,'approve')
    with connect(demo_app.config['DATABASE'],True) as db:
        e=json.loads(db.execute('SELECT payload FROM events WHERE id=?',(ID,)).fetchone()['payload'])
        e['plan']['target']='different';save(db,e)
    assert change(client,'execute').status_code==422

def test_auto_not_reexecuted(client):
    assert change(client,'approve',id='EVT-0009').status_code==422

def test_default_time_is_demo(client):assert client.get('/api/events').json['total']>0

def test_pagination_and_snapshot(client):
    q={'region':'ap-northeast-2','severity':'CRITICAL'}
    snap=client.get('/api/snapshot',query_string=q).json
    ids=[];cursor=None
    while True:
        page=client.get('/api/events',query_string={**q,'limit':2,**({'cursor':cursor} if cursor else {})}).json
        ids += [e['id'] for e in page['items']];cursor=page['nextCursor']
        if not cursor:break
    assert len(ids)==len(set(ids))==snap['summary']['total']
    assert ids==[e['id'] for e in snap['items']]
    assert sum(snap['summary']['regions'].values())==len(snap['regionalItems'])

def test_csv_matches_filter(client):
    q={'source':'Trivy','region':'all'}
    total=client.get('/api/snapshot',query_string=q).json['summary']['total']
    text=client.get('/api/export/events.csv',query_string=q).data.decode('utf-8-sig')
    assert len(list(csv.reader(io.StringIO(text))))-1==total

def test_environment_filter(client):
    page=client.get('/api/events?environment=staging').json
    assert page['items'] and all(e['environment']=='staging' for e in page['items'])

@pytest.mark.parametrize('q',[{'from':10,'to':1},{'region':'../etc'},{'severity':'bad'},{'from':DEMO_NOW-32*86400000,'to':DEMO_NOW},{'q':'x'*201}])
def test_bad_query(client,q):assert client.get('/api/events',query_string=q).status_code==400

def test_unknown_event(client):assert client.get('/api/events/no-such-event').status_code==404

def test_unintegrated_services_and_health(client,demo_app):
    assert client.get('/health').json['aws_connected'] is False
    assert client.get('/health').json['checks']['worker']=='stopped'
    work(demo_app);assert client.get('/health').json['checks']['worker']=='ok'

def test_live_no_aws_calls(live_app,monkeypatch):
    import socket
    monkeypatch.setattr(socket.socket,'connect',lambda *a:pytest.fail('network access'))
    assert live_app.test_client().get('/health').json['aws_connected'] is False
    assert live_app.config['WRITE_ENABLED'] is False

def test_readonly(demo_app):
    demo_app.config['WRITE_ENABLED']=False
    assert change(login(demo_app),'approve').status_code==409

def test_evidence(client):
    e=client.get('/api/events/'+ID+'/evidence').json
    assert len(e['items'])==12

def test_headers(client):
    r=client.get('/api/events');assert r.headers['Cache-Control']=='no-store'
    assert "script-src 'self'" in r.headers['Content-Security-Policy']

def test_audit(client):
    change(client,'approve');assert any(r['action']=='approve' and r['actor']=='operator' for r in client.get('/api/audit').json['items'])

def test_login_rate_limit(demo_app):
    c=demo_app.test_client();csrf=c.get('/api/auth/session').json['csrfToken']
    for _ in range(5):c.post('/api/auth/login',json={'username':'bad','password':'bad'},headers={'X-CSRF-Token':csrf})
    assert c.post('/api/auth/login',json={'username':'bad','password':'bad'},headers={'X-CSRF-Token':csrf}).status_code==429

def test_logout(client):
    assert client.post('/api/auth/logout',json={}).status_code==200
    assert client.get('/api/events').status_code==401

