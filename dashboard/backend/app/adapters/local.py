"""Persistent local simulation. All mutations require an explicit approved plan.

This adapter has no AWS imports. Jobs complete only in the separate local worker.
"""
import hashlib
import json
import uuid
from .demo import DemoAdapter,_build_events,_measure,_scenario_after
from ..storage import connect,save,encode,audit,ms
from ..api.errors import ApiProblem
from ..services.filters import apply_filters,paginate


def plan_hash(event):
    return hashlib.sha256(encode({k:event.get(k) for k in
        ('resource','region','environment','plan','criterion','criterionVersion')}).encode()).hexdigest()


def public(event):
    event['planHash']=plan_hash(event)
    return event


class LocalAdapter(DemoAdapter):
    def __init__(self,path):
        self.path=path
        with connect(path,True) as db:
            if db.execute("SELECT 1 FROM metadata WHERE key='seed_version'").fetchone():
                return
            for e in _build_events():
                e['legacyScenario']=e['scenario']
                e['scenario']={'NMS-01':'SEC-10','NMS-02':'SEC-10','IAM-01':'SEC-05'}.get(e['scenario'],e['scenario'])
                if e['scenario']=='SEC-02':
                    e['mode']='MANUAL'
                e['criterionVersion']='demo-20260918'
                e['dataMode']='demo'
                # Manual simulation includes non-SSM image replacement; this is never a live capability.
                e['actionable']=e['mode']=='MANUAL' and e['legacyScenario'] in ('SEC-02','SEC-03','SEC-04','DETECT-01')
                e['plan']={'version':'local-1','document':e['playbook'] or 'LOCAL-MANUAL-SIMULATION',
                    'target':e['resource'],'change':e['recommendation'],'simulation':True} if e['actionable'] else None
                if e['source']=='Trivy':
                    e['plan']['imageBefore']='sha256:demo-app-1.2'
                    e['plan']['imageAfter']='sha256:demo-app-1.3'
                e.update(approvalHash=None,activeExecutionId=None)
                if e.get('sourceLocation'):
                    e['sourceLocation'].pop('actorId',None)
                save(db,e)
            db.execute("INSERT INTO metadata VALUES('seed_version','1')")

    @property
    def _events(self):
        with connect(self.path) as db:
            return {r['id']:public(json.loads(r['payload'])) for r in db.execute('SELECT * FROM events ORDER BY id')}

    @property
    def _executions(self):
        with connect(self.path) as db:
            return {r['id']:json.loads(r['payload']) for r in db.execute('SELECT * FROM jobs')}

    def list_events(self,q):
        rows=apply_filters(list(self._events.values()),q)
        if q.get('view')=='vulnerabilities':
            rows=[e for e in rows if e['source'] in ('Inspector','Trivy')]
        if q.get('view')=='responses':
            rows=[e for e in rows if len(e['history'])>1 or e['status']=='PENDING_APPROVAL']
        result=paginate(rows,q)
        result['snapshot']=hashlib.sha256(encode(rows).encode()).hexdigest()[:20]
        return result

    def snapshot(self,q):
        # One SQLite read provides one revision for regional totals, charts and the paged table.
        events=list(self._events.values())
        rows=apply_filters(events,q)
        if q.get('view')=='vulnerabilities':rows=[e for e in rows if e['source'] in ('Inspector','Trivy')]
        if q.get('view')=='responses':rows=[e for e in rows if len(e['history'])>1 or e['status']=='PENDING_APPROVAL']
        regional=apply_filters(events,{**q,'region':'all','ignoreRegion':True})
        result={'total':len(rows),'resolved':sum(e['status']=='RESOLVED' for e in rows),'regions':{},'sources':{},'severity':{}}
        for e in regional:result['regions'][e['region']]=result['regions'].get(e['region'],0)+1
        for e in rows:
            for field,key in [('source','sources'),('severity','severity')]:
                result[key][e[field]]=result[key].get(e[field],0)+1
        return {'items':rows,'regionalItems':regional,'summary':result,'mode':'demo','asOf':q['to'],
                'collectedAt':ms(),'snapshot':hashlib.sha256(encode(rows).encode()).hexdigest()[:20]}

    def approve(self,event_id,body,actor,key):return self._change(event_id,'approve',body,actor,key)
    def cancel(self,event_id,body,actor,key):return self._change(event_id,'cancel',body,actor,key)
    def execute(self,event_id,body,actor,key):return self._change(event_id,'execute',body,actor,key)
    def verify(self,event_id,body,actor,key):return self._change(event_id,'verify',body,actor,key)

    def _change(self,event_id,action,body,actor,key):
        if set(body)-{'expected_status','plan_hash','dry_run'}:
            raise ApiProblem(400,'허용되지 않은 조치 파라미터입니다.',code='INVALID_PARAMETER')
        if 'dry_run' in body and type(body['dry_run']) is not bool:
            raise ApiProblem(400,'dry_run은 true/false여야 합니다.',code='INVALID_PARAMETER')
        request_hash=hashlib.sha256(encode([actor,event_id,action,body]).encode()).hexdigest()
        with connect(self.path,True) as db:
            previous=db.execute('SELECT * FROM requests WHERE key=?',(key,)).fetchone()
            if previous:
                if previous['hash']!=request_hash:
                    raise ApiProblem(409,'다른 요청에 사용된 요청 키입니다.',code='DUPLICATE_EXECUTION')
                return json.loads(previous['response'])
            record=db.execute('SELECT payload FROM events WHERE id=?',(event_id,)).fetchone()
            if not record:raise ApiProblem(404,'이벤트를 찾을 수 없습니다.',code='EVENT_NOT_FOUND')
            e=json.loads(record['payload'])
            if not e.get('actionable'):
                raise ApiProblem(422,'등록된 수동 조치가 없습니다. 자동 대응은 이 화면에서 재실행하지 않습니다.',code='GATE_WHITELIST')
            if not body.get('expected_status') or e['status']!=body['expected_status']:
                raise ApiProblem(409,'상태가 변경되었습니다. 상세 정보를 다시 확인해주세요.',code='STATE_CONFLICT')
            fp=plan_hash(e)
            if body.get('plan_hash')!=fp:
                raise ApiProblem(409,'대상 또는 변경 내용이 달라졌습니다. 재검토가 필요합니다.',code='STATE_CONFLICT')
            allowed={'approve':{'NEW','PENDING_APPROVAL','VERIFICATION_FAILED','EXECUTION_FAILED'},
                     'cancel':{'APPROVED','PENDING_APPROVAL'},'execute':{'APPROVED'},
                     'verify':{'PENDING_VERIFICATION','VERIFICATION_FAILED'}}
            if e['status'] not in allowed[action]:
                raise ApiProblem(409,'현재 상태에서 허용되지 않는 작업입니다.',code='STATE_CONFLICT')
            if action=='execute' and (not e.get('approver') or e.get('approvalHash')!=fp):
                raise ApiProblem(422,'현재 변경 내용에 대한 승인이 필요합니다.',code='APPROVAL_REQUIRED')
            if action=='verify' and e['execution']!='SUCCEEDED':
                raise ApiProblem(409,'조치 실행 성공 후 재검증할 수 있습니다.',code='STATE_CONFLICT')
            if body.get('dry_run'):
                result={'dryRun':True,'allowed':True,'event':public(e)}
            else:
                if action=='approve':
                    e.update(status='APPROVED',approver=actor,approvedAt=ms(),approvalHash=fp)
                elif action=='cancel':
                    e.update(status='PENDING_APPROVAL',approver=None,approvedAt=None,approvalHash=None)
                else:
                    job={'executionId':str(uuid.uuid4()),'eventId':event_id,'kind':'REMEDIATION' if action=='execute' else 'VERIFICATION',
                         'document':e.get('playbook'),'status':'RUNNING','startedAt':ms(),'endedAt':None,
                         'progress':{'step':'작업 대기','completed':0,'total':1},'failureMessage':None,
                         'planHash':fp,'plan':e['plan'],'actor':actor}
                    db.execute('INSERT INTO jobs VALUES(?,?,?,?,?)',(job['executionId'],event_id,job['kind'],'RUNNING',encode(job)))
                    e['activeExecutionId']=job['executionId']
                    if action=='execute':
                        e.update(status='EXECUTING',execution='RUNNING',verification='NOT_RUN',afterValue=None,afterAt=None,
                                 after=_measure(None,e['unit'],None))
                    else:e.update(status='VERIFYING',verification='CHECKING')
                e['history'].append({'at':ms(),'text':f'{actor}: {action} (로컬 모의 작업)','actor':actor,'decision':action})
                save(db,e)
                result={'execution':job,'event':public(e)} if action in ('execute','verify') else public(e)
            audit(db,actor,event_id,action,{'planHash':fp,'dryRun':bool(body.get('dry_run'))})
            db.execute('INSERT INTO requests VALUES(?,?,?)',(key,request_hash,encode(result)))
            return result

    def execution_status(self,event_id,execution_id):
        with connect(self.path) as db:
            job=db.execute('SELECT payload FROM jobs WHERE id=? AND event_id=?',(execution_id,event_id)).fetchone()
            e=db.execute('SELECT payload FROM events WHERE id=?',(event_id,)).fetchone()
        return {'execution':json.loads(job['payload']),'event':public(json.loads(e['payload']))} if job and e else None

    def work_once(self):
        # Pure local simulation: completing the job and updating the event commit atomically.
        # A killed worker leaves the persisted job pending; the next worker safely resumes it.
        with connect(self.path,True) as db:
            db.execute("INSERT OR REPLACE INTO metadata VALUES('worker_heartbeat',?)",(str(ms()),))
            for row in db.execute("SELECT * FROM jobs WHERE state='RUNNING'").fetchall():
                job=json.loads(row['payload'])
                e=json.loads(db.execute('SELECT payload FROM events WHERE id=?',(row['event_id'],)).fetchone()['payload'])
                if job['planHash']!=plan_hash(e):
                    job.update(status='FAILED',failureMessage='승인 이후 변경 내용이 달라졌습니다.')
                    e.update(status='EXECUTION_FAILED',execution='FAILED')
                elif job['kind']=='REMEDIATION':
                    job['status']='SUCCEEDED'
                    e.update(status='PENDING_VERIFICATION',execution='SUCCEEDED')
                else:
                    failed=e['source']=='Trivy'
                    value=2 if failed else _scenario_after({**e,'scenario':e['legacyScenario']}) if e['unit']=='%' else 0
                    e.update(verification='FAILED' if failed else 'PASSED',status='VERIFICATION_FAILED' if failed else 'RESOLVED',
                             afterValue=value,afterAt=ms(),after=_measure(value,e['unit'],ms()))
                    job['status']='SUCCEEDED'
                job.update(endedAt=ms(),progress={'step':'로컬 모의 작업 완료','completed':1,'total':1})
                e['activeExecutionId']=None
                e['history'].append({'at':ms(),'text':f"로컬 {job['kind']} 완료: {e['status']}",'actor':'local-worker','decision':'completed'})
                save(db,e)
                db.execute('UPDATE jobs SET state=?,payload=? WHERE id=?',(job['status'],encode(job),row['id']))
                audit(db,'local-worker',e['id'],'completed',{'jobId':row['id'],'status':e['status']})

    def health_checks(self):
        with connect(self.path) as db:
            row=db.execute("SELECT value FROM metadata WHERE key='worker_heartbeat'").fetchone()
        return {'database':'ok','worker':'ok' if row and ms()-int(row['value'])<10000 else 'stopped'}

    def evidence(self,event_id):
        result=super().evidence(event_id)
        if result:
            for item in result['items']:
                if item['source'] in ('aws','dynamodb'):item['source']='demo'
        return result
