"""Single-host live workflow. SQLite owns durable jobs; AWS owns observations.

Requests only enqueue jobs. A worker submits SSM with a persisted ClientToken,
polls the result, then runs verification as a separate job. No AWS credentials
are needed to test this service: replace _call with a fake or botocore Stubber.
"""
import copy
import hashlib
import ipaddress
import json
import math
import uuid
from datetime import datetime, timezone, timedelta

from .live import LiveAdapter, _short, _now_ms
from .local import plan_hash
from ..catalog import loader
from ..api.errors import ApiProblem
from ..storage import connect, encode, audit, ms


ALLOWED = {
    'plan': {'NEW', 'PENDING_APPROVAL', 'EXECUTION_FAILED', 'VERIFICATION_FAILED'},
    'approve': {'NEW', 'PENDING_APPROVAL', 'EXECUTION_FAILED', 'VERIFICATION_FAILED'},
    'cancel': {'APPROVED'},
    'execute': {'APPROVED'},
    'verify': {'PENDING_VERIFICATION', 'VERIFICATION_FAILED'},
}


class LiveService(LiveAdapter):
    def __init__(self, config, path):
        super().__init__(config)
        self.path = path

    def _decorate(self, event):
        e = copy.deepcopy(event)
        spec = loader.get(e['scenario']) or {}
        document = e.get('playbook')
        target = _short(e.get('resource', ''))
        supported = ((document == 'ASR-RevokeSecurityGroupIngress' and target.startswith('sg-'))
                     or (document == 'ASR-DisableExposedAccessKey' and target.startswith(('AKIA', 'ASIA'))))
        # Other v11 improvements are operator procedures, not fabricated SSM successes.
        e['actionable'] = bool(spec)
        e['dataMode'] = 'live'
        e['criterionVersion'] = hashlib.sha256(encode(spec.get('verify', {})).encode()).hexdigest()[:16]
        e['plan'] = {'target': e['resource'], 'document': document if supported else 'MANUAL',
                     'version': '$DEFAULT', 'simulation': False,
                     'change': ('대상 보안 그룹의 모든 0.0.0.0/0 및 ::/0 인바운드 규칙 제거'
                                if document == 'ASR-RevokeSecurityGroupIngress' else e['recommendation']),
                     'manual': not supported} if spec else None
        e['blockedReason'] = None if spec else '분류된 점검 기준이 없어 담당자 분석이 필요합니다.'
        verify_type = spec.get('verify', {}).get('type')
        e['verificationMethod'] = 'aws' if verify_type in ('sg_ingress_count', 'iam_key_status', 'cloudwatch_metric', 'inspector_cve_count') or (verify_type == 'config_compliance' and spec.get('verify', {}).get('rules')) else 'operator-evidence'
        e['planHash'] = plan_hash(e)
        return e

    def _events(self):
        rows = {e['id']: self._decorate(e) for e in super()._events()}
        for e in rows.values():
            external_id = e.get('externalExecutionId')
            if external_id and external_id != 'n/a':
                try:
                    run = self._cached('external:' + external_id, 5,
                                       lambda: self._call('ssm', 'get_automation_execution', AutomationExecutionId=external_id)['AutomationExecution'])
                except ApiProblem:
                    continue
                if run.get('AutomationExecutionStatus') == 'Success':
                    e.update(status='PENDING_VERIFICATION', execution='SUCCEEDED')
                elif run.get('AutomationExecutionStatus') in ('Failed', 'Cancelled', 'TimedOut', 'Rejected'):
                    e.update(status='EXECUTION_FAILED', execution='FAILED')
        with connect(self.path) as db:
            for row in db.execute('SELECT id,payload FROM live_events'):
                saved = json.loads(row['payload'])
                # Preserve the approved target and evidence even when an upstream
                # finding disappears after remediation. Never silently retarget it.
                rows[row['id']] = saved
        return sorted(rows.values(), key=lambda e: (-e['at'], e['id']))

    def approve(self, event_id, body, actor, key):
        return self._change(event_id, 'approve', body, actor, key)

    def cancel(self, event_id, body, actor, key):
        return self._change(event_id, 'cancel', body, actor, key)

    def execute(self, event_id, body, actor, key):
        return self._change(event_id, 'execute', body, actor, key)

    def verify(self, event_id, body, actor, key):
        return self._change(event_id, 'verify', body, actor, key)

    def prepare_plan(self, event_id, body, actor, key):
        return self._change(event_id, 'plan', body, actor, key)

    def _nacl_plan(self, e, parameters):
        required = {'networkAclId', 'sourceIp', 'ruleNumber', 'sourceEvidence'}
        if e['scenario'] != 'SEC-06' or not isinstance(parameters, dict) or set(parameters) != required:
            raise ApiProblem(400, 'SEC-06 NACL 대상과 출발지 증적이 필요합니다.', code='INVALID_PARAMETER')
        try:
            address = ipaddress.IPv4Address(parameters['sourceIp'])
        except (ValueError, TypeError):
            raise ApiProblem(400, '유효한 출발지 IPv4 주소가 필요합니다.', code='INVALID_PARAMETER')
        number = parameters['ruleNumber']
        target = parameters['networkAclId']
        reference = parameters['sourceEvidence']
        if (type(number) is not int or not 1 <= number <= 99 or not isinstance(target, str)
                or not target.startswith('acl-') or not isinstance(reference, str) or not 1 <= len(reference.strip()) <= 2000):
            raise ApiProblem(400, 'NACL ID, 규칙 번호 1~99, 출발지 증적을 확인하세요.', code='INVALID_PARAMETER')
        if e.get('sourceIp') and str(address) != e['sourceIp']:
            raise ApiProblem(409, '탐지된 출발지와 다릅니다.', code='STATE_CONFLICT')
        acls = self._call('ec2', 'describe_network_acls', NetworkAclIds=[target]).get('NetworkAcls', [])
        if len(acls) != 1 or any(not entry.get('Egress') and entry.get('RuleNumber') == number for entry in acls[0].get('Entries', [])):
            raise ApiProblem(409, '대상이 없거나 이미 사용 중인 규칙 번호입니다.', code='STATE_CONFLICT')
        return {'target': target, 'document': 'ASR-BlockIpWithNacl', 'version': '$DEFAULT',
                'manual': False, 'simulation': False, 'sourceEvidence': reference,
                'change': f'{target} 인바운드 규칙 {number}: {address}/32 모든 프로토콜 차단',
                'parameters': {'NetworkAclId': [target], 'AttackerCidr': [str(address) + '/32'], 'RuleNumber': [str(number)]}}

    def _save(self, db, e):
        db.execute('INSERT INTO live_events VALUES(?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload',
                   (e['id'], encode(e)))

    def _record_change(self, db, e, action, actor, job=None):
        e['history'].append({'at': ms(), 'actor': actor, 'decision': action, 'text': f'{actor}: {action}'})
        self._save(db, e)
        audit(db, actor, e['id'], action, {'mode': 'live', 'status': e['status']})
        record_id = str(uuid.uuid4())
        payload = {'action_id': record_id, 'finding_id': e['id'], 'created_at': str(ms()),
                   'decision': action, 'actor': actor, 'resource_id': e['resource'],
                   'before_state': encode(e.get('before')), 'after_state': encode(e.get('after')),
                   'ssm_execution_id': (job or {}).get('awsExecutionId') or 'n/a',
                   'status': e['status']}
        if self.config.REMEDIATION_ACTIONS_TABLE:
            db.execute('INSERT INTO live_outbox VALUES(?,?)', (record_id, encode(payload)))

    def _change(self, event_id, action, body, actor, key):
        self._require_write(action)
        if set(body) - {'expected_status', 'plan_hash', 'dry_run', 'evidence', 'parameters'}:
            raise ApiProblem(400, '허용되지 않은 파라미터입니다.', code='INVALID_PARAMETER')
        if 'dry_run' in body and type(body['dry_run']) is not bool:
            raise ApiProblem(400, 'dry_run은 boolean이어야 합니다.', code='INVALID_PARAMETER')
        fingerprint = hashlib.sha256(encode([actor, event_id, action, body]).encode()).hexdigest()
        # Replay before reading AWS, including after a process restart or outage.
        with connect(self.path) as db:
            old = db.execute('SELECT * FROM live_requests WHERE key=?', (key,)).fetchone()
        if old:
            return self._replay_request(old, fingerprint)
        observed = self._require(event_id)
        new_plan = self._nacl_plan(observed, body.get('parameters')) if action == 'plan' else None
        # Resolve the default document once at approval, then execute only that
        # immutable numeric version even if AWS's default changes later.
        document_version = None
        if action == 'approve' and observed.get('plan') and not observed['plan']['manual']:
            document_version = self._call('ssm', 'describe_document', Name=observed['plan']['document'])['Document']['DocumentVersion']
            if not str(document_version).isdigit():
                raise ApiProblem(502, '플레이북 버전을 확인할 수 없습니다.', code='UPSTREAM_ERROR')
        with connect(self.path, True) as db:
            old = db.execute('SELECT * FROM live_requests WHERE key=?', (key,)).fetchone()
            if old:
                return self._replay_request(old, fingerprint)
            saved = db.execute('SELECT payload FROM live_events WHERE id=?', (event_id,)).fetchone()
            e = json.loads(saved['payload']) if saved else copy.deepcopy(observed)
            if not e.get('actionable'):
                raise ApiProblem(422, '지원되지 않는 점검 항목입니다.', code='GATE_WHITELIST')
            if body.get('expected_status') != e['status'] or body.get('plan_hash') != plan_hash(e):
                raise ApiProblem(409, '상태 또는 변경 계획이 달라졌습니다.', code='STATE_CONFLICT')
            if e['status'] not in ALLOWED[action]:
                raise ApiProblem(409, '현재 상태에서 허용되지 않는 작업입니다.', code='STATE_CONFLICT')
            if action == 'execute' and (not e.get('approver') or e.get('approvalHash') != plan_hash(e)):
                raise ApiProblem(422, '현재 계획에 대한 승인이 필요합니다.', code='APPROVAL_REQUIRED')
            if action == 'verify' and e['execution'] != 'SUCCEEDED':
                raise ApiProblem(409, '조치 성공 후 재검증할 수 있습니다.', code='STATE_CONFLICT')
            evidence = body.get('evidence')
            if action == 'execute' and e['plan']['manual']:
                if not isinstance(evidence, dict) or set(evidence) != {'note', 'reference'} or not all(
                        isinstance(v, str) and 1 <= len(v.strip()) <= 2000 for v in evidence.values()):
                    raise ApiProblem(400, '수동 조치 완료 내용과 증적 참조가 필요합니다.', code='INVALID_PARAMETER')
            if action == 'verify' and e['verificationMethod'] == 'operator-evidence':
                self._validate_evidence(e, evidence)
            if body.get('dry_run'):
                result = {'dryRun': True, 'allowed': True, 'event': e}
            else:
                job = None
                if action == 'plan':
                    e.update(plan=new_plan, status='PENDING_APPROVAL', approvalHash=None, approver=None, approvedAt=None)
                    e['planHash'] = plan_hash(e)
                elif action == 'approve':
                    if document_version:
                        e['plan']['version'] = document_version
                        e['planHash'] = plan_hash(e)
                    e.update(status='APPROVED', approver=actor, approvedAt=ms(), approvalHash=plan_hash(e))
                elif action == 'cancel':
                    e.update(status='PENDING_APPROVAL', approver=None, approvedAt=None, approvalHash=None)
                elif action == 'execute' and e['plan']['manual']:
                    e.update(status='PENDING_VERIFICATION', execution='SUCCEEDED', verification='NOT_RUN',
                             manualEvidence=evidence, before=e.get('before'), after=None, executedAt=ms())
                else:
                    job = {'executionId': str(uuid.uuid4()), 'eventId': event_id,
                           'kind': 'REMEDIATION' if action == 'execute' else 'VERIFICATION',
                           'document': e['plan']['document'], 'status': 'RUNNING', 'startedAt': ms(),
                           'endedAt': None, 'failureMessage': None, 'actor': actor,
                           'progress': {'step': '작업 대기', 'completed': 0, 'total': 1}}
                    if action == 'verify' and e['verificationMethod'] == 'operator-evidence':
                        job['evidence'] = evidence
                    db.execute('INSERT INTO live_jobs VALUES(?,?,?,?)',
                               (job['executionId'], event_id, 'RUNNING', encode(job)))
                    e['activeExecutionId'] = job['executionId']
                    if action == 'execute':
                        e.update(status='EXECUTING', execution='RUNNING', verification='NOT_RUN', after=None,
                                 afterAt=None, afterValue=None)
                    else:
                        e.update(status='VERIFYING', verification='CHECKING')
                self._record_change(db, e, action, actor, job)
                result = {'execution': job, 'event': e} if action in ('execute', 'verify') else e
            db.execute('INSERT INTO live_requests VALUES(?,?,?)', (key, fingerprint, encode(result)))
            return result

    @staticmethod
    def _replay_request(row, fingerprint):
        if row['hash'] != fingerprint:
            raise ApiProblem(409, '다른 요청에 사용된 요청 키입니다.', code='DUPLICATE_EXECUTION')
        return json.loads(row['response'])

    def execution_status(self, event_id, execution_id):
        with connect(self.path) as db:
            job = db.execute('SELECT payload FROM live_jobs WHERE id=? AND event_id=?', (execution_id, event_id)).fetchone()
            event = db.execute('SELECT payload FROM live_events WHERE id=?', (event_id,)).fetchone()
        if job and event:
            return {'execution': json.loads(job['payload']), 'event': json.loads(event['payload'])}
        return None

    def _measure_live(self, e):
        spec = (loader.get(e['scenario']) or {}).get('verify', {})
        checker = {'sg_ingress_count': self._verify_sg_ingress, 'iam_key_status': self._verify_iam_key,
                   'inspector_cve_count': self._verify_cve_count,
                   'cloudwatch_metric': self._verify_metric,
                   'config_compliance': self._verify_config}.get(spec.get('type'))
        if not checker:
            raise ApiProblem(422, '이 항목은 동일 기준의 외부 점검 증적이 필요합니다.', code='EVIDENCE_REQUIRED')
        value = checker(e, spec)
        return {'value': value, 'unit': e['unit'], 'at': ms(), 'label': f"{value}{e['unit']}",
                'criterionVersion': e['criterionVersion'], 'resource': e['resource']}

    def _validate_evidence(self, e, proof):
        fields = {'resource', 'criterionVersion', 'value', 'observedAt', 'reference'}
        if not isinstance(proof, dict) or set(proof) != fields:
            raise ApiProblem(400, '대상·검사 버전·측정값·검사 시각·증적 참조가 필요합니다.', code='EVIDENCE_REQUIRED')
        if (proof['resource'] != e['resource'] or proof['criterionVersion'] != e['criterionVersion']
                or type(proof['value']) not in (float, int) or not math.isfinite(proof['value']) or proof['value'] < 0
                or type(proof['observedAt']) is not int or not e.get('executedAt', e.get('approvedAt', 0)) <= proof['observedAt'] <= ms()
                or not isinstance(proof['reference'], str) or not 1 <= len(proof['reference'].strip()) <= 2000):
            raise ApiProblem(422, '동일 대상·동일 기준의 조치 이후 증적이 필요합니다.', code='EVIDENCE_REQUIRED')

    def _verify_config(self, e, spec):
        rules = spec.get('rules')
        if not rules:
            raise ApiProblem(422, '점검할 Config 규칙이 지정되지 않았습니다.', code='EVIDENCE_REQUIRED')
        result = self._call('config', 'describe_compliance_by_config_rule', ConfigRuleNames=rules)
        found = {item['ConfigRuleName']: item.get('Compliance', {}).get('ComplianceType')
                 for item in result.get('ComplianceByConfigRules', [])}
        if any(found.get(rule) not in ('COMPLIANT', 'NON_COMPLIANT') for rule in rules):
            raise ApiProblem(422, 'Config 평가 데이터가 불충분합니다.', code='EVIDENCE_REQUIRED')
        return sum(found[rule] == 'NON_COMPLIANT' for rule in rules)

    def _verify_metric(self, e, spec):
        alarms = self._call('cloudwatch', 'describe_alarms', AlarmNames=[e['id'].removeprefix('alarm:')]).get('MetricAlarms', [])
        if len(alarms) != 1 or not alarms[0].get('MetricName'):
            raise ApiProblem(422, '단일 지표 알람을 확인할 수 없습니다.', code='EVIDENCE_REQUIRED')
        alarm = alarms[0]
        end = datetime.now(timezone.utc)
        period = spec.get('period', 300)
        start = end - timedelta(seconds=period)
        # Require a full post-action interval; missing samples never mean zero.
        if int(start.timestamp()*1000) < e.get('executedAt', 0):
            raise ApiProblem(422, '조치 후 관찰 구간이 아직 지나지 않았습니다.', code='EVIDENCE_REQUIRED')
        points = self._call('cloudwatch', 'get_metric_statistics', Namespace=alarm['Namespace'],
                            MetricName=alarm['MetricName'], Dimensions=alarm.get('Dimensions', []),
                            StartTime=start, EndTime=end, Period=period,
                            Statistics=[spec.get('statistic', 'Average')]).get('Datapoints', [])
        if not points:
            raise ApiProblem(422, '조치 이후 지표 데이터가 없습니다.', code='EVIDENCE_REQUIRED')
        stat = spec.get('statistic', 'Average')
        return max(point[stat] for point in points)

    def work_once(self):
        if not self.config.WRITE_ENABLED:
            return
        # One host, multiple workers: SQLite serializes job progression. A crash
        # rolls back the local transaction; SSM's persisted token makes retry safe.
        with connect(self.path, True) as db:
            db.execute("INSERT OR REPLACE INTO metadata VALUES('live_worker_heartbeat',?)", (str(ms()),))
            jobs = db.execute("SELECT * FROM live_jobs WHERE state='RUNNING'").fetchall()
            for row in jobs:
                job = json.loads(row['payload'])
                e = json.loads(db.execute('SELECT payload FROM live_events WHERE id=?', (row['event_id'],)).fetchone()['payload'])
                try:
                    if job['kind'] == 'VERIFICATION':
                        if job.get('evidence'):
                            proof = job['evidence']
                            measured = {**proof, 'at': proof['observedAt'], 'unit': e['unit'],
                                        'label': f"{proof['value']}{e['unit']}", 'source': 'operator-evidence'}
                        else:
                            measured = self._measure_live(e)
                        spec = (loader.get(e['scenario']) or {}).get('verify', {})
                        passed = measured['value'] <= spec['threshold'] if 'threshold' in spec else measured['value'] == 0
                        e.update(after=measured, afterValue=measured['value'], afterAt=measured['at'],
                                 verification='PASSED' if passed else 'FAILED',
                                 status='RESOLVED' if passed else 'VERIFICATION_FAILED')
                        job['status'] = 'SUCCEEDED'
                    elif not job.get('awsExecutionId'):
                        if not job.get('submission'):
                            e['before'] = self._measure_live(e)
                            e['beforeAt'] = e['before']['at']
                            job['submission'] = dict(DocumentName=job['document'], ClientToken=job['executionId'],
                                                     DocumentVersion=e['plan']['version'],
                                                     Parameters=dict(e['plan'].get('parameters') or self._parameters(e, job['document']),
                                                                     AutomationAssumeRole=[self._automation_role_arn()]))
                            # Commit the exact request and Before evidence BEFORE
                            # any external mutation; submit on the next worker tick.
                            job['progress']['step'] = '실행 요청 준비 완료'
                        else:
                            result = self._call('ssm', 'start_automation_execution', **job['submission'])
                            job['awsExecutionId'] = result['AutomationExecutionId']
                            job['failureMessage'] = None
                            job['progress']['step'] = 'SSM 실행 중'
                    else:
                        run = self._call('ssm', 'get_automation_execution', AutomationExecutionId=job['awsExecutionId'])['AutomationExecution']
                        state = run['AutomationExecutionStatus']
                        if state == 'Success':
                            job['failureMessage'] = None
                            job['status'] = 'SUCCEEDED'
                            e.update(status='PENDING_VERIFICATION', execution='SUCCEEDED', executedAt=ms())
                        elif state in ('Failed', 'TimedOut', 'Cancelled', 'Rejected'):
                            job.update(status='FAILED', failureMessage='SSM 실행 실패: ' + state)
                            e.update(status='EXECUTION_FAILED', execution='FAILED')
                except ApiProblem as exc:
                    # Submission timeouts are ambiguous: keep the durable job and
                    # retry with the SAME token, never submit a new logical action.
                    job['failureMessage'] = exc.title
                    if exc.status < 500:
                        job['status'] = 'FAILED'
                        e.update(status='VERIFICATION_FAILED' if job['kind']=='VERIFICATION' else 'EXECUTION_FAILED')
                        e['verification' if job['kind']=='VERIFICATION' else 'execution'] = 'FAILED'
                if job['status'] != 'RUNNING':
                    job.update(endedAt=ms(), progress={'step': '작업 완료', 'completed': 1, 'total': 1})
                    e['activeExecutionId'] = None
                    self._record_change(db, e, 'completed', job['actor'], job)
                else:
                    self._save(db, e)
                db.execute('UPDATE live_jobs SET state=?,payload=? WHERE id=?',
                           (job['status'], encode(job), job['executionId']))
        self.flush_outbox()

    def flush_outbox(self):
        with connect(self.path) as db:
            rows = db.execute('SELECT * FROM live_outbox LIMIT 100').fetchall()
        for row in rows:
            record = json.loads(row['payload'])
            try:
                self._call('dynamodb', 'put_item', TableName=self.config.REMEDIATION_ACTIONS_TABLE,
                           Item={key: {'S': value} for key, value in record.items()})
            except ApiProblem:
                continue
            with connect(self.path, True) as db:
                db.execute('DELETE FROM live_outbox WHERE id=?', (row['id'],))

    def evidence(self, event_id):
        from ..services.evidence import build_evidence
        e = self.get_event(event_id)
        if not e:
            return None
        with connect(self.path) as db:
            jobs = [json.loads(row['payload']) for row in db.execute('SELECT payload FROM live_jobs WHERE event_id=?', (event_id,))]
        ids = [job['awsExecutionId'] for job in jobs if job.get('awsExecutionId')]
        if e.get('externalExecutionId'):
            ids.append(e['externalExecutionId'])
        result = build_evidence(e, ssm_execution_ids=ids)
        result['manualEvidence'] = e.get('manualEvidence')
        return result
