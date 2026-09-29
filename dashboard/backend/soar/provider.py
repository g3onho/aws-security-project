"""Data-provider boundary with no generated-observation fallback.

AwsProvider 는 조립만 한다(설계 2.3):
  - boto3 호출·페이지 처리·캐시 → integrations/aws
  - AWS 원본 → 대시보드 도메인 자료 변환 → repositories
표준 API 서비스(contracts.StandardService)가 부르는 메서드 이름과 반환 모양은 바꾸지 않는다.
"""
from .errors import Problem
from .integrations.aws.cache import SharedCache
from .integrations.aws.cloudwatch import Alarms
from .integrations.aws.blocklist import BlocklistStore
from .integrations.aws.dynamodb import DynamoTable
from .integrations.aws.honeypot import HoneypotSources
from .integrations.aws.inspector import InspectorFindings
from .integrations.aws.securityhub import SecurityHubFindings
from .integrations.aws.session import AwsSession
from .integrations.aws.ssm import AutomationExecutions
from .integrations.aws.stored import StoredFindings, StoredVulnerabilities
from .repositories import executions, infra
from .repositories.actions import ActionRepository
from .repositories.alarms import AlarmRepository
from .repositories.correlations import CorrelationRepository
from .repositories.findings import FindingRepository, classify, remote_ip  # noqa: F401 — 기존 import 경로 유지
from .repositories.metrics import MetricRepository
from .repositories.resources import ResourceRepository
from .repositories.sync import freshness
from .repositories.vulnerabilities import VulnerabilityRepository
from .store import now_ms

__all__ = ["AwsProvider", "UnconfiguredProvider", "classify", "remote_ip"]


class UnconfiguredProvider:
    connected = False
    regions = ()
    honeypot = None    # 허니팟 원천·차단 목록은 AWS 연결이 있어야 생긴다
    blocklist = None

    @property
    def as_of(self):
        return now_ms()

    def require_ready(self):
        raise Problem(503, "실데이터 공급자가 연결되지 않았습니다.", "DATA_SOURCE_NOT_CONFIGURED")

    def execution_result(self, event):
        self.require_ready()

    def measure(self, event):
        self.require_ready()

    def discover_attackers(self, regions):
        self.require_ready()

    def run_web_attack(self, attackers, parameters):
        self.require_ready()

    def attack_command_status(self, commands):
        self.require_ready()

    def discover_service_host(self, region):
        self.require_ready()

    def discover_load_targets(self, region):
        self.require_ready()

    def send_commands(self, target, steps):
        self.require_ready()

    def status(self):
        return {"connected": False, "state": "not_configured", "detail": "DATA_PROVIDER is not configured"}


class AwsProvider:
    """Read-only AWS data provider used by the dashboard."""
    connected = False
    regions = ()
    FINDINGS_TTL = SecurityHubFindings.TTL
    FINDINGS_MAX = SecurityHubFindings.MAX
    INSPECTOR_TTL = InspectorFindings.TTL
    INSPECTOR_SEVERITIES = InspectorFindings.SEVERITIES

    def __init__(self, region, session_factory=None, actions_table=None, correlated_table=None,
                 findings_table=None, vulnerabilities_table=None, event_source="securityhub",
                 vulnerability_source="inspector", auto_policy=None, name_prefix=None, honeypot_log_group=None,
                 honeypot_alarm_name=None, blocklist_table=None, private_nacl_id=None, unblock_document=None,
                 automation_role_arn=None):
        self.region = region
        self.regions = (region,)
        self._aws = AwsSession(region, session_factory)
        self.connected = self._aws.connected
        self.account_id = self._aws.account_id
        # Security Hub 와 Inspector 가 캐시·잠금 하나를 공유한다(분리하면 중복 조회).
        cache = SharedCache()
        # 탐지·취약점 원본: AWS 직접 조회(기존) 또는 DynamoDB 적재(v21, EVENT_SOURCE·VULNERABILITY_SOURCE).
        # 어느 쪽이든 같은 원본 모양을 돌려주고 같은 repository 가 변환한다.
        stored_events = event_source == "dynamodb"
        stored_vulns = vulnerability_source == "dynamodb"
        self._inspector = (StoredVulnerabilities(self._aws, vulnerabilities_table, cache) if stored_vulns
                           else InspectorFindings(self._aws, cache))
        securityhub = (StoredFindings(self._aws, findings_table, cache) if stored_events
                       else SecurityHubFindings(self._aws, cache))
        # auto_policy: 자동 조치 판정(설정 기준 예상, guidance.AutoPolicy). 없으면 이벤트에 판정을 싣지 않는다.
        self._findings = FindingRepository(securityhub, region, auto_policy)
        self._sync = {"events": ("탐지", securityhub) if stored_events else None,
                      "vulnerabilities": ("취약점", self._inspector) if stored_vulns else None}
        self._resources = ResourceRepository(self._aws, region)
        self._metrics = MetricRepository(self._aws, clock=now_ms)
        self._vulnerabilities = VulnerabilityRepository(self._inspector, self._aws, region)
        # DynamoDB (Terraform modules/soar 가 만든 테이블. 이름은 배포 설정 env 로 주입)
        self._actions = ActionRepository(DynamoTable(self._aws, actions_table)) if actions_table else None
        self._correlations = CorrelationRepository(DynamoTable(self._aws, correlated_table)) if correlated_table else None
        # 인프라 모니터링 경보(이름 접두어 = Terraform name_prefix)와 자동 조치 SSM 실행 결과(조치 전/후)
        self._alarms = (AlarmRepository(Alarms(self._aws, name_prefix), region, self.account_id, auto_policy)
                        if name_prefix else None)
        self._executions = AutomationExecutions(self._aws)
        # 허니팟 세션 로그·미끼·알람(읽기 전용)과 차단 IP 목록(표·NACL·해제 SSM). 설정이 없으면 None → 화면에 미배포/미설정 표시.
        self.honeypot = (HoneypotSources(self._aws, honeypot_log_group, honeypot_alarm_name)
                         if honeypot_log_group else None)
        self.blocklist = (BlocklistStore(self._aws, blocklist_table, private_nacl_id, unblock_document,
                                         automation_role_arn, actions_table=actions_table)
                          if blocklist_table and private_nacl_id and unblock_document and automation_role_arn else None)

    @property
    def as_of(self):
        return now_ms()

    def require_ready(self):
        self._aws.require_ready()

    def status(self):
        if self.connected:
            return {"connected": True, "state": "credentials_verified", "region": self.region}
        return {"connected": False, "state": "unavailable", "region": self.region,
                "detail": self._aws.error or "connection_failed"}

    def sync_status(self, kind):
        """DynamoDB 적재를 읽을 때만 {asOf, warnings}. AWS 직접 조회면 None(지금 조회한 값이라 지연 없음)."""
        source = self._sync.get("vulnerabilities" if kind == "vulnerabilities" else "events")
        if source is None:
            return None
        label, integration = source
        return freshness(integration.sync_status(), label, now_ms())

    def observations(self, query=None):
        return self._findings.observations(query)

    def resources(self, query=None):
        return self._resources.list(query)

    def metric_for(self, resource, query=None):
        return self._metrics.metric_for(resource, query)

    def metric_history(self, resources, query):
        return self._metrics.history_for(resources, query)

    def vulnerabilities(self, query=None, events=None):
        return self._vulnerabilities.list()

    def actions(self, finding_id=None):
        """자동조치 판정 기록. 테이블 설정이 없으면 configured=False(빈 목록으로 위장하지 않는다).
        finding_id 를 주면 그 finding 의 기록만(인덱스 Query)."""
        if self._actions is None:
            return {"configured": False, "items": [], "truncated": False}
        found = self._actions.for_finding(finding_id) if finding_id else self._actions.list()
        return {"configured": True, **found}

    def correlations(self):
        return self._correlations.by_guardduty_id() if self._correlations else {}

    def alarms(self):
        """CloudWatch 지표 알람 상태. 이름 접두어 설정(NAME_PREFIX)이 없으면 configured=False."""
        if self._alarms is None:
            return {"configured": False, "items": []}
        return self._alarms.list()

    def execution(self, execution_id, fetch=True):
        """자동 조치 SSM 실행의 전/후 증거(실행 결과이지 재검증이 아니다). (found, evidence|None)."""
        found, raw = self._executions.get(execution_id, fetch=fetch)
        return found, executions.evidence(raw) if found else None

    def services(self, query=None, events=None):
        resources = self._resources.list(query or {})
        return infra.services(resources, self.as_of, self.region)

    def warm(self):
        """앱 기동 직후 취약점 목록을 미리 받아 둔다. 첫 사용자가 11초를 기다리지 않게."""
        self._inspector.warm()

    def execution_result(self, event):
        raise Problem(403, "실제 조치 공급자는 아직 활성화되지 않았습니다.", "ACTION_PROVIDER_DISABLED")

    def measure(self, event):
        raise Problem(403, "실제 재검증 공급자는 아직 활성화되지 않았습니다.", "ACTION_PROVIDER_DISABLED")

    # --- 지리별 공격 실행(웹보안검사 [시작]) ---------------------------------
    # SSM Command 문서는 리전별 리소스라, 공격자가 있는 각 리전의 ssm 클라이언트로
    # SendCommand 한다. 결과 지리 표시는 기존 GuardDuty finding(observations) 경로가 맡는다.

    def discover_attackers(self, regions):
        """각 리전에서 태그 AttackerFor=dvwa 인 running 인스턴스를 찾는다.
        -> [{regionLabel, instanceId, regionCode}]. IP가 바뀌어도 견고하게 태그로 탐색."""
        self.require_ready()
        found = []
        for code in regions:
            ec2 = self._aws.regional_client("ec2", code)
            try:
                reservations = ec2.describe_instances(Filters=[
                    {"Name": "tag:AttackerFor", "Values": ["dvwa"]},
                    {"Name": "instance-state-name", "Values": ["running"]},
                ]).get("Reservations", [])
            except Exception:
                continue
            for res in reservations:
                for inst in res.get("Instances", []):
                    label = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "RegionLabel"), code)
                    found.append({"regionLabel": label, "instanceId": inst["InstanceId"], "regionCode": code})
        return found

    def run_web_attack(self, attackers, parameters):
        """attackers: [{regionCode, instanceId, regionLabel, documentName}]. 실행한 command 목록을 돌려준다."""
        self.require_ready()
        launched = []
        for a in attackers:
            ssm = self._aws.regional_client("ssm", a["regionCode"])
            params = {k: [str(v)] for k, v in parameters.items() if v is not None and v != ""}
            params["RegionLabel"] = [a["regionLabel"]]
            try:
                resp = ssm.send_command(DocumentName=a["documentName"], InstanceIds=[a["instanceId"]],
                                        Parameters=params, TimeoutSeconds=600)
            except Exception as error:  # AccessDenied(IAM 미부여)·InvalidDocument(문서 미등록) 등을 명확히 전달
                name = type(error).__name__
                code = getattr(getattr(error, "response", None), "get", lambda *_: {})("Error", {}).get("Code", name) \
                    if hasattr(error, "response") else name
                raise Problem(502, f"{a['regionLabel']} 공격 실행 실패: {code}. "
                              "대시보드 롤의 ssm:SendCommand 권한과 리전별 ATK 문서를 확인하세요.",
                              "GEO_ATTACK_SEND_FAILED")
            launched.append({"regionLabel": a["regionLabel"], "regionCode": a["regionCode"],
                             "instanceId": a["instanceId"], "commandId": resp["Command"]["CommandId"]})
        return launched

    def attack_command_status(self, commands):
        """commands: [{regionCode, instanceId, commandId, regionLabel}] -> 리전별 진행상태·출력 요약."""
        self.require_ready()
        out = []
        for c in commands:
            ssm = self._aws.regional_client("ssm", c["regionCode"])
            try:
                inv = ssm.get_command_invocation(CommandId=c["commandId"], InstanceId=c["instanceId"])
                out.append({"regionLabel": c["regionLabel"], "status": inv["Status"],
                            "output": (inv.get("StandardOutputContent") or "")[-4000:]})
            except Exception as error:  # 등록 직후엔 InvocationDoesNotExist 가능
                out.append({"regionLabel": c["regionLabel"], "status": "Pending",
                            "detail": type(error).__name__})
        return out

    # --- 서울 서비스 호스트 대상 스캔·부하 실행(전부 실행의 SEC-02/07/10) ------------
    # 웹 공격(geo)과 달리 이들은 서비스 3-tier 호스트(docker-host)에서 로컬로 돈다.
    # 인스턴스는 태그 Role=service-3tier 로 홈 리전에서 런타임 탐색한다(IP·ID 하드코딩 회피).

    def discover_host_by_role(self, region, role, region_label="seoul"):
        """홈 리전에서 태그 Role=<role> 인 running 인스턴스 하나를 찾는다.
        -> {regionLabel, regionCode, instanceId} 또는 None."""
        self.require_ready()
        ec2 = self._aws.regional_client("ec2", region)
        try:
            reservations = ec2.describe_instances(Filters=[
                {"Name": "tag:Role", "Values": [role]},
                {"Name": "instance-state-name", "Values": ["running"]},
            ]).get("Reservations", [])
        except Exception:
            return None
        for res in reservations:
            for inst in res.get("Instances", []):
                return {"regionLabel": region_label, "regionCode": region, "instanceId": inst["InstanceId"]}
        return None

    def discover_service_host(self, region):
        """서비스 3-tier 호스트(docker-host). SEC-07 비밀값 스캔 대상 코드가 여기 있다."""
        return self.discover_host_by_role(region, "service-3tier")

    def discover_load_targets(self, region):
        """부하(SEC-10) 대상: 홈 리전의 running EC2 중 대시보드(Role=soar-dashboard)를 뺀 전부.
        stress-ng 는 실행 노드 자신을 부하시키므로, 부하를 줄 각 인스턴스에 직접 보낸다.
        -> [{regionLabel:<이름 접미어>, regionCode, instanceId}]. 대시보드를 부하시키면 UI 가 죽으므로 제외."""
        self.require_ready()
        ec2 = self._aws.regional_client("ec2", region)
        try:
            reservations = ec2.describe_instances(Filters=[
                {"Name": "tag:Role", "Values": ["*"]},
                {"Name": "instance-state-name", "Values": ["running"]},
            ]).get("Reservations", [])
        except Exception:
            return []
        targets = []
        for res in reservations:
            for inst in res.get("Instances", []):
                tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                if tags.get("Role") == "soar-dashboard":
                    continue  # 대시보드 자신은 부하 제외
                name = tags.get("Name", inst["InstanceId"])
                label = name.rsplit("-", 1)[-1] if "-" in name else name  # 접두어 제거 → docker-host 등
                targets.append({"regionLabel": label, "regionCode": region, "instanceId": inst["InstanceId"]})
        return targets

    def send_commands(self, target, steps):
        """target: {regionCode, instanceId}. steps: [{sec, documentName, parameters}].
        각 step 을 그 문서 전용 파라미터로 SendCommand 한다 -> launched(각 sec 포함)."""
        self.require_ready()
        ssm = self._aws.regional_client("ssm", target["regionCode"])
        launched = []
        for step in steps:
            params = {k: [str(v)] for k, v in (step.get("parameters") or {}).items()
                      if v is not None and v != ""}
            try:
                resp = ssm.send_command(DocumentName=step["documentName"],
                                        InstanceIds=[target["instanceId"]],
                                        Parameters=params, TimeoutSeconds=600)
            except Exception as error:
                name = type(error).__name__
                code = getattr(getattr(error, "response", None), "get", lambda *_: {})("Error", {}).get("Code", name)                     if hasattr(error, "response") else name
                raise Problem(502, f"{step['sec']} 실행 실패: {code}. "
                              "대시보드 롤의 ssm:SendCommand 권한과 대상 문서를 확인하세요.",
                              "SCAN_SEND_FAILED")
            launched.append({"sec": step["sec"], "regionLabel": target.get("regionLabel", "seoul"),
                             "regionCode": target["regionCode"], "instanceId": target["instanceId"],
                             "commandId": resp["Command"]["CommandId"]})
        return launched
