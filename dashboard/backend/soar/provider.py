"""Data-provider boundary with no generated-observation fallback.

AwsProvider 는 조립만 한다(설계 2.3):
  - boto3 호출·페이지 처리·캐시 → integrations/aws
  - AWS 원본 → 대시보드 도메인 자료 변환 → repositories
표준 API 서비스(contracts.StandardService)가 부르는 메서드 이름과 반환 모양은 바꾸지 않는다.
"""
from .errors import Problem
from .integrations.aws.cache import SharedCache
from .integrations.aws.dynamodb import DynamoTable
from .integrations.aws.inspector import InspectorFindings
from .integrations.aws.securityhub import SecurityHubFindings
from .integrations.aws.session import AwsSession
from .repositories import infra
from .repositories.actions import ActionRepository
from .repositories.correlations import CorrelationRepository
from .repositories.findings import FindingRepository, classify, remote_ip  # noqa: F401 — 기존 import 경로 유지
from .repositories.metrics import MetricRepository
from .repositories.resources import ResourceRepository
from .repositories.vulnerabilities import VulnerabilityRepository
from .store import now_ms

__all__ = ["AwsProvider", "UnconfiguredProvider", "classify", "remote_ip"]


class UnconfiguredProvider:
    connected = False
    regions = ()

    @property
    def as_of(self):
        return now_ms()

    def require_ready(self):
        raise Problem(503, "실데이터 공급자가 연결되지 않았습니다.", "DATA_SOURCE_NOT_CONFIGURED")

    def execution_result(self, event):
        self.require_ready()

    def measure(self, event):
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

    def __init__(self, region, session_factory=None, actions_table=None, correlated_table=None):
        self.region = region
        self.regions = (region,)
        self._aws = AwsSession(region, session_factory)
        self.connected = self._aws.connected
        self.account_id = self._aws.account_id
        # Security Hub 와 Inspector 가 캐시·잠금 하나를 공유한다(분리하면 중복 조회).
        cache = SharedCache()
        self._inspector = InspectorFindings(self._aws, cache)
        self._findings = FindingRepository(SecurityHubFindings(self._aws, cache), region)
        self._resources = ResourceRepository(self._aws, region)
        self._metrics = MetricRepository(self._aws, clock=now_ms)
        self._vulnerabilities = VulnerabilityRepository(self._inspector, self._aws, region)
        # DynamoDB (Terraform modules/soar 가 만든 테이블. 이름은 배포 설정 env 로 주입)
        self._actions = ActionRepository(DynamoTable(self._aws, actions_table)) if actions_table else None
        self._correlations = CorrelationRepository(DynamoTable(self._aws, correlated_table)) if correlated_table else None

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

    def observations(self, query=None):
        return self._findings.observations(query)

    def resources(self, query=None):
        return self._resources.list(query)

    def metric_for(self, resource, query=None):
        return self._metrics.metric_for(resource, query)

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
