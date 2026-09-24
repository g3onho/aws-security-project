"""Security Hub GetFindings 조회와 짧은 캐시."""
import time

from .paging import collect


class SecurityHubFindings:
    # GetFindings 한도는 계정당 초당 3회 수준. 화면 한 번에 여러 API 가 이 목록을 쓰고
    # 30초 자동 새로고침까지 겹치면 TooManyRequests 로 전부 죽는다 — 최신 N건만, 잠깐 캐시.
    TTL = 60
    MAX = 500

    def __init__(self, session, cache):
        self._session = session
        self._cache = cache

    def active(self, region):
        with self._cache.lock:
            hit = self._cache.entries.get(region)
            if hit and time.monotonic() - hit[0] < self.TTL:
                return hit[1]
            # Inspector CVE 는 취약점 점검 화면(inspector2 직접 조회)에서 본다. 여기 섞이면
            # ACTIVE 1060건 중 1000건 가까이가 CVE 라 탐지 이벤트가 묻히고 MAX 에 잘린다(실측 2026-09-23).
            # 통과해 RESOLVED 된 점검(289건)과 INFORMATIONAL 경고(237건)도 탐지가 아니다 — 남는 것은
            # 실패한 점검·위협 탐지 약 90건(실측 2026-09-23). 같은 필드의 NOT_EQUALS 는 AND 로 묶인다.
            filters = {"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                       "ProductName": [{"Value": "Inspector", "Comparison": "NOT_EQUALS"}],
                       "WorkflowStatus": [{"Value": "RESOLVED", "Comparison": "NOT_EQUALS"},
                                          {"Value": "SUPPRESSED", "Comparison": "NOT_EQUALS"}],
                       "SeverityLabel": [{"Value": "INFORMATIONAL", "Comparison": "NOT_EQUALS"}]}
            if region:
                filters["Region"] = [{"Value": region, "Comparison": "EQUALS"}]
            findings = collect(self._session.client("securityhub"), "get_findings", "Findings",
                               max_items=self.MAX, Filters=filters,
                               SortCriteria=[{"Field": "UpdatedAt", "SortOrder": "desc"}])
            self._cache.entries[region] = (time.monotonic(), findings)
            return findings
