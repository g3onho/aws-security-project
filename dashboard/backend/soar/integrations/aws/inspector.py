"""Inspector2 ACTIVE finding 조회. 심각도별 병렬 조회 + stale-while-revalidate 캐시."""
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .paging import collect

KEY = "__inspector__"


class InspectorFindings:
    # 화면은 200건씩 페이지를 받는데 페이지마다 Inspector 전체(수천 건, 수십 초)를 다시 긁으면
    # 취약점 탭이 끝없이 "불러오는 중"이다. ACTIVE 만, 5분 캐시(스캔 결과는 자주 안 바뀐다).
    TTL = 300
    # list_findings 는 한 페이지 100건이 상한이라 ACTIVE 4933건 = 51페이지 순차 22초(실측 2026-09-23).
    # 심각도별로 나눠 병렬로 받으면 가장 큰 묶음(UNTRIAGED 2481건) 시간인 약 11초로 준다.
    SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNTRIAGED")

    def __init__(self, session, cache):
        self._session = session
        self._cache = cache
        self._refreshing = False

    def _fetch(self):
        client = self._session.client("inspector2")

        def part(severity):
            return collect(client, "list_findings", "findings", filterCriteria={
                "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
                "severity": [{"comparison": "EQUALS", "value": severity}]})
        with ThreadPoolExecutor(len(self.SEVERITIES)) as pool:
            findings = [f for rows in pool.map(part, self.SEVERITIES) for f in rows]
        self._cache.entries[KEY] = (time.monotonic(), findings)
        return findings

    def _refresh(self):
        try:
            self._fetch()
        except Exception:  # noqa: BLE001 — 백그라운드 갱신 실패는 이전 캐시를 계속 쓴다
            logging.getLogger(__name__).exception("inspector refresh failed")
        finally:
            self._refreshing = False

    def warm(self):
        """앱 기동 직후 취약점 목록을 미리 받아 둔다. 첫 사용자가 11초를 기다리지 않게."""
        if not self._refreshing:
            self._refreshing = True
            threading.Thread(target=self._refresh, daemon=True).start()

    def active(self):
        # 만료된 캐시는 그대로 돌려주고 뒤에서 갱신한다(stale-while-revalidate).
        with self._cache.lock:
            hit = self._cache.entries.get(KEY)
            if hit and time.monotonic() - hit[0] >= self.TTL:
                self.warm()
            return hit[1] if hit else self._fetch()
