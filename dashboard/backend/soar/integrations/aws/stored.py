"""DynamoDB 에 적재된 탐지·취약점 조회 (v21, modules/soar finding_sync 가 쓴다).

SecurityHubFindings·InspectorFindings 와 같은 메서드(active)로 같은 원본 모양(행의 raw)을 돌려준다.
그래서 repositories/findings.py·vulnerabilities.py 변환 코드를 그대로 쓰고, 두 경로의 결과가 같다.
Security Hub 500건 상한·Inspector 수천 건 순차 조회가 없다 — 열린 행만 인덱스로 Query 한다.
"""
import logging
import threading
import time

from boto3.dynamodb.types import TypeDeserializer

from .dynamodb import _plain
from .paging import collect

SYNC_KEY = "__sync__"
_deserializer = TypeDeserializer()


def _rows(items):
    return [_plain({k: _deserializer.deserialize(v) for k, v in item.items()}) for item in items]


class _StoredTable:
    TTL = 30  # 적재는 이벤트로 거의 실시간이다. 화면 여러 API·자동 새로고침이 겹쳐도 Query 는 30초에 한 번.
    KEY = INDEX = OPEN = CACHE = None

    def __init__(self, session, table, cache):
        self._session = session
        self.table = table
        self._cache = cache
        self._refreshing = False

    def _fetch(self):
        items = collect(self._session.client("dynamodb"), "query", "Items", TableName=self.table,
                        IndexName=self.INDEX, KeyConditionExpression="#s = :s",
                        ExpressionAttributeNames={"#s": "view_state"},
                        ExpressionAttributeValues={":s": {"S": self.OPEN}})
        raws = [row["raw"] for row in _rows(items) if isinstance(row.get("raw"), dict)]
        status = self._status()
        self._cache.entries[self.CACHE] = (time.monotonic(), raws, status)
        return self._cache.entries[self.CACHE]

    def _status(self):
        """동기화 상태 행. 읽지 못하면 {'unreadable': True}(빈 상태로 위장하지 않는다)."""
        try:
            item = self._session.client("dynamodb").get_item(
                TableName=self.table, Key={self.KEY: {"S": SYNC_KEY}}).get("Item")
        except Exception:  # noqa: BLE001 — 원인은 로그로만(설계 2.3 원칙 7)
            logging.getLogger(__name__).exception("sync status read failed")
            return {"unreadable": True}
        return _rows([item])[0] if item else None

    def _hit(self):
        with self._cache.lock:
            hit = self._cache.entries.get(self.CACHE)
            if hit and time.monotonic() - hit[0] < self.TTL:
                return hit
            return self._fetch()

    def sync_status(self):
        return self._hit()[2]


class StoredFindings(_StoredTable):
    """Security Hub 탐지(Inspector 제외). SecurityHubFindings.active(region) 대체."""
    KEY, INDEX, OPEN, CACHE = "finding_id", "view_state-updated_at", "OPEN", "__stored_findings__"

    def active(self, region):
        rows = self._hit()[1]
        return rows if not region else [row for row in rows if row.get("Region") == region]


class StoredVulnerabilities(_StoredTable):
    """Inspector 취약점. InspectorFindings.active() 대체. 캐시가 같으면 같은 목록 객체를 돌려준다
    (VulnerabilityRepository 가 is 비교로 가공 결과를 재사용한다)."""
    KEY, INDEX, OPEN, CACHE = "finding_arn", "view_state-last_observed_at", "ACTIVE", "__stored_vulnerabilities__"
    TTL = 60

    def active(self):
        return self._hit()[1]

    def warm(self):
        if self._refreshing:
            return
        self._refreshing = True

        def run():
            try:
                self._hit()
            except Exception:  # noqa: BLE001 — 첫 요청이 다시 시도한다
                logging.getLogger(__name__).exception("stored vulnerabilities warm failed")
            finally:
                self._refreshing = False
        threading.Thread(target=run, daemon=True).start()
