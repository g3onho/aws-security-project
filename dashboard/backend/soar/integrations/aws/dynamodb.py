"""DynamoDB 테이블 전체 조회(Scan) + 짧은 캐시.

기간 목록은 Scan(쌓는 쪽이 반복 판정을 한 행으로 합치고 30일 TTL 로 지워 규모가 제한된다).
특정 finding 의 이력은 finding_id-created_at 인덱스를 Query 한다. 인덱스가 아직 없거나 권한이
없으면(배포 순서 차이) None 을 돌려주고 호출부가 Scan 결과로 대신한다.
"""
import threading
import time
from decimal import Decimal

from boto3.dynamodb.types import TypeDeserializer
from botocore.exceptions import ClientError

from .paging import collect

_deserializer = TypeDeserializer()
INDEX_UNAVAILABLE = {"AccessDeniedException", "ValidationException", "ResourceNotFoundException"}


def _plain(value):
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (list, set, tuple)):
        return [_plain(v) for v in value]
    return value


class DynamoTable:
    TTL = 30
    MAX = 5000

    def __init__(self, session, name):
        self._session = session
        self.name = name
        self._lock = threading.Lock()
        self._hit = None

    def scan(self):
        """(rows, truncated). 행은 파이썬 기본 타입(dict/str/int/float/list)."""
        with self._lock:
            if self._hit and time.monotonic() - self._hit[0] < self.TTL:
                return self._hit[1]
            items = collect(self._session.client("dynamodb"), "scan", "Items",
                            max_items=self.MAX, TableName=self.name)
            rows = [_plain({k: _deserializer.deserialize(v) for k, v in item.items()}) for item in items]
            self._hit = (time.monotonic(), (rows, len(rows) >= self.MAX))
            return self._hit[1]

    def query_index(self, index, key, value):
        """인덱스 Query. 인덱스·권한이 없으면 None(Scan 으로 대신하라는 뜻)."""
        try:
            items = collect(self._session.client("dynamodb"), "query", "Items", TableName=self.name,
                            IndexName=index, KeyConditionExpression="#k = :v",
                            ExpressionAttributeNames={"#k": key}, ExpressionAttributeValues={":v": {"S": value}})
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") in INDEX_UNAVAILABLE:
                return None
            raise
        return [_plain({k: _deserializer.deserialize(v) for k, v in item.items()}) for item in items]
