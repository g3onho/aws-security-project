"""DynamoDB 조치 이력(remediation-actions) → 자동조치 기록 도메인 자료.

두 기록 형식을 모두 읽는다.
  - v20 이전: action_id=asr-<초>, region·account_id·status 없음
  - v20 이후: status·region·account_id·playbook_id·occurrence_count·last_seen_at·expires_at
리전·계정이 없으면 finding_id(ARN)에서 추출한다. 그래도 모르면 None — 범위 제한 사용자에게는 보이지 않는다.
"""
import re
import time

from ..integrations.aws.paging import to_ms
from .findings import event_id

ARN = re.compile(r"^arn:aws[\w-]*:[\w-]+:(?P<region>[a-z]{2}(?:-[a-z]+)+-\d):(?P<account>\d{12}):")
LEGACY_STATUS = {"manual-notified": "NOTIFIED", "dry-run": "DRY_RUN", "auto-executed": "IN_PROGRESS"}


def _text(value):
    return None if value in (None, "", "n/a", "pending") else str(value)


def normalize(item):
    finding_id = str(item.get("finding_id") or "unknown")
    match = ARN.match(finding_id)
    created = to_ms(item.get("created_at"))
    return {
        "actionId": str(item.get("action_id")), "createdAt": created,
        "updatedAt": to_ms(item.get("updated_at") or item.get("created_at")),
        "lastSeenAt": to_ms(item.get("last_seen_at") or item.get("created_at")),
        "findingId": finding_id, "eventId": event_id(finding_id),
        "findingType": item.get("finding_type"), "decision": item.get("decision") or "unknown",
        "status": item.get("status") or LEGACY_STATUS.get(item.get("decision"), "UNKNOWN"),
        "resource": item.get("resource_id") if item.get("resource_id") not in (None, "", "n/a") else None,
        "region": item.get("region") or (match.group("region") if match else None),
        "accountId": item.get("account_id") or (match.group("account") if match else None),
        "playbookId": _text(item.get("playbook_id")),
        "executionId": _text(item.get("ssm_execution_id")),
        "beforeText": _text(item.get("before_state")), "afterText": _text(item.get("after_state")),
        "occurrenceCount": int(item.get("occurrence_count") or 1),
        "expiresAt": item.get("expires_at"),
    }


INDEX = "finding_id-created_at"  # Terraform modules/soar storage.tf


def _live(rows):
    now = int(time.time())
    # TTL 삭제는 최대 48시간 늦을 수 있다 — 만료 시각이 지난 행은 여기서 뺀다.
    return [normalize(row) for row in rows
            if not (isinstance(row.get("expires_at"), (int, float)) and row["expires_at"] < now)]


class ActionRepository:
    def __init__(self, table):
        self._table = table

    def list(self):
        rows, truncated = self._table.scan()
        return {"items": _live(rows), "truncated": truncated}

    def for_finding(self, finding_id):
        """한 finding 의 이력만. 인덱스를 못 쓰면 Scan 결과에서 고른다."""
        rows = self._table.query_index(INDEX, "finding_id", finding_id)
        if rows is None:
            listed = self.list()
            return {"items": [r for r in listed["items"] if r["findingId"] == finding_id],
                    "truncated": listed["truncated"], "index": False}
        return {"items": _live(rows), "truncated": False, "index": True}
