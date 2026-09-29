"""차단 IP 목록 — DynamoDB 행(만료·예외·해제 사유)과 NACL 실제 상태를 맞대어 화면용 자료로 만든다(순수 변환).

기준은 **NACL 1~99 Deny(실제 차단)** 이다. 표(ip_blocklist)는 만료·예외·해제 사유를 붙이는 메타데이터이므로,
둘이 다르면 어느 쪽도 숨기지 않고 mismatch 로 알린다.
  - nacl-missing         : 표는 ACTIVE 인데 NACL 에 Deny 가 없다(SSM 이 진행 중이면 applying 으로 본다)
  - record-missing       : NACL 에 Deny 가 있는데 표에 기록이 없다(수동 차단·이전 배포)
  - nacl-still-blocked   : 표는 해제됨인데 NACL 에 Deny 가 아직 남아 있다

상태(state): applying · blocked · expiring(만료 시각이 지나 해제 대기) · releasing · released · expired · failed ·
            mismatch · unrecorded
"""
import ipaddress
import re
from collections import Counter

from ..integrations.aws.paging import to_ms

DURATIONS = {1: "1시간", 24: "24시간", 168: "7일", 0: "영구"}  # 화면 선택지(시간, 0 = 영구). 기본값은 Terraform 변수.
SSM_RUNNING = {"Pending", "InProgress", "Waiting", "Cancelling", "RunbookInProgress", "PendingApproval",
               "Scheduled", "ChangeCalendarOverrideApproved"}
SSM_SUCCESS = {"Success", "CompletedWithSuccess"}
STATES = ("applying", "blocked", "expiring", "releasing", "released", "expired", "failed", "mismatch", "unrecorded")
RULE_MIN, RULE_MAX = 1, 99


def valid_ip(text):
    """차단·해제 대상 주소로 쓸 수 있는 IPv4 단일 주소인가(0.0.0.0·멀티캐스트 등 제외)."""
    if not isinstance(text, str) or not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", text):
        return False
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    return address.version == 4 and not (address.is_unspecified or address.is_multicast or address.is_loopback
                                         or address.is_link_local or address.is_reserved)


def normalize(item):
    def ms(value):
        return to_ms(value) if value else None
    expires = item.get("expires_at")
    evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
    return {
        "ip": str(item.get("ip")), "status": item.get("status") or "UNKNOWN",
        "ruleNumber": int(item["rule_number"]) if item.get("rule_number") is not None else None,
        "naclId": item.get("nacl_id"), "source": item.get("source"),
        "blockedAt": ms(item.get("blocked_at")), "updatedAt": ms(item.get("updated_at")),
        "expiresAt": int(expires) * 1000 if isinstance(expires, (int, float)) and expires else None,
        "allowlisted": item.get("allowlisted") is True,
        "releasedAt": ms(item.get("released_at")), "releasedBy": item.get("released_by"),
        "releaseReason": item.get("release_reason"), "releaseKind": item.get("release_kind"),
        "lastError": item.get("last_error"), "version": int(item.get("version") or 0),
        "executionId": item.get("ssm_execution_id"), "unblockExecutionId": item.get("unblock_execution_id"),
        "evidence": {"hits": evidence.get("hits"), "alarm": evidence.get("alarm")},
    }


def _ssm(lookup, execution_id):
    """(status|None). lookup 은 {execution_id: 상태} — 없으면 아직 못 읽음(None)."""
    return lookup.get(execution_id) if execution_id else None


def _row_state(row, in_nacl, now_ms, lookup):
    status = row["status"]
    mismatch = None
    if status == "ACTIVE":
        if in_nacl:
            expired = row["expiresAt"] is not None and row["expiresAt"] <= now_ms
            return ("expiring" if expired else "blocked"), None
        if _ssm(lookup, row["executionId"]) in SSM_RUNNING:
            return "applying", None
        return "mismatch", "nacl-missing"
    if status == "RELEASING":
        return "releasing", None
    if status in {"RELEASED", "EXPIRED"}:
        return status.lower(), ("nacl-still-blocked" if in_nacl else None)
    if status == "FAILED":
        return "failed", ("nacl-still-blocked" if in_nacl else None)
    return "mismatch", mismatch


def merge(rows, denies, now_ms, lookup=None):
    """rows: 정규화된 표 행, denies: {ip: 규칙 번호}(NACL 1~99 인바운드 Deny /32), lookup: {실행 ID: SSM 상태}.
    반환: 화면 행 목록(최근 차단 먼저)."""
    lookup = lookup or {}
    known = denies is not None  # NACL 을 읽지 못하면 실제 차단 여부를 모른다 — 표의 상태만 보이고 inNacl 은 None
    denies = denies or {}
    items, seen = [], set()
    for row in rows:
        ip = row["ip"]
        seen.add(ip)
        in_nacl = ip in denies and (row["ruleNumber"] is None or denies[ip] == row["ruleNumber"])
        if not known:
            state, mismatch = _row_state(row, row["status"] == "ACTIVE", now_ms, lookup)
        else:
            state, mismatch = _row_state(row, in_nacl, now_ms, lookup)
            if row["status"] in {"ACTIVE", "FAILED"} and ip in denies and row["ruleNumber"] not in (None, denies[ip]):
                state, mismatch = "mismatch", "rule-changed"  # 표의 번호와 NACL 의 번호가 다르다
        items.append({**row, "state": state, "mismatch": mismatch, "inNacl": (ip in denies) if known else None,
                      "naclRule": denies.get(ip), "permanent": row["expiresAt"] is None and row["status"] == "ACTIVE"})
    for ip, rule in denies.items():
        if ip in seen:
            continue
        items.append({"ip": ip, "status": "UNRECORDED", "ruleNumber": rule, "naclId": None,
                      "source": None, "blockedAt": None, "updatedAt": None, "expiresAt": None, "allowlisted": False, "releasedAt": None,
                      "releasedBy": None, "releaseReason": None, "releaseKind": None, "lastError": None, "version": 0,
                      "executionId": None, "unblockExecutionId": None, "evidence": {"hits": None, "alarm": None},
                      "state": "unrecorded", "mismatch": "record-missing", "inNacl": True, "naclRule": rule,
                      "permanent": False})
    items.sort(key=lambda r: (-(r["blockedAt"] or 0), r["ip"]))
    return items


def counts(items):
    tally = Counter(item["state"] for item in items)
    return {state: tally.get(state, 0) for state in STATES} | {
        "allowlisted": sum(1 for i in items if i["allowlisted"]),
        "mismatch": sum(1 for i in items if i["mismatch"])}


def expiry_for(hours, now_ms):
    """선택한 기간(시간, 0 = 영구) → 만료 시각(ms). 지금부터 센다."""
    if hours not in DURATIONS:
        raise ValueError("hours")
    return None if hours == 0 else now_ms + hours * 3_600_000


CSV_COLUMNS = ("ip", "state", "source", "ruleNumber", "blockedAt", "expiresAt", "allowlisted", "releasedAt",
               "releasedBy", "releaseReason", "sessionCount", "commandCount", "lastSeenAt", "intents", "topCommands")
