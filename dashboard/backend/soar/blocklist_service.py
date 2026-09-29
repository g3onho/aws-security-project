"""차단 IP 관리 서비스 — 목록(NACL 대조)·보고서·오탐 해제·차단 기간·예외 등록.

원칙
  - 실제 차단의 기준은 NACL 1~99 Deny. 표(ip_blocklist)와 다르면 mismatch 로 보인다.
  - 변경은 조치 담당자(operator)만, WRITE_ENABLED 일 때만. 인증·CSRF 는 앱 공통 가드가 먼저 본다.
  - 모든 변경은 Idempotency-Key + expectedVersion(낙관적 잠금) + 표의 조건부 갱신으로 중복·경합을 막는다.
  - 해제는 SSM ASR-UnblockIpWithNacl 이 NACL 의 그 번호가 "Deny + 그 IP/32" 일 때만 지운다(문서가 한 번 더 확인).
  - 해제의 마무리(RELEASING → RELEASED)는 block_expiry Lambda 와 이 서비스의 조회가 같은 규칙으로 한다.
  - 승인 ≠ 실행 ≠ 해결: SSM 이 성공해도 NACL 에서 Deny 가 사라졌는지는 다음 조회의 NACL 대조가 확인한다.
"""
import csv
import hashlib
import io
import json
import logging
import re

from .contracts import iso
from .errors import Problem
from .honeypot_service import DEFAULT_WRITER_ROLES, authorize, parse_window
from .repositories import honeypot as hp
from .repositories.blocklist import (CSV_COLUMNS, DURATIONS, SSM_RUNNING, SSM_SUCCESS, counts, expiry_for, merge,
                                     normalize, valid_ip)
from .store import encode, now_ms

LOG = logging.getLogger(__name__)
RECONCILE_LIMIT = 10        # 한 요청에서 새로 읽는 SSM 실행 결과 수(조회 지연 제한)
STUCK_RELEASE_MS = 300_000  # 실행 ID 없이 RELEASING 에 머문 행을 되돌리는 기준(SSM 시작 실패·프로세스 중단)


def _iso_now():
    return iso(now_ms())


class BlocklistService:
    def __init__(self, provider, workflow, store, honeypot, settings):
        self.provider, self.workflow, self.store, self.honeypot = provider, workflow, store, honeypot
        self.gateway = getattr(provider, "blocklist", None)
        self.writes_enabled = settings["WRITE_ENABLED"]
        self.writer_roles = frozenset(settings.get("BLOCKLIST_WRITE_ROLES") or DEFAULT_WRITER_ROLES)
        self.default_ttl_hours = settings.get("IP_BLOCK_TTL_HOURS")

    # --- 공통 -------------------------------------------------------------------------------
    def _guard(self, actor):
        self.provider.require_ready()
        principal = self.workflow.principal(actor)
        authorize(self.provider, principal)
        if self.gateway is None:
            raise Problem(409, "차단 IP 목록 설정이 없습니다(IP_BLOCKLIST_TABLE·PRIVATE_NACL_ID).", "BLOCKLIST_NOT_CONFIGURED")
        return principal

    def _writer(self, principal):
        if not self.writes_enabled:
            raise Problem(403, "현재 조회 전용 모드입니다.", "WRITE_DISABLED")
        if principal["role"] not in self.writer_roles:
            raise Problem(403, "이 작업을 수행할 권한이 없습니다.", "FORBIDDEN")
        scope = principal.get("scope") or {}
        if any(scope.get(k) is not None for k in ("accounts", "regions", "resources")):
            raise Problem(403, "범위가 제한된 계정은 차단 목록을 변경할 수 없습니다.", "FORBIDDEN")

    # --- 조회 -------------------------------------------------------------------------------
    def list(self, raw_query, actor):
        principal = self._guard(actor)
        raw = dict(raw_query)
        raw.pop("format", None)
        now = now_ms()
        start, end, _ = parse_window(raw, now)
        warnings = []
        try:
            rows = [normalize(item) for item in self.gateway.rows()]
        except Exception as error:  # noqa: BLE001
            LOG.exception("blocklist table read failed")
            raise Problem(502, "차단 IP 목록 표를 읽지 못했습니다.", "BLOCKLIST_UNAVAILABLE",
                          detail=type(error).__name__) from error
        try:
            denies = self.gateway.nacl_denies()
        except Exception as error:  # noqa: BLE001
            denies = None
            warnings.append(f"NACL 을 읽지 못해 실제 차단 여부를 대조하지 못했습니다({type(error).__name__}). 표의 상태만 보입니다.")
        lookup = self._reconcile(rows, denies, now, warnings)
        items = merge(rows, denies, now, lookup)
        evidence = self._evidence(start, end, warnings)
        for item in items:
            item["sessions"] = evidence.get(item["ip"]) if evidence is not None else None
        data = {"items": items, "counts": counts(items), "naclId": self.gateway.nacl_id,
                "durations": [{"hours": h, "label": label} for h, label in DURATIONS.items()],
                "defaultTtlHours": self.default_ttl_hours, "from": iso(start), "to": iso(end),
                "canWrite": bool(self.writes_enabled and principal["role"] in self.writer_roles)}
        return data, warnings, bool(warnings)

    def _evidence(self, start, end, warnings):
        """IP 별 미끼 세션 요약(보고서 근거). 허니팟 로그를 못 읽으면 None(0 으로 위장하지 않는다)."""
        if not self.honeypot.deployed():
            return None
        try:
            by_id, warn, _ = self.honeypot.load(start, end)
        except Problem as error:
            warnings.append(f"미끼 세션 근거를 읽지 못했습니다({error.detail or error.code}).")
            return None
        warnings.extend(warn)
        ips = {s["srcIp"] for s in by_id.values() if s["srcIp"]}
        return {ip: hp.by_ip(by_id, ip) for ip in ips}

    def _reconcile(self, rows, denies, now, warnings):
        """RELEASING 마무리와 '적용 중' 판정용 SSM 상태 조회. 반환: {실행 ID: SSM 상태}. 행은 제자리에서 고친다."""
        lookup, budget = {}, RECONCILE_LIMIT

        def status_of(execution_id):
            nonlocal budget
            if execution_id in lookup:
                return lookup[execution_id]
            if budget <= 0:
                return None
            budget -= 1
            try:
                found, evidence = self.provider.execution(execution_id)
            except Exception:  # noqa: BLE001
                return None
            lookup[execution_id] = (evidence or {}).get("status") if found and evidence else "NotFound"
            return lookup[execution_id]

        for row in rows:
            try:
                if row["status"] == "RELEASING":
                    self._finish_release(row, status_of, now, warnings)
                elif row["status"] == "ACTIVE" and denies is not None and row["ip"] not in denies and row["executionId"]:
                    status_of(row["executionId"])  # merge 가 '적용 중'과 mismatch 를 가르는 데 쓴다
            except Exception as error:  # noqa: BLE001 — 한 행 실패가 목록을 막지 않는다
                LOG.warning("blocklist reconcile failed for %s: %s", row["ip"], error)
        return lookup

    def _finish_release(self, row, status_of, now, warnings):
        ip, version, execution_id = row["ip"], row["version"], row["unblockExecutionId"]
        cond = lambda expected: ("#c0 = :c0 AND #c1 = :c1", {"#c0": "status", "#c1": "version"},  # noqa: E731
                                 {":c0": "RELEASING", ":c1": expected})
        if not execution_id:
            updated = row.get("updatedAt")
            if updated is not None and now - updated > STUCK_RELEASE_MS:
                if self.gateway.update(ip, {"status": "ACTIVE", "last_error": "해제 시작 실패(실행 ID 없음) — 되돌림",
                                            "updated_at": _iso_now()}, condition=cond(version)):
                    row.update(status="ACTIVE", lastError="해제 시작 실패(실행 ID 없음) — 되돌림", version=version + 1)
            return
        status = status_of(execution_id)
        if status in SSM_SUCCESS:
            final = "EXPIRED" if row["releaseKind"] == "expiry" else "RELEASED"
            if self.gateway.update(ip, {"status": final, "released_at": _iso_now(), "updated_at": _iso_now()},
                                   remove=("last_error",), condition=cond(version)):
                row.update(status=final, releasedAt=now, version=version + 1, lastError=None)
        elif status is not None and status not in SSM_RUNNING:
            message = f"해제 SSM {status}"
            if self.gateway.update(ip, {"status": "ACTIVE", "last_error": message, "updated_at": _iso_now()},
                                   condition=cond(version)):
                row.update(status="ACTIVE", lastError=message, version=version + 1)

    # --- 보고서 -----------------------------------------------------------------------------
    def report_csv(self, data):
        """목록 → CSV(수식 주입 방지). 시각은 UTC ISO 8601."""
        out = io.StringIO()
        writer = csv.writer(out, lineterminator="\r\n")
        writer.writerow(CSV_COLUMNS)
        for item in data["items"]:
            sessions = item.get("sessions") or {}
            values = {**item, "sessionCount": sessions.get("sessionCount"), "commandCount": sessions.get("commandCount"),
                      "lastSeenAt": sessions.get("lastSeenAt"), "intents": " ".join(sessions.get("intents") or []),
                      "topCommands": " | ".join(c["key"] for c in sessions.get("topCommands") or [])}
            for column in ("blockedAt", "expiresAt", "releasedAt", "lastSeenAt"):
                values[column] = iso(values.get(column)) if values.get(column) else ""
            writer.writerow([hp.csv_safe(values.get(column)) for column in CSV_COLUMNS])
        return "﻿" + out.getvalue()  # BOM: 엑셀에서 한글이 깨지지 않게

    # --- 변경 공통 ---------------------------------------------------------------------------
    @staticmethod
    def _key(key):
        if not isinstance(key, str) or not 1 <= len(key) <= 200 or not re.fullmatch(r"[\x21-\x7e]+", key):
            raise Problem(400, "유효한 Idempotency-Key가 필요합니다.", "INVALID_IDEMPOTENCY_KEY")

    def _cached(self, key, actor, fingerprint):
        with self.store.connect() as db:
            cached = db.execute("SELECT * FROM requests WHERE key=?", (key,)).fetchone()
        if not cached:
            return None
        if cached["actor"] != actor or cached["fingerprint"] != fingerprint:
            raise Problem(409, "이미 다른 요청에 사용한 Idempotency-Key입니다.", "IDEMPOTENCY_CONFLICT")
        return json.loads(cached["response"]), cached["status"]

    def _commit(self, key, actor, fingerprint, response, status, action, detail):
        with self.store.connect(write=True) as db:
            db.execute("INSERT OR IGNORE INTO requests VALUES (?,?,?,?,?,?)",
                       (key, actor, fingerprint, status, encode(response), now_ms()))
            self.store.audit(db, actor, None, action, detail)

    @staticmethod
    def _body(body, required, optional=()):
        if not isinstance(body, dict):
            raise Problem(400, "JSON 객체 본문이 필요합니다.", "INVALID_PARAMETER")
        if set(body) - set(required) - set(optional) or set(required) - set(body):
            raise Problem(400, "필수 필드가 누락되었거나 허용되지 않은 필드가 있습니다.", "INVALID_PARAMETER")
        reason = body.get("reason")
        if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 500:
            raise Problem(400, "reason은 1~500자의 사유여야 합니다.", "INVALID_PARAMETER")
        if type(body.get("expectedVersion")) is not int or body["expectedVersion"] < 0:
            raise Problem(400, "expectedVersion은 0 이상의 정수여야 합니다.", "INVALID_PARAMETER")

    # --- 오탐 해제 ---------------------------------------------------------------------------
    def release(self, ip, body, actor, key, request_id):
        principal = self._guard(actor)
        self._writer(principal)
        if not valid_ip(ip):
            raise Problem(400, "ip는 IPv4 단일 주소여야 합니다.", "INVALID_PARAMETER")
        self._body(body, ("reason", "expectedVersion"), ("allowlist",))
        allowlist = body.get("allowlist", False)
        if not isinstance(allowlist, bool):
            raise Problem(400, "allowlist는 true 또는 false여야 합니다.", "INVALID_PARAMETER")
        self._key(key)
        fingerprint = hashlib.sha256(encode([actor, "release", ip, body]).encode()).hexdigest()
        cached = self._cached(key, actor, fingerprint)
        if cached:
            return cached
        raw = self.gateway.row(ip)
        try:
            denies = self.gateway.nacl_denies()
        except Exception as error:  # noqa: BLE001 — 실제 NACL 을 모르면 무엇을 지울지 정할 수 없다
            raise Problem(502, "NACL 을 읽지 못해 해제할 수 없습니다.", "NACL_UNAVAILABLE", detail=type(error).__name__) from error
        row = normalize(raw) if raw else None
        if row and row["status"] == "RELEASING":
            if raw.get("release_request_key") == key:  # 같은 요청의 재시도 — 이미 시작한 해제를 그대로 알린다
                return self._replay(row), 202
            raise Problem(409, "이미 해제가 진행 중입니다.", "RELEASE_IN_PROGRESS")
        if row and row["status"] in {"RELEASED", "EXPIRED"} and ip not in denies:
            raise Problem(409, "이미 해제된 IP 입니다.", "ALREADY_RELEASED")
        expected = row["version"] if row else 0
        if body["expectedVersion"] != expected:
            raise Problem(409, "차단 정보가 바뀌었습니다. 새로고침해주세요.", "VERSION_CONFLICT")
        if row is None and ip not in denies:
            raise Problem(404, "차단 목록과 NACL 어디에도 이 IP 가 없습니다.", "IP_NOT_FOUND")
        rule = denies.get(ip)
        now = _iso_now()
        common = {"released_by": actor, "release_reason": body["reason"].strip(), "release_kind": "manual",
                  "updated_at": now}
        if allowlist:
            common["allowlisted"] = True
        prior = {"status": row["status"] if row else None, "allowlisted": row["allowlisted"] if row else False}
        if rule is None:
            # NACL 에 이미 Deny 가 없다 → 지울 것이 없으므로 SSM 없이 표만 마무리한다.
            done = self.gateway.update(ip, {**common, "status": "RELEASED", "released_at": now,
                                            "release_reason": common["release_reason"] + " (NACL 에 이미 Deny 없음)"},
                                       condition=("#c0 = :c0", {"#c0": "version"}, {":c0": row["version"]}))
            if not done:
                raise Problem(409, "차단 정보가 바뀌었습니다. 새로고침해주세요.", "VERSION_CONFLICT")
            response, status = {"ip": ip, "state": "released", "executionId": None, "version": row["version"] + 1,
                                "note": "NACL 에 Deny 가 이미 없어 표만 해제로 표시했습니다."}, 200
            self._commit(key, actor, fingerprint, response, status, "blocklist-release",
                         {"ip": ip, "reason": body["reason"], "allowlist": allowlist, "requestId": request_id, "note": "nacl-absent"})
            return response, status
        nacl_id = (row or {}).get("naclId") or self.gateway.nacl_id
        sets = {**common, "status": "RELEASING", "release_request_key": key, "nacl_id": nacl_id, "rule_number": rule}
        if row is None:  # 표에 기록이 없던 수동 차단
            created = self.gateway.create_unrecorded(ip, {**sets, "source": "MANUAL", "allowlisted": allowlist})
            if not created:
                raise Problem(409, "차단 정보가 바뀌었습니다. 새로고침해주세요.", "VERSION_CONFLICT")
        else:
            moved = self.gateway.update(ip, sets, remove=("last_error",), condition=(
                "#c0 = :c0 AND #c1 = :c1", {"#c0": "version", "#c1": "status"},
                {":c0": row["version"], ":c1": row["status"]}))
            if not moved:
                raise Problem(409, "차단 정보가 바뀌었습니다. 새로고침해주세요.", "VERSION_CONFLICT")
        try:
            execution_id = self.gateway.start_unblock(ip, nacl_id, rule, f"{ip}|{key}")
        except Exception as error:  # noqa: BLE001 — 시작하지 못했으니 표를 되돌린다(차단은 그대로)
            LOG.exception("unblock start failed")
            self._revert(ip, prior, key, f"해제 시작 실패: {type(error).__name__}")
            raise Problem(502, "해제 실행(SSM)을 시작하지 못했습니다. 차단은 그대로 유지됩니다.", "UNBLOCK_START_FAILED",
                          detail=type(error).__name__) from error
        self.gateway.update(ip, {"unblock_execution_id": execution_id}, condition=(
            "#c0 = :c0", {"#c0": "release_request_key"}, {":c0": key}))
        try:
            self.gateway.record_action(ip, nacl_id, rule, execution_id, actor, body["reason"].strip(), "UNBLOCK-MANUAL")
        except Exception:  # noqa: BLE001 — 조치 이력 기록 실패가 해제를 막지 않는다(로컬 감사 기록은 남는다)
            LOG.exception("unblock action history write failed")
        response = {"ip": ip, "state": "releasing", "executionId": execution_id, "version": expected + 2,
                    "statusUrl": "/api/blocklist"}
        self._commit(key, actor, fingerprint, response, 202, "blocklist-release",
                     {"ip": ip, "rule": rule, "naclId": nacl_id, "reason": body["reason"], "allowlist": allowlist,
                      "executionId": execution_id, "requestId": request_id})
        return response, 202

    def _replay(self, row):
        return {"ip": row["ip"], "state": "releasing", "executionId": row["unblockExecutionId"],
                "version": row["version"], "statusUrl": "/api/blocklist"}

    def _revert(self, ip, prior, key, message):
        sets = {"status": prior["status"] or "FAILED", "last_error": message, "updated_at": _iso_now(),
                "allowlisted": prior["allowlisted"]}
        try:
            self.gateway.update(ip, sets, condition=("#c0 = :c0", {"#c0": "release_request_key"}, {":c0": key}))
        except Exception:  # noqa: BLE001
            LOG.exception("release revert failed")

    # --- 차단 기간·예외 등록 --------------------------------------------------------------------
    def patch(self, ip, body, actor, key, request_id):
        principal = self._guard(actor)
        self._writer(principal)
        if not valid_ip(ip):
            raise Problem(400, "ip는 IPv4 단일 주소여야 합니다.", "INVALID_PARAMETER")
        self._body(body, ("reason", "expectedVersion"), ("durationHours", "allowlisted"))
        if "durationHours" not in body and "allowlisted" not in body:
            raise Problem(400, "durationHours 또는 allowlisted 중 하나는 필요합니다.", "INVALID_PARAMETER")
        if "durationHours" in body and (type(body["durationHours"]) is not int or body["durationHours"] not in DURATIONS):
            raise Problem(400, f"durationHours는 {sorted(DURATIONS)} 중 하나여야 합니다(0 = 영구).", "INVALID_PARAMETER")
        if "allowlisted" in body and not isinstance(body["allowlisted"], bool):
            raise Problem(400, "allowlisted는 true 또는 false여야 합니다.", "INVALID_PARAMETER")
        self._key(key)
        fingerprint = hashlib.sha256(encode([actor, "patch", ip, body]).encode()).hexdigest()
        cached = self._cached(key, actor, fingerprint)
        if cached:
            return cached
        raw = self.gateway.row(ip)
        if raw is None:
            raise Problem(404, "차단 목록에 없는 IP 입니다(기록 없는 차단은 먼저 해제하거나 기록해야 합니다).", "IP_NOT_FOUND")
        row = normalize(raw)
        if body["expectedVersion"] != row["version"]:
            raise Problem(409, "차단 정보가 바뀌었습니다. 새로고침해주세요.", "VERSION_CONFLICT")
        sets, remove, now = {"updated_at": _iso_now()}, [], now_ms()
        if "durationHours" in body:
            if row["status"] != "ACTIVE":
                raise Problem(409, "차단 중인 IP 만 기간을 바꿀 수 있습니다.", "INVALID_TRANSITION")
            expires = expiry_for(body["durationHours"], now)
            if expires is None:
                remove.append("expires_at")
            else:
                sets["expires_at"] = expires // 1000
            sets["expiry_changed_by"], sets["expiry_reason"] = actor, body["reason"].strip()
        if "allowlisted" in body:
            sets["allowlisted"] = body["allowlisted"]
        applied = self.gateway.update(ip, sets, remove=remove, condition=(
            "#c0 = :c0 AND #c1 = :c1", {"#c0": "version", "#c1": "status"}, {":c0": row["version"], ":c1": row["status"]}))
        if not applied:
            raise Problem(409, "차단 정보가 바뀌었습니다(만료 처리 등). 새로고침해주세요.", "VERSION_CONFLICT")
        response = {"ip": ip, "version": row["version"] + 1,
                    "expiresAt": iso(expiry_for(body["durationHours"], now)) if body.get("durationHours") else None,
                    "allowlisted": body.get("allowlisted", row["allowlisted"])}
        self._commit(key, actor, fingerprint, response, 200, "blocklist-patch",
                     {"ip": ip, "changes": {k: body[k] for k in ("durationHours", "allowlisted") if k in body},
                      "reason": body["reason"], "requestId": request_id})
        return response, 200
