"""The only command handler for approval, cancellation, execution and verification.

HTTP retries return the original committed response. A job receives an immutable
event/plan snapshot, so a later data refresh cannot change what was approved.
"""
import hashlib
import json
import uuid

from .domain import STATUSES, plan_hash, public_event
from .errors import Problem
from .store import encode, now_ms

APPROVABLE = {"NEW", "PENDING_APPROVAL", "EXECUTION_FAILED"}
VERIFIABLE = {"PENDING_VERIFICATION", "VERIFICATION_FAILED"}
PERMISSIONS = {
    "viewer": {"dashboard:read"},
    "approver": {"dashboard:read", "soar:approve", "soar:cancel"},
    "operator": {"dashboard:read", "soar:approve", "soar:cancel", "soar:execute", "soar:verify"},
}


class Workflow:
    def __init__(self, store, provider, approval_ttl=900):
        self.store = store
        self.provider = provider
        self.approval_ttl_ms = int(approval_ttl * 1000)

    def principal(self, actor):
        with self.store.connect() as db:
            return self._principal(db, actor)

    @staticmethod
    def _principal(db, actor):
        user = db.execute("SELECT name,role,scope FROM users WHERE name=?", (actor,)).fetchone()
        if not user:
            raise Problem(401, "로그인이 필요합니다.", "AUTH_REQUIRED")
        return {"name": user["name"], "role": user["role"], "scope": json.loads(user["scope"])}

    @staticmethod
    def _authorize(event, principal, permission):
        if permission not in PERMISSIONS.get(principal["role"], set()):
            raise Problem(403, "이 작업을 수행할 권한이 없습니다.", "FORBIDDEN")
        for key, field in (("accounts", "accountId"), ("regions", "region"), ("resources", "resource")):
            allowed = principal["scope"].get(key)
            if allowed is not None and event.get(field) not in allowed:
                raise Problem(404, "허용 범위에서 이벤트를 찾을 수 없습니다.", "EVENT_NOT_FOUND")

    def authorize_event(self, event, actor, permission="dashboard:read"):
        self._authorize(event, self.principal(actor), permission)

    def allowed_actions(self, event, actor):
        principal = self.principal(actor)
        return self._allowed_actions(event, principal)

    def _allowed_actions(self, event, principal):
        try:
            self._authorize(event, principal, "dashboard:read")
            self._check_actionable(event)
        except Problem:
            return []
        candidates = []
        if event["status"] in APPROVABLE or event.get("actionState") == "CANCELLED":
            candidates.append("approve")
        if event["status"] in {"PENDING_APPROVAL", "APPROVED"} and event.get("actionState") != "CANCELLED":
            candidates.append("cancel")
        if event["status"] == "APPROVED":
            if (event.get("expiresAt") or 0) > now_ms():
                candidates.append("execute")
            else:
                candidates.append("approve")
        if event["status"] in VERIFIABLE and event.get("execution") == "SUCCEEDED":
            candidates.append("verify")
        return [action for action in candidates if f"soar:{action}" in PERMISSIONS[principal["role"]]]

    def visible_events(self, actor):
        principal = self.principal(actor)
        result = []
        for event in self.store.events():
            try:
                self._authorize(event, principal, "dashboard:read")
            except Problem as error:
                if error.status == 404:
                    continue
                raise
            dto = public_event(event)
            dto["allowedActions"] = self._allowed_actions(event, principal)
            result.append(dto)
        return result

    def events(self):
        return [public_event(event) for event in self.store.events()]

    def get_event(self, event_id):
        with self.store.connect() as db:
            return public_event(self._require(db, event_id))

    def _require(self, db, event_id):
        event = self.store.event(db, event_id)
        if event is None:
            raise Problem(404, "이벤트를 찾을 수 없습니다.", "EVENT_NOT_FOUND")
        return event

    def change(self, event_id, action, body, actor, key):
        self.provider.require_ready()
        if action not in {"approve", "cancel", "execute", "verify", "plan"}:
            raise Problem(404, "지원하지 않는 조치입니다.", "NOT_FOUND")
        self._validate_body(body)
        if body.get("dry_run") and action not in {"execute", "verify"}:
            raise Problem(400, "dry_run은 실행·재검증 요청에만 사용할 수 있습니다.")
        content = {key: value for key, value in body.items() if key != "request_id"}
        fingerprint = hashlib.sha256(encode([actor, event_id, action, content]).encode()).hexdigest()
        with self.store.connect(write=True) as db:
            principal = self._principal(db, actor)
            event = self._require(db, event_id)
            self._authorize(event, principal, "soar:" + ("approve" if action == "plan" else action))
            cached = db.execute("SELECT * FROM requests WHERE key=?", (key,)).fetchone()
            if cached:
                if cached["actor"] != actor or cached["fingerprint"] != fingerprint:
                    raise Problem(409, "이미 다른 요청에 사용한 Idempotency-Key입니다.", "IDEMPOTENCY_CONFLICT")
                return json.loads(cached["response"]), cached["status"]
            self._check_preconditions(event, body)
            if action == "plan":
                raise Problem(422, "조치 계획 공급자가 이 작업을 지원하지 않습니다.", "UNSUPPORTED_PLAN")
            self._check_actionable(event)
            timestamp = now_ms()
            if action == "approve":
                renewable = event["status"] == "APPROVED" and (event.get("expiresAt") or 0) <= timestamp
                if not renewable:
                    self._require_state(event, APPROVABLE)
                plan = event["plan"]
                if body.get("playbook_id", plan["document"]) != plan["document"]:
                    raise Problem(422, "서버가 허용한 플레이북이 아닙니다.", "PLAYBOOK_NOT_ALLOWED")
                if body.get("parameters", plan.get("parameters", {})) != plan.get("parameters", {}):
                    raise Problem(422, "서버 조치 계획과 매개변수가 다릅니다.", "PLAN_CHANGED")
                event.update(status="APPROVED", actionState="APPROVED", approver=actor,
                             actionId=str(uuid.uuid4()), approvalId=str(uuid.uuid4()),
                             expiresAt=timestamp + self.approval_ttl_ms, approvedAt=timestamp,
                             _approvedPlanHash=plan_hash(event), _approvalSnapshot=plan.copy())
                self._history(event, timestamp, "조치 계획 승인")
                result, status = public_event(event), 200
            elif action == "cancel":
                self._require_state(event, {"APPROVED", "PENDING_APPROVAL"})
                if event.get("actionState") == "CANCELLED":
                    raise Problem(409, "이미 취소된 승인입니다.", "INVALID_TRANSITION")
                event.update(status="PENDING_APPROVAL", actionState="CANCELLED", approver=None,
                             actionId=event.get("actionId") or str(uuid.uuid4()),
                             expiresAt=None, approvalId=None, _approvedPlanHash=None)
                self._history(event, timestamp, "실행 전 승인 취소")
                result, status = public_event(event), 200
            else:
                if action == "execute":
                    self._require_state(event, {"APPROVED"})
                    if not event.get("expiresAt") or event["expiresAt"] <= timestamp:
                        raise Problem(409, "승인이 만료됐습니다. 다시 승인해주세요.", "APPROVAL_EXPIRED")
                    if "approval_id" in body and body["approval_id"] != event.get("approvalId"):
                        raise Problem(409, "현재 승인과 일치하지 않습니다.", "APPROVAL_CONFLICT")
                    if event.get("_approvedPlanHash") != plan_hash(event):
                        raise Problem(409, "승인 이후 계획이 변경됐습니다. 다시 승인해주세요.", "PLAN_CHANGED")
                else:
                    self._require_state(event, VERIFIABLE)
                    if "action_id" in body and body["action_id"] != event.get("actionId"):
                        raise Problem(409, "현재 조치와 일치하지 않습니다.", "ACTION_CONFLICT")
                    if event.get("execution") != "SUCCEEDED":
                        raise Problem(409, "조치가 성공한 뒤 재검증할 수 있습니다.", "INVALID_TRANSITION")
                    if event.get("_executedPlanHash") != plan_hash(event):
                        raise Problem(409, "실행 당시의 검증 기준과 다릅니다.", "PLAN_CHANGED")
                if body.get("dry_run"):
                    result = {"event": public_event(event), "execution": None, "dryRun": True}
                    status = 202
                else:
                    job_id = str(uuid.uuid4())
                    # Snapshot before the transient state. Retries and crash recovery use this exact input.
                    payload = {"event": event, "actor": actor, "planHash": plan_hash(event),
                               "requestId": body.get("request_id")}
                    db.execute("INSERT INTO jobs(id,event_id,kind,state,payload,created_at,updated_at) "
                               "VALUES (?,?,?,'QUEUED',?,?,?)",
                               (job_id, event_id, action, encode(payload), timestamp, timestamp))
                    event["activeExecutionId"] = job_id
                    if action == "execute":
                        event.update(status="EXECUTING", actionState="QUEUED", execution="RUNNING", verification="NOT_RUN",
                                     afterValue=None, afterAt=None)
                    else:
                        event.update(status="VERIFYING", actionState="VERIFY_QUEUED", verification="CHECKING")
                    self._history(event, timestamp, "조치 대기열 등록" if action == "execute" else "동일 기준 재검증 대기열 등록")
                    result = {"event": public_event(event), "execution": {
                        "executionId": job_id, "status": "RUNNING", "kind": action,
                        "startedAt": timestamp}, "dryRun": False}
                    status = 202
            if not body.get("dry_run"):
                event["version"] += 1
                event["updatedAt"] = timestamp
            if "event" in result:
                result["event"] = public_event(event)
            else:
                result = public_event(event)
            returned_event = result.get("event", result)
            returned_event["allowedActions"] = self._allowed_actions(event, principal)
            self.store.save_event(db, event)
            self.store.audit(db, actor, event_id, action, {
                "planHash": plan_hash(event), "dryRun": body.get("dry_run", False),
                "executionId": (result.get("execution") or {}).get("executionId") if isinstance(result.get("execution"), dict) else None,
                "jobId": event.get("activeExecutionId"), "requestId": body.get("request_id"),
                "event": public_event(event), "reason": body.get("reason", ""),
            })
            db.execute("INSERT INTO requests VALUES (?,?,?,?,?,?)",
                       (key, actor, fingerprint, status, encode(result), timestamp))
            return result, status

    @staticmethod
    def _validate_body(body):
        if not isinstance(body, dict):
            raise Problem(400, "JSON 객체 본문이 필요합니다.")
        try:
            encode(body).encode("utf-8")
        except (ValueError, TypeError, UnicodeError) as error:
            raise Problem(400, "유효한 JSON 값만 사용할 수 있습니다.") from error
        if set(body) - {"expected_status", "plan_hash", "dry_run", "parameters", "evidence",
                        "expected_version", "reason", "playbook_id", "approval_id", "action_id", "request_id"}:
            raise Problem(400, "허용되지 않은 조치 파라미터입니다.")
        if "expected_status" in body and (not isinstance(body["expected_status"], str)
                                          or body["expected_status"] not in STATUSES):
            raise Problem(400, "expected_status 값이 올바르지 않습니다.")
        if "plan_hash" in body and not isinstance(body["plan_hash"], str):
            raise Problem(400, "plan_hash는 문자열이어야 합니다.")
        if "dry_run" in body and type(body["dry_run"]) is not bool:
            raise Problem(400, "dry_run은 true 또는 false여야 합니다.")
        if "parameters" in body and not isinstance(body["parameters"], dict):
            raise Problem(400, "parameters는 JSON 객체여야 합니다.")
        if "expected_version" in body and (type(body["expected_version"]) is not int or body["expected_version"] < 1):
            raise Problem(400, "expectedVersion은 양의 정수여야 합니다.")
        if "reason" in body and (not isinstance(body["reason"], str) or len(body["reason"]) > 1000):
            raise Problem(400, "reason은 1000자 이하 문자열이어야 합니다.")
        if body.get("evidence") is not None:
            # User-authored evidence cannot replace a measured result.
            raise Problem(422, "임의 계획·수동 증적 입력은 지원하지 않습니다.", "UNSUPPORTED_PLAN")

    @staticmethod
    def _check_preconditions(event, body):
        if "expected_version" in body:
            if body["expected_version"] != event["version"]:
                raise Problem(409, "조치 버전이 변경됐습니다. 새로고침해주세요.", "VERSION_CONFLICT")
            return
        if body.get("expected_status") != event["status"]:
            raise Problem(409, "이벤트 상태가 변경됐습니다. 새로고침해주세요.", "STATE_CONFLICT")
        if body.get("plan_hash") != plan_hash(event):
            raise Problem(409, "조치 계획이 변경됐습니다. 새로고침해주세요.", "PLAN_CHANGED")

    @staticmethod
    def _check_actionable(event):
        if not event.get("actionable") or not event.get("plan"):
            raise Problem(422, "이 이벤트는 대시보드 조치 대상이 아닙니다.", "NOT_ACTIONABLE")

    @staticmethod
    def _require_state(event, allowed):
        if event["status"] not in allowed:
            raise Problem(409, "현재 상태에서는 이 조치를 실행할 수 없습니다.", "INVALID_TRANSITION")

    @staticmethod
    def _history(event, timestamp, text, decision=None):
        event.setdefault("history", []).append({"at": timestamp, "text": text, "decision": decision, "source": "manual"})

    def execution(self, event_id, job_id):
        with self.store.connect() as db:
            event = self._require(db, event_id)
            job = db.execute("SELECT * FROM jobs WHERE id=? AND event_id=?", (job_id, event_id)).fetchone()
            if not job:
                raise Problem(404, "실행 기록을 찾을 수 없습니다.", "EXECUTION_NOT_FOUND")
            execution = {"executionId": job["id"], "kind": job["kind"],
                         "status": "RUNNING" if job["state"] in {"QUEUED", "RUNNING"} else job["state"],
                         "startedAt": job["created_at"], "finishedAt": job["updated_at"] if job["result"] else None}
            if job["result"]:
                execution["result"] = json.loads(job["result"])
            return {"event": public_event(event), "execution": execution}
