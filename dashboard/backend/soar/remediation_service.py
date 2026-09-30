"""대시보드 원클릭 조치 — 확인창에서 바로 실행하고, 실행 뒤 같은 기준으로 자동 재검증한다.

원칙
  - 계획(문서·대상)은 서버가 탐지에서 만든다. 브라우저는 사유와 '이 계획을 보고 눌렀다'는 playbookId 만 보낸다.
  - 실행은 조치 담당자(operator)만, WRITE_ENABLED 일 때만. 인증·CSRF 는 앱 공통 가드가 먼저 본다.
  - Idempotency-Key 하나 = 실행 한 번. 시작 응답을 잃어도 같은 키로 다시 보내면 SSM ClientToken 이 같은 실행으로 이어 준다.
  - 실행 전 지금 상태를 읽는다. 이미 기준을 만족하면 실행하지 않고 그 사실을 기록한다. 조치하면 안 되는 대상(태그 없는
    보안그룹·프로젝트 밖 VPC)이면 막는다.
  - SSM 실행 성공 ≠ 해결. 실행이 끝나면 같은 기준으로 다시 읽어 통과해야 '해결 확인'이다. 재검증을 못 읽었으면
    통과가 아니라 '재검증 오류'다.
  - 진행 상태 갱신은 조회 때 한다(별도 백그라운드 작업 없음). 조회 전용 작업이라 재시도해도 안전하다.
"""
import hashlib
import json
import logging
import re
import uuid

from .contracts import iso
from .errors import Problem
from .remediation_plans import resolve
from .scope import matches as scope_matches
from .store import encode, now_ms

LOG = logging.getLogger(__name__)
ACTIVE = ("STARTING", "RUNNING", "VERIFYING")
SSM_OK = {"Success", "CompletedWithSuccess"}
SSM_BAD = {"Failed", "TimedOut", "Cancelled", "Rejected", "CompletedWithFailure"}
RECHECKABLE = ("NOT_RESOLVED", "VERIFY_ERROR")
HISTORY_LIMIT = 200


def _code(error):
    response = getattr(error, "response", None)
    if isinstance(response, dict):
        return response.get("Error", {}).get("Code") or type(error).__name__
    return type(error).__name__


def _definite(error):
    """AWS 가 명시적으로 거절한 오류(요청이 실행되지 않았다). 시간 초과·연결 오류는 시작 여부를 알 수 없다."""
    response = getattr(error, "response", None)
    if not isinstance(response, dict) or not response.get("Error", {}).get("Code"):
        return False
    status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return isinstance(status, int) and 400 <= status < 500 and status not in (408, 429)


class RemediationService:
    def __init__(self, provider, workflow, store, settings, events):
        self.provider, self.workflow, self.store = provider, workflow, store
        self.events = events                       # actor → 그 사용자에게 보이는 탐지 목록
        self.writes_enabled = settings["WRITE_ENABLED"]
        self.project_vpc_id = settings.get("PROJECT_VPC_ID")

    # --- 저장 ---------------------------------------------------------------------------------
    def _row(self, row):
        payload = json.loads(row["payload"])
        return {"id": row["id"], "eventId": row["event_id"], "actor": row["actor"], "requestKey": row["request_key"],
                "state": row["state"], "executionId": row["execution_id"], "createdAt": row["created_at"],
                "updatedAt": row["updated_at"], **payload}

    def _get(self, remediation_id):
        with self.store.connect() as db:
            row = db.execute("SELECT * FROM remediations WHERE id=?", (remediation_id,)).fetchone()
        return self._row(row) if row else None

    def _by_key(self, key):
        with self.store.connect() as db:
            row = db.execute("SELECT * FROM remediations WHERE request_key=?", (key,)).fetchone()
        return self._row(row) if row else None

    def _rows(self, event_id=None, limit=HISTORY_LIMIT):
        sql, args = "SELECT * FROM remediations", []
        if event_id:
            sql += " WHERE event_id=?"
            args.append(event_id)
        with self.store.connect() as db:
            rows = db.execute(sql + " ORDER BY created_at DESC, id LIMIT ?", (*args, limit)).fetchall()
        return [self._row(row) for row in rows]

    def _save(self, item, **changes):
        """상태·필드를 바꿔 저장한다. state 는 허용된 이동만(이미 끝난 실행을 되살리지 않는다)."""
        previous = item["state"]
        state = changes.pop("state", item["state"])
        execution_id = changes.pop("executionId", item["executionId"])
        item.update(changes)
        item.update(state=state, executionId=execution_id, updatedAt=now_ms())
        payload = {k: v for k, v in item.items() if k not in ("id", "eventId", "actor", "requestKey", "state", "executionId",
                                                              "createdAt", "updatedAt")}
        saved = False
        with self.store.connect(write=True) as db:
            updated = db.execute("UPDATE remediations SET state=?, execution_id=?, payload=?, updated_at=? WHERE id=? AND state=?",
                                 (state, execution_id, encode(payload), item["updatedAt"], item["id"], previous))
            saved = updated.rowcount == 1
            if saved and state != previous and state in ("EXEC_FAILED", "VERIFIED", "NOT_RESOLVED", "VERIFY_ERROR"):
                # 결과가 정해질 때마다 남긴다(실행 시작은 execute 가 이미 기록).
                self.store.audit(db, item["actor"], None, "remediation-" + state.lower().replace("_", "-"),
                                 {"eventId": item["eventId"], "remediationId": item["id"], "playbookId": item["plan"]["playbookId"]})
        if not saved:
            current = self._get(item["id"])
            if current is None:
                raise RuntimeError("조치 기록이 갱신 중 사라졌습니다.")
            return current
        return item

    # --- DTO ----------------------------------------------------------------------------------
    @staticmethod
    def dto(item):
        return {"id": item["id"], "eventId": item["eventId"], "actor": item["actor"], "state": item["state"],
                "playbookId": item["plan"]["playbookId"], "title": item["plan"]["title"], "change": item["plan"]["change"],
                "criterion": item["plan"]["criterion"], "parameters": item["plan"]["parameters"],
                "target": item["plan"]["target"], "reason": item["reason"], "executionId": item["executionId"],
                "ssmStatus": item.get("ssmStatus"), "before": item.get("before"), "after": item.get("after"),
                "verification": item.get("verification"), "error": item.get("error"), "requestId": item.get("requestId"),
                "resource": item["snapshot"]["resource"], "region": item["snapshot"]["region"],
                "eventTitle": item["snapshot"]["title"], "severity": item["snapshot"]["severity"],
                "controlId": item["snapshot"]["controlId"], "dataMode": "live",
                "createdAt": iso(item["createdAt"]), "updatedAt": iso(item["updatedAt"])}

    # --- 진행 상태 갱신(조회 때) ---------------------------------------------------------------
    def _verify(self, item):
        """같은 기준으로 다시 읽는다. 읽지 못하면 통과로 보지 않고 VERIFY_ERROR."""
        try:
            measured = self.provider.remediation_measure(item["plan"])
        except Exception as error:  # noqa: BLE001
            LOG.warning("remediation verify failed for %s: %s", item["id"], error)
            return self._save(item, state="VERIFY_ERROR", error=f"재검증을 읽지 못했습니다({_code(error)}). 통과로 보지 않습니다.",
                              verification={"passed": None, "text": None, "checkedAt": iso(now_ms())})
        verification = {"passed": bool(measured["compliant"]), "text": measured["text"], "checkedAt": iso(now_ms())}
        return self._save(item, state="VERIFIED" if verification["passed"] else "NOT_RESOLVED", error=None,
                          verification=verification, after={"text": measured["text"], "at": iso(now_ms())})

    def _advance(self, item):
        state = item["state"]
        if state == "RUNNING" and item["executionId"]:
            try:
                found, evidence = self.provider.execution(item["executionId"], fetch=True)
            except Exception as error:  # noqa: BLE001 — 읽지 못한 것을 실패·성공으로 단정하지 않는다
                return self._save(item, error=f"SSM 실행 상태를 읽지 못했습니다({_code(error)}). 실행 결과는 알 수 없습니다.")
            if not found or evidence is None:
                return self._save(item, error="SSM 실행 기록을 찾지 못했습니다. 실행 결과는 알 수 없습니다.")
            status = evidence.get("status")
            if status in SSM_OK:
                item = self._save(item, state="VERIFYING", ssmStatus=status, error=None)
                return self._verify(item)
            if status in SSM_BAD:
                return self._save(item, state="EXEC_FAILED", ssmStatus=status,
                                  error=evidence.get("failureMessage") or f"SSM 실행이 {status} 로 끝났습니다.")
            return self._save(item, ssmStatus=status, error=None)
        if state in ("VERIFYING", "VERIFY_ERROR"):
            return self._verify(item)
        return item

    def _refresh(self, items):
        out = []
        for item in items:
            try:
                out.append(self._advance(item) if item["state"] in ACTIVE + ("VERIFY_ERROR",) else item)
            except Exception:  # noqa: BLE001 — 한 건 실패가 목록을 막지 않는다
                LOG.exception("remediation refresh failed for %s", item["id"])
                out.append(item)
        return out

    # --- 조회 ---------------------------------------------------------------------------------
    def _visible(self, items, principal):
        return [item for item in items if scope_matches({"accountId": item["snapshot"].get("accountId"),
                                                         "region": item["snapshot"]["region"],
                                                         "resource": item["snapshot"]["resource"]}, principal)]

    def _event(self, event_id, actor):
        for event in self.events(actor):
            if event["id"] == event_id:
                return event
        raise Problem(404, "허용 범위에서 이벤트를 찾을 수 없습니다.", "EVENT_NOT_FOUND")

    def _foreign(self, event):
        """대시보드가 연결된 계정·리전 밖 자원이면 그 이유. 세션은 한 계정·한 리전에만 붙어 있다."""
        region, account = getattr(self.provider, "region", None), getattr(self.provider, "account_id", None)
        if region and event.get("region") and event["region"] != region:
            return f"이 이벤트는 {event['region']} 리전 자원이고 대시보드는 {region} 리전에 연결돼 있어 조치하지 않습니다."
        if event.get("accountId") and account and event["accountId"] != account:
            return "이 이벤트는 연결된 계정과 다른 계정의 것이라 조치하지 않습니다."
        return None

    def _blocker(self, principal, plan):
        """지금 이 사용자가 이 계획을 실행하지 못하는 이유. 없으면 None."""
        if not self.writes_enabled:
            return "현재 조회 전용 모드(WRITE_ENABLED=false)라 실행할 수 없습니다."
        if principal["role"] != "operator":
            return "조치 실행은 조치 담당자(operator) 역할만 할 수 있습니다."
        missing = self.provider.remediation_missing() if hasattr(self.provider, "remediation_missing") else "조치 공급자가 없습니다."
        return missing

    def plan(self, event_id, actor):
        """확인창용 미리보기. 읽기만 한다(현재 상태 확인은 조회 호출)."""
        self.provider.require_ready()
        principal = self.workflow.principal(actor)
        event = self._event(event_id, actor)
        plan = resolve(event, self.project_vpc_id)
        latest = self._refresh(self._visible(self._rows(event_id, limit=5), principal))
        result = {"eventId": event_id, "supported": plan["supported"], "eligible": plan["eligible"], "reason": plan["reason"],
                  "latest": [self.dto(item) for item in latest], "canExecute": False,
                  "canWrite": bool(self.writes_enabled and principal["role"] == "operator"), "blockedReason": None,
                  "blockOverridable": False,
                  "accountId": getattr(self.provider, "account_id", None), "mode": "demo" if getattr(self.provider, "demo", False) else "aws"}
        if not plan["supported"]:
            return result
        result.update({k: plan[k] for k in ("playbookId", "title", "change", "criterion", "parameters", "category", "target")})
        blocker = self._blocker(principal, plan) or self._foreign(event)
        if any(item["state"] in ACTIVE for item in latest):
            blocker = blocker or "이미 실행 중인 조치가 있습니다."
        result["blockedReason"] = blocker
        result["canExecute"] = blocker is None
        # 현재 상태(조치 전 값). 실행 권한이 없어도 읽기만이므로 보여 준다. 읽지 못하면 이유를 함께 알린다.
        if self.provider.remediation_missing() is None and not self._foreign(event):
            try:
                check = self.provider.remediation_precheck(plan)
                result["current"] = check["state"]
                if check["blocked"]:
                    result["canExecute"], result["blockedReason"] = False, check["blocked"]
                    result["blockOverridable"] = bool(check.get("overridable"))
                elif check["state"] and check["state"]["compliant"]:
                    result["alreadyCompliant"] = True
            except Exception as error:  # noqa: BLE001
                result["currentError"] = f"현재 상태를 읽지 못했습니다({_code(error)})."
                result["canExecute"] = False
                result["blockedReason"] = result["blockedReason"] or result["currentError"]
        return result

    def list(self, raw, actor):
        self.provider.require_ready()
        principal = self.workflow.principal(actor)
        event_id = (raw.get("eventId") or [None])[0]
        items = self._refresh(self._visible(self._rows(event_id), principal))
        return {"items": [self.dto(item) for item in items]}

    def history_items(self, q, principal):
        """조치 이력 화면용. 기간(from~to)은 시작 시각 기준, 리전·자원 필터는 조치 이력과 같다."""
        sql = "SELECT * FROM remediations WHERE created_at>=? AND created_at<?"
        args = [q["from"], q["to"]]
        if q.get("eventId"):
            sql += " AND event_id=?"
            args.append(q["eventId"])
        with self.store.connect() as db:
            rows = db.execute(sql + " ORDER BY created_at DESC, id", args).fetchall()
        items = self._visible([self._row(row) for row in rows], principal)
        items = [item for item in items if all(q.get(k) is None or q[k] == item["snapshot"][k]
                                               for k in ("region", "resource"))]
        return [self.dto(item) for item in self._refresh(items)]

    # --- 실행 ---------------------------------------------------------------------------------
    @staticmethod
    def _key(key):
        if not isinstance(key, str) or not 1 <= len(key) <= 200 or not re.fullmatch(r"[\x21-\x7e]+", key):
            raise Problem(400, "유효한 Idempotency-Key가 필요합니다.", "INVALID_IDEMPOTENCY_KEY")

    def _audit(self, actor, event_id, action, detail):
        with self.store.connect(write=True) as db:
            self.store.audit(db, actor, None, action, {"eventId": event_id, **detail})

    def execute(self, event_id, body, actor, key, request_id):
        self.provider.require_ready()
        if not self.writes_enabled:
            raise Problem(403, "현재 조회 전용 모드입니다.", "WRITE_DISABLED")
        if (not isinstance(body, dict) or not {"reason", "playbookId"} <= set(body)
                or not set(body) <= {"reason", "playbookId", "acknowledgeRisk"}
                or not isinstance(body["playbookId"], str) or not isinstance(body["reason"], str)
                or not 1 <= len(body["reason"].strip()) <= 500
                or not isinstance(body.get("acknowledgeRisk", False), bool)):
            raise Problem(400, "reason(1~500자)과 playbookId 가 필요합니다.", "INVALID_PARAMETER")
        self._key(key)
        event = self._event(event_id, actor)
        self.workflow.authorize_event(event, actor, "soar:execute")
        fingerprint = hashlib.sha256(encode([actor, "remediate", event_id, body]).encode()).hexdigest()
        existing = self._by_key(key)
        if existing:
            if existing["actor"] != actor or existing["eventId"] != event_id or existing["fingerprint"] != fingerprint:
                raise Problem(409, "이미 다른 요청에 사용한 Idempotency-Key입니다.", "IDEMPOTENCY_CONFLICT")
            if existing["state"] == "STARTING":       # 시작 응답을 잃은 재시도: 같은 ClientToken 으로 이어 간다
                return self._start(existing, request_id)
            return self.dto(existing), 200
        plan = resolve(event, self.project_vpc_id)
        if not plan["supported"]:
            raise Problem(409, plan["reason"], "REMEDIATION_UNSUPPORTED")
        if plan["playbookId"] != body["playbookId"]:
            raise Problem(409, "이벤트의 조치 계획이 바뀌었습니다. 다시 열어 확인해 주세요.", "PLAN_CHANGED")
        foreign = self._foreign(event)
        if foreign:
            raise Problem(409, foreign, "SCOPE_MISMATCH")
        missing = self.provider.remediation_missing()
        if missing:
            raise Problem(409, missing, "REMEDIATION_NOT_CONFIGURED")
        try:
            check = self.provider.remediation_precheck(plan)
        except Exception as error:  # noqa: BLE001 — 지금 상태를 모르면 실행하지 않는다
            raise Problem(502, "실행 전 대상 상태를 읽지 못해 조치하지 않았습니다.", "PRECHECK_FAILED", detail=_code(error)) from error
        if check["blocked"]:
            # 가용성 위험을 감수하는 차단만, 조작자가 팝업에서 위험을 확인했을 때 넘어간다.
            if not (check.get("overridable") and body.get("acknowledgeRisk")):
                raise Problem(409, check["blocked"], "REMEDIATION_BLOCKED")
            self._audit(actor, event_id, "remediation.override",
                        {"playbookId": plan["playbookId"], "blocked": check["blocked"], "reason": body["reason"].strip()})
            try:   # 차단 시 precheck 는 현재 상태를 재지 않는다 — 조치 전/후 비교를 위해 여기서 읽는다
                check = {**check, "state": self.provider.remediation_measure(plan)}
            except Exception as error:  # noqa: BLE001
                raise Problem(502, "실행 전 대상 상태를 읽지 못해 조치하지 않았습니다.", "PRECHECK_FAILED", detail=_code(error)) from error
        now = now_ms()
        snapshot = {k: event.get(k) for k in ("resource", "region", "accountId", "title", "severity", "controlId")}
        item = {"id": "rem-" + uuid.uuid4().hex[:16], "eventId": event_id, "actor": actor, "requestKey": key,
                "state": "STARTING", "executionId": None, "createdAt": now, "updatedAt": now, "fingerprint": fingerprint,
                "plan": {k: plan[k] for k in ("playbookId", "title", "change", "criterion", "parameters", "target", "category", "needsTag")},
                "reason": body["reason"].strip(), "snapshot": snapshot, "requestId": request_id,
                "before": {"text": check["state"]["text"], "at": iso(now)}, "after": None, "verification": None,
                "error": None, "ssmStatus": None}
        if check["state"]["compliant"]:
            item.update(state="ALREADY_COMPLIANT", verification={"passed": True, "text": check["state"]["text"], "checkedAt": iso(now)},
                        after={"text": check["state"]["text"], "at": iso(now)})
        self._insert(item)
        self._audit(actor, event_id, "remediation-" + ("skipped" if item["state"] == "ALREADY_COMPLIANT" else "start"),
                    {"remediationId": item["id"], "playbookId": plan["playbookId"], "reason": item["reason"], "requestId": request_id})
        if item["state"] == "ALREADY_COMPLIANT":
            return self.dto(item), 200
        return self._start(item, request_id)

    def _insert(self, item):
        payload = {k: v for k, v in item.items() if k not in ("id", "eventId", "actor", "requestKey", "state", "executionId",
                                                              "createdAt", "updatedAt")}
        try:
            with self.store.connect(write=True) as db:
                db.execute("INSERT INTO remediations(id,event_id,actor,request_key,state,execution_id,payload,created_at,updated_at) "
                           "VALUES (?,?,?,?,?,?,?,?,?)", (item["id"], item["eventId"], item["actor"], item["requestKey"], item["state"],
                                                          item["executionId"], encode(payload), item["createdAt"], item["updatedAt"]))
        except Exception as error:  # 같은 이벤트에 실행 중인 조치가 있으면 부분 유일 인덱스가 막는다
            if "UNIQUE" in str(error).upper() or type(error).__name__ == "IntegrityError":
                raise Problem(409, "이 이벤트에는 이미 실행 중인 조치가 있습니다.", "REMEDIATION_IN_PROGRESS") from error
            raise

    def _start(self, item, request_id):
        try:
            execution_id = self.provider.remediation_start(item["plan"], f"{item['eventId']}|{item['requestKey']}")
        except Exception as error:  # noqa: BLE001
            LOG.exception("remediation start failed")
            if _definite(error):
                self._save(item, state="START_FAILED", error=f"SSM 이 실행을 시작하지 않았습니다({_code(error)}). 아무것도 바뀌지 않았습니다.")
                self._audit(item["actor"], item["eventId"], "remediation-start-failed", {"remediationId": item["id"], "code": _code(error)})
                raise Problem(502, "SSM 실행을 시작하지 못했습니다. 대상은 바뀌지 않았습니다.", "REMEDIATION_START_FAILED", detail=_code(error)) from error
            self._save(item, error=f"시작 응답을 받지 못했습니다({type(error).__name__}). 시작 여부를 알 수 없어 같은 요청으로 다시 확인합니다.")
            raise Problem(502, "실행 시작 결과를 확인하지 못했습니다. 같은 창에서 다시 시도하면 중복 실행 없이 이어집니다.",
                          "REMEDIATION_RESULT_UNKNOWN", detail=type(error).__name__) from error
        item = self._save(item, state="RUNNING", executionId=execution_id, error=None, requestId=request_id)
        return self.dto(item), 202

    def recheck(self, remediation_id, actor):
        """재검증만 다시 읽는다(조회). 조치는 다시 실행하지 않는다."""
        self.provider.require_ready()
        principal = self.workflow.principal(actor)
        item = next(iter(self._visible([i for i in [self._get(remediation_id)] if i], principal)), None)
        if item is None:
            raise Problem(404, "조치 기록을 찾을 수 없습니다.", "REMEDIATION_NOT_FOUND")
        if principal["role"] != "operator":
            raise Problem(403, "이 작업을 수행할 권한이 없습니다.", "FORBIDDEN")
        if item["state"] not in RECHECKABLE:
            raise Problem(409, "재검증을 다시 읽을 수 있는 상태가 아닙니다.", "INVALID_STATE")
        return self.dto(self._verify(item))
