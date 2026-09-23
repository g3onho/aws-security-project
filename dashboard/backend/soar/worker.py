"""Durable job runner; results must come from the configured execution provider."""
import json
import logging
import math
import threading
import uuid

from .store import encode, now_ms
from .domain import public_event
from .workflow import Workflow

LOG = logging.getLogger(__name__)


class Worker:
    def __init__(self, store, provider, lease_seconds=30):
        self.store = store
        self.provider = provider
        self.lease_ms = int(lease_seconds * 1000)
        self._stop = threading.Event()
        self._thread = None

    def _claim(self):
        timestamp = now_ms()
        with self.store.connect(write=True) as db:
            db.execute("INSERT INTO metadata VALUES ('worker_heartbeat',?) "
                       "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(timestamp),))
            job = db.execute("SELECT * FROM jobs WHERE state='QUEUED' OR "
                             "(state='RUNNING' AND lease_until < ?) ORDER BY created_at,id LIMIT 1",
                             (timestamp,)).fetchone()
            if job is None:
                return None
            token = str(uuid.uuid4())
            db.execute("UPDATE jobs SET state='RUNNING',lease_until=?,lease_token=?,updated_at=? WHERE id=?",
                       (timestamp + self.lease_ms, token, timestamp, job["id"]))
            event = self.store.event(db, job["event_id"])
            event.update(actionState="RUNNING" if job["kind"] == "execute" else "VERIFYING",
                         version=event["version"] + 1, updatedAt=timestamp)
            self.store.save_event(db, event)
            return {**dict(job), "lease_token": token, "payload": json.loads(job["payload"])}

    def run_once(self):
        self.provider.require_ready()
        job = self._claim()
        if job is None:
            return False
        try:
            event = job["payload"]["event"]
            Workflow(self.store, self.provider).authorize_event(event, job["payload"]["actor"], "soar:" + job["kind"])
            result = (self.provider.execution_result(event) if job["kind"] == "execute"
                      else self.provider.measure(event))
            if not isinstance(result, dict):
                raise ValueError("Provider result must be an object")
            if not result.get("source") or not result.get("evidenceId"):
                raise ValueError("Provider results require a source and evidence identifier")
            if job["kind"] == "execute" and result.get("status") != "SUCCEEDED":
                raise ValueError("Execution completion must be confirmed by the provider")
            if job["kind"] == "verify":
                # Missing evidence cannot become a pass through truthy/coerced values.
                value = result.get("value")
                if (type(result.get("passed")) is not bool or type(value) not in {int, float}
                        or not math.isfinite(value) or value < 0):
                    raise ValueError("Verification needs a measured value and explicit pass/fail")
                if result.get("unit") != event["unit"] or not result.get("source"):
                    raise ValueError("Verification tool or units changed")
                if result.get("criterionVersion") != event.get("criterionVersion"):
                    raise ValueError("Verification criterion changed")
            self._finish(job, result)
        except Exception:
            LOG.exception("Provider job %s failed", job["id"])
            self._finish(job, {"error": "연결된 공급자의 작업 처리 실패"}, failed=True)
        return True

    def _finish(self, job, result, failed=False):
        timestamp = now_ms()
        with self.store.connect(write=True) as db:
            current = db.execute("SELECT * FROM jobs WHERE id=?", (job["id"],)).fetchone()
            if current["state"] != "RUNNING" or current["lease_token"] != job["lease_token"]:
                return  # Another worker reclaimed the expired lease; do not overwrite its result.
            event = self.store.event(db, job["event_id"])
            if event.get("activeExecutionId") != job["id"]:
                raise RuntimeError("Job no longer belongs to the active event transition")
            event["activeExecutionId"] = None
            if failed:
                event["status"] = "EXECUTION_FAILED" if job["kind"] == "execute" else "VERIFICATION_FAILED"
                event["actionState"] = "EXECUTION_FAILED" if job["kind"] == "execute" else "VERIFICATION_ERROR"
                event["execution" if job["kind"] == "execute" else "verification"] = "FAILED"
                text = "작업 실패. 감사 기록을 확인해주세요."
            elif job["kind"] == "execute":
                event.update(status="PENDING_VERIFICATION", actionState="EXECUTED", execution="SUCCEEDED", verification="NOT_RUN",
                             _executedPlanHash=job["payload"]["planHash"])
                text = "조치 완료. 동일 기준 재검증 필요"
            else:
                passed = result["passed"]
                result = {**result, "at": timestamp}
                event.update(status="RESOLVED" if passed else "VERIFICATION_FAILED",
                             actionState="VERIFIED" if passed else "VERIFICATION_FAILED",
                             verification="PASSED" if passed else "FAILED",
                             afterValue=result["value"], afterAt=result.get("at", timestamp),
                             after={**result, "resource": event["resource"],
                                    "criterionVersion": event["criterionVersion"]})
                text = "동일 기준 재검증 통과" if passed else "재검증 실패: 잔여 위험 존재"
            Workflow._history(event, timestamp, text, "completed" if job["kind"] == "execute" else "verified")
            event.update(version=event["version"] + 1, updatedAt=timestamp)
            self.store.save_event(db, event)
            db.execute("UPDATE jobs SET state=?,result=?,updated_at=?,lease_until=0 WHERE id=?",
                       ("FAILED" if failed else "SUCCEEDED", encode(result), timestamp, job["id"]))
            self.store.audit(db, job["payload"]["actor"], job["event_id"], job["kind"] + "-completed", {
                "executionId": job["id"], "status": event["status"], "result": result,
                "jobId": job["id"], "requestId": job["payload"].get("requestId"), "event": public_event(event),
            })

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="dashboard-worker", daemon=True)
        self._thread.start()

    def _loop(self):
        while not self._stop.is_set():
            try:
                worked = self.run_once()
            except Exception:
                LOG.exception("Local worker iteration failed")
                worked = False
            self._stop.wait(0.02 if worked else 0.5)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def health(self):
        with self.store.connect() as db:
            row = db.execute("SELECT value FROM metadata WHERE key='worker_heartbeat'").fetchone()
        return "ok" if row and now_ms() - int(row[0]) < 10000 else "stopped"
