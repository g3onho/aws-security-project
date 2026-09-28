"""SSM Automation 실행 결과 조회(GetAutomationExecution) + 캐시.

자동 조치 기록(DynamoDB)에는 실행 ID·상태만 있고, 조치 전/후 값은 SSM 문서 단계 출력(before·after)에 있다.
끝난 실행은 결과가 바뀌지 않으므로 프로세스가 살아 있는 동안 캐시하고, 진행 중이면 짧게 캐시한다.
실행 기록이 없으면(보존 기간이 지나 지워짐) None 을 잠시 캐시한다.
"""
import threading
import time

from botocore.exceptions import ClientError

from .paging import to_ms

TERMINAL = {"Success", "Failed", "TimedOut", "Cancelled", "CompletedWithSuccess", "CompletedWithFailure", "Rejected"}


def _step(step):
    return {"name": step.get("StepName"), "action": step.get("Action"), "status": step.get("StepStatus"),
            "outputs": {key: [str(v) for v in values] for key, values in (step.get("Outputs") or {}).items()},
            "failureMessage": step.get("FailureMessage")}


class AutomationExecutions:
    RUNNING_TTL = 15
    MISSING_TTL = 600
    MAX_ENTRIES = 1000

    def __init__(self, session):
        self._session = session
        self._lock = threading.Lock()
        self._cache = {}

    def get(self, execution_id, fetch=True):
        """(found, 실행 요약|None). fetch=False 면 캐시만 본다(요청당 조회 수 제한용).
        found=False 는 '아직 안 읽음', (True, None) 은 '실행 기록 없음'."""
        now = time.monotonic()
        with self._lock:
            hit = self._cache.get(execution_id)
            if hit and (hit[0] is None or now < hit[0]):
                return True, hit[1]
        if not fetch:
            return False, None
        try:
            raw = self._session.client("ssm").get_automation_execution(
                AutomationExecutionId=execution_id)["AutomationExecution"]
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") != "AutomationExecutionNotFoundException":
                raise
            self._put(execution_id, None, now + self.MISSING_TTL)
            return True, None
        status = raw.get("AutomationExecutionStatus")
        value = {"status": status, "document": raw.get("DocumentName"),
                 "failureMessage": raw.get("FailureMessage"),
                 "startedAt": to_ms(raw["ExecutionStartTime"]) if raw.get("ExecutionStartTime") else None,
                 "endedAt": to_ms(raw["ExecutionEndTime"]) if raw.get("ExecutionEndTime") else None,
                 "steps": [_step(step) for step in raw.get("StepExecutions") or []]}
        self._put(execution_id, value, None if status in TERMINAL else now + self.RUNNING_TTL)
        return True, value

    def _put(self, key, value, expires):
        with self._lock:
            if len(self._cache) >= self.MAX_ENTRIES:
                self._cache.pop(next(iter(self._cache)))  # 가장 먼저 넣은 것부터
            self._cache[key] = (expires, value)
