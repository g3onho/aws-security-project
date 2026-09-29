"""허니팟 원천 조회: 세션 로그(CloudWatch Logs), 미끼 인스턴스(EC2), 탐지 알람(CloudWatch).

읽기 전용이다. 원본 행을 그대로 돌려주고 해석은 repositories/honeypot.py 가 한다.
실패는 예외로 올린다 — 서비스가 "읽지 못함(unknown)"으로 표시하며, 빈 목록으로 바꾸지 않는다.
"""
import threading
import time

from .paging import to_ms


class HoneypotSources:
    MAX_EVENTS = 20000   # 창 하나에서 읽는 로그 행 상한(넘으면 truncated)
    MAX_PAGES = 200
    TTL = 20             # 자동 새로고침·여러 화면 요청이 겹쳐도 같은 창은 이 시간 안에 한 번만 읽는다
    CACHE_ENTRIES = 8

    def __init__(self, session, log_group, alarm_name=None):
        self._session = session
        self.log_group = log_group
        self.alarm_name = alarm_name or None
        self._lock = threading.Lock()
        self._cache = {}

    def events(self, start_ms, end_ms):
        """(원본 로그 행 목록, truncated). 창은 분 단위로 맞춰 캐시한다."""
        key = (start_ms // 60000, end_ms // 60000)
        with self._lock:
            hit = self._cache.get(key)
            if hit and time.monotonic() - hit[0] < self.TTL:
                return hit[1]
            client = self._session.client("logs")
            rows, token, truncated = [], None, False
            for _ in range(self.MAX_PAGES):
                kwargs = {"logGroupName": self.log_group, "startTime": start_ms, "endTime": end_ms}
                if token:
                    kwargs["nextToken"] = token
                page = client.filter_log_events(**kwargs)
                rows.extend({"timestamp": e.get("timestamp"), "logStreamName": e.get("logStreamName"),
                             "message": e.get("message")} for e in page.get("events", []))
                token = page.get("nextToken")
                if len(rows) >= self.MAX_EVENTS:
                    rows, truncated = rows[:self.MAX_EVENTS], bool(token) or len(rows) > self.MAX_EVENTS
                    break
                if not token:
                    break
            else:
                truncated = True  # 페이지 상한에서 멈췄다
            if len(self._cache) >= self.CACHE_ENTRIES:
                self._cache.pop(next(iter(self._cache)))
            self._cache[key] = (time.monotonic(), (rows, truncated))
            return rows, truncated

    def instances(self):
        """태그 Scenario=HONEYPOT 인 인스턴스(종료됨 제외) → [{id, state, privateIp, launchedAt}]."""
        found = self._session.client("ec2").describe_instances(Filters=[
            {"Name": "tag:Scenario", "Values": ["HONEYPOT"]},
            {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]}])
        return [{"id": i.get("InstanceId"), "state": (i.get("State") or {}).get("Name"),
                 "privateIp": i.get("PrivateIpAddress"),
                 "launchedAt": to_ms(i["LaunchTime"]) if i.get("LaunchTime") else None}
                for r in found.get("Reservations", []) for i in r.get("Instances", [])]

    def alarm(self):
        """탐지 알람 상태. 알람이 없으면 None."""
        if not self.alarm_name:
            return None
        alarms = self._session.client("cloudwatch").describe_alarms(
            AlarmNames=[self.alarm_name], AlarmTypes=["MetricAlarm"]).get("MetricAlarms", [])
        if not alarms:
            return None
        a = alarms[0]
        return {"name": a.get("AlarmName"), "state": a.get("StateValue"),
                "updatedAt": to_ms(a["StateUpdatedTimestamp"]) if a.get("StateUpdatedTimestamp") else None,
                "actionsEnabled": a.get("ActionsEnabled")}

    def alarm_transitions(self, start_ms, end_ms):
        """알람 상태 전이 기록 → [{at, to}] (최근순). 시각은 ms."""
        if not self.alarm_name:
            return []
        from datetime import datetime, timezone
        items = self._session.client("cloudwatch").describe_alarm_history(
            AlarmName=self.alarm_name, HistoryItemType="StateUpdate", MaxRecords=100,
            StartDate=datetime.fromtimestamp(start_ms / 1000, timezone.utc),
            EndDate=datetime.fromtimestamp(end_ms / 1000, timezone.utc)).get("AlarmHistoryItems", [])
        out = []
        for item in items:
            summary = item.get("HistorySummary") or ""
            target = "ALARM" if "to ALARM" in summary else "OK" if "to OK" in summary else (
                "INSUFFICIENT_DATA" if "to INSUFFICIENT_DATA" in summary else None)
            if target and item.get("Timestamp"):
                out.append({"at": to_ms(item["Timestamp"]), "to": target})
        return out
