"""CloudWatch GetMetricData · DescribeAlarms. GetMetricData 는 모든 페이지를 받아 시계열 누락을 막는다."""
import threading
import time

from .paging import collect


def get_metric_data(session, queries, start, end):
    client = session.client("cloudwatch")
    results = {}
    token = None
    while True:
        args = {"MetricDataQueries": queries, "StartTime": start, "EndTime": end}
        if token:
            args["NextToken"] = token
        page = client.get_metric_data(**args)
        for item in page.get("MetricDataResults", []):
            if item.get("StatusCode") not in (None, "Complete") and not (item.get("StatusCode") == "PartialData" and page.get("NextToken")):
                raise RuntimeError("CloudWatch returned incomplete metric data")
            identifier = item.get("Id", "cpu")
            result = results.setdefault(identifier, {"Id": identifier, "Timestamps": [], "Values": []})
            result["Timestamps"].extend(item.get("Timestamps", []))
            result["Values"].extend(item.get("Values", []))
        token = page.get("NextToken")
        if not token:
            return {"MetricDataResults": list(results.values())}


class Alarms:
    """이름 접두어(NAME_PREFIX-)로 프로젝트 지표 알람 상태를 읽는다. 화면 여러 API·자동 새로고침이 겹쳐도
    DescribeAlarms 는 TTL 에 한 번."""
    TTL = 30

    def __init__(self, session, prefix):
        self._session = session
        self.prefix = prefix
        self._lock = threading.Lock()
        self._hit = None

    def list(self):
        with self._lock:
            if self._hit and time.monotonic() - self._hit[0] < self.TTL:
                return self._hit[1]
            alarms = collect(self._session.client("cloudwatch"), "describe_alarms", "MetricAlarms",
                             AlarmNamePrefix=self.prefix + "-", AlarmTypes=["MetricAlarm"])
            self._hit = (time.monotonic(), alarms)
            return alarms
