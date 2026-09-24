"""CloudWatch CPU·메모리 → 시각별 병합 시계열."""
import os
from datetime import datetime, timezone

from ..integrations.aws.cloudwatch import get_metric_data


class MetricRepository:
    def __init__(self, session, clock):
        self._session = session
        self._clock = clock

    def metric_for(self, resource, query=None):
        query = query or {}
        now = self._clock()
        start = datetime.fromtimestamp(int(query.get("from", now - 86400000)) / 1000, tz=timezone.utc)
        end = datetime.fromtimestamp(int(query.get("to", now)) / 1000, tz=timezone.utc)
        period = int(query.get("periodSeconds", 300))
        dims = [{"Name": "InstanceId", "Value": resource["id"]}]
        queries = [{"Id": "cpu", "MetricStat": {"Metric": {"Namespace": "AWS/EC2", "MetricName": "CPUUtilization", "Dimensions": dims}, "Period": period, "Stat": "Average"}, "ReturnData": True}]
        # 메모리는 CloudWatch Agent 가 <NAME_PREFIX>/host 에 올린다(에이전트 없는 호스트는 비어 있음).
        if os.getenv("NAME_PREFIX"):
            queries.append({"Id": "memory", "MetricStat": {"Metric": {"Namespace": os.environ["NAME_PREFIX"] + "/host", "MetricName": "MemoryUsedPercent", "Dimensions": dims}, "Period": period, "Stat": "Average"}, "ReturnData": True})
        response = get_metric_data(self._session, queries, start, end)
        by_at = {}
        for result in response.get("MetricDataResults") or []:
            metric = result.get("Id", "cpu")
            for ts, value in zip(result.get("Timestamps", []), result.get("Values", [])):
                point = by_at.setdefault(int(ts.timestamp() * 1000), {"cpu": None, "memory": None})
                point[metric] = round(value, 1)  # 화면에 1.0388888888888888% 로 찍히지 않게
        return {"period": period, "points": [{"at": at, **values} for at, values in sorted(by_at.items())]}
