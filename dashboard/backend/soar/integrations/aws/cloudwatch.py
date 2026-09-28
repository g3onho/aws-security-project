"""CloudWatch GetMetricData. 모든 페이지를 받아 시계열 누락을 막는다."""


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
