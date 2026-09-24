"""CloudWatch GetMetricData."""


def get_metric_data(session, queries, start, end):
    return session.client("cloudwatch").get_metric_data(MetricDataQueries=queries, StartTime=start, EndTime=end)
