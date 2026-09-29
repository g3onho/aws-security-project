"""CloudWatch 지표 알람(DescribeAlarms) → 인프라 모니터링 경보 상태.

알람 이름은 Terraform modules/soar 가 정한다: <prefix>-<호스트>-cpu-high · -mem-high · mysql-bruteforce ·
ssh-reject · waf-<규칙> · finding-sync-errors · finding-sync-dlq.
treat_missing_data = notBreaching 인 알람은 로그·지표가 전혀 안 들어와도 OK 로 보인다 — 이유(StateReason)로
'데이터 없음'을 따로 표시한다(확인 불가를 정상으로 보이지 않게).
"""
from ..integrations.aws.paging import to_ms

NO_DATA_MARKERS = ("no datapoints were received", "treated as [nonbreaching]")
# 계속 들어와야 하는 지표(EC2 CPU·Agent 메모리)만 데이터 없음을 '확인 필요'로 본다.
# 공격·오류 같은 사건이 있어야 지표가 생기는 알람은 데이터 없음이 평소 상태다.
CONTINUOUS_KINDS = ("cpu", "memory")


def _kind(short):
    if short.endswith("-cpu-high"):
        host = short[:-len("-cpu-high")]
        return "cpu", "SEC-10", f"CPU 사용률 높음 · {host}", host
    if short.endswith("-mem-high"):
        host = short[:-len("-mem-high")]
        return "memory", "SEC-10", f"메모리 사용률 높음 · {host}", host
    if short == "mysql-bruteforce":
        return "mysql-bruteforce", "SEC-06A", "MySQL 로그인 실패 급증", None
    if short == "ssh-reject":
        return "ssh-reject", "SEC-06B", "SSH(22) 접속 거부 급증 (Flow Logs)", None
    if short.startswith("waf-"):
        return "waf", "SEC-08", f"WAF 차단 급증 · {short[4:]}", None
    if short.startswith("finding-sync-"):
        return "pipeline", None, "탐지 적재(finding_sync) " + ("오류" if short.endswith("errors") else "실패 대기열(DLQ)"), None
    return "other", None, short, None


def _auto_response(kind, policy):
    token = {"mysql-bruteforce": "SEC-06A", "ssh-reject": "SEC-06B"}.get(kind)
    if not token or policy is None or not policy.configured:
        return None
    if token not in policy.controls:
        return {"mode": "manual", "label": "알림만", "detail": f"{token} 가 자동 조치 목록에 없어 알림만 보냅니다."}
    if not policy.enabled:
        return {"mode": "dry-run", "label": "판단만(dry-run)", "detail": "공격 IP 를 찾아 기록만 하고 차단하지 않습니다."}
    return {"mode": "auto", "label": "공격 IP 자동 차단",
            "detail": "ALARM 이 되면 로그에서 최다 출발지 IP 를 찾아 Private NACL(1~99번)에 Deny 를 추가합니다."}


def normalize(alarm, prefix, region, account_id, policy=None):
    name = str(alarm.get("AlarmName") or "")
    short = name[len(prefix) + 1:] if prefix and name.startswith(prefix + "-") else name
    kind, scenario, label, host = _kind(short)
    dimensions = {d.get("Name"): d.get("Value") for d in alarm.get("Dimensions") or []}
    reason = str(alarm.get("StateReason") or "")
    state = alarm.get("StateValue") or "INSUFFICIENT_DATA"
    no_data = state == "OK" and any(m in reason.lower() for m in NO_DATA_MARKERS)
    needs_check = state == "INSUFFICIENT_DATA" or (no_data and kind in CONTINUOUS_KINDS)
    return {"name": name, "label": label, "kind": kind, "scenario": scenario, "host": host,
            "state": state, "noData": no_data, "needsCheck": needs_check,
            "reason": reason[:300] or None,
            "updatedAt": to_ms(alarm["StateUpdatedTimestamp"]) if alarm.get("StateUpdatedTimestamp") else None,
            "metric": alarm.get("MetricName"), "namespace": alarm.get("Namespace"),
            "threshold": alarm.get("Threshold"), "comparison": alarm.get("ComparisonOperator"),
            "periodSeconds": alarm.get("Period"), "evaluationPeriods": alarm.get("EvaluationPeriods"),
            "notifies": bool(alarm.get("AlarmActions")), "autoResponse": _auto_response(kind, policy),
            "resource": dimensions.get("InstanceId"), "region": region, "accountId": account_id}


ORDER = {"ALARM": 0, "INSUFFICIENT_DATA": 1, "OK": 2}


class AlarmRepository:
    def __init__(self, alarms, region, account_id, policy=None):
        self._alarms = alarms
        self._region = region
        self._account_id = account_id
        self._policy = policy

    def list(self):
        rows = [normalize(alarm, self._alarms.prefix, self._region, self._account_id, self._policy)
                for alarm in self._alarms.list()]
        rows.sort(key=lambda row: (ORDER.get(row["state"], 3), row["noData"], row["name"]))
        return {"items": rows, "configured": True}
