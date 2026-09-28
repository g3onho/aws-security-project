"""
waf_finding — WAF 차단 알람(ALARM)을 Security Hub finding 으로 가져옵니다. (SEC-08)
트리거: CloudWatch Alarm State Change (EventBridge ④)  /  소비자: Flask 대시보드

대시보드는 Security Hub finding 만 이벤트로 읽습니다. 알람만으로는 화면에 뜨지 않아
이 함수가 계정 자체 제품(default)으로 finding 을 만듭니다.

Compliance 필드를 넣지 않습니다. sh_to_asr 규칙은 Compliance.Status 가 있는 finding 만
받으므로, 이 finding 은 asr_trigger(자동조치 판단)와 SNS 알림을 다시 타지 않습니다.
"""
import os
import json
import datetime
import collections
import boto3

REGION = os.environ["AWS_REGION"]
ACCOUNT_ID = os.environ["ACCOUNT_ID"]
WEB_ACL_ARN = os.environ["WEB_ACL_ARN"]

securityhub = boto3.client("securityhub")
wafv2 = boto3.client("wafv2")

# 알람 이름 끝(-waf-<key>)으로 구분합니다. key 는 soar/cloudwatch.tf local.waf_rules 와 같습니다.
SEVERITY = {"sqli": "HIGH", "common": "MEDIUM", "rate": "MEDIUM"}
TITLE = {
    "sqli": "WAF SQL Injection 차단 급증",
    "common": "WAF 공통 웹 공격 차단 급증",
    "rate": "WAF IP 요청률 제한 차단",
}
# get_sampled_requests 가 받는 룰 지표 이름. soar/cloudwatch.tf local.waf_rules 값과 같아야 합니다.
RULE_METRIC = {"sqli": "SQLiRuleSet", "common": "CommonRuleSet", "rate": "RateLimitPerIp"}

# 국가 중심 좌표. 샘플 요청은 2글자 국가코드까지만 주므로 도시 단위 정밀도는 없습니다.
# ponytail: 주요국만. 없는 국가는 좌표 없이(선 없이) 들어갑니다 — 필요하면 GeoIP 조회로 교체.
COUNTRY_GEO = {
    "US": (37.09, -95.71, "United States"), "KR": (35.91, 127.77, "South Korea"),
    "JP": (36.20, 138.25, "Japan"), "CN": (35.86, 104.20, "China"),
    "RU": (61.52, 105.32, "Russia"), "DE": (51.17, 10.45, "Germany"),
    "GB": (55.38, -3.44, "United Kingdom"), "FR": (46.23, 2.21, "France"),
    "NL": (52.13, 5.29, "Netherlands"), "SG": (1.35, 103.82, "Singapore"),
    "IN": (20.59, 78.96, "India"), "BR": (-14.24, -51.93, "Brazil"),
    "CA": (56.13, -106.35, "Canada"), "AU": (-25.27, 133.78, "Australia"),
    "VN": (14.06, 108.28, "Vietnam"), "ID": (-0.79, 113.92, "Indonesia"),
    "HK": (22.32, 114.17, "Hong Kong"), "TW": (23.70, 120.96, "Taiwan"),
    "IE": (53.41, -8.24, "Ireland"), "SE": (60.13, 18.64, "Sweden"),
}


def top_blocked_source(key, end_time):
    """알람 직전 1분간 가장 많이 차단된 클라이언트 IP — 지도 공격 흐름선의 출발지.

    WAF finding 은 CloudWatch 알람(건수 임계치)에서 만들어져 공격자 IP 가 없었다. 그래서
    통합 관제 지도에 WAF 웹 공격이 선으로 뜨지 않았다. 여기서 샘플 요청(alb.tf 의 룰마다
    sampled_requests_enabled = true)을 읽어 가장 잦은 차단 IP 를 출발지로 붙인다.
    실패해도 finding 자체는 그대로 올라가야 하므로 예외는 삼킨다.
    """
    metric = RULE_METRIC.get(key)
    if not metric:
        return None
    try:
        sampled = wafv2.get_sampled_requests(
            WebAclArn=WEB_ACL_ARN, RuleMetricName=metric, Scope="REGIONAL",
            TimeWindow={"StartTime": end_time - datetime.timedelta(minutes=1), "EndTime": end_time},
            MaxItems=500,
        )["SampledRequests"]
    except Exception as exc:  # 권한·윈도우 범위 등 — 출발지만 비우고 계속한다.
        print(json.dumps({"sampled_requests_failed": str(exc)}))
        return None
    counts = collections.Counter()
    for item in sampled:
        if item.get("Action") != "BLOCK":
            continue
        request = item.get("Request") or {}
        ip = request.get("ClientIP")
        if ip:
            counts[(ip, request.get("Country") or "")] += int(item.get("Weight") or 1)
    if not counts:
        return None
    (ip, country), _ = counts.most_common(1)[0]
    return {"ip": ip, "country": country}


def origin_fields(source):
    """출발지를 대시보드가 이미 읽는 모양으로 넣는다.

    dashboard/backend/soar/repositories/findings.py remote_ip() 는 키에 'remoteIpDetails' 가
    들어있고 꼬리가 아래와 같은 ProductFields 를 찾는다. GuardDuty 와 같은 모양이라 백엔드
    수정 없이 그대로 지도 선이 된다.
    """
    if not source:
        return {}
    prefix = "aws/waf/service/action/webRequestAction/remoteIpDetails"
    fields = {f"{prefix}/ipAddressV4": source["ip"]}
    geo = COUNTRY_GEO.get((source.get("country") or "").upper())
    if geo:
        lat, lon, name = geo
        fields[f"{prefix}/country/countryName"] = name
        fields[f"{prefix}/city/cityName"] = name
        fields[f"{prefix}/geoLocation/lat"] = str(lat)
        fields[f"{prefix}/geoLocation/lon"] = str(lon)
    return fields


def _rfc3339(ts):
    """알람 시각 '2026-09-23T06:10:00.000+0000' -> Security Hub 가 받는 RFC3339."""
    return datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z").isoformat()


def build_finding(detail, account, region, acl_arn):
    alarm = detail["alarmName"]
    key = alarm.rsplit("-waf-", 1)[-1]
    state = detail["state"]
    at = _rfc3339(state["timestamp"])
    origin = origin_fields(top_blocked_source(key, datetime.datetime.fromisoformat(at)))
    return {
        "SchemaVersion": "2018-10-08",
        # 같은 ALARM 전환은 같은 Id -> 재시도해도 중복 없이 덮어씁니다.
        "Id": f"{alarm}/{state['timestamp']}",
        "ProductArn": f"arn:aws:securityhub:{region}:{account}:product/{account}/default",
        "GeneratorId": "soar-waf-alarm",
        "AwsAccountId": account,
        "Types": ["TTPs/Initial Access/Web Application Attack"],
        "CreatedAt": at,
        "UpdatedAt": at,
        "Severity": {"Label": SEVERITY.get(key, "MEDIUM")},
        "Title": TITLE.get(key, "WAF 차단 급증"),
        "Description": (state.get("reason") or "WAF blocked requests exceeded threshold")[:1024],
        "Resources": [{"Type": "AwsWafv2WebAcl", "Id": acl_arn, "Region": region}],
        **({"ProductFields": origin} if origin else {}),
    }


def handler(event, _context):
    finding = build_finding(event.get("detail", {}), ACCOUNT_ID, REGION, WEB_ACL_ARN)
    resp = securityhub.batch_import_findings(Findings=[finding])
    print(json.dumps({"imported": finding["Id"], "failed": resp.get("FailedCount", 0),
                      "errors": resp.get("FailedFindings", [])}, ensure_ascii=False))
    return {"statusCode": 200, "failed": resp.get("FailedCount", 0)}
