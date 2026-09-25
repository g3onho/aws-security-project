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
import boto3

REGION = os.environ["AWS_REGION"]
ACCOUNT_ID = os.environ["ACCOUNT_ID"]
WEB_ACL_ARN = os.environ["WEB_ACL_ARN"]

securityhub = boto3.client("securityhub")

# 알람 이름 끝(-waf-<key>)으로 구분합니다. key 는 soar/cloudwatch.tf local.waf_rules 와 같습니다.
SEVERITY = {"sqli": "HIGH", "common": "MEDIUM", "rate": "MEDIUM"}
TITLE = {
    "sqli": "WAF SQL Injection 차단 급증",
    "common": "WAF 공통 웹 공격 차단 급증",
    "rate": "WAF IP 요청률 제한 차단",
}


def _rfc3339(ts):
    """알람 시각 '2026-09-23T06:10:00.000+0000' -> Security Hub 가 받는 RFC3339."""
    return datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z").isoformat()


def build_finding(detail, account, region, acl_arn):
    alarm = detail["alarmName"]
    key = alarm.rsplit("-waf-", 1)[-1]
    state = detail["state"]
    at = _rfc3339(state["timestamp"])
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
    }


def handler(event, _context):
    finding = build_finding(event.get("detail", {}), ACCOUNT_ID, REGION, WEB_ACL_ARN)
    resp = securityhub.batch_import_findings(Findings=[finding])
    print(json.dumps({"imported": finding["Id"], "failed": resp.get("FailedCount", 0),
                      "errors": resp.get("FailedFindings", [])}, ensure_ascii=False))
    return {"statusCode": 200, "failed": resp.get("FailedCount", 0)}
