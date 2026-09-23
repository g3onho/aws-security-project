"""waf_finding.build_finding 검증.

lambda_src/ 바로 아래에 둡니다. archive_file 은 waf_finding/ 하위만 압축하므로
이 파일은 Lambda zip 에 들어가지 않습니다.

    python modules/soar/lambda_src/test_waf_finding.py
"""
import os
import sys
from pathlib import Path

# handler 는 import 시점에 환경변수를 읽습니다.
os.environ.setdefault("AWS_REGION", "ap-northeast-2")
for k in ("ACCOUNT_ID", "WEB_ACL_ARN"):
    os.environ.setdefault(k, "test")

sys.path.insert(0, str(Path(__file__).parent / "waf_finding"))
import handler  # noqa: E402

ACL = "arn:aws:wafv2:ap-northeast-2:111122223333:regional/webacl/soar-sec-dev-web-acl/abc"
DETAIL = {
    "alarmName": "soar-sec-dev-waf-sqli",
    "state": {"value": "ALARM", "timestamp": "2026-09-23T06:10:00.123+0000",
              "reason": "Threshold Crossed: 1 datapoint [42.0] >= 10.0"},
}


def _build(detail=DETAIL):
    return handler.build_finding(detail, "111122223333", "ap-northeast-2", ACL)


def test_rfc3339():
    f = _build()
    # Security Hub 는 '+0000' 을 거부합니다. '+00:00' 이어야 합니다.
    assert f["CreatedAt"] == "2026-09-23T06:10:00.123000+00:00", f["CreatedAt"]


def test_severity_by_alarm_suffix():
    assert _build()["Severity"]["Label"] == "HIGH"
    rate = dict(DETAIL, alarmName="soar-sec-dev-waf-rate")
    assert _build(rate)["Severity"]["Label"] == "MEDIUM"


def test_no_compliance_so_asr_trigger_ignores_it():
    # sh_to_asr 는 Compliance.Status 가 있는 finding 만 받습니다.
    assert "Compliance" not in _build()


def test_same_alarm_transition_same_id():
    assert _build()["Id"] == _build()["Id"]


def test_product_arn_is_account_default():
    assert _build()["ProductArn"].endswith(":product/111122223333/default")


if __name__ == "__main__":
    test_rfc3339()
    test_severity_by_alarm_suffix()
    test_no_compliance_so_asr_trigger_ignores_it()
    test_same_alarm_transition_same_id()
    test_product_arn_is_account_default()
    print("ok - waf_finding 5건 통과")
