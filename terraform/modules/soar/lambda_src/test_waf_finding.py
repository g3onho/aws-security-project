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
sys.modules.pop("handler", None)
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


class _FakeWafv2:
    """get_sampled_requests 스텁."""

    def __init__(self, samples):
        self.samples = samples
        self.called_with = None

    def get_sampled_requests(self, **kwargs):
        self.called_with = kwargs
        return {"SampledRequests": self.samples}


def _with_samples(samples, detail=DETAIL):
    real = handler.wafv2
    handler.wafv2 = _FakeWafv2(samples)
    try:
        return _build(detail), handler.wafv2
    finally:
        handler.wafv2 = real


ORIGIN = "aws/waf/service/action/webRequestAction/remoteIpDetails"


def test_top_blocked_ip_becomes_origin():
    finding, fake = _with_samples([
        {"Action": "ALLOW", "Weight": 9, "Request": {"ClientIP": "10.0.0.9", "Country": "KR"}},
        {"Action": "BLOCK", "Weight": 1, "Request": {"ClientIP": "1.2.3.4", "Country": "KR"}},
        {"Action": "BLOCK", "Weight": 5, "Request": {"ClientIP": "54.89.137.202", "Country": "US"}},
    ])
    fields = finding["ProductFields"]
    # 가장 많이 차단된 IP 가 출발지가 된다(ALLOW 는 세지 않는다).
    assert fields[f"{ORIGIN}/ipAddressV4"] == "54.89.137.202", fields
    assert fields[f"{ORIGIN}/geoLocation/lat"] == "37.09", fields
    assert fake.called_with["RuleMetricName"] == "SQLiRuleSet"


def test_origin_matches_dashboard_parser():
    """대시보드 remote_ip() 가 실제로 읽어내는지 — 키 모양이 틀어지면 선이 조용히 사라진다."""
    backend = Path(__file__).resolve().parents[4] / "dashboard" / "backend"
    if not (backend / "soar" / "repositories" / "findings.py").exists():
        print("  (skip) dashboard/backend 없음")
        return
    sys.path.insert(0, str(backend))
    from soar.repositories.findings import remote_ip

    finding, _ = _with_samples(
        [{"Action": "BLOCK", "Weight": 2, "Request": {"ClientIP": "54.89.137.202", "Country": "US"}}])
    parsed = remote_ip(finding["ProductFields"])
    assert parsed["sourceIp"] == "54.89.137.202", parsed
    assert parsed["sourceLocation"]["lat"] == 37.09, parsed
    assert parsed["geoStatus"] == "located", parsed


def test_unknown_country_has_ip_but_no_line():
    # 좌표를 모르면 IP 만 남긴다 — 지도는 좌표 없는 흐름을 '위치 미상'으로 세고 선을 안 그린다.
    finding, _ = _with_samples(
        [{"Action": "BLOCK", "Weight": 1, "Request": {"ClientIP": "8.8.8.8", "Country": "ZZ"}}])
    fields = finding["ProductFields"]
    assert fields[f"{ORIGIN}/ipAddressV4"] == "8.8.8.8", fields
    assert not any(k.endswith("/geoLocation/lat") for k in fields), fields


def test_sampling_failure_still_imports_finding():
    class _Boom:
        def get_sampled_requests(self, **kwargs):
            raise RuntimeError("AccessDenied")

    real, handler.wafv2 = handler.wafv2, _Boom()
    try:
        finding = _build()
    finally:
        handler.wafv2 = real
    assert "ProductFields" not in finding, finding
    assert finding["Title"]  # 출발지를 못 구해도 finding 자체는 그대로 올라간다


if __name__ == "__main__":
    test_rfc3339()
    test_severity_by_alarm_suffix()
    test_no_compliance_so_asr_trigger_ignores_it()
    test_same_alarm_transition_same_id()
    test_product_arn_is_account_default()
    test_top_blocked_ip_becomes_origin()
    test_origin_matches_dashboard_parser()
    test_unknown_country_has_ip_but_no_line()
    test_sampling_failure_still_imports_finding()
    print("ok - waf_finding 9건 통과")
