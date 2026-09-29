"""_parse_finding 의 finding_id 추출 검증.

lambda_src/ 바로 아래에 둡니다. archive_file 은 asr_trigger/ 하위만 압축하므로
이 파일은 Lambda zip 에 들어가지 않습니다.

    python modules/soar/lambda_src/test_parse_finding.py
"""
import os
import sys
from pathlib import Path

# handler 는 import 시점에 환경변수를 읽습니다.
os.environ.setdefault("AWS_REGION", "ap-northeast-2")
for k in ("ACCOUNT_ID", "REMEDIATION_ACTIONS_TABLE", "SNS_TOPIC_ARN",
          "DOC_REVOKE_SG", "DOC_DISABLE_KEY", "DOC_NGINX_HARDEN",
          "AUTOMATION_ROLE_ARN"):
    os.environ.setdefault(k, "test")

sys.path.insert(0, str(Path(__file__).parent / "asr_trigger"))
sys.modules.pop("handler", None)
import handler  # noqa: E402


def test_security_hub():
    got = handler._parse_finding({"detail": {"findings": [{
        "Id": "arn:aws:securityhub:ap-northeast-2:111122223333:subscription/x/finding/abc",
        "Title": "EC2.19 ...",
        "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/EC2.19",
        "Resources": [{"Type": "AwsEc2SecurityGroup", "Id": "arn:aws:ec2:::security-group/sg-0abc"}],
    }]}})
    assert got["finding_id"].endswith("/abc"), got["finding_id"]
    assert got["group_id"] == "sg-0abc", got["group_id"]


def test_guardduty():
    got = handler._parse_finding({"id": "eventbridge-evt", "detail": {
        "id": "gd-finding-123",
        "type": "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
        "resource": {"accessKeyDetails": {"accessKeyId": "AKIAEXAMPLE"}},
    }})
    # correlator 도 detail.id 를 finding_id 로 쓰므로 두 테이블이 같은 키로 조인됩니다.
    assert got["finding_id"] == "gd-finding-123", got["finding_id"]
    assert got["access_key_id"] == "AKIAEXAMPLE"


def test_missing_id_does_not_crash():
    got = handler._parse_finding({"detail": {"type": "Recon:EC2/PortProbeUnprotectedPort"}})
    assert got["finding_id"] == "unknown", got["finding_id"]


if __name__ == "__main__":
    test_security_hub()
    test_guardduty()
    test_missing_id_does_not_crash()
    print("ok - finding_id 추출 3건 통과")
