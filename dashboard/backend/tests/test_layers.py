"""설계 2.3·2.4 경계 검사: boto3 는 integrations/aws 안에서만, 캐시·잠금은 하나, 가공 결과 재사용 유지."""
import ast
from pathlib import Path

from soar.provider import AwsProvider
from tests.test_provider import FakeSession

SOAR = Path(__file__).resolve().parents[1] / "soar"


def imports_of(path):
    names = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
    return names


def test_boto3_is_imported_only_inside_integrations_aws():
    offenders = [str(p.relative_to(SOAR)) for p in SOAR.rglob("*.py")
                 if {"boto3", "botocore"} & imports_of(p) and "integrations" not in p.parts]
    assert offenders == []


def test_repositories_and_routes_do_not_touch_flask_request_or_aws_sdk():
    for path in list((SOAR / "repositories").glob("*.py")) + [SOAR / "standard_api.py"]:
        assert not {"boto3", "botocore"} & imports_of(path), path
    for path in (SOAR / "repositories").glob("*.py"):
        assert "flask" not in imports_of(path), path


def test_security_hub_and_inspector_share_one_cache_and_lock():
    provider = AwsProvider("ap-northeast-2", session_factory=lambda region: FakeSession(region))
    assert provider._findings._securityhub._cache is provider._inspector._cache


def test_account_id_from_sts_reaches_resources_for_scope_checks():
    provider = AwsProvider("ap-northeast-2", session_factory=lambda region: FakeSession(region))
    assert provider.account_id == "123456789012"
    assert provider.resources({})["items"][0]["accountId"] == "123456789012"


def test_vulnerability_rows_are_reused_while_the_inspector_cache_is_unchanged():
    inspector = type("Inspector", (), {"list_findings": lambda self, **kw: {"findings": [
        {"findingArn": "arn:f1", "severity": kw["filterCriteria"]["severity"][0]["value"], "resourceId": "i-1",
         "packageVulnerabilityDetails": {"vulnerabilityId": "CVE-1", "vulnerablePackages": [{"name": "openssl"}]}}]}})()
    session = FakeSession("ap-northeast-2")
    session.client = lambda name, **kw: inspector if name == "inspector2" else FakeSession.client(session, name)
    provider = AwsProvider("ap-northeast-2", session_factory=lambda region: session)
    first = provider.vulnerabilities({})["items"]
    assert provider.vulnerabilities({})["items"] is first
