"""탐지 설명표·AWS 조치 안내·자동 조치 판정(설정 기준 예상) — v23.

판정은 terraform/modules/soar 의 asr_trigger·EventBridge 규칙을 옮긴 것이라, 두 곳이 어긋나지 않는지도 검사한다.
"""
import ast
import re
from pathlib import Path

import pytest

from soar import guidance
from soar.guidance import AutoPolicy, annotate, control_id, explain, guardduty_type, remediation
from soar.guidance_catalog import CONTROLS, GUARDDUTY, OTHERS, WHERE

SOAR_MODULE = Path(__file__).resolve().parents[3] / "terraform" / "modules" / "soar"
PATTERNS = ("restricted-ssh,restricted-common-ports,vpc-sg-open-only-to-authorized-ports,EC2.13,EC2.14,EC2.19,"
            "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration,UnauthorizedAccess:IAMUser/MaliciousIPCaller,"
            "CredentialAccess:IAMUser/AnomalousBehavior,Discovery:IAMUser/AnomalousBehavior")
CONTROL_LIST = "EC2.2,EC2.7,EC2.182,S3.1,IAM.7,SSM.6,SSM.7,SEC-06A,SEC-06B"
SG = [{"Type": "AwsEc2SecurityGroup", "Id": "arn:aws:ec2:ap-northeast-2:111122223333:security-group/sg-0abc"}]


def control(cid, title="t", status="FAILED", **extra):
    return {"ProductName": "Security Hub", "GeneratorId": f"security-control/{cid}", "Title": title,
            "Compliance": {"Status": status, "SecurityControlId": cid}, "RecordState": "ACTIVE", **extra}


def guardduty(asff_type, resources=None):
    return {"ProductName": "GuardDuty", "GeneratorId": "arn:aws:guardduty:ap-northeast-2:111122223333:detector/d",
            "Types": [f"TTPs/Initial Access/{asff_type}"], "Resources": resources or []}


@pytest.fixture
def policy():
    return AutoPolicy(PATTERNS, CONTROL_LIST, "true")


def test_control_id_follows_the_lambda_order():
    assert control_id({"Compliance": {"SecurityControlId": "EC2.19"}, "GeneratorId": "security-control/EC2.2"}) == "EC2.19"
    assert control_id({"ProductFields": {"ControlId": "IAM.7"}}) == "IAM.7"
    assert control_id({"GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/S3.1"}) == "S3.1"
    assert control_id({"GeneratorId": "arn:aws:guardduty:ap-northeast-2:1:detector/abc"}) is None


def test_guardduty_type_is_restored_from_security_hub_types():
    assert guardduty_type(guardduty("UnauthorizedAccess:EC2-SSHBruteForce")) == "UnauthorizedAccess:EC2/SSHBruteForce"
    assert guardduty_type(guardduty("UnauthorizedAccess:IAMUser/MaliciousIPCaller")) == "UnauthorizedAccess:IAMUser/MaliciousIPCaller"
    assert guardduty_type(guardduty("Backdoor:EC2-C&CActivity.B!DNS")) == "Backdoor:EC2/C&CActivity.B!DNS"
    assert guardduty_type({"ProductName": "Security Hub", "Types": ["A:B-C"]}) is None


def test_explanations_cover_controls_guardduty_config_waf_and_products():
    assert explain(control("EC2.2"), "EC2.2")["title"] == CONTROLS["EC2.2"]["title"]
    ssh = explain(guardduty("UnauthorizedAccess:EC2-SSHBruteForce"), None, "UnauthorizedAccess:EC2/SSHBruteForce")
    assert ssh["key"] == "UnauthorizedAccess:EC2/SSHBruteForce" and ssh["scenario"] == "SEC-06B"
    family = explain(guardduty("Impact:EC2-AbusedDomainRequest.Reputation"), None, "Impact:EC2/AbusedDomainRequest.Reputation")
    assert family["key"] == "family:Impact" and family["kind"] == "guardduty-family"
    config = explain({"ProductName": "Config", "Title": "soar-sec-dev-restricted-common-ports"})
    assert config["key"] == "config:restricted-common-ports" and config["scenario"] == "SEC-03"
    by_field = explain({"ProductName": "Config", "Title": "x",
                        "ProductFields": {"aws/config/ConfigRuleName": "soar-sec-dev-restricted-ssh"}})
    assert by_field["key"] == "config:restricted-ssh"
    assert explain({"ProductName": "Default", "GeneratorId": "soar-waf-alarm"})["scenario"] == "SEC-08"
    assert explain({"ProductName": "IAM Access Analyzer"})["key"] == "product:IAM Access Analyzer"
    assert explain(control("Macie.1"), "Macie.1") is None  # 표에 없으면 AWS 원문만


def test_catalog_entries_are_complete_and_name_where_to_fix():
    for key, entry in {**CONTROLS, **GUARDDUTY, **OTHERS}.items():
        assert entry["title"] and entry["problem"] and entry["risk"] and entry["fix"], key
        assert entry["where"] in WHERE, key
        assert entry["scenario"] is None or re.fullmatch(r"SEC-\d\d[AB]?(·SEC-\d\d[AB]?)*", entry["scenario"]), key


def test_remediation_link_is_https_and_only_generated_for_security_hub_controls():
    assert remediation(control("EC2.19"), "EC2.19")["url"] == "https://docs.aws.amazon.com/console/securityhub/EC2.19/remediation"
    given = control("S3.1", Remediation={"Recommendation": {"Text": "For information on how to correct this issue, consult the documentation.",
                                                             "Url": "https://docs.aws.amazon.com/console/securityhub/S3.1/remediation"}})
    assert remediation(given, "S3.1")["text"].startswith("For information")
    unsafe = control("S3.1", Remediation={"Recommendation": {"Url": "javascript:alert(1)"}})
    assert remediation(unsafe, "S3.1")["url"].startswith("https://docs.aws.amazon.com/")
    assert remediation(guardduty("UnauthorizedAccess:EC2-SSHBruteForce")) is None


def test_unconfigured_policy_is_unknown_not_manual():
    result = AutoPolicy().evaluate(control("EC2.2"), "EC2.2")
    assert result["mode"] == "unknown" and result["playbookId"] is None


def test_control_list_runs_the_matching_playbook_and_dry_run_only_records(policy):
    auto = policy.evaluate(control("EC2.2", Resources=SG), "EC2.2")
    assert (auto["mode"], auto["playbookId"]) == ("conditional", "ASR-RemoveDefaultSgRules") and "프로젝트 VPC" in auto["condition"]
    assert policy.evaluate(control("EC2.2"), "EC2.2")["mode"] == "manual"  # 보안그룹 자원 없음 → Lambda 도 수동
    assert policy.evaluate(control("IAM.7"), "IAM.7")["playbookId"] == "ASR-SetIamPasswordPolicy"
    dry = AutoPolicy(PATTERNS, CONTROL_LIST, "false").evaluate(control("S3.1"), "S3.1")
    assert dry["mode"] == "dry-run" and dry["playbookId"] == "ASR-BlockS3AccountPublicAccess"
    removed = AutoPolicy(PATTERNS, "EC2.7", "true").evaluate(control("S3.1"), "S3.1")
    assert removed["mode"] == "manual"  # 목록에서 빼면 기존 패턴 규칙대로(대부분 수동)


def test_whitelisted_security_group_findings_depend_on_the_tag(policy):
    title = "Security groups should not allow unrestricted access to ports with high risk"
    sg = policy.evaluate(control("EC2.19", title, Resources=SG), "EC2.19")
    assert sg["mode"] == "conditional" and sg["playbookId"] == "ASR-RevokeSecurityGroupIngress"
    assert "AutoRemediation=enabled" in sg["condition"]
    assert policy.evaluate(control("EC2.19", title), "EC2.19")["mode"] == "manual"  # 보안그룹 ID 없음
    # EC2.2 는 EC2.21·EC2.22 를 잡지 않는다(정확 일치)
    assert policy.evaluate(control("EC2.22", "Unused security groups"), "EC2.22")["mode"] == "manual"
    config = {"ProductName": "Config", "Title": "soar-sec-dev-restricted-ssh", "Compliance": {"Status": "FAILED"},
              "Resources": SG, "GeneratorId": "arn:aws:config:ap-northeast-2:1:config-rule/config-rule-a"}
    assert policy.evaluate(config)["mode"] == "conditional"


def test_findings_without_compliance_or_outside_routing_have_no_automatic_path(policy):
    assert policy.evaluate({"ProductName": "IAM Access Analyzer", "Title": "x"})["mode"] == "none"
    assert policy.evaluate(control("EC2.2", status="PASSED"), "EC2.2")["mode"] == "none"
    waf = policy.evaluate({"ProductName": "Default", "GeneratorId": "soar-waf-alarm"})
    assert waf["mode"] == "none" and "WAF" in waf["reason"]
    ssh = guardduty("UnauthorizedAccess:EC2-SSHBruteForce")
    assert policy.evaluate(ssh, None, guardduty_type(ssh))["mode"] == "none"


def test_guardduty_credential_findings_disable_long_term_keys_only(policy):
    long_term = guardduty("UnauthorizedAccess:IAMUser-MaliciousIPCaller",
                          [{"Type": "AwsIamAccessKey", "Id": "AWS::IAM::AccessKey:AKIAEXAMPLEKEY000001"}])
    assert policy.evaluate(long_term, None, guardduty_type(long_term))["mode"] == "auto"
    session = guardduty("UnauthorizedAccess:IAMUser-InstanceCredentialExfiltration.OutsideAWS",
                        [{"Type": "AwsIamAccessKey", "Id": "AWS::IAM::AccessKey:ASIAEXAMPLEKEY000001"}])
    result = policy.evaluate(session, None, guardduty_type(session))
    assert result["mode"] == "conditional" and "ASIA" in result["condition"]
    root = guardduty("Policy:IAMUser-RootCredentialUsage")
    assert policy.evaluate(root, None, guardduty_type(root))["mode"] == "none"


def test_annotate_adds_all_detail_fields(policy):
    got = annotate(control("EC2.2", Resources=SG), policy)
    assert set(got) == {"controlId", "findingType", "remediation", "guidance", "autoRemediation"}
    assert annotate(control("EC2.2"), None)["autoRemediation"] is None


# --- asr_trigger·EventBridge 와 어긋나지 않는지 --------------------------------------------------

def _assigned(path, name):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f"{name} not found in {path}")


@pytest.mark.skipif(not SOAR_MODULE.is_dir(), reason="Terraform 소스가 없는 배포본")
def test_playbook_table_matches_the_lambda_and_terraform_documents():
    lambda_table = _assigned(SOAR_MODULE / "lambda_src" / "asr_trigger" / "handler.py", "CONTROL_PLAYBOOKS")
    env_docs = dict(re.findall(r'(DOC_[A-Z0-9_]+)\s*=\s*aws_ssm_document\.automation\["(ASR-[A-Za-z0-9]+)"\]',
                               (SOAR_MODULE / "lambda.tf").read_text(encoding="utf-8")))
    assert set(lambda_table) == set(guidance.CONTROL_PLAYBOOKS)
    for cid, (env, label) in lambda_table.items():
        assert guidance.CONTROL_PLAYBOOKS[cid] == (env_docs[env], label), cid
        assert (SOAR_MODULE / "documents" / f"{env_docs[env]}.yaml").is_file(), cid
    eventbridge = (SOAR_MODULE / "eventbridge.tf").read_text(encoding="utf-8")
    routed = re.search(r"type\s*=\s*\[(.*?)\]", eventbridge).group(1)
    assert tuple(re.findall(r'prefix = "([^"]+)"', routed)) == guidance.GUARDDUTY_ROUTED
