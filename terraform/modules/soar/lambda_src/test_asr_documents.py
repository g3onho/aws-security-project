"""규칙 ID 자동 조치 SSM 문서(DEC-017) 스크립트 검증 — 가짜 boto3 로 실행해 "위반이면 바꾸고, 이미 준수면
안 바꾼다"(멱등)와 안전 조건(기본 보안그룹·프로젝트 VPC 확인, 비밀번호 정책의 기존 값 유지)을 확인한다.

lambda_src/ 바로 아래에 둡니다. archive_file 은 하위 폴더만 압축하므로 Lambda zip 에 들어가지 않습니다.

    python modules/soar/lambda_src/test_asr_documents.py
"""
import sys
import types
from pathlib import Path

import yaml
from botocore.exceptions import ClientError

sys.dont_write_bytecode = True
DOCS = Path(__file__).resolve().parent.parent / "documents"


def run(doc_name, clients, payload=None):
    """문서의 executeScript 를 가짜 boto3 로 실행한다. clients: {서비스 이름: 가짜 클라이언트}."""
    doc = yaml.safe_load((DOCS / f"{doc_name}.yaml").read_text(encoding="utf-8"))
    step = next(s for s in doc["mainSteps"] if s["action"] == "aws:executeScript")
    fake = types.ModuleType("boto3")
    fake.client = lambda name, **kw: clients[name]
    fake.session = types.SimpleNamespace(Session=lambda: types.SimpleNamespace(region_name="ap-northeast-2"))
    saved = sys.modules.get("boto3")
    sys.modules["boto3"] = fake
    try:
        scope = {}
        exec(compile(step["inputs"]["Script"], doc_name, "exec"), scope)
        return scope["handler"](payload or {}, None)
    finally:
        if saved is not None:
            sys.modules["boto3"] = saved


class Calls(list):
    def rec(self, name, **kw):
        self.append((name, kw))


def sts():
    return types.SimpleNamespace(get_caller_identity=lambda: {"Account": "111122223333"})


# --- EC2.2 ---------------------------------------------------------------------------

def default_sg(calls, name="default", vpc="vpc-0aaa1111bbbb2222c", inbound=None, outbound=None):
    state = {"in": inbound if inbound is not None else [{"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": "sg-0abc1234"}]}],
             "out": outbound if outbound is not None else [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}

    def describe(GroupIds):
        return {"SecurityGroups": [{"GroupId": GroupIds[0], "GroupName": name, "VpcId": vpc,
                                    "IpPermissions": state["in"], "IpPermissionsEgress": state["out"]}]}

    def revoke_in(GroupId, IpPermissions):
        calls.rec("revoke_in", GroupId=GroupId)
        state["in"] = []

    def revoke_out(GroupId, IpPermissions):
        calls.rec("revoke_out", GroupId=GroupId)
        state["out"] = []
    return types.SimpleNamespace(describe_security_groups=describe, revoke_security_group_ingress=revoke_in,
                                 revoke_security_group_egress=revoke_out)


def test_default_sg_rules_are_removed():
    calls = Calls()
    out = run("ASR-RemoveDefaultSgRules", {"ec2": default_sg(calls)},
              {"sg_id": "sg-0abc1234", "vpc_id": "vpc-0aaa1111bbbb2222c"})
    assert [c[0] for c in calls] == ["revoke_in", "revoke_out"] and out["changed"] is True
    assert '"inbound": []' in out["after"] and '"outbound": []' in out["after"]


def test_default_sg_already_empty_is_left_alone():
    calls = Calls()
    out = run("ASR-RemoveDefaultSgRules", {"ec2": default_sg(calls, inbound=[], outbound=[])},
              {"sg_id": "sg-0abc1234", "vpc_id": "vpc-0aaa1111bbbb2222c"})
    assert not calls and out["changed"] is False


def test_non_default_or_other_vpc_group_is_refused():
    for kwargs in ({"name": "db-auto-sg"}, {"vpc": "vpc-0default000000000"}):
        calls = Calls()
        try:
            run("ASR-RemoveDefaultSgRules", {"ec2": default_sg(calls, **kwargs)},
                {"sg_id": "sg-0abc1234", "vpc_id": "vpc-0aaa1111bbbb2222c"})
        except ValueError:
            pass
        else:
            raise AssertionError(f"refusal expected for {kwargs}")
        assert not calls


# --- EC2.7 · EC2.182 -------------------------------------------------------------------

def test_ebs_default_encryption_is_enabled_once():
    state, calls = {"on": False}, Calls()
    ec2 = types.SimpleNamespace(get_ebs_encryption_by_default=lambda: {"EbsEncryptionByDefault": state["on"]},
                                enable_ebs_encryption_by_default=lambda: calls.rec("enable") or state.update(on=True))
    assert run("ASR-EnableEbsDefaultEncryption", {"ec2": ec2})["changed"] is True
    assert run("ASR-EnableEbsDefaultEncryption", {"ec2": ec2})["changed"] is False and len(calls) == 1


def test_snapshot_block_public_access_is_set_to_block_all():
    state, calls = {"s": "unblocked"}, Calls()
    ec2 = types.SimpleNamespace(get_snapshot_block_public_access_state=lambda: {"State": state["s"]},
                                enable_snapshot_block_public_access=lambda State: calls.rec("enable", State=State)
                                or state.update(s=State))
    out = run("ASR-BlockEbsSnapshotPublicAccess", {"ec2": ec2})
    assert out["changed"] is True and calls == [("enable", {"State": "block-all-sharing"})]


def test_snapshot_api_missing_in_runtime_fails_without_change():
    try:
        run("ASR-BlockEbsSnapshotPublicAccess", {"ec2": types.SimpleNamespace()})
    except RuntimeError as error:
        assert "콘솔" in str(error)
    else:
        raise AssertionError("RuntimeError expected")


# --- S3.1 ----------------------------------------------------------------------------

def test_account_public_access_block_all_four_flags():
    state, calls = {"cfg": None}, Calls()

    def get(AccountId):
        if state["cfg"] is None:
            raise ClientError({"Error": {"Code": "NoSuchPublicAccessBlockConfiguration"}}, "GetPublicAccessBlock")
        return {"PublicAccessBlockConfiguration": state["cfg"]}

    def put(AccountId, PublicAccessBlockConfiguration):
        calls.rec("put", AccountId=AccountId)
        state["cfg"] = PublicAccessBlockConfiguration
    s3c = types.SimpleNamespace(get_public_access_block=get, put_public_access_block=put)
    out = run("ASR-BlockS3AccountPublicAccess", {"s3control": s3c, "sts": sts()})
    assert out["changed"] is True and calls == [("put", {"AccountId": "111122223333"})]
    assert all(state["cfg"].values()) and len(state["cfg"]) == 4
    assert run("ASR-BlockS3AccountPublicAccess", {"s3control": s3c, "sts": sts()})["changed"] is False


# --- IAM.7 ---------------------------------------------------------------------------

def iam_client(policy, calls):
    state = {"p": policy}

    def get():
        if state["p"] is None:
            raise ClientError({"Error": {"Code": "NoSuchEntity"}}, "GetAccountPasswordPolicy")
        return {"PasswordPolicy": state["p"]}

    def update(**kw):
        calls.rec("update", **kw)
        state["p"] = dict(kw)
    return types.SimpleNamespace(get_account_password_policy=get, update_account_password_policy=update)


def test_password_policy_created_with_iam7_defaults_and_user_change_allowed():
    calls = Calls()
    run("ASR-SetIamPasswordPolicy", {"iam": iam_client(None, calls)})
    kw = calls[0][1]
    assert kw["MinimumPasswordLength"] == 8 and kw["AllowUsersToChangePassword"] is True
    assert all(kw[k] for k in ("RequireSymbols", "RequireNumbers", "RequireUppercaseCharacters", "RequireLowercaseCharacters"))
    assert "MaxPasswordAge" not in kw and "PasswordReusePrevention" not in kw  # 기존 비밀번호가 바로 만료되지 않게


def test_password_policy_keeps_stronger_existing_values():
    calls = Calls()
    existing = {"MinimumPasswordLength": 14, "RequireSymbols": False, "RequireNumbers": True,
                "RequireUppercaseCharacters": True, "RequireLowercaseCharacters": True,
                "AllowUsersToChangePassword": False, "MaxPasswordAge": 90, "PasswordReusePrevention": 5}
    run("ASR-SetIamPasswordPolicy", {"iam": iam_client(existing, calls)})
    kw = calls[0][1]
    assert kw["MinimumPasswordLength"] == 14 and kw["RequireSymbols"] is True
    assert kw["AllowUsersToChangePassword"] is False and kw["MaxPasswordAge"] == 90 and kw["PasswordReusePrevention"] == 5


def test_compliant_password_policy_is_not_touched():
    calls = Calls()
    ok = {"MinimumPasswordLength": 12, "RequireSymbols": True, "RequireNumbers": True,
          "RequireUppercaseCharacters": True, "RequireLowercaseCharacters": True}
    assert run("ASR-SetIamPasswordPolicy", {"iam": iam_client(ok, calls)})["changed"] is False and not calls


# --- SSM.6 · SSM.7 --------------------------------------------------------------------

def ssm_client(value, calls):
    state = {"v": value}
    return types.SimpleNamespace(
        get_service_setting=lambda SettingId: calls.rec("get", SettingId=SettingId) or {"ServiceSetting": {"SettingValue": state["v"]}},
        update_service_setting=lambda SettingId, SettingValue: calls.rec("update", SettingId=SettingId, SettingValue=SettingValue)
        or state.update(v=SettingValue))


def test_automation_logging_goes_to_cloudwatch():
    calls = Calls()
    out = run("ASR-EnableSsmAutomationLogging", {"ssm": ssm_client("S3", calls), "sts": sts()})
    update = [c for c in calls if c[0] == "update"][0][1]
    assert update["SettingValue"] == "CloudWatch" and out["changed"] is True
    assert update["SettingId"] == ("arn:aws:ssm:ap-northeast-2:111122223333:servicesetting/"
                                   "ssm/automation/customer-script-log-destination")


def test_document_public_sharing_is_disabled_once():
    calls = Calls()
    client = ssm_client("Enable", calls)
    assert run("ASR-BlockSsmDocumentPublicSharing", {"ssm": client})["changed"] is True
    assert run("ASR-BlockSsmDocumentPublicSharing", {"ssm": client})["changed"] is False
    updates = [c for c in calls if c[0] == "update"]
    assert updates == [("update", {"SettingId": "/ssm/documents/console/public-sharing-permission", "SettingValue": "Disable"})]


if __name__ == "__main__":
    count = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            count += 1
    print(f"ok - 규칙 ID 자동 조치 문서 {count}건 통과")
