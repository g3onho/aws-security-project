"""asr_trigger 자동 조치 확장 검증 (DEC-017 규칙 ID 정확 일치 · DEC-018/019 SEC-06A·06B NACL 차단).

lambda_src/ 바로 아래에 둡니다. archive_file 은 asr_trigger/ 하위만 압축하므로 Lambda zip 에 들어가지 않습니다.
다른 Lambda 테스트와 모듈 이름(handler)이 겹치므로 파일별로 실행합니다.

    AWS_DEFAULT_REGION=ap-northeast-2 python modules/soar/lambda_src/test_auto_remediation.py
"""
import json
import os
import sys
from pathlib import Path

os.environ.setdefault("AWS_REGION", "ap-northeast-2")
os.environ.setdefault("AWS_DEFAULT_REGION", "ap-northeast-2")
for k in ("ACCOUNT_ID", "REMEDIATION_ACTIONS_TABLE", "SNS_TOPIC_ARN",
          "DOC_REVOKE_SG", "DOC_DISABLE_KEY", "DOC_NGINX_HARDEN", "AUTOMATION_ROLE_ARN"):
    os.environ.setdefault(k, "test")
os.environ["AUTO_REMEDIABLE_PATTERNS"] = "EC2.19"
os.environ["AUTO_REMEDIABLE_CONTROLS"] = "EC2.2,EC2.7,EC2.182,S3.1,IAM.7,SSM.6,SSM.7,SEC-06A,SEC-06B"
os.environ["ENABLE_AUTO_REMEDIATION"] = "true"
for env, doc in (("DOC_DEFAULT_SG", "ASR-RemoveDefaultSgRules"), ("DOC_EBS_ENCRYPTION", "ASR-EnableEbsDefaultEncryption"),
                 ("DOC_SNAPSHOT_BPA", "ASR-BlockEbsSnapshotPublicAccess"), ("DOC_S3_ACCOUNT_BPA", "ASR-BlockS3AccountPublicAccess"),
                 ("DOC_PASSWORD_POLICY", "ASR-SetIamPasswordPolicy"), ("DOC_SSM_AUTOMATION_LOG", "ASR-EnableSsmAutomationLogging"),
                 ("DOC_SSM_PUBLIC_SHARING", "ASR-BlockSsmDocumentPublicSharing"), ("DOC_BLOCK_IP", "ASR-BlockIpWithNacl")):
    os.environ[env] = doc
os.environ["MYSQL_ALARM_NAME"] = "soar-sec-dev-mysql-bruteforce"
os.environ["MYSQL_LOG_GROUP"] = "/soar-sec/dev/db/mysql"
os.environ["SSH_ALARM_NAME"] = "soar-sec-dev-ssh-reject"
os.environ["FLOWLOG_GROUP"] = "/soar-sec/dev/vpc/flowlogs"
FLOW_PATTERN = ('[version, account, eni, srcaddr=10.0.*, dstaddr, srcport, dstport="22", protocol="6", '
                'packets, bytes, start, end, action="REJECT", status]')
os.environ["FLOWLOG_REJECT_PATTERN"] = FLOW_PATTERN
os.environ["PRIVATE_NACL_ID"] = "acl-0123456789abcdef0"
os.environ["VPC_CIDR"] = "10.0.0.0/16"
os.environ["PROJECT_VPC_ID"] = "vpc-0aaa1111bbbb2222c"

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parent / "asr_trigger"))
sys.modules.pop("handler", None)
import handler  # noqa: E402

ACCOUNT = "111122223333"


class FakeTable:
    """action_id(해시)·created_at(정렬) 키와 finding_id 인덱스만 흉내 낸다."""
    def __init__(self):
        self.rows = {}

    def query(self, KeyConditionExpression, Limit=None, IndexName=None):
        want = KeyConditionExpression.get_expression()["values"][1]
        field = "finding_id" if IndexName else "action_id"
        return {"Items": [dict(r) for _, r in sorted(self.rows.items()) if r.get(field) == want][:Limit]}

    def put_item(self, Item):
        self.rows[(Item["action_id"], Item["created_at"])] = dict(Item)

    def update_item(self, Key, UpdateExpression, ExpressionAttributeValues, ExpressionAttributeNames=None):
        row = self.rows[(Key["action_id"], Key["created_at"])]
        v = ExpressionAttributeValues
        if "occurrence_count" in UpdateExpression:
            row["occurrence_count"] = row.get("occurrence_count", v[":first"]) + v[":one"]
            row.update(last_seen_at=v[":now"], reason=v.get(":r", row.get("reason")))
        else:
            row.update(status=v[":s"], after_state=v[":a"])


class Fakes:
    def __init__(self, log_messages=(), protected=(), nacl_entries=None, managed_enis=()):
        self.table, self.sent, self.started, self.log_calls = FakeTable(), [], [], []
        fakes = self
        handler.dynamodb = type("D", (), {"Table": lambda _s, name: fakes.table})()
        handler.sns = type("S", (), {"publish": lambda _s, **kw: fakes.sent.append(kw)})()
        handler.ssm = type("M", (), {"start_automation_execution":
                                     lambda _s, **kw: fakes.started.append(kw) or
                                     {"AutomationExecutionId": f"exec-{len(fakes.started)}"}})()
        entries = nacl_entries if nacl_entries is not None else [
            {"RuleNumber": 100, "RuleAction": "allow", "Egress": False, "CidrBlock": "10.0.0.0/16"},
            {"RuleNumber": 32767, "RuleAction": "deny", "Egress": False, "CidrBlock": "0.0.0.0/0"},
            {"RuleNumber": 100, "RuleAction": "allow", "Egress": True, "CidrBlock": "0.0.0.0/0"}]
        instances = [{"PrivateIpAddress": ip, "NetworkInterfaces": [{"PrivateIpAddresses": [{"PrivateIpAddress": ip}]}]}
                     for ip in protected]
        handler.ec2 = type("E", (), {
            "describe_security_groups": lambda _s, **kw: {"SecurityGroups": [{"Tags": []}]},
            "describe_instances": lambda _s, **kw: {"Reservations": [{"Instances": instances}]},
            "describe_network_acls": lambda _s, **kw: {"NetworkAcls": [{"Entries": entries}]},
            # AWS 관리 ENI(ALB·VPC 엔드포인트)는 RequesterManaged 또는 interface 가 아닌 유형
            "describe_network_interfaces": lambda _s, **kw: {"NetworkInterfaces": [
                {"RequesterManaged": True, "InterfaceType": "interface", "PrivateIpAddresses": [{"PrivateIpAddress": ip}]}
                for ip in managed_enis] + [{"InterfaceType": "interface", "PrivateIpAddresses": [{"PrivateIpAddress": "10.0.9.9"}]}]}})()

        def filter_log_events(_s, **kw):
            fakes.log_calls.append(kw)
            return {"events": [{"message": m} for m in log_messages]}
        handler.logs = type("L", (), {"filter_log_events": filter_log_events})()


def sh_event(control=None, generator="x", region="ap-northeast-2", resources=None, fid="finding-1", title="t"):
    finding = {"Id": fid, "Title": title, "GeneratorId": generator, "Region": region, "AwsAccountId": ACCOUNT,
               "Resources": resources or [{"Type": "AwsAccount", "Id": f"AWS::::Account:{ACCOUNT}"}]}
    if control:
        finding["Compliance"] = {"Status": "FAILED", "SecurityControlId": control}
    return {"source": "aws.securityhub", "region": region, "account": ACCOUNT, "detail": {"findings": [finding]}}


def alarm_event(reason_data=None, name="soar-sec-dev-mysql-bruteforce"):
    state = {"value": "ALARM", "timestamp": "2026-09-28T03:05:40.000+0000"}
    if reason_data is not None:
        state["reasonData"] = json.dumps(reason_data)
    return {"source": "aws.cloudwatch", "region": "ap-northeast-2", "account": ACCOUNT,
            "resources": [f"arn:aws:cloudwatch:ap-northeast-2:{ACCOUNT}:alarm:{name}"],
            "detail": {"alarmName": name, "state": state}}


def flow(src, port="22", proto="6", action="REJECT", dst="10.0.1.10"):
    return f"2 {ACCOUNT} eni-0abc {src} {dst} 51234 {port} {proto} 1 60 1759028400 1759028460 {action} OK"


def denied(host, n=1):
    return [f"2026-09-28T03:01:00.000000Z 8 [Note] [MY-010926] [Server] Access denied for user 'root'@'{host}' (using password: YES)"] * n


def only_row(table):
    assert len(table.rows) == 1, table.rows
    return next(iter(table.rows.values()))


# --- 규칙 ID ---------------------------------------------------------------------

def test_control_id_sources():
    assert handler._control_id({"Compliance": {"SecurityControlId": "EC2.2"}}) == "EC2.2"
    assert handler._control_id({"ProductFields": {"ControlId": "S3.1"}}) == "S3.1"
    assert handler._control_id({"GeneratorId": "security-control/EC2.182"}) == "EC2.182"
    assert handler._control_id({"GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/IAM.7"}) == "IAM.7"
    assert handler._control_id({"GeneratorId": "arn:aws:guardduty:ap-northeast-2:1:detector/x"}) == ""


def test_default_sg_control_runs_its_playbook_with_the_group():
    f = Fakes()
    res = [{"Type": "AwsEc2SecurityGroup", "Id": "arn:aws:ec2:ap-northeast-2:1:security-group/sg-0abc1234",
            "Details": {"AwsEc2SecurityGroup": {"GroupName": "default", "VpcId": "vpc-0aaa1111bbbb2222c"}}}]
    out = handler.handler(sh_event("EC2.2", resources=res), None)
    assert out["decision"] == "auto-executed" and out["control"] == "EC2.2"
    call = f.started[0]
    assert call["DocumentName"] == "ASR-RemoveDefaultSgRules"
    assert call["Parameters"]["SecurityGroupId"] == ["sg-0abc1234"]
    assert call["Parameters"]["VpcId"] == ["vpc-0aaa1111bbbb2222c"]
    row = only_row(f.table)
    assert row["status"] == "IN_PROGRESS" and row["control_id"] == "EC2.2" and "EC2.2" in row["reason"]
    assert row["action_id"] == "ssm-exec-1" and row["playbook_id"] == "ASR-RemoveDefaultSgRules"


def test_default_sg_outside_project_vpc_goes_manual():
    f = Fakes()
    res = [{"Type": "AwsEc2SecurityGroup", "Id": "arn:aws:ec2:ap-northeast-2:1:security-group/sg-0def5678",
            "Details": {"AwsEc2SecurityGroup": {"GroupName": "default", "VpcId": "vpc-0default000000000"}}}]
    out = handler.handler(sh_event("EC2.2", resources=res, fid="f-other-vpc"), None)
    assert out["decision"] == "manual-notified" and "프로젝트 VPC" in out["reason"] and not f.started


def test_account_level_controls_need_no_resource_parameters():
    for control, doc in (("EC2.7", "ASR-EnableEbsDefaultEncryption"), ("EC2.182", "ASR-BlockEbsSnapshotPublicAccess"),
                         ("S3.1", "ASR-BlockS3AccountPublicAccess"), ("IAM.7", "ASR-SetIamPasswordPolicy"),
                         ("SSM.6", "ASR-EnableSsmAutomationLogging"), ("SSM.7", "ASR-BlockSsmDocumentPublicSharing")):
        f = Fakes()
        out = handler.handler(sh_event(control, fid=f"f-{control}"), None)
        assert out["decision"] == "auto-executed", (control, out)
        assert f.started[0]["DocumentName"] == doc
        assert set(f.started[0]["Parameters"]) == {"AutomationAssumeRole"}


def test_prefix_of_listed_control_is_not_matched():
    # EC2.2 가 목록에 있어도 EC2.21 은 규칙 분기로 가지 않는다(부분 일치 금지) → 화이트리스트 밖 수동.
    f = Fakes()
    out = handler.handler(sh_event("EC2.21", fid="f-21"), None)
    assert out == {"decision": "manual-notified", "reason": "not in whitelist"}
    assert not f.started and only_row(f.table)["reason"].startswith("자동 조치 대상 아님")


def test_generator_id_only_finding_is_matched():
    f = Fakes()
    out = handler.handler(sh_event(generator="security-control/SSM.7", fid="f-gen"), None)
    assert out["decision"] == "auto-executed" and f.started[0]["DocumentName"] == "ASR-BlockSsmDocumentPublicSharing"


def test_dry_run_switch_blocks_control_execution():
    f = Fakes()
    handler.ENABLE_AUTO = False
    try:
        out = handler.handler(sh_event("EC2.7", fid="f-dry"), None)
    finally:
        handler.ENABLE_AUTO = True
    assert out["decision"] == "dry-run" and not f.started
    assert only_row(f.table)["status"] == "DRY_RUN"


def test_other_region_or_missing_group_goes_manual():
    f = Fakes()
    out = handler.handler(sh_event("EC2.7", region="us-east-1", fid="f-region"), None)
    assert out["decision"] == "manual-notified" and "리전" in out["reason"] and not f.started
    f = Fakes()
    out = handler.handler(sh_event("EC2.2", fid="f-nogroup"), None)
    assert out["decision"] == "manual-notified" and "보안그룹" in out["reason"] and not f.started


def test_running_remediation_for_same_finding_is_not_repeated():
    f = Fakes()
    handler.handler(sh_event("S3.1", fid="f-same"), None)
    out = handler.handler(sh_event("S3.1", fid="f-same"), None)
    assert out["decision"] == "skipped" and len(f.started) == 1
    # 종료 이벤트가 결과를 기록하면 다시 위반될 때(재시연) 새로 실행한다.
    handler.handler({"source": "aws.ssm", "detail": {"ExecutionId": "exec-1", "Status": "Success",
                                                     "Definition": "ASR-BlockS3AccountPublicAccess"}}, None)
    out = handler.handler(sh_event("S3.1", fid="f-same"), None)
    assert out["decision"] == "auto-executed" and len(f.started) == 2


def test_existing_sg_path_still_uses_patterns_and_records_reason():
    f = Fakes()
    res = [{"Type": "AwsEc2SecurityGroup", "Id": "arn:aws:ec2:::security-group/sg-0manual"}]
    out = handler.handler(sh_event("EC2.19", generator="security-control/EC2.19", title="EC2.19 open port",
                                   resources=res, fid="f-sg"), None)
    assert out == {"decision": "manual-notified", "reason": "no auto tag"}  # Fakes 의 SG 는 태그 없음(대조군)
    assert only_row(f.table)["reason"] == "AutoRemediation 태그 없는 보안그룹(대조군)"


# --- SEC-06A -----------------------------------------------------------------------

def test_bruteforce_alarm_blocks_top_source_with_next_free_rule():
    f = Fakes(log_messages=denied("10.0.2.55", 12) + denied("10.0.2.77", 2), protected=["10.0.1.10"],
              nacl_entries=[{"RuleNumber": 1, "RuleAction": "deny", "Egress": False, "CidrBlock": "10.0.2.99/32"},
                            {"RuleNumber": 100, "RuleAction": "allow", "Egress": False, "CidrBlock": "10.0.0.0/16"}])
    out = handler.handler(alarm_event(), None)
    assert out["decision"] == "auto-executed" and out["ip"] == "10.0.2.55" and out["rule"] == 2
    params = f.started[0]["Parameters"]
    assert f.started[0]["DocumentName"] == "ASR-BlockIpWithNacl"
    assert params["NetworkAclId"] == ["acl-0123456789abcdef0"] and params["AttackerCidr"] == ["10.0.2.55/32"]
    assert params["RuleNumber"] == ["2"]
    row = only_row(f.table)
    assert row["control_id"] == "SEC-06A" and "12회" in row["reason"] and row["finding_id"].endswith("mysql-bruteforce")


def test_bruteforce_window_comes_from_alarm_reason_data():
    f = Fakes(log_messages=denied("10.0.2.55", 3))
    handler.handler(alarm_event({"startDate": "2026-09-28T03:00:00.000+0000", "period": 300,
                                 "recentDatapoints": [12.0]}), None)
    call = f.log_calls[0]
    assert call["endTime"] - call["startTime"] == 300_000
    assert call["filterPattern"] == '"Access denied for user"' and call["logGroupName"] == "/soar-sec/dev/db/mysql"


def test_bruteforce_hostname_form_is_converted():
    f = Fakes(log_messages=denied("ip-10-0-2-55.ap-northeast-2.compute.internal", 5))
    out = handler.handler(alarm_event(), None)
    assert out["ip"] == "10.0.2.55" and f.started


def test_bruteforce_never_blocks_protected_or_outside_addresses():
    f = Fakes(log_messages=denied("10.0.2.20", 9), protected=["10.0.2.20"])
    out = handler.handler(alarm_event(), None)
    assert out["decision"] == "manual-notified" and "보호 자산" in out["reason"] and not f.started
    f = Fakes(log_messages=denied("203.0.113.9", 9))
    out = handler.handler(alarm_event(), None)
    assert out["decision"] == "manual-notified" and "VPC CIDR" in out["reason"] and not f.started


def test_bruteforce_already_blocked_ip_is_not_blocked_twice():
    f = Fakes(log_messages=denied("10.0.2.55", 9),
              nacl_entries=[{"RuleNumber": 5, "RuleAction": "deny", "Egress": False, "CidrBlock": "10.0.2.55/32"}])
    out = handler.handler(alarm_event(), None)
    assert out["decision"] == "auto-skipped" and not f.started
    assert only_row(f.table)["status"] == "NO_CHANGE"


def test_bruteforce_without_log_evidence_goes_manual():
    f = Fakes(log_messages=[])
    out = handler.handler(alarm_event(), None)
    assert out["decision"] == "manual-notified" and "출발지 IP" in out["reason"] and not f.started


def test_other_cloudwatch_alarms_are_ignored():
    f = Fakes(log_messages=denied("10.0.2.55", 9))
    event = alarm_event()
    event["detail"]["alarmName"] = "soar-sec-dev-docker-host-cpu-high"
    assert handler.handler(event, None)["decision"] == "ignored" and not f.started and not f.table.rows


def test_ssh_reject_alarm_reads_flow_logs_and_blocks_top_internal_source():
    f = Fakes(log_messages=[flow("10.0.2.55")] * 15 + [flow("10.0.2.77")] * 3)
    out = handler.handler(alarm_event(name="soar-sec-dev-ssh-reject"), None)
    assert out["decision"] == "auto-executed" and out["control"] == "SEC-06B" and out["ip"] == "10.0.2.55"
    call = f.log_calls[0]
    assert call["logGroupName"] == "/soar-sec/dev/vpc/flowlogs" and call["filterPattern"] == FLOW_PATTERN
    assert f.started[0]["Parameters"]["AttackerCidr"] == ["10.0.2.55/32"]
    row = only_row(f.table)
    assert row["control_id"] == "SEC-06B" and "22번 거부 15회" in row["reason"] and "Flow Logs" in row["finding_type"]


def test_flow_log_lines_other_than_rejected_ssh_are_not_counted():
    f = Fakes(log_messages=[flow("10.0.2.55", action="ACCEPT"), flow("10.0.2.55", port="3306"),
                            flow("10.0.2.55", proto="17"), "malformed line"])
    out = handler.handler(alarm_event(name="soar-sec-dev-ssh-reject"), None)
    assert out["decision"] == "manual-notified" and "Flow Logs" in out["reason"] and not f.started


def test_ssh_block_needs_its_own_list_token():
    f = Fakes(log_messages=[flow("10.0.2.55")] * 15)
    saved = handler.CONTROLS
    handler.CONTROLS = saved - {"SEC-06B"}
    try:
        out = handler.handler(alarm_event(name="soar-sec-dev-ssh-reject"), None)
    finally:
        handler.CONTROLS = saved
    assert out["decision"] == "manual-notified" and "SEC-06B" in out["reason"] and not f.started


def test_mysql_and_ssh_for_same_attacker_block_once():
    f = Fakes(log_messages=denied("10.0.2.55", 12))
    handler.handler(alarm_event(), None)
    blocked = [{"RuleNumber": 1, "RuleAction": "deny", "Egress": False, "CidrBlock": "10.0.2.55/32"}]
    handler.ec2.describe_network_acls = lambda **kw: {"NetworkAcls": [{"Entries": blocked}]}
    handler.logs.filter_log_events = lambda **kw: {"events": [{"message": flow("10.0.2.55")}] * 15}
    out = handler.handler(alarm_event(name="soar-sec-dev-ssh-reject"), None)
    assert out["decision"] == "auto-skipped" and len(f.started) == 1


def test_username_cannot_choose_the_blocked_address():
    spoof = ["2026-09-28T03:01:00.000000Z 8 [Note] [MY-010926] [Server] Access denied for user "
             "'x'@'10.0.1.25'@'10.0.2.55' (using password: YES)"] * 9
    f = Fakes(log_messages=spoof)
    out = handler.handler(alarm_event(), None)
    assert out["ip"] == "10.0.2.55" and f.started[0]["Parameters"]["AttackerCidr"] == ["10.0.2.55/32"]


def test_invalid_hostname_is_ignored_instead_of_crashing():
    f = Fakes(log_messages=denied("ip-999-0-0-1", 9) + denied("10.0.2.77", 2))
    out = handler.handler(alarm_event(), None)
    assert out["decision"] == "auto-executed" and out["ip"] == "10.0.2.77"


def test_already_blocked_top_source_does_not_hide_the_next_attacker():
    f = Fakes(log_messages=[flow("10.0.2.55")] * 40 + [flow("10.0.2.77")] * 12,
              nacl_entries=[{"RuleNumber": 1, "RuleAction": "deny", "Egress": False, "CidrBlock": "10.0.2.55/32"}])
    out = handler.handler(alarm_event(name="soar-sec-dev-ssh-reject"), None)
    assert out["decision"] == "auto-executed" and out["ip"] == "10.0.2.77" and out["rule"] == 2
    assert "건너뜀" in only_row(f.table)["reason"]


def test_managed_network_interfaces_are_protected():
    f = Fakes(log_messages=denied("10.0.0.40", 20), managed_enis=["10.0.0.40"])
    out = handler.handler(alarm_event(), None)
    assert out["decision"] == "manual-notified" and "보호 자산" in out["reason"] and not f.started


def test_ten_soar_denies_go_manual_before_starting_ssm():
    denies = [{"RuleNumber": n, "RuleAction": "deny", "Egress": False, "CidrBlock": f"10.0.3.{n}/32"} for n in range(1, 11)]
    f = Fakes(log_messages=denied("10.0.2.55", 9), nacl_entries=denies)
    out = handler.handler(alarm_event(), None)
    assert out["decision"] == "manual-notified" and "상한" in out["reason"] and not f.started


def test_repeated_decisions_for_different_ips_are_separate_rows():
    f = Fakes(log_messages=denied("10.0.2.55", 9))
    saved = handler.ENABLE_AUTO
    handler.ENABLE_AUTO = False
    try:
        handler.handler(alarm_event(), None)
        handler.logs.filter_log_events = lambda **kw: {"events": [{"message": m} for m in denied("10.0.2.77", 9)]}
        handler.handler(alarm_event(), None)
    finally:
        handler.ENABLE_AUTO = saved
    rows = sorted(r["resource_id"] for r in f.table.rows.values())
    assert rows == ["acl-0123456789abcdef0 ← 10.0.2.55/32", "acl-0123456789abcdef0 ← 10.0.2.77/32"]


if __name__ == "__main__":
    count = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            count += 1
    print(f"ok - 자동 조치 확장 {count}건 통과")
