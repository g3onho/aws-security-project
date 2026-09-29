"""v23 화면 개편용 선택 필드: 조치 이력 전/후(SSM 보고값)·판정 이유, 자동 대응 요약, 인프라 경보·3계층, 취약점 조치 안내.

새 API 는 없다. 기존 응답에 선택 필드만 더한다(openapi.yaml 함께 갱신).
"""
import json
import time
from datetime import datetime, timedelta, timezone

import pytest
from botocore.exceptions import ClientError

from soar.guidance import AutoPolicy
from soar.provider import AwsProvider
from soar.repositories import alarms as alarm_repo
from soar.repositories.actions import ActionRepository
from soar.repositories.executions import describe, evidence
from soar.repositories.findings import event_id
from soar.repositories.vulnerabilities import update_command
from soar.store import now_ms
from tests.test_action_history import FakeTable, Provider, client_for
from tests.test_provider import FakeSession

NOW = datetime.now(timezone.utc)
iso = lambda d: d.isoformat().replace("+00:00", "Z")
GD_ARN = "arn:aws:guardduty:ap-northeast-2:111122223333:detector/d/finding/gd-1"
SG_BEFORE = json.dumps([{"IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.0.0.0/16"}]}])
SG_AFTER = json.dumps([{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.0.0.0/16"}]}])


def record(**over):
    row = {"action_id": "ssm-exec-1", "created_at": iso(NOW - timedelta(minutes=10)), "decision": "auto-executed",
           "status": "SUCCESS", "finding_id": "arn:aws:securityhub:ap-northeast-2:111122223333:finding/sg",
           "finding_type": "EC2.19 open port", "resource_id": "sg-0abc", "region": "ap-northeast-2",
           "account_id": "111122223333", "playbook_id": "ASR-RevokeSecurityGroupIngress",
           "before_state": "sg:sg-0abc open", "after_state": "SSM Success", "ssm_execution_id": "exec-1",
           "occurrence_count": 1, "last_seen_at": iso(NOW - timedelta(minutes=5)),
           "updated_at": iso(NOW - timedelta(minutes=5)), "expires_at": int(time.time()) + 86400,
           "reason": "보안그룹 전체 공개 규칙 회수(화이트리스트 + 태그)", "control_id": "EC2.19", "record_version": 3}
    row.update(over)
    return row


def ssm_execution(status="Success", before=SG_BEFORE, after=SG_AFTER, **extra):
    return {"status": status, "document": "ASR-RevokeSecurityGroupIngress", "failureMessage": None,
            "startedAt": now_ms() - 600000, "endedAt": now_ms() - 590000,
            "steps": [{"name": "revokeOpenIngress", "action": "aws:executeScript", "status": status,
                       "outputs": {"before": [before], "after": [after], "revoked_count": ["1"]}, "failureMessage": None}],
            **extra}


class DetailProvider(Provider):
    """조치 이력 Provider + SSM 실행 결과·경보."""

    def __init__(self, rows=(), executions=None, fail_execution=False, alarm_items=None, alarm_fail=False, **kw):
        super().__init__(rows, **kw)
        self.executions, self.fail_execution = executions or {}, fail_execution
        self.alarm_items, self.alarm_fail, self.fetched = alarm_items, alarm_fail, []

    def execution(self, execution_id, fetch=True):
        if self.fail_execution:
            raise RuntimeError("AccessDeniedException: internal")
        if not fetch:
            return False, None
        self.fetched.append(execution_id)
        raw = self.executions.get(execution_id)
        return True, evidence(raw) if raw else None

    def alarms(self):
        if self.alarm_fail:
            raise RuntimeError("throttled")
        if self.alarm_items is None:
            return {"configured": False, "items": []}
        return {"configured": True, "items": self.alarm_items}

    def resources(self, query=None):
        return {"items": [{"id": "i-0aaa", "name": "docker-host", "region": "ap-northeast-2",
                           "accountId": "111122223333", "role": "service-3tier"}], "total": 1}

    def services(self, query=None, events=None):
        return {"items": [{"id": "i-0aaa", "name": "docker-host", "status": "UP", "source": "EC2", "detail": "running",
                           "tier": "service-3tier"}], "dependencies": [], "checkedAt": now_ms()}


# --- SSM 실행 결과 → 조치 전/후 -------------------------------------------------------------

def test_describe_turns_asr_outputs_into_readable_lines():
    assert describe(SG_BEFORE) == ["TCP 3306 ← 0.0.0.0/0", "TCP 443 ← 10.0.0.0/16"]
    nacl = json.dumps([{"RuleNumber": 32767, "RuleAction": "deny", "Protocol": "-1", "CidrBlock": "0.0.0.0/0", "Egress": False},
                       {"RuleNumber": 1, "RuleAction": "deny", "Protocol": "-1", "CidrBlock": "10.0.2.15/32", "Egress": False},
                       {"RuleNumber": 100, "RuleAction": "allow", "Protocol": "6", "PortRange": {"From": 443, "To": 443},
                        "CidrBlock": "0.0.0.0/0", "Egress": False}])
    assert describe(nacl) == ["규칙 1 차단 전체 ← 10.0.2.15/32", "규칙 100 허용 TCP 443 ← 0.0.0.0/0"]
    default_sg = json.dumps({"inbound": [{"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": "sg-0def"}]}], "outbound": []})
    assert describe(default_sg) == ["인바운드 전체 ← sg-0def"]
    assert describe(json.dumps({"BlockPublicAcls": True})) == ["BlockPublicAcls = true"]
    assert describe(json.dumps({})) == ["(설정 없음)"] and describe(json.dumps([])) == ["(규칙 없음)"]
    assert describe("EBS 기본 암호화=False") == ["EBS 기본 암호화=False"] and describe(None) is None


def test_evidence_lists_what_changed_and_reads_payload_fallback():
    got = evidence(ssm_execution())
    assert got["removed"] == ["TCP 3306 ← 0.0.0.0/0"] and got["added"] == [] and got["changed"] is True
    payload = {"status": "Success", "steps": [{"name": "s", "outputs": {"OutputPayload": [json.dumps(
        {"Payload": {"before": "공개 공유 권한=Enable", "after": "공개 공유 권한=Disable", "changed": True}})]}}]}
    assert evidence(payload)["added"] == ["공개 공유 권한=Disable"] and evidence(payload)["changed"] is True
    failed = evidence({"status": "Failed", "failureMessage": "Step fails when it is executing", "steps": []})
    assert failed["failureMessage"].startswith("Step fails") and failed["before"] is None and evidence(None) is None


def test_empty_rule_lists_are_not_counted_as_changes():
    default_sg = ssm_execution(before=json.dumps({"inbound": [{"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": "sg-0d"}]}],
                                                  "outbound": []}),
                               after=json.dumps({"inbound": [], "outbound": []}))
    got = evidence(default_sg)
    assert got["removed"] == ["인바운드 전체 ← sg-0d"] and got["added"] == [] and got["after"] == ["(규칙 없음)"]


def test_record_titles_cover_controls_bruteforce_tokens_and_guardduty_types():
    from soar.guidance import control_title
    assert control_title("EC2.2") == "VPC 기본 보안그룹에 규칙이 남아 있음"
    assert control_title("SEC-06B").startswith("SSH 접속 시도 거부 급증")
    assert control_title(None, "UnauthorizedAccess:IAMUser/MaliciousIPCaller") == "알려진 악성 IP 에서 API 호출"
    assert control_title("Macie.1", "unknown") is None


def test_history_shows_reason_control_and_ssm_before_after_as_execution_not_resolution(tmp_path):
    provider = DetailProvider([record()], executions={"exec-1": ssm_execution()})
    auto = client_for(tmp_path, provider).get("/api/history").json["data"]["items"][0]
    assert auto["reason"].startswith("보안그룹") and auto["controlId"] == "EC2.19"
    assert auto["controlTitle"] == "보안그룹이 위험 포트를 인터넷에 공개"
    assert auto["execution"]["removed"] == ["TCP 3306 ← 0.0.0.0/0"]
    assert auto["execution"]["source"] == "ssm-output" and auto["execution"]["verification"] == "NOT_RUN"
    assert auto["beforeState"]["source"] == "ssm-output" and "3306" in auto["beforeState"]["text"]
    assert auto["actionState"] == "EXECUTED" and auto["verification"] == "NOT_RUN"  # 실행 ≠ 해결


def test_old_records_without_reason_or_execution_keep_their_text(tmp_path):
    old = record(action_id="fnd-1", decision="manual-notified", status="NOTIFIED", ssm_execution_id="n/a",
                 reason=None, control_id=None, record_version=None)
    old.pop("reason"), old.pop("control_id")
    row = client_for(tmp_path, DetailProvider([old])).get("/api/history").json["data"]["items"][0]
    assert row["reason"] is None and row["controlId"] is None and row["execution"] is None
    assert row["beforeState"]["source"] == "asr_trigger"


def test_ssm_lookup_is_budgeted_and_failures_are_reported(tmp_path, monkeypatch):
    import soar.contracts as contracts
    monkeypatch.setattr(contracts, "EXECUTION_FETCH_LIMIT", 1)
    rows = [record(action_id=f"ssm-{i}", ssm_execution_id=f"exec-{i}") for i in range(3)]
    provider = DetailProvider(rows, executions={f"exec-{i}": ssm_execution() for i in range(3)})
    body = client_for(tmp_path, provider).get("/api/history").json
    assert len(provider.fetched) == 1
    assert any("SSM 실행 결과 2건은 다음 새로고침에서 표시" in w for w in body["meta"]["warnings"])
    failing = client_for(tmp_path / "b", DetailProvider([record()], fail_execution=True)).get("/api/history")
    assert failing.status_code == 200 and "SSM 실행 결과(조치 전/후)를 불러오지 못했습니다." in failing.json["meta"]["warnings"]
    assert "internal" not in failing.get_data(as_text=True)


def test_guardduty_direct_records_link_to_the_event_by_finding_id_tail(tmp_path):
    rows = [record(action_id="ssm-key", finding_id="gd-1", control_id="n/a", ssm_execution_id="n/a",
                   playbook_id="ASR-DisableExposedAccessKey")]
    provider = DetailProvider(rows)
    client = client_for(tmp_path, provider)
    assert client.get("/api/history").json["data"]["items"][0]["eventId"] == "SH-GD"
    items = client.get("/api/history?eventId=SH-GD").json["data"]["items"]
    assert [row["actionId"] for row in items] == ["ssm-key"] and provider.asked == "gd-1"


def test_no_change_records_are_not_shown_as_running_or_executed(tmp_path):
    skipped = record(action_id="fnd-skip", decision="auto-skipped", status="NO_CHANGE", ssm_execution_id="n/a",
                     control_id="SEC-06A", reason="인증 실패 12회 · 최다 출발지 10.0.2.15 · 이미 NACL 에서 차단 중")
    row = client_for(tmp_path, DetailProvider([skipped])).get("/api/history").json["data"]["items"][0]
    assert row["automationStatus"] == "NO_CHANGE" and row["actionState"] == "CANCELLED"
    assert row["controlTitle"].startswith("MySQL 무차별 대입")


# --- 통합 관제 요약 ------------------------------------------------------------------------

def test_summary_counts_automation_in_the_period_and_lists_recent(tmp_path):
    rows = [record(),
            record(action_id="ssm-fail", status="FAILED", last_seen_at=iso(NOW - timedelta(minutes=3))),
            record(action_id="fnd-m", decision="manual-notified", status="NOTIFIED", ssm_execution_id="n/a"),
            record(action_id="fnd-old", decision="manual-notified", status="NOTIFIED", ssm_execution_id="n/a",
                   last_seen_at=iso(NOW - timedelta(days=3)), created_at=iso(NOW - timedelta(days=3)))]
    summary = client_for(tmp_path, DetailProvider(rows)).get("/api/summary").json["data"]
    auto = summary["automation"]
    assert auto["configured"] is True and auto["total"] == 3  # 기본 1일 — 3일 전 기록은 빠진다
    assert (auto["autoExecuted"], auto["succeeded"], auto["failed"], auto["manual"]) == (2, 1, 1, 1)
    assert auto["recent"][0]["actionId"] == "ssm-fail" and auto["recent"][0]["controlTitle"]
    assert summary["alarms"] is None  # 경보 설정 없음


def test_summary_automation_reports_missing_table_and_failure_without_breaking(tmp_path):
    assert client_for(tmp_path, DetailProvider(configured=False)).get("/api/summary").json["data"]["automation"] == {"configured": False}
    failing = client_for(tmp_path / "b", DetailProvider(fail=True)).get("/api/summary")
    assert failing.status_code == 200 and failing.json["data"]["automation"] is None


# --- 인프라: 서버 가동·3계층·경보 ---------------------------------------------------------------

def alarm(name, state="OK", reason="Threshold Crossed: 1 datapoint [1.0] was not greater than the threshold (80.0).",
          instance=None, **extra):
    return {"AlarmName": name, "StateValue": state, "StateReason": reason, "MetricName": "m", "Namespace": "n",
            "Threshold": 80.0, "ComparisonOperator": "GreaterThanThreshold", "Period": 300, "EvaluationPeriods": 2,
            "AlarmActions": ["arn:aws:sns:ap-northeast-2:111122223333:alerts"],
            "StateUpdatedTimestamp": NOW - timedelta(minutes=1),
            "Dimensions": [{"Name": "InstanceId", "Value": instance}] if instance else [], **extra}


def test_alarm_names_map_to_scenarios_and_no_data_is_not_healthy():
    policy = AutoPolicy("", "SEC-06A", "true")
    rows = {a["name"]: a for a in (alarm_repo.normalize(item, "soar-sec-dev", "ap-northeast-2", "111122223333", policy) for item in [
        alarm("soar-sec-dev-docker-host-cpu-high", instance="i-0aaa"),
        alarm("soar-sec-dev-mysql-bruteforce", reason="Threshold Crossed: no datapoints were received for 1 period "
                                                      "and 1 missing datapoint was treated as [NonBreaching]."),
        alarm("soar-sec-dev-ssh-reject", state="ALARM"), alarm("soar-sec-dev-waf-sqli"),
        alarm("soar-sec-dev-finding-sync-dlq")])}
    cpu = rows["soar-sec-dev-docker-host-cpu-high"]
    assert (cpu["kind"], cpu["scenario"], cpu["host"], cpu["resource"]) == ("cpu", "SEC-10", "docker-host", "i-0aaa")
    mysql = rows["soar-sec-dev-mysql-bruteforce"]
    assert mysql["noData"] is True and mysql["autoResponse"]["mode"] == "auto"
    assert mysql["needsCheck"] is False  # 사건이 있어야 지표가 생기는 알람의 데이터 없음은 평소 상태
    no_data_reason = "no datapoints were received for 1 period and 1 missing datapoint was treated as [NonBreaching]."
    mem = alarm_repo.normalize(alarm("soar-sec-dev-db-mem-high", reason=no_data_reason), "soar-sec-dev", "r", "a", policy)
    assert mem["noData"] is True and mem["needsCheck"] is True  # 계속 들어와야 하는 지표의 데이터 없음
    insufficient = alarm_repo.normalize(alarm("soar-sec-dev-db-cpu-high", state="INSUFFICIENT_DATA"), "soar-sec-dev", "r", "a", policy)
    assert insufficient["needsCheck"] is True
    assert rows["soar-sec-dev-ssh-reject"]["needsCheck"] is False
    assert rows["soar-sec-dev-ssh-reject"]["autoResponse"]["mode"] == "manual"  # SEC-06B 가 목록에 없음
    assert rows["soar-sec-dev-waf-sqli"]["scenario"] == "SEC-08" and rows["soar-sec-dev-finding-sync-dlq"]["kind"] == "pipeline"


def test_infra_status_splits_servers_marks_tiers_unknown_and_lists_alarms(tmp_path):
    items = [alarm_repo.normalize(a, "soar-sec-dev", "ap-northeast-2", "111122223333") for a in (
        alarm("soar-sec-dev-docker-host-cpu-high", instance="i-0aaa"), alarm("soar-sec-dev-ssh-reject", state="ALARM"))]
    client = client_for(tmp_path, DetailProvider(alarm_items=items))
    data = client.get("/api/infra/status").json["data"]
    assert [c["resource"] for c in data["components"]] == ["i-0aaa"] and data["components"][0]["kind"] == "server"
    assert [t["name"] for t in data["tiers"]] == ["Nginx", "Flask", "MySQL"]
    assert all(t["status"] == "unknown" and t["observedAt"] is None for t in data["tiers"])  # 확인 불가 ≠ 정상
    assert {a["name"] for a in data["alarms"]} == {"soar-sec-dev-docker-host-cpu-high", "soar-sec-dev-ssh-reject"}
    summary = client.get("/api/summary").json["data"]["alarms"]
    assert summary["alarm"] == 1 and summary["firing"][0]["scenario"] == "SEC-06B"
    # 자원 범위 사용자는 자원 없는 알람을 보지 못한다(안전 쪽)
    scoped = client_for(tmp_path / "s", DetailProvider(alarm_items=items),
                        {"accounts": None, "regions": None, "resources": ["i-0aaa"]})
    assert [a["resource"] for a in scoped.get("/api/infra/status").json["data"]["alarms"]] == ["i-0aaa"]


def test_alarm_read_failure_is_a_warning_not_an_empty_healthy_list(tmp_path):
    body = client_for(tmp_path, DetailProvider(alarm_fail=True)).get("/api/infra/status").json
    assert body["data"]["alarms"] is None and body["meta"]["warnings"] == ["CloudWatch 경보 상태를 불러오지 못했습니다."]


# --- AWS 연동: 경보·SSM 실행 결과 --------------------------------------------------------------

class FakeCloudWatch:
    def __init__(self):
        self.calls = []

    def describe_alarms(self, **kw):
        self.calls.append(kw)
        return {"MetricAlarms": [alarm("soar-sec-dev-docker-host-mem-high", instance="i-1")]}


class FakeSsm:
    def __init__(self, missing=False):
        self.calls, self.missing = [], missing

    def get_automation_execution(self, AutomationExecutionId):
        self.calls.append(AutomationExecutionId)
        if self.missing:
            raise ClientError({"Error": {"Code": "AutomationExecutionNotFoundException"}}, "GetAutomationExecution")
        return {"AutomationExecution": {
            "AutomationExecutionStatus": "Success", "DocumentName": "ASR-RevokeSecurityGroupIngress",
            "ExecutionStartTime": NOW - timedelta(minutes=2), "ExecutionEndTime": NOW - timedelta(minutes=1),
            "StepExecutions": [{"StepName": "revokeOpenIngress", "Action": "aws:executeScript", "StepStatus": "Success",
                                "Outputs": {"before": [SG_BEFORE], "after": [SG_AFTER], "revoked_count": ["1"]}}]}}


def aws_provider(ssm, cloudwatch=None, prefix="soar-sec-dev"):
    session = FakeSession("ap-northeast-2")
    session.client = lambda name, **kw: {"ssm": ssm, "cloudwatch": cloudwatch}.get(name) or FakeSession.client(session, name)
    return AwsProvider("ap-northeast-2", session_factory=lambda region: session, name_prefix=prefix,
                       auto_policy=AutoPolicy("", "EC2.2", "true"))


def test_aws_provider_reads_alarms_by_prefix_and_caches():
    cloudwatch = FakeCloudWatch()
    provider = aws_provider(FakeSsm(), cloudwatch)
    first = provider.alarms()
    assert first["configured"] and first["items"][0]["kind"] == "memory" and first["items"][0]["accountId"] == "123456789012"
    provider.alarms()
    assert len(cloudwatch.calls) == 1 and cloudwatch.calls[0]["AlarmNamePrefix"] == "soar-sec-dev-"
    assert aws_provider(FakeSsm(), prefix=None).alarms() == {"configured": False, "items": []}


def test_aws_provider_caches_finished_executions_and_missing_ones():
    ssm = FakeSsm()
    provider = aws_provider(ssm)
    assert provider.execution("exec-1", fetch=False) == (False, None)
    found, got = provider.execution("exec-1")
    assert found and got["removed"] == ["TCP 3306 ← 0.0.0.0/0"]
    provider.execution("exec-1")
    assert ssm.calls == ["exec-1"]  # 끝난 실행은 다시 부르지 않는다
    missing = aws_provider(FakeSsm(missing=True))
    assert missing.execution("gone") == (True, None) and missing.execution("gone") == (True, None)


# --- 취약점 조치 안내 --------------------------------------------------------------------------

def test_update_command_prefers_inspector_and_generates_only_safe_known_cases():
    assert update_command({"remediation": "apt-get install --only-upgrade openssl"}, "AWS_EC2_INSTANCE", None) == \
        ("apt-get install --only-upgrade openssl", "inspector")
    assert update_command({"name": "openssl", "packageManager": "OS"}, "AWS_EC2_INSTANCE", "UBUNTU_24_04")[0] == \
        "sudo apt-get update && sudo apt-get install --only-upgrade -y openssl"
    assert update_command({"name": "kernel", "packageManager": "OS"}, "AWS_EC2_INSTANCE", "AMAZON_LINUX_2023")[0] == \
        "sudo dnf upgrade -y kernel"
    assert update_command({"name": "requests", "packageManager": "PIP", "fixedInVersion": "2.32.3"},
                          "AWS_EC2_INSTANCE", "UBUNTU_24_04")[0] == "pip install --upgrade 'requests==2.32.3'"
    assert update_command({"name": "openssl; rm -rf /", "packageManager": "OS"}, "AWS_EC2_INSTANCE", "UBUNTU_24_04") == (None, None)
    assert update_command({"name": "openssl", "packageManager": "OS"}, "AWS_ECR_CONTAINER_IMAGE", None) == (None, None)
