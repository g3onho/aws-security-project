"""SSM StartAutomationExecution ClientToken 형식 — 데모 프로바이더는 이 경로를 안 타므로 따로 검증한다."""
import re

from soar.integrations.aws.remediation import RemediationGateway

UUID = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")


class _Ssm:
    def __init__(self):
        self.calls = []

    def start_automation_execution(self, **kw):
        self.calls.append(kw)
        return {"AutomationExecutionId": "exec-1"}


class _Session:
    def __init__(self, ssm):
        self.ssm = ssm

    def client(self, name):
        assert name == "ssm"
        return self.ssm


def _gateway(ssm):
    g = RemediationGateway.__new__(RemediationGateway)
    g._session, g.automation_role_arn = _Session(ssm), "arn:aws:iam::1:role/auto"
    return g


def test_client_token_is_36_char_uuid_and_stable_per_seed():
    ssm = _Ssm()
    g = _gateway(ssm)
    g.start("ASR-RevokeSecurityGroupIngress", {"SecurityGroupId": "sg-1"}, "ev|key-1")
    g.start("ASR-RevokeSecurityGroupIngress", {"SecurityGroupId": "sg-1"}, "ev|key-1")
    g.start("ASR-RevokeSecurityGroupIngress", {"SecurityGroupId": "sg-1"}, "ev|key-2")
    a, b, c = (call["ClientToken"] for call in ssm.calls)
    assert len(a) == 36 and UUID.match(a), a
    assert a == b          # 같은 요청 재시도는 같은 실행(멱등)
    assert a != c          # 다른 요청은 다른 실행
