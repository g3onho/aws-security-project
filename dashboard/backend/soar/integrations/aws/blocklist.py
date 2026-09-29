"""차단 IP 목록 AWS 경계: DynamoDB 표(ip_blocklist)·NACL 조회·해제 SSM 시작·조치 이력 기록.

표는 asr_trigger(차단 기록)·block_expiry(만료)와 같이 쓴다. 이 모듈의 쓰기는 전부 조건부 갱신(status·version)이며,
항목 삭제·표 전체 쓰기는 하지 않는다. 대시보드 IAM 도 UpdateItem·PutItem 만 허용한다.
"""
import hashlib
import time
from datetime import datetime, timezone

from boto3.dynamodb.types import TypeDeserializer, TypeSerializer
from botocore.exceptions import ClientError

from .paging import collect
from .dynamodb import _plain

_ser, _de = TypeSerializer(), TypeDeserializer()


def _typed(values):
    return {key: _ser.serialize(value) for key, value in values.items()}


def _row(item):
    return _plain({k: _de.deserialize(v) for k, v in item.items()})


class BlocklistStore:
    def __init__(self, session, table, nacl_id, unblock_document, automation_role_arn, actions_table=None,
                 action_ttl_days=30):
        self._session = session
        self.table = table
        self.nacl_id = nacl_id
        self.unblock_document = unblock_document
        self.automation_role_arn = automation_role_arn
        self.actions_table = actions_table
        self.action_ttl_days = action_ttl_days

    # --- 읽기 -----------------------------------------------------------------------
    def rows(self):
        items = collect(self._session.client("dynamodb"), "scan", "Items", TableName=self.table)
        return [_row(item) for item in items]

    def row(self, ip):
        got = self._session.client("dynamodb").get_item(TableName=self.table, Key=_typed({"ip": ip}), ConsistentRead=True)
        return _row(got["Item"]) if got.get("Item") else None

    def nacl_denies(self):
        """NACL 인바운드 Deny /32 규칙(번호 1~99) → {ip: 규칙 번호}. NACL 을 못 읽으면 예외."""
        acls = self._session.client("ec2").describe_network_acls(NetworkAclIds=[self.nacl_id])["NetworkAcls"]
        found = {}
        for entry in (acls[0].get("Entries") if acls else []) or []:
            cidr, number = entry.get("CidrBlock") or "", entry.get("RuleNumber") or 0
            if (not entry.get("Egress") and entry.get("RuleAction") == "deny" and 1 <= number <= 99
                    and cidr.endswith("/32")):
                found[cidr[:-3]] = number
        return found

    # --- 조건부 쓰기 ------------------------------------------------------------------
    def update(self, ip, sets, remove=(), condition=None):
        """sets: {속성: 값}. condition: (식, 이름 토큰 {"#c0": 속성}, 값 토큰 {":c0": 값}) — 토큰은 #c·:c 로 시작해야
        이 함수의 토큰(#a·#r·#v·:a·:one·:zero)과 겹치지 않는다. 조건이 안 맞으면 False(다른 쪽이 먼저 바꿈).
        버전은 자동으로 1 올린다."""
        names, values, parts = {"#v": "version"}, {":one": 1, ":zero": 0}, []
        for n, (attr, value) in enumerate(sorted(sets.items())):
            names[f"#a{n}"], values[f":a{n}"] = attr, value
            parts.append(f"#a{n} = :a{n}")
        expr = "SET " + ", ".join(parts) + ", #v = if_not_exists(#v, :zero) + :one"
        for n, attr in enumerate(remove):
            names[f"#r{n}"] = attr
        if remove:
            expr += " REMOVE " + ", ".join(f"#r{n}" for n in range(len(remove)))
        kwargs = {"TableName": self.table, "Key": _typed({"ip": ip}), "UpdateExpression": expr}
        if condition:
            kwargs["ConditionExpression"] = condition[0]
            names.update(condition[1])
            values.update(condition[2])
        kwargs["ExpressionAttributeNames"], kwargs["ExpressionAttributeValues"] = names, _typed(values)
        try:
            self._session.client("dynamodb").update_item(**kwargs)
            return True
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return False
            raise

    def create_unrecorded(self, ip, sets):
        """표에 기록이 없던 수동 차단을 해제할 때 행을 새로 만든다(이미 있으면 False)."""
        item = {"ip": ip, "version": 1, **sets}
        try:
            self._session.client("dynamodb").put_item(
                TableName=self.table, Item=_typed(item), ConditionExpression="attribute_not_exists(ip)")
            return True
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return False
            raise

    def start_unblock(self, ip, nacl_id, rule_number, token_seed):
        """ASR-UnblockIpWithNacl 시작. 같은 요청(token_seed)의 재시도는 SSM 이 같은 실행으로 돌려준다."""
        client_token = hashlib.sha256(token_seed.encode()).hexdigest()[:32]
        return self._session.client("ssm").start_automation_execution(
            DocumentName=self.unblock_document,
            Parameters={"NetworkAclId": [nacl_id], "AttackerCidr": [f"{ip}/32"], "RuleNumber": [str(rule_number)],
                        "AutomationAssumeRole": [self.automation_role_arn]},
            ClientToken=client_token)["AutomationExecutionId"]

    def record_action(self, ip, nacl_id, rule_number, execution_id, actor, reason, control):
        """조치 이력에 한 줄(대시보드 조치 이력·asr_trigger 의 SSM 종료 갱신과 같은 형식)."""
        if not self.actions_table:
            return False
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        item = {"action_id": "ssm-" + execution_id, "created_at": now, "finding_id": f"blocklist:{ip}",
                "decision": "auto-executed", "status": "IN_PROGRESS", "finding_type": "차단 IP 해제 (NACL Deny 삭제)",
                "resource_id": f"{nacl_id} ← {ip}/32", "region": self._session.region, "account_id": "",
                "playbook_id": self.unblock_document, "before_state": f"규칙 {rule_number} Deny {ip}/32",
                "after_state": "해제 중", "ssm_execution_id": execution_id, "occurrence_count": 1,
                "last_seen_at": now, "updated_at": now,
                "expires_at": int(time.time()) + self.action_ttl_days * 86400,
                "reason": f"{actor} 요청: {reason}"[:500], "control_id": control, "record_version": 3}
        self._session.client("dynamodb").put_item(TableName=self.actions_table, Item=_typed(item))
        return True
