"""
block_expiry — IP 차단(Private NACL 1~99 Deny)의 만료·해제를 마무리합니다 (v25, DEC-021).

EventBridge 가 5분마다 부릅니다. 한 번에 두 가지를 합니다.
  1) 만료: status=ACTIVE 이고 expires_at 이 지난 행 → ASR-UnblockIpWithNacl 실행 → status=RELEASING
     (expires_at 이 없는 행은 영구 차단이라 건드리지 않는다.)
  2) 마무리: status=RELEASING 인 행 → SSM 실행 결과를 보고
       Success → EXPIRED(만료) / RELEASED(대시보드 오탐 해제), Failed·TimedOut → ACTIVE 로 되돌림
     대시보드의 오탐 해제도 같은 RELEASING 상태를 쓰므로 이 함수가 마무리한다
     (대시보드도 조회할 때 같은 규칙으로 마무리한다 — 이 함수를 끈 배포에서도 해제가 끝나도록).

안전장치
  - 지우기 전에 NACL 을 다시 읽어 "그 번호 = 인바운드 Deny + 그 IP/32" 일 때만 실행한다. 아니면(이미 없음·번호 재사용)
    지울 것이 없으므로 행만 마무리한다. 문서도 같은 확인을 한 번 더 한다.
  - 만료 자동 재시도는 MAX_ATTEMPTS 번까지. 넘으면 ACTIVE 로 두고 알림만 보낸다(사람이 확인).
  - 조건부 갱신(status·version)으로 대시보드·이 함수가 같은 행을 동시에 바꿔도 한 쪽만 적용된다.
  - 조치 이력(REMEDIATION_ACTIONS_TABLE)에 실행마다 한 줄 남긴다. SSM 종료 이벤트가 같은 줄의 결과를 갱신한다(asr_trigger).
"""
import datetime
import os
import time

import boto3
from botocore.exceptions import ClientError

BLOCKLIST_TABLE = os.environ["IP_BLOCKLIST_TABLE"]
ACTIONS_TABLE = os.environ["REMEDIATION_ACTIONS_TABLE"]
DOC_UNBLOCK_IP = os.environ["DOC_UNBLOCK_IP"]
AUTOMATION_ROLE_ARN = os.environ["AUTOMATION_ROLE_ARN"]
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
ACTION_TTL_DAYS = int(os.environ.get("ACTION_TTL_DAYS", "30"))
MAX_ATTEMPTS = 3  # 만료 해제 자동 재시도 상한
STUCK_SECONDS = 300  # RELEASING 인데 실행 ID 가 없는 행을 되돌리는 기준(대시보드 blocklist_service.STUCK_RELEASE_MS 와 같은 값)

ssm = boto3.client("ssm")
ec2 = boto3.client("ec2")
sns = boto3.client("sns")
dynamodb = boto3.resource("dynamodb")

SUCCESS = {"Success", "CompletedWithSuccess"}
FAILURE = {"Failed", "CompletedWithFailure", "TimedOut", "Cancelled", "Rejected"}


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _epoch(text):
    try:
        return datetime.datetime.fromisoformat(str(text).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _rows():
    table = dynamodb.Table(BLOCKLIST_TABLE)
    items, kwargs = [], {}
    while True:
        page = table.scan(**kwargs)
        items.extend(page.get("Items", []))
        if "LastEvaluatedKey" not in page:
            return items
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]


def _notify(subject, message):
    if SNS_TOPIC_ARN:
        try:
            sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject[:99], Message=message)
        except Exception as exc:  # noqa: BLE001 — 알림 실패가 해제를 막지 않는다
            print(f"notify failed: {exc}")


def _nacl_has_deny(nacl_id, rule, ip):
    """그 NACL 에 (번호 = rule, 인바운드, Deny, CIDR = ip/32) 규칙이 아직 있는가."""
    acl = ec2.describe_network_acls(NetworkAclIds=[nacl_id])["NetworkAcls"][0]
    return any(e.get("RuleNumber") == rule and not e.get("Egress") and e.get("RuleAction") == "deny"
               and e.get("CidrBlock") == f"{ip}/32" for e in acl.get("Entries", []))


def _update(ip, sets, values, names=None, condition=None, remove=None):
    """조건부 갱신. 조건이 안 맞으면(다른 쪽이 먼저 바꿈) False."""
    expr = "SET " + ", ".join(sets) + ", version = if_not_exists(version, :zero) + :one"
    if remove:
        expr += " REMOVE " + ", ".join(remove)
    kwargs = {"Key": {"ip": ip}, "UpdateExpression": expr,
              "ExpressionAttributeValues": {**values, ":one": 1, ":zero": 0}}
    if names:
        kwargs["ExpressionAttributeNames"] = names
    if condition:
        kwargs["ConditionExpression"] = condition
    try:
        dynamodb.Table(BLOCKLIST_TABLE).update_item(**kwargs)
        return True
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return False
        raise


def _record_action(ip, row, exec_id, reason, control):
    """조치 이력 한 줄(대시보드 조치 이력에 보인다). 실패해도 해제는 계속."""
    now = _now()
    try:
        dynamodb.Table(ACTIONS_TABLE).put_item(Item={
            "action_id": "ssm-" + exec_id, "created_at": now, "finding_id": f"blocklist:{ip}",
            "decision": "auto-executed", "status": "IN_PROGRESS",
            "finding_type": "차단 IP 해제 (NACL Deny 삭제)",
            "resource_id": f"{row.get('nacl_id')} ← {ip}/32",
            "region": os.environ.get("AWS_REGION", ""), "account_id": "",
            "playbook_id": DOC_UNBLOCK_IP, "before_state": f"규칙 {row.get('rule_number')} Deny {ip}/32",
            "after_state": "해제 중", "ssm_execution_id": exec_id, "occurrence_count": 1,
            "last_seen_at": now, "updated_at": now,
            "expires_at": int(time.time()) + ACTION_TTL_DAYS * 86400,
            "reason": reason, "control_id": control, "record_version": 3})
    except Exception as exc:  # noqa: BLE001
        print(f"action history write failed: {exc}")


def _start_unblock(ip, row):
    return ssm.start_automation_execution(
        DocumentName=DOC_UNBLOCK_IP,
        Parameters={"NetworkAclId": [row["nacl_id"]], "AttackerCidr": [f"{ip}/32"],
                    "RuleNumber": [str(int(row["rule_number"]))], "AutomationAssumeRole": [AUTOMATION_ROLE_ARN]},
    )["AutomationExecutionId"]


def _expire(row, now_epoch):
    """만료된 ACTIVE 한 건 → 해제 시작 또는 (지울 것이 없으면) 바로 EXPIRED."""
    ip, version = row["ip"], int(row.get("version", 0))
    attempts = int(row.get("release_attempts", 0))
    if attempts >= MAX_ATTEMPTS:
        return {"ip": ip, "result": "manual", "reason": f"자동 해제 {attempts}회 실패 — 대시보드에서 확인"}
    if not (row.get("nacl_id") and row.get("rule_number") is not None):
        return {"ip": ip, "result": "skipped", "reason": "NACL·규칙 번호 기록 없음"}
    if not _nacl_has_deny(row["nacl_id"], int(row["rule_number"]), ip):
        done = _update(ip, ["#s = :s", "released_at = :at", "released_by = :by", "release_reason = :r",
                            "release_kind = :k", "updated_at = :at"],
                       {":s": "EXPIRED", ":at": _now(), ":by": "system", ":k": "expiry", ":a": "ACTIVE", ":v": version,
                        ":r": "만료 — NACL 에 해당 Deny 규칙이 이미 없음"},
                       names={"#s": "status"}, condition="#s = :a AND version = :v")
        return {"ip": ip, "result": "expired-no-rule" if done else "conflict"}
    exec_id = _start_unblock(ip, row)
    started = _update(ip, ["#s = :s", "release_kind = :k", "released_by = :by", "release_reason = :r",
                           "unblock_execution_id = :x", "release_attempts = :n", "updated_at = :at"],
                      {":s": "RELEASING", ":k": "expiry", ":by": "system", ":r": "차단 기간 만료",
                       ":x": exec_id, ":n": attempts + 1, ":at": _now(), ":a": "ACTIVE", ":v": version},
                      names={"#s": "status"}, condition="#s = :a AND version = :v")
    if not started:
        return {"ip": ip, "result": "conflict", "execution": exec_id}  # 다른 쪽이 먼저 처리. 문서는 멱등이라 무해
    _record_action(ip, row, exec_id, "차단 기간 만료로 자동 해제", "UNBLOCK-EXPIRY")
    _notify(f"[차단 만료] {ip} 해제 시작", f"NACL {row['nacl_id']} 규칙 {row['rule_number']}\nSSM execution: {exec_id}")
    return {"ip": ip, "result": "releasing", "execution": exec_id}


def _finish(row):
    """RELEASING 한 건 → SSM 결과로 EXPIRED/RELEASED 또는 ACTIVE 복귀."""
    ip, version, exec_id = row["ip"], int(row.get("version", 0)), row.get("unblock_execution_id")
    if not exec_id:
        # 해제 시작(SSM) 전에 프로세스가 멈췄거나 시작에 실패한 행. 잠시 기다린 뒤에도 실행 ID 가 없으면 차단 상태로 되돌린다.
        started = _epoch(row.get("updated_at"))
        if started is not None and time.time() - started > STUCK_SECONDS:
            ok = _update(ip, ["#s = :s", "last_error = :e", "updated_at = :at"],
                         {":s": "ACTIVE", ":e": "해제 시작 실패(실행 ID 없음) — 되돌림", ":at": _now(), ":r": "RELEASING", ":v": version},
                         names={"#s": "status"}, condition="#s = :r AND version = :v")
            return {"ip": ip, "result": "reverted" if ok else "conflict", "reason": "실행 ID 없음"}
        return {"ip": ip, "result": "skipped", "reason": "실행 ID 없음"}
    try:
        status = ssm.get_automation_execution(AutomationExecutionId=exec_id)["AutomationExecution"][
            "AutomationExecutionStatus"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "AutomationExecutionNotFoundException":
            raise
        status = "NotFound"
    names, common = {"#s": "status"}, {":r": "RELEASING", ":v": version, ":at": _now()}
    if status in SUCCESS:
        final = "EXPIRED" if row.get("release_kind") == "expiry" else "RELEASED"
        ok = _update(ip, ["#s = :s", "released_at = :at", "updated_at = :at"], {**common, ":s": final},
                     names=names, condition="#s = :r AND version = :v", remove=["last_error"])
        return {"ip": ip, "result": final.lower() if ok else "conflict"}
    if status in FAILURE or status == "NotFound":
        ok = _update(ip, ["#s = :s", "last_error = :e", "updated_at = :at"],
                     {**common, ":s": "ACTIVE", ":e": f"해제 SSM {status}"},
                     names=names, condition="#s = :r AND version = :v")
        if ok:
            _notify(f"[해제 실패] {ip}", f"SSM {status} ({exec_id}). 차단은 그대로 유지됩니다.")
        return {"ip": ip, "result": "reverted" if ok else "conflict", "ssm": status}
    return {"ip": ip, "result": "in-progress", "ssm": status}


def handler(event, _context):
    now_epoch = int(time.time())
    out = {"released": [], "finished": [], "errors": []}
    for row in _rows():
        try:
            if row.get("status") == "RELEASING":
                out["finished"].append(_finish(row))
            elif (row.get("status") == "ACTIVE" and row.get("expires_at") is not None
                  and int(row["expires_at"]) <= now_epoch):
                out["released"].append(_expire(row, now_epoch))
        except Exception as exc:  # noqa: BLE001 — 한 건 실패가 나머지를 막지 않는다
            print(f"block_expiry failed for {row.get('ip')}: {exc}")
            out["errors"].append({"ip": row.get("ip"), "error": type(exc).__name__})
    print(out)
    return out
