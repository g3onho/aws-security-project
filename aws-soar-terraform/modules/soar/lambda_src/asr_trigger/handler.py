"""
asr_trigger — Security Hub / GuardDuty finding 을 받아 자동조치 여부를 판정합니다.

안전장치 3중:
  1) 화이트리스트 패턴 매칭 (AUTO_REMEDIABLE_PATTERNS)  <- 1차 판단 기준(finding 유형)
  2) 대상 리소스의 AutoRemediation=enabled 태그          <- 2차(자원 허용 여부)
  3) ENABLE_AUTO_REMEDIATION 변수                          <- 전체 dry-run 스위치

모두 통과하면 finding 유형에 맞는 SSM Automation(ASR-*)을 실행하고,
통과하지 못하면 SNS 로 담당자에게 알림만 보냅니다(수동 조치 경로).

조치 전/후 비교(Before-After)는 SSM 문서가 반환하는 값을 이 함수가
DynamoDB 조치 이력 테이블에 직접 기록해 보장합니다.

조치 이력 기록 규칙 (v20)
  - 같은 finding 에 같은 판정(manual-notified / dry-run)이 반복되면 새 행을 만들지 않고
    occurrence_count·last_seen_at 만 갱신한다(action_id = fnd-<finding+판정 해시>).
  - 자동 실행은 실행마다 새 행(action_id = ssm-<SSM 실행 ID>). SSM 종료 이벤트가 같은 행의
    status·after_state 를 갱신한다(aws.ssm 이벤트도 이 함수가 받는다).
  - expires_at 이 지난 행은 DynamoDB TTL 이 지운다(ACTION_TTL_DAYS).
  - 기록 실패는 로그만 남기고 알림(SNS)·조치는 계속한다.
"""
import os
import re
import json
import time
import hashlib
import datetime
import boto3
from boto3.dynamodb.conditions import Key

REGION = os.environ["AWS_REGION"]
ACCOUNT_ID = os.environ["ACCOUNT_ID"]
ACTIONS_TABLE = os.environ["REMEDIATION_ACTIONS_TABLE"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
ENABLE_AUTO = os.environ.get("ENABLE_AUTO_REMEDIATION", "false").lower() == "true"
PATTERNS = [p for p in os.environ.get("AUTO_REMEDIABLE_PATTERNS", "").split(",") if p]

DOC_REVOKE_SG = os.environ["DOC_REVOKE_SG"]
DOC_DISABLE_KEY = os.environ["DOC_DISABLE_KEY"]
DOC_NGINX_HARDEN = os.environ["DOC_NGINX_HARDEN"]
AUTOMATION_ROLE_ARN = os.environ["AUTOMATION_ROLE_ARN"]
TTL_DAYS = int(os.environ.get("ACTION_TTL_DAYS", "30"))

# 판정 → 조치 이력 status. SSM 종료 이벤트가 IN_PROGRESS 를 결과로 바꾼다.
STATUS = {"manual-notified": "NOTIFIED", "dry-run": "DRY_RUN", "auto-executed": "IN_PROGRESS"}
TERMINAL = {"Success": "SUCCESS", "CompletedWithSuccess": "SUCCESS", "Failed": "FAILED",
            "CompletedWithFailure": "FAILED", "TimedOut": "TIMED_OUT", "Cancelled": "CANCELLED"}

ssm = boto3.client("ssm")
ec2 = boto3.client("ec2")
sns = boto3.client("sns")
dynamodb = boto3.resource("dynamodb")


def _now():
    return datetime.datetime.utcnow().isoformat() + "Z"


def _matches_whitelist(text):
    return any(re.search(re.escape(p), text, re.IGNORECASE) for p in PATTERNS)


def _sg_has_auto_tag(group_id):
    try:
        resp = ec2.describe_security_groups(GroupIds=[group_id])
    except Exception as exc:  # noqa: BLE001
        print(f"describe_security_groups failed: {exc}")
        return False
    for sg in resp.get("SecurityGroups", []):
        for tag in sg.get("Tags", []):
            if tag["Key"] == "AutoRemediation" and tag["Value"] == "enabled":
                return True
    return False


def _action_id(detail, decision, exec_id):
    if exec_id:
        return "ssm-" + exec_id  # SSM 종료 이벤트가 이 키로 결과를 갱신한다
    digest = hashlib.sha256(f"{detail.get('finding_id', 'unknown')}|{decision}".encode()).hexdigest()[:32]
    return "fnd-" + digest


def _record(decision, detail, before=None, after=None, exec_id=None, playbook=None):
    table = dynamodb.Table(ACTIONS_TABLE)
    now = _now()
    action_id = _action_id(detail, decision, exec_id)
    expires_at = int(time.time()) + TTL_DAYS * 86400
    if not exec_id:
        # 같은 finding·같은 판정의 반복 → 기존 행의 횟수·마지막 시각만 갱신(키는 바꾸지 않는다).
        found = table.query(KeyConditionExpression=Key("action_id").eq(action_id), Limit=1).get("Items") or []
        if found:
            table.update_item(
                Key={"action_id": action_id, "created_at": found[0]["created_at"]},
                UpdateExpression="SET occurrence_count = if_not_exists(occurrence_count, :first) + :one, "
                                 "last_seen_at = :now, updated_at = :now, expires_at = :exp",
                ExpressionAttributeValues={":first": 1, ":one": 1, ":now": now, ":exp": expires_at})
            return action_id
    table.put_item(Item={
        "action_id": action_id,
        "created_at": now,
        # 어느 finding 때문에 이 조치가 났는지. 대시보드가 이 값으로 조인합니다.
        "finding_id": detail.get("finding_id", "unknown"),
        "decision": decision,          # auto-executed / manual-notified / dry-run
        "status": STATUS.get(decision, "UNKNOWN"),
        "finding_type": detail.get("finding_type", "unknown"),
        "resource_id": detail.get("resource_id", "n/a"),
        "region": detail.get("region") or REGION,
        "account_id": detail.get("account_id") or ACCOUNT_ID,
        "playbook_id": playbook or "n/a",
        "before_state": before or "n/a",
        "after_state": after or "pending",
        "ssm_execution_id": exec_id or "n/a",
        "occurrence_count": 1,
        "last_seen_at": now,
        "updated_at": now,
        "expires_at": expires_at,
        "record_version": 2,
    })
    return action_id


def _safe_record(*args, **kwargs):
    """기록 실패가 알림·조치를 막지 않게 한다."""
    try:
        return _record(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001
        print(f"action history write failed: {exc}")
        return None


def _handle_automation_result(event):
    """SSM Automation 종료 이벤트 → 같은 조치 이력 행의 status·after_state 갱신."""
    d = event.get("detail", {})
    status, exec_id = TERMINAL.get(d.get("Status")), d.get("ExecutionId")
    if not status or not exec_id:
        return {"updated": False, "reason": "not a terminal automation status"}
    table = dynamodb.Table(ACTIONS_TABLE)
    found = table.query(KeyConditionExpression=Key("action_id").eq("ssm-" + exec_id), Limit=1).get("Items") or []
    if not found:
        # 대시보드·CLI 가 직접 시작한 실행은 이 함수의 기록이 없다.
        return {"updated": False, "reason": "execution not started by asr_trigger"}
    now = _now()
    table.update_item(
        Key={"action_id": "ssm-" + exec_id, "created_at": found[0]["created_at"]},
        UpdateExpression="SET #s = :s, after_state = :a, updated_at = :now, completed_at = :now",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": status, ":a": f"SSM {d.get('Status')}", ":now": now})
    return {"updated": True, "status": status}


def _notify(subject, message):
    if SNS_TOPIC_ARN:
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject[:99], Message=message)


def _parse_finding(event):
    """Security Hub / GuardDuty 이벤트에서 필요한 값만 뽑습니다."""
    detail = event.get("detail", {})
    # Security Hub custom action / imported finding
    findings = detail.get("findings")
    if findings:
        f = findings[0]
        ftype = f.get("Types", ["unknown"])[0] if f.get("Types") else f.get("GeneratorId", "unknown")
        gen = f.get("GeneratorId", "")
        resource_id = ""
        group_id = ""
        for r in f.get("Resources", []):
            if r.get("Type") == "AwsEc2SecurityGroup":
                resource_id = r.get("Id", "")
                group_id = resource_id.split("/")[-1]
            elif not resource_id:
                resource_id = r.get("Id", "")
        return {
            # finding 원본 ID. 조치 이력(remediation_actions)과 finding 을 잇는 유일한 키입니다.
            "finding_id": f.get("Id") or "unknown",
            "finding_type": f.get("Title", ftype),
            "generator": gen,
            "match_text": " ".join([f.get("Title", ""), ftype, gen]),
            "resource_id": resource_id,
            "group_id": group_id,
            "access_key_id": "",
            "region": f.get("Region") or event.get("region") or REGION,
            "account_id": f.get("AwsAccountId") or event.get("account") or ACCOUNT_ID,
        }
    # GuardDuty direct
    gd_type = detail.get("type", "unknown")
    res = detail.get("resource", {})
    access_key = res.get("accessKeyDetails", {}).get("accessKeyId", "")
    return {
        "finding_id": detail.get("id") or event.get("id") or "unknown",
        "finding_type": gd_type,
        "generator": "guardduty",
        "match_text": gd_type,
        "resource_id": res.get("instanceDetails", {}).get("instanceId", ""),
        "group_id": "",
        "access_key_id": access_key,
        "region": detail.get("region") or event.get("region") or REGION,
        "account_id": detail.get("accountId") or event.get("account") or ACCOUNT_ID,
    }


def _start_automation(doc_name, params):
    return ssm.start_automation_execution(
        DocumentName=doc_name,
        Parameters={**params, "AutomationAssumeRole": [AUTOMATION_ROLE_ARN]},
    )["AutomationExecutionId"]


def handler(event, _context):
    if event.get("source") == "aws.ssm":
        return _handle_automation_result(event)
    detail = _parse_finding(event)
    text = detail["match_text"]

    # 안전장치 1 — 화이트리스트
    if not _matches_whitelist(text):
        _safe_record("manual-notified", detail)
        _notify(f"[수동조치 필요] {detail['finding_type']}",
                f"화이트리스트 미포함 finding. 대시보드에서 검토/승인하세요.\n{json.dumps(detail, ensure_ascii=False)}")
        return {"decision": "manual-notified", "reason": "not in whitelist"}

    # 안전장치 3 — 전체 dry-run
    if not ENABLE_AUTO:
        _safe_record("dry-run", detail)
        _notify(f"[dry-run] {detail['finding_type']}",
                "ENABLE_AUTO_REMEDIATION=false. 판단만 하고 실행하지 않았습니다.")
        return {"decision": "dry-run"}

    # finding 유형별 분기
    ftype = (detail["finding_type"] + " " + detail["generator"]).lower()

    # (A) SG 포트 노출 -> 인바운드 회수. 안전장치 2(SG 태그) 확인.
    if "port" in ftype or "sg" in ftype or "ssh" in ftype or "ingress" in ftype or "3306" in text:
        group_id = detail["group_id"]
        if not group_id:
            _safe_record("manual-notified", detail)
            _notify("[수동조치] 대상 SG 미확인", json.dumps(detail, ensure_ascii=False))
            return {"decision": "manual-notified", "reason": "no group id"}
        if not _sg_has_auto_tag(group_id):
            _safe_record("manual-notified", detail, before=f"sg:{group_id}")
            _notify(f"[수동조치] {group_id} 는 AutoRemediation 태그 없음(대조군)",
                    "db-manual-sg 등 태그 없는 대상은 승인 후 수동 조치합니다.")
            return {"decision": "manual-notified", "reason": "no auto tag"}
        exec_id = _start_automation(DOC_REVOKE_SG, {"SecurityGroupId": [group_id]})
        _safe_record("auto-executed", detail, before=f"sg:{group_id} open", after="revoke in progress",
                     exec_id=exec_id, playbook=DOC_REVOKE_SG)
        _notify(f"[자동조치 실행] SG {group_id} 규칙 회수", f"SSM execution: {exec_id}")
        return {"decision": "auto-executed", "playbook": DOC_REVOKE_SG, "execution": exec_id}

    # (B) IAM Access Key 노출 -> 비활성화
    if "credential" in ftype or "unauthorizedaccess" in ftype or detail["access_key_id"]:
        key_id = detail["access_key_id"]
        if not key_id:
            _safe_record("manual-notified", detail)
            _notify("[수동조치] 노출 키 ID 미확인", json.dumps(detail, ensure_ascii=False))
            return {"decision": "manual-notified", "reason": "no access key id"}
        exec_id = _start_automation(DOC_DISABLE_KEY, {"AccessKeyId": [key_id]})
        _safe_record("auto-executed", detail, before=f"key:{key_id} Active", after="Inactive in progress",
                     exec_id=exec_id, playbook=DOC_DISABLE_KEY)
        _notify(f"[자동조치 실행] Access Key {key_id} 비활성화", f"SSM execution: {exec_id}")
        return {"decision": "auto-executed", "playbook": DOC_DISABLE_KEY, "execution": exec_id}

    # 화이트리스트엔 있지만 처리기가 없는 경우
    _safe_record("manual-notified", detail)
    _notify(f"[수동조치] 처리기 없음: {detail['finding_type']}", json.dumps(detail, ensure_ascii=False))
    return {"decision": "manual-notified", "reason": "no handler"}
