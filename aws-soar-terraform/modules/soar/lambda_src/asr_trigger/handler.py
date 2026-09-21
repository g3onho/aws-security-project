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
"""
import os
import re
import json
import datetime
import boto3

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


def _record(action_id, decision, detail, before=None, after=None, exec_id=None):
    dynamodb.Table(ACTIONS_TABLE).put_item(Item={
        "action_id": action_id,
        "created_at": _now(),
        # 어느 finding 때문에 이 조치가 났는지. 대시보드가 이 값으로 조인합니다.
        "finding_id": detail.get("finding_id", "unknown"),
        "decision": decision,          # auto-executed / manual-notified / dry-run
        "finding_type": detail.get("finding_type", "unknown"),
        "resource_id": detail.get("resource_id", "n/a"),
        "before_state": before or "n/a",
        "after_state": after or "pending",
        "ssm_execution_id": exec_id or "n/a",
    })


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
    }


def _start_automation(doc_name, params):
    return ssm.start_automation_execution(
        DocumentName=doc_name,
        Parameters={**params, "AutomationAssumeRole": [AUTOMATION_ROLE_ARN]},
    )["AutomationExecutionId"]


def handler(event, _context):
    detail = _parse_finding(event)
    action_id = f"asr-{int(datetime.datetime.utcnow().timestamp())}"
    text = detail["match_text"]

    # 안전장치 1 — 화이트리스트
    if not _matches_whitelist(text):
        _record(action_id, "manual-notified", detail)
        _notify(f"[수동조치 필요] {detail['finding_type']}",
                f"화이트리스트 미포함 finding. 대시보드에서 검토/승인하세요.\n{json.dumps(detail, ensure_ascii=False)}")
        return {"decision": "manual-notified", "reason": "not in whitelist"}

    # 안전장치 3 — 전체 dry-run
    if not ENABLE_AUTO:
        _record(action_id, "dry-run", detail)
        _notify(f"[dry-run] {detail['finding_type']}",
                "ENABLE_AUTO_REMEDIATION=false. 판단만 하고 실행하지 않았습니다.")
        return {"decision": "dry-run"}

    # finding 유형별 분기
    ftype = (detail["finding_type"] + " " + detail["generator"]).lower()

    # (A) SG 포트 노출 -> 인바운드 회수. 안전장치 2(SG 태그) 확인.
    if "port" in ftype or "sg" in ftype or "ssh" in ftype or "ingress" in ftype or "3306" in text:
        group_id = detail["group_id"]
        if not group_id:
            _record(action_id, "manual-notified", detail)
            _notify("[수동조치] 대상 SG 미확인", json.dumps(detail, ensure_ascii=False))
            return {"decision": "manual-notified", "reason": "no group id"}
        if not _sg_has_auto_tag(group_id):
            _record(action_id, "manual-notified", detail, before=f"sg:{group_id}")
            _notify(f"[수동조치] {group_id} 는 AutoRemediation 태그 없음(대조군)",
                    "db-manual-sg 등 태그 없는 대상은 승인 후 수동 조치합니다.")
            return {"decision": "manual-notified", "reason": "no auto tag"}
        exec_id = _start_automation(DOC_REVOKE_SG, {"SecurityGroupId": [group_id]})
        _record(action_id, "auto-executed", detail, before=f"sg:{group_id} open", after="revoke in progress", exec_id=exec_id)
        _notify(f"[자동조치 실행] SG {group_id} 규칙 회수", f"SSM execution: {exec_id}")
        return {"decision": "auto-executed", "playbook": DOC_REVOKE_SG, "execution": exec_id}

    # (B) IAM Access Key 노출 -> 비활성화
    if "credential" in ftype or "unauthorizedaccess" in ftype or detail["access_key_id"]:
        key_id = detail["access_key_id"]
        if not key_id:
            _record(action_id, "manual-notified", detail)
            _notify("[수동조치] 노출 키 ID 미확인", json.dumps(detail, ensure_ascii=False))
            return {"decision": "manual-notified", "reason": "no access key id"}
        exec_id = _start_automation(DOC_DISABLE_KEY, {"AccessKeyId": [key_id]})
        _record(action_id, "auto-executed", detail, before=f"key:{key_id} Active", after="Inactive in progress", exec_id=exec_id)
        _notify(f"[자동조치 실행] Access Key {key_id} 비활성화", f"SSM execution: {exec_id}")
        return {"decision": "auto-executed", "playbook": DOC_DISABLE_KEY, "execution": exec_id}

    # 화이트리스트엔 있지만 처리기가 없는 경우
    _record(action_id, "manual-notified", detail)
    _notify(f"[수동조치] 처리기 없음: {detail['finding_type']}", json.dumps(detail, ensure_ascii=False))
    return {"decision": "manual-notified", "reason": "no handler"}
