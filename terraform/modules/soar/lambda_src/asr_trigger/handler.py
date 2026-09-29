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
  - reason(판정 이유)·control_id(규칙 ID)를 함께 남긴다. 대시보드 조치 이력이 "왜 자동/수동인지"를 보여준다.

자동 조치 확장 (decisions.md DEC-017·DEC-018)
  - Security Hub 규칙 ID 가 AUTO_REMEDIABLE_CONTROLS 에 **정확히** 있으면 규칙별 ASR 문서를 실행한다.
    (패턴 부분 일치를 쓰지 않는 이유: "EC2.2" 가 EC2.21·EC2.22 까지 잡힌다.)
    대상은 재부팅이 없고 Terraform 이 관리하지 않는 계정·리전 설정뿐이다(CONTROL_PLAYBOOKS).
    같은 finding 의 자동 실행이 IN_PROGRESS 면 다시 실행하지 않는다. 문서는 현재 상태를 먼저 읽고
    이미 준수 상태면 바꾸지 않는다(멱등). 게이트: 규칙 목록(①) + 전체 dry-run 스위치(③).
  - AUTO_REMEDIABLE_CONTROLS 에 "SEC-06A" 가 있으면 MySQL 인증 실패 알람(ALARM)에서 MySQL 오류 로그를,
    "SEC-06B" 가 있으면 SSH(22) 거부 알람(ALARM)에서 VPC Flow Logs 의 REJECT 기록을 읽어(방화벽 거부 로그처럼)
    최다 출발지 IP 1개를 Private NACL 1~99 번대 Deny 로 막는다(ASR-BlockIpWithNacl).
    VPC CIDR 밖 주소·보호 자산 주소는 막지 않고 알림만 보낸다. 이미 막힌 IP 면 실행하지 않는다.

차단 IP 목록 (v25, DEC-021)
  - IP_BLOCKLIST_TABLE 이 있으면 차단을 시작할 때 그 표에 ACTIVE 행(규칙 번호·만료 시각·근거)을 올린다. 만료·해제는
    block_expiry Lambda 와 대시보드가 ASR-UnblockIpWithNacl 로 처리한다. 차단 SSM 이 실패하면 행은 FAILED 가 된다.
  - 표에서 allowlisted=true 인 IP(오탐 예외)는 자동 차단하지 않고 '수동 대응 필요'로만 기록한다.
"""
import os
import re
import json
import time
import hashlib
import datetime
import ipaddress
import boto3
from boto3.dynamodb.conditions import Key

REGION = os.environ["AWS_REGION"]
ACCOUNT_ID = os.environ["ACCOUNT_ID"]
ACTIONS_TABLE = os.environ["REMEDIATION_ACTIONS_TABLE"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
ENABLE_AUTO = os.environ.get("ENABLE_AUTO_REMEDIATION", "false").lower() == "true"
PATTERNS = [p for p in os.environ.get("AUTO_REMEDIABLE_PATTERNS", "").split(",") if p]
# 규칙 ID 정확 일치 목록(DEC-017) + "SEC-06A"(DEC-018).
CONTROLS = {c.strip() for c in os.environ.get("AUTO_REMEDIABLE_CONTROLS", "").split(",") if c.strip()}

DOC_REVOKE_SG = os.environ["DOC_REVOKE_SG"]
DOC_DISABLE_KEY = os.environ["DOC_DISABLE_KEY"]
DOC_NGINX_HARDEN = os.environ["DOC_NGINX_HARDEN"]
DOC_BLOCK_IP = os.environ.get("DOC_BLOCK_IP", "")
AUTOMATION_ROLE_ARN = os.environ["AUTOMATION_ROLE_ARN"]
TTL_DAYS = int(os.environ.get("ACTION_TTL_DAYS", "30"))
FINDING_INDEX = os.environ.get("ACTIONS_FINDING_INDEX", "finding_id-created_at")

# 규칙 ID → (문서 이름 환경변수, 조치 이름). 항목을 늘리면 SSM 문서·자동화 역할 권한·변수 기본값·
# decisions.md 를 함께 바꾼다. 재부팅이 필요한 조치·Terraform 이 소유한 속성은 넣지 않는다.
CONTROL_PLAYBOOKS = {
    "EC2.2": ("DOC_DEFAULT_SG", "기본 보안그룹 규칙 제거"),
    "EC2.7": ("DOC_EBS_ENCRYPTION", "EBS 기본 암호화 켜기"),
    "EC2.182": ("DOC_SNAPSHOT_BPA", "EBS 스냅샷 공개 차단"),
    "S3.1": ("DOC_S3_ACCOUNT_BPA", "S3 계정 퍼블릭 액세스 차단"),
    "IAM.7": ("DOC_PASSWORD_POLICY", "IAM 비밀번호 정책 강화"),
    "SSM.6": ("DOC_SSM_AUTOMATION_LOG", "SSM Automation 로그 켜기"),
    "SSM.7": ("DOC_SSM_PUBLIC_SHARING", "SSM 문서 공개 공유 차단"),
}

# SEC-06A — MySQL 인증 실패 알람 / SEC-06B — SSH(22) 거부 알람 → 공격 IP NACL 차단
MYSQL_ALARM_NAME = os.environ.get("MYSQL_ALARM_NAME", "")
MYSQL_LOG_GROUP = os.environ.get("MYSQL_LOG_GROUP", "")
SSH_ALARM_NAME = os.environ.get("SSH_ALARM_NAME", "")
# A6 — 미끼서버(허니팟) 접속 알람 → 공격 IP NACL 차단 (HONEYPOT). 접속 자체가 신호.
HONEYPOT_ALARM_NAME = os.environ.get("HONEYPOT_ALARM_NAME", "")
HONEYPOT_LOG_GROUP = os.environ.get("HONEYPOT_LOG_GROUP", "")
FLOWLOG_GROUP = os.environ.get("FLOWLOG_GROUP", "")
# 지표 필터와 같은 패턴(cloudwatch.tf local.ssh_reject_pattern) — 알람이 센 기록만 다시 읽는다.
FLOWLOG_REJECT_PATTERN = os.environ.get("FLOWLOG_REJECT_PATTERN", "")
# 알람이 본 구간(period × evaluation_periods). reasonData 를 못 읽을 때만 쓴다.
ALARM_WINDOW_SECONDS = int(os.environ.get("ALARM_WINDOW_SECONDS", "300"))
PRIVATE_NACL_ID = os.environ.get("PRIVATE_NACL_ID", "")
# EC2.2 는 이 VPC 의 기본 보안그룹만 자동 조치한다(계정 기본 VPC 등은 수동). 비우면 VPC 확인을 문서에 맡기지 못해 수동.
PROJECT_VPC_ID = os.environ.get("PROJECT_VPC_ID", "")
VPC_CIDR = os.environ.get("VPC_CIDR", "")
# 이 역할 태그의 인스턴스 주소는 절대 막지 않는다(보호 대상 서비스·시연 DB·대시보드).
PROTECTED_ROLES = [r for r in os.environ.get("PROTECTED_ROLES", "service-3tier,database,soar-dashboard").split(",") if r]
# v25(DEC-021) 차단 IP 목록: 차단을 기록하고(만료 시각 포함), 오탐 예외로 등록된 IP 는 자동 차단하지 않는다.
# 테이블 설정이 없으면 두 기능 모두 건너뛴다(이전 배포와 같은 동작).
IP_BLOCKLIST_TABLE = os.environ.get("IP_BLOCKLIST_TABLE", "")
IP_BLOCK_TTL_HOURS = int(os.environ.get("IP_BLOCK_TTL_HOURS", "24"))  # 0 = 영구
# 시연용 분 단위 차단 기간. 0 이면 쓰지 않고 위 시간 단위 설정을 따른다. 0 보다 크면 시간 단위 설정보다 우선한다.
IP_BLOCK_TTL_MINUTES = int(os.environ.get("IP_BLOCK_TTL_MINUTES", "0"))
LOG_PAGE_LIMIT = 10  # FilterLogEvents 페이지 상한(Lambda 시간 초과 방지). 알람 구간 로그는 보통 1쪽이다.
# 사용자 이름은 공격자가 정한다('x'@'10.0.1.25' 같은 값을 넣을 수 있다). 줄 끝의 비밀번호 표시 바로 앞 host 만 믿는다.
AUTH_FAIL = re.compile(r"Access denied for user '.*'@'([^']+)' \(using password: (?:YES|NO)\)\s*$")
MAX_SOAR_DENY = 10  # ASR-BlockIpWithNacl 의 1~99 Deny 동시 상한과 같은 값
EC2_HOSTNAME = re.compile(r"^ip-(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})(?:\.|$)")

# 판정 → 조치 이력 status. SSM 종료 이벤트가 IN_PROGRESS 를 결과로 바꾼다.
STATUS = {"manual-notified": "NOTIFIED", "dry-run": "DRY_RUN", "auto-executed": "IN_PROGRESS",
          "auto-skipped": "NO_CHANGE"}
TERMINAL = {"Success": "SUCCESS", "CompletedWithSuccess": "SUCCESS", "Failed": "FAILED",
            "CompletedWithFailure": "FAILED", "TimedOut": "TIMED_OUT", "Cancelled": "CANCELLED"}

ssm = boto3.client("ssm")
ec2 = boto3.client("ec2")
sns = boto3.client("sns")
logs = boto3.client("logs")
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
    # 알람 경로는 finding ID 가 알람 ARN 하나라 IP 까지 넣는다(dedupe_key). IP 가 다르면 다른 줄.
    key = detail.get("dedupe_key") or detail.get("finding_id", "unknown")
    digest = hashlib.sha256(f"{key}|{decision}".encode()).hexdigest()[:32]
    return "fnd-" + digest


def _record(decision, detail, before=None, after=None, exec_id=None, playbook=None, reason=None, control=None):
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
                                 "last_seen_at = :now, updated_at = :now, expires_at = :exp, reason = :r",
                ExpressionAttributeValues={":first": 1, ":one": 1, ":now": now, ":exp": expires_at,
                                           ":r": reason or "n/a"})
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
        # 왜 이 판정인지(대시보드 조치 이력 표시). 규칙 ID 는 Security Hub 규칙이면 EC2.2 처럼, SEC-06A 는 그대로.
        "reason": reason or "n/a",
        "control_id": control or "n/a",
        "record_version": 3,
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
    if status != "SUCCESS":
        _mark_block_failed(found[0], exec_id, d.get("Status"))
    return {"updated": True, "status": status}


def _notify(subject, message):
    if SNS_TOPIC_ARN:
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject[:99], Message=message)


def _control_id(finding):
    """Security Hub 규칙 ID(EC2.2 등). 통합 규칙 finding 은 Compliance.SecurityControlId,
    예전 형식은 ProductFields.ControlId, 둘 다 없으면 GeneratorId 끝(security-control/EC2.2)."""
    control = (finding.get("Compliance") or {}).get("SecurityControlId") \
        or (finding.get("ProductFields") or {}).get("ControlId")
    if control:
        return str(control)
    match = re.search(r"([A-Za-z0-9]+\.\d+)$", finding.get("GeneratorId") or "")
    return match.group(1) if match else ""


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
        vpc_id = ""
        for r in f.get("Resources", []):
            if r.get("Type") == "AwsEc2SecurityGroup":
                resource_id = r.get("Id", "")
                group_id = resource_id.split("/")[-1]
                vpc_id = ((r.get("Details") or {}).get("AwsEc2SecurityGroup") or {}).get("VpcId", "")
            elif not resource_id:
                resource_id = r.get("Id", "")
        return {
            # finding 원본 ID. 조치 이력(remediation_actions)과 finding 을 잇는 유일한 키입니다.
            "finding_id": f.get("Id") or "unknown",
            "finding_type": f.get("Title", ftype),
            "generator": gen,
            "control_id": _control_id(f),
            "match_text": " ".join([f.get("Title", ""), ftype, gen]),
            "resource_id": resource_id,
            "group_id": group_id,
            "vpc_id": vpc_id,
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
        "control_id": "",
        "match_text": gd_type,
        "resource_id": res.get("instanceDetails", {}).get("instanceId", ""),
        "group_id": "",
        "vpc_id": "",
        "access_key_id": access_key,
        "region": detail.get("region") or event.get("region") or REGION,
        "account_id": detail.get("accountId") or event.get("account") or ACCOUNT_ID,
    }


def _start_automation(doc_name, params):
    return ssm.start_automation_execution(
        DocumentName=doc_name,
        Parameters={**params, "AutomationAssumeRole": [AUTOMATION_ROLE_ARN]},
    )["AutomationExecutionId"]


# --- 규칙 ID 자동 조치 (DEC-017) --------------------------------------------------

def _in_progress(finding_id):
    """같은 finding 의 자동 실행이 아직 끝나지 않았으면 True. 조회 실패는 False(문서가 멱등이라 재실행이
    무해하다 — 현재 상태를 먼저 읽고 이미 준수 상태면 바꾸지 않는다)."""
    try:
        items = dynamodb.Table(ACTIONS_TABLE).query(
            IndexName=FINDING_INDEX, KeyConditionExpression=Key("finding_id").eq(finding_id)).get("Items") or []
    except Exception as exc:  # noqa: BLE001
        print(f"in-progress lookup failed: {exc}")
        return False
    return any(i.get("decision") == "auto-executed" and i.get("status") == "IN_PROGRESS" for i in items)


def _remediate_control(detail):
    control = detail["control_id"]
    doc_env, label = CONTROL_PLAYBOOKS[control]
    doc = os.environ.get(doc_env, "")
    reason = f"{control} 자동 조치 대상({label})"
    if not ENABLE_AUTO:
        _safe_record("dry-run", detail, reason=reason + " · 전체 dry-run", control=control)
        _notify(f"[dry-run] {control} {label}", "ENABLE_AUTO_REMEDIATION=false. 판단만 하고 실행하지 않았습니다.")
        return {"decision": "dry-run", "control": control}
    problem = ("문서 이름 설정 없음" if not doc else
               f"finding 리전({detail['region']})이 Lambda 리전({REGION})과 다름" if detail["region"] != REGION else
               None)
    if control == "EC2.2" and not problem:
        problem = ("대상 보안그룹 ID 없음" if not detail["group_id"] else
                   "프로젝트 VPC ID 설정 없음" if not PROJECT_VPC_ID else
                   f"프로젝트 VPC({PROJECT_VPC_ID}) 밖의 기본 보안그룹({detail['vpc_id']})"
                   if detail["vpc_id"] and detail["vpc_id"] != PROJECT_VPC_ID else None)
    if problem:
        _safe_record("manual-notified", detail, reason=f"{control} 자동 조치 불가: {problem}", control=control)
        _notify(f"[수동조치] {control} {label}", f"{problem}\n{json.dumps(detail, ensure_ascii=False)}")
        return {"decision": "manual-notified", "reason": problem}
    if _in_progress(detail["finding_id"]):
        return {"decision": "skipped", "reason": "same finding remediation in progress"}
    params = {"SecurityGroupId": [detail["group_id"]], "VpcId": [PROJECT_VPC_ID]} if control == "EC2.2" else {}
    exec_id = _start_automation(doc, params)
    _safe_record("auto-executed", detail, before=f"{control} 위반", after=f"{label} 실행 중",
                 exec_id=exec_id, playbook=doc, reason=reason, control=control)
    _notify(f"[자동조치 실행] {control} {label}", f"SSM execution: {exec_id}")
    return {"decision": "auto-executed", "control": control, "playbook": doc, "execution": exec_id}


# --- SEC-06A MySQL · SEC-06B SSH 무차별 대입 → 공격 IP NACL 차단 (DEC-018·DEC-019) ---------

# 알람 종류 → (목록 토큰, 조치 이력에 보일 이름)
BRUTEFORCE_KINDS = {"mysql": ("SEC-06A", "MySQL 무차별 대입 (SEC-06A)"),
                    "ssh": ("SEC-06B", "SSH 접속 시도 거부 급증 (SEC-06B · Flow Logs)"),
                    "honeypot": ("HONEYPOT", "미끼서버 접속 (A6 허니팟)")}


def _bruteforce_kind(event):
    """알람이 ALARM 으로 바뀐 이벤트면 'mysql' / 'ssh' / 'honeypot', 아니면 None."""
    d = event.get("detail", {})
    if event.get("source") != "aws.cloudwatch" or (d.get("state") or {}).get("value") != "ALARM":
        return None
    name = d.get("alarmName")
    if MYSQL_ALARM_NAME and name == MYSQL_ALARM_NAME:
        return "mysql"
    if SSH_ALARM_NAME and name == SSH_ALARM_NAME:
        return "ssh"
    if HONEYPOT_ALARM_NAME and name == HONEYPOT_ALARM_NAME:
        return "honeypot"
    return None


def _parse_time(text):
    for pattern in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.datetime.strptime(text, pattern)
        except (TypeError, ValueError):
            continue
    return None


def _alarm_window(detail):
    """알람이 평가한 구간 [시작, 끝] (epoch ms). reasonData 의 startDate·period·recentDatapoints 로 계산하고,
    못 읽으면 상태 시각 기준 ALARM_WINDOW_SECONDS(= period × evaluation_periods) 전부터."""
    state = detail.get("state") or {}
    try:
        data = json.loads(state.get("reasonData") or "{}")
    except ValueError:
        data = {}
    start = _parse_time(data.get("startDate"))
    if start and data.get("period"):
        span = int(data["period"]) * max(1, len(data.get("recentDatapoints") or [1]))
        begin = int(start.timestamp() * 1000)
        return begin, begin + span * 1000
    end_at = _parse_time(state.get("timestamp")) or datetime.datetime.now(datetime.timezone.utc)
    end = int(end_at.timestamp() * 1000)
    return end - ALARM_WINDOW_SECONDS * 1000, end


def _host_ip(host):
    """IPv4 주소 또는 EC2 사설 호스트명(ip-10-0-2-55…) → 주소. 올바른 IPv4 가 아니면 None."""
    match = EC2_HOSTNAME.match(host)
    candidate = ".".join(match.groups()) if match else host
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return str(address) if address.version == 4 else None


def _mysql_source(message):
    match = AUTH_FAIL.search(message)
    return _host_ip(match.group(1)) if match else None


def _honeypot_source(message):
    """미끼서버 접속 로그(JSON 한 줄, {"event":"connect","src_ip":...})의 출발지."""
    try:
        return _host_ip(json.loads(message).get("src_ip", ""))
    except (ValueError, AttributeError):
        return None


def _flowlog_source(message):
    """Flow Logs 기본 형식(v2): version account eni srcaddr dstaddr srcport dstport protocol packets bytes
    start end action log-status. 22번(TCP) REJECT 인 행의 srcaddr."""
    fields = message.split()
    if len(fields) < 14 or fields[6] != "22" or fields[7] != "6" or fields[12] != "REJECT":
        return None
    return _host_ip(fields[3])


def _failure_sources(kind, start, end):
    """알람 구간 로그 → {출발지 IP: 횟수}. mysql = MySQL 오류 로그, ssh = VPC Flow Logs 22번 거부 기록."""
    sources = {"mysql": (MYSQL_LOG_GROUP, '"Access denied for user"', _mysql_source),
               "ssh": (FLOWLOG_GROUP, FLOWLOG_REJECT_PATTERN, _flowlog_source),
               "honeypot": (HONEYPOT_LOG_GROUP, '{ $.event = "connect" }', _honeypot_source)}
    group, pattern, parse = sources[kind]
    counts, token = {}, None
    for _ in range(LOG_PAGE_LIMIT):
        kwargs = {"logGroupName": group, "startTime": start, "endTime": end, "filterPattern": pattern}
        if token:
            kwargs["nextToken"] = token
        page = logs.filter_log_events(**kwargs)
        for event in page.get("events", []):
            ip = parse(event.get("message", ""))
            if ip:
                counts[ip] = counts.get(ip, 0) + 1
        token = page.get("nextToken")
        if not token:
            break
    return counts


def _protected_ips():
    """막으면 안 되는 사설 IP: 보호 자산(PROTECTED_ROLES 태그) 인스턴스, 그리고 프로젝트 VPC 의 AWS 관리 ENI
    (ALB 노드·VPC 엔드포인트·NAT 등 — 막으면 서비스·SSM 경로가 끊긴다)."""
    ips = set()
    if PROJECT_VPC_ID:
        vpc_filter = [{"Name": "vpc-id", "Values": [PROJECT_VPC_ID]}]
        for eni in ec2.describe_network_interfaces(Filters=vpc_filter).get("NetworkInterfaces", []):
            if eni.get("RequesterManaged") or eni.get("InterfaceType", "interface") != "interface":
                ips.update(a["PrivateIpAddress"] for a in eni.get("PrivateIpAddresses", []) if a.get("PrivateIpAddress"))
    resp = ec2.describe_instances(Filters=[{"Name": "tag:Role", "Values": PROTECTED_ROLES}])
    for reservation in resp.get("Reservations", []):
        for instance in reservation.get("Instances", []):
            if instance.get("PrivateIpAddress"):
                ips.add(instance["PrivateIpAddress"])
            for eni in instance.get("NetworkInterfaces", []):
                ips.update(a["PrivateIpAddress"] for a in eni.get("PrivateIpAddresses", []) if a.get("PrivateIpAddress"))
    return ips


def _nacl_ingress(nacl_id):
    acl = ec2.describe_network_acls(NetworkAclIds=[nacl_id])["NetworkAcls"][0]
    return [e for e in acl.get("Entries", []) if not e.get("Egress")]


def _allowlisted_ips(candidates):
    """차단 목록 표에서 오탐 예외(allowlisted=true)로 등록된 IP 집합. 표 설정이 없으면 빈 집합.
    읽기에 실패하면 예외를 그대로 올린다(호출부가 수동 대응으로 돌린다 — 예외 IP 를 실수로 막지 않기 위해)."""
    if not IP_BLOCKLIST_TABLE:
        return set()
    table = dynamodb.Table(IP_BLOCKLIST_TABLE)
    found = set()
    for ip in candidates:
        item = table.get_item(Key={"ip": ip}, ConsistentRead=True).get("Item")
        if item and item.get("allowlisted") is True:
            found.add(ip)
    return found


def _block_ttl_seconds():
    """차단 기간(초). 분 단위 설정(시연용)이 있으면 그것을, 없으면 시간 단위 설정을 쓴다. 0 = 영구."""
    if IP_BLOCK_TTL_MINUTES > 0:
        return IP_BLOCK_TTL_MINUTES * 60
    return max(IP_BLOCK_TTL_HOURS, 0) * 3600


def _record_block(ip, rule, token, count, exec_id, alarm_name):
    """차단 시작 시 차단 목록 표에 ACTIVE 행을 올린다(upsert). 예외 등록·버전은 유지하고 해제 흔적은 지운다.
    SSM 실행이 실패하면 _handle_automation_result 가 FAILED 로 바꾼다. 기록 실패는 차단·알림을 막지 않는다."""
    if not IP_BLOCKLIST_TABLE:
        return
    now = int(time.time())
    names = {"#s": "status", "#src": "source", "#v": "version"}
    values = {":s": "ACTIVE", ":r": rule, ":n": PRIVATE_NACL_ID, ":src": token, ":at": _now(),
              ":ev": {"hits": count, "alarm": alarm_name}, ":x": exec_id, ":one": 1}
    sets = ("#s = :s, rule_number = :r, nacl_id = :n, #src = :src, blocked_at = :at, evidence = :ev, "
            "ssm_execution_id = :x, updated_at = :at, allowlisted = if_not_exists(allowlisted, :f)")
    values[":f"] = False
    ttl_seconds = _block_ttl_seconds()
    if ttl_seconds > 0:
        sets += ", expires_at = :exp"
        values[":exp"] = now + ttl_seconds
    remove = "released_at, released_by, release_reason, release_kind, unblock_execution_id, last_error, release_attempts"
    if ttl_seconds <= 0:
        remove += ", expires_at"
    try:
        dynamodb.Table(IP_BLOCKLIST_TABLE).update_item(
            Key={"ip": ip}, ExpressionAttributeNames=names, ExpressionAttributeValues=values,
            UpdateExpression=f"SET {sets} ADD #v :one REMOVE {remove}")
    except Exception as exc:  # noqa: BLE001
        print(f"ip blocklist write failed: {exc}")


def _mark_block_failed(action_row, exec_id, ssm_status):
    """차단 SSM 실행이 실패로 끝나면 차단 목록 행을 FAILED 로(그 실행이 만든 행일 때만)."""
    if not IP_BLOCKLIST_TABLE or action_row.get("playbook_id") != DOC_BLOCK_IP or not DOC_BLOCK_IP:
        return
    match = re.search(r"← (\d{1,3}(?:\.\d{1,3}){3})/32$", action_row.get("resource_id", ""))
    if not match:
        return
    try:
        dynamodb.Table(IP_BLOCKLIST_TABLE).update_item(
            Key={"ip": match.group(1)}, UpdateExpression="SET #s = :f, last_error = :e, updated_at = :now",
            ConditionExpression="ssm_execution_id = :x AND #s = :a",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":f": "FAILED", ":e": f"차단 SSM {ssm_status}", ":now": _now(),
                                       ":x": exec_id, ":a": "ACTIVE"})
    except Exception as exc:  # noqa: BLE001 — 조건 불일치(다른 실행이 갱신)도 여기로 온다
        print(f"ip blocklist failure mark skipped: {exc}")


def _block_bruteforce_source(event, kind):
    d = event.get("detail", {})
    token, title = BRUTEFORCE_KINDS[kind]
    alarm_arn = (event.get("resources") or [None])[0] or f"alarm:{d.get('alarmName')}"
    detail = {"finding_id": alarm_arn, "finding_type": title,
              "resource_id": PRIVATE_NACL_ID or "n/a", "region": event.get("region") or REGION,
              "account_id": event.get("account") or ACCOUNT_ID}

    def manual(problem):
        _safe_record("manual-notified", detail, reason=f"{token} 자동 차단 불가: {problem}", control=token)
        _notify(f"[수동조치] {title}", problem)
        return {"decision": "manual-notified", "reason": problem}

    if token not in CONTROLS:
        return manual(f"자동 차단 대상 목록(AUTO_REMEDIABLE_CONTROLS)에 {token} 없음")
    source_group = {"mysql": MYSQL_LOG_GROUP, "ssh": FLOWLOG_GROUP, "honeypot": HONEYPOT_LOG_GROUP}[kind]
    if not (DOC_BLOCK_IP and PRIVATE_NACL_ID and source_group and VPC_CIDR
            and (kind != "ssh" or FLOWLOG_REJECT_PATTERN)):
        return manual("차단 설정 누락(문서·NACL·로그 그룹·VPC CIDR)")
    start, end = _alarm_window(d)
    try:
        counts = _failure_sources(kind, start, end)
    except Exception as exc:  # noqa: BLE001 — 권한·로그 그룹 문제로 Lambda 가 죽으면 이력·알림이 안 남는다
        return manual(f"로그 조회 실패({source_group}): {type(exc).__name__}")
    if not counts:
        hint = {"mysql": "로그 전송 경로·logs 엔드포인트 확인",
                "ssh": "Flow Logs 로그 그룹 수집 확인",
                "honeypot": "미끼서버 로그 전송 확인"}[kind]
        return manual(f"알람 구간 로그에서 출발지 IP 를 찾지 못함({hint})")
    # 막을 수 없는 주소(VPC 밖·보호 자산)와 이미 막힌 주소를 먼저 빼고 남은 최다 출발지를 고른다.
    # 이미 막힌 IP 도 Flow Logs 에는 REJECT 로 계속 남으므로, 빼지 않으면 새 공격 IP 를 가린다.
    entries = _nacl_ingress(PRIVATE_NACL_ID)
    denied_cidrs = {e.get("CidrBlock") for e in entries if e.get("RuleAction") == "deny"}
    network, protected = ipaddress.ip_network(VPC_CIDR, strict=False), _protected_ips()
    try:
        allowlisted = _allowlisted_ips([c for c in counts if c not in protected])
    except Exception as exc:  # noqa: BLE001
        return manual(f"오탐 예외 목록 확인 실패({type(exc).__name__}) — 예외 IP 를 막지 않도록 자동 차단 보류")
    skipped = []
    ip = count = None
    for candidate, hits in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        why = (f"{candidate} 는 VPC CIDR({VPC_CIDR}) 밖 주소" if ipaddress.ip_address(candidate) not in network else
               f"{candidate} 는 보호 자산 주소" if candidate in protected else
               f"{candidate} 는 오탐 예외 등록 IP(자동 차단 제외)" if candidate in allowlisted else
               "blocked" if f"{candidate}/32" in denied_cidrs else None)
        if why is None:
            ip, count = candidate, hits
            break
        skipped.append((candidate, hits, why))
    label = {"mysql": "인증 실패", "ssh": "22번 거부", "honeypot": "미끼 접속"}[kind]
    if ip is None:
        top, hits, why = skipped[0]
        detail["resource_id"] = f"{PRIVATE_NACL_ID} ← {top}/32"
        detail["dedupe_key"] = f"{alarm_arn}|{top}"
        if all(w == "blocked" for _, _, w in skipped):
            _safe_record("auto-skipped", detail, reason=f"{label} {hits}회 · 최다 출발지 {top} · 이미 NACL 에서 차단 중",
                         control=token)
            return {"decision": "auto-skipped", "ip": top, "reason": "already blocked"}
        return manual(next(w for _, _, w in skipped if w != "blocked"))
    cidr = f"{ip}/32"
    detail["resource_id"] = f"{PRIVATE_NACL_ID} ← {cidr}"
    detail["dedupe_key"] = f"{alarm_arn}|{ip}"  # 반복 판정 한 줄 = 알람 + IP (IP 가 바뀌면 새 줄)
    reason = f"{label} {count}회 · 최다 출발지 {ip}" + (
        f" (이미 차단·제외 {len(skipped)}개 주소 건너뜀)" if skipped else "")
    if not ENABLE_AUTO:
        _safe_record("dry-run", detail, reason=reason + " · 전체 dry-run", control=token)
        _notify(f"[dry-run] {title}", reason)
        return {"decision": "dry-run", "ip": ip}
    soar_denies = [e for e in entries if e.get("RuleAction") == "deny" and 1 <= (e.get("RuleNumber") or 0) <= 99]
    if len(soar_denies) >= MAX_SOAR_DENY:
        return manual(f"NACL 1~99 Deny 가 {len(soar_denies)}개로 상한 {MAX_SOAR_DENY}개 도달 — 오래된 차단을 먼저 해제")
    used = {e.get("RuleNumber") for e in entries}
    free = next((n for n in range(1, 100) if n not in used), None)
    if free is None:
        return manual("NACL 1~99 번대에 빈 규칙 번호 없음")
    exec_id = _start_automation(DOC_BLOCK_IP, {"NetworkAclId": [PRIVATE_NACL_ID], "AttackerCidr": [cidr],
                                               "RuleNumber": [str(free)]})
    _safe_record("auto-executed", detail, before=f"{cidr} 허용", after=f"규칙 {free} Deny 추가 중",
                 exec_id=exec_id, playbook=DOC_BLOCK_IP, reason=reason, control=token)
    _record_block(ip, free, token, count, exec_id, d.get("alarmName", ""))
    _notify(f"[자동조치 실행] {title} 출발지 차단", f"{reason}\nNACL 규칙 {free}\nSSM execution: {exec_id}")
    return {"decision": "auto-executed", "control": token, "ip": ip, "rule": free, "execution": exec_id}


def handler(event, _context):
    if event.get("source") == "aws.ssm":
        return _handle_automation_result(event)
    if event.get("source") == "aws.cloudwatch":
        kind = _bruteforce_kind(event)
        if kind:
            return _block_bruteforce_source(event, kind)
        return {"decision": "ignored", "reason": "not a brute-force alarm"}
    detail = _parse_finding(event)
    text = detail["match_text"]

    # 규칙 ID 자동 조치(DEC-017) — 정확 일치. 패턴 화이트리스트보다 먼저 본다.
    if detail["control_id"] in CONTROLS and detail["control_id"] in CONTROL_PLAYBOOKS:
        return _remediate_control(detail)

    # 안전장치 1 — 화이트리스트
    if not _matches_whitelist(text):
        _safe_record("manual-notified", detail, reason="자동 조치 대상 아님(화이트리스트 밖)",
                     control=detail["control_id"])
        _notify(f"[수동조치 필요] {detail['finding_type']}",
                f"화이트리스트 미포함 finding. 대시보드에서 검토/승인하세요.\n{json.dumps(detail, ensure_ascii=False)}")
        return {"decision": "manual-notified", "reason": "not in whitelist"}

    # 안전장치 3 — 전체 dry-run
    if not ENABLE_AUTO:
        _safe_record("dry-run", detail, reason="전체 dry-run(ENABLE_AUTO_REMEDIATION=false)",
                     control=detail["control_id"])
        _notify(f"[dry-run] {detail['finding_type']}",
                "ENABLE_AUTO_REMEDIATION=false. 판단만 하고 실행하지 않았습니다.")
        return {"decision": "dry-run"}

    # finding 유형별 분기
    ftype = (detail["finding_type"] + " " + detail["generator"]).lower()

    # (A) SG 포트 노출 -> 인바운드 회수. 안전장치 2(SG 태그) 확인.
    if "port" in ftype or "sg" in ftype or "ssh" in ftype or "ingress" in ftype or "3306" in text:
        group_id = detail["group_id"]
        if not group_id:
            _safe_record("manual-notified", detail, reason="대상 보안그룹 ID 없음", control=detail["control_id"])
            _notify("[수동조치] 대상 SG 미확인", json.dumps(detail, ensure_ascii=False))
            return {"decision": "manual-notified", "reason": "no group id"}
        if not _sg_has_auto_tag(group_id):
            _safe_record("manual-notified", detail, before=f"sg:{group_id}",
                         reason="AutoRemediation 태그 없는 보안그룹(대조군)", control=detail["control_id"])
            _notify(f"[수동조치] {group_id} 는 AutoRemediation 태그 없음(대조군)",
                    "db-manual-sg 등 태그 없는 대상은 승인 후 수동 조치합니다.")
            return {"decision": "manual-notified", "reason": "no auto tag"}
        exec_id = _start_automation(DOC_REVOKE_SG, {"SecurityGroupId": [group_id]})
        _safe_record("auto-executed", detail, before=f"sg:{group_id} open", after="revoke in progress",
                     exec_id=exec_id, playbook=DOC_REVOKE_SG,
                     reason="보안그룹 전체 공개 규칙 회수(화이트리스트 + 태그)", control=detail["control_id"])
        _notify(f"[자동조치 실행] SG {group_id} 규칙 회수", f"SSM execution: {exec_id}")
        return {"decision": "auto-executed", "playbook": DOC_REVOKE_SG, "execution": exec_id}

    # (B) IAM Access Key 노출 -> 비활성화
    if "credential" in ftype or "unauthorizedaccess" in ftype or detail["access_key_id"]:
        key_id = detail["access_key_id"]
        if not key_id:
            _safe_record("manual-notified", detail, reason="노출된 액세스 키 ID 없음", control=detail["control_id"])
            _notify("[수동조치] 노출 키 ID 미확인", json.dumps(detail, ensure_ascii=False))
            return {"decision": "manual-notified", "reason": "no access key id"}
        exec_id = _start_automation(DOC_DISABLE_KEY, {"AccessKeyId": [key_id]})
        _safe_record("auto-executed", detail, before=f"key:{key_id} Active", after="Inactive in progress",
                     exec_id=exec_id, playbook=DOC_DISABLE_KEY,
                     reason="노출 의심 액세스 키 비활성화(화이트리스트)", control=detail["control_id"])
        _notify(f"[자동조치 실행] Access Key {key_id} 비활성화", f"SSM execution: {exec_id}")
        return {"decision": "auto-executed", "playbook": DOC_DISABLE_KEY, "execution": exec_id}

    # 화이트리스트엔 있지만 처리기가 없는 경우
    _safe_record("manual-notified", detail, reason="화이트리스트에는 있으나 처리기 없음", control=detail["control_id"])
    _notify(f"[수동조치] 처리기 없음: {detail['finding_type']}", json.dumps(detail, ensure_ascii=False))
    return {"decision": "manual-notified", "reason": "no handler"}
