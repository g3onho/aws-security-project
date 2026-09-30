"""
tier_check — 보호 대상 docker-host 의 3계층(Nginx·Flask·MySQL) 점검 결과를 DynamoDB 에 저장합니다.

EventBridge 가 주기(tier_check_rate_minutes)마다 부릅니다. 대시보드는 컨테이너에 접속하지 않고
이 표(TIER_STATUS_TABLE)의 저장된 증거만 읽습니다(dashboard-design.md, DEC-016).

흐름
  1) 태그(Role=service-3tier)가 붙은 실행 중 인스턴스를 찾는다. 정확히 1대가 아니면 추측하지 않고 확인 불가로 기록한다.
  2) SSM Run Command 문서(TIER-Check)를 실행한다. 문서는 읽기 전용이며 "TIER|web|healthy|설명" 줄을 출력한다.
  3) 계층별 결과(tier/web · tier/app · tier/db)를 표에 덮어쓴다. 행마다 점검 시각과 stale_after_seconds 를 남겨
     대시보드가 오래된 결과를 정상으로 보이지 않게 한다.

안전장치
  - 점검을 못 했거나(SSM 오류·시간 초과·대상 불명) 출력이 없는 계층은 healthy 가 아니라 unknown 으로 기록한다.
    측정 도구의 실패는 통과도 장애 확정도 아니다.
  - 상태가 unhealthy·degraded·unknown 인 이유는 detail 에 남긴다.
  - 늦게 끝난 이전 실행이 새 결과를 덮지 않도록 checked_at 이 더 새로울 때만 쓴다.
  - 이 함수는 인스턴스·컨테이너·보안 설정을 바꾸지 않는다(SendCommand 는 읽기 전용 문서 하나만).
"""
import datetime
import os
import time

import boto3
from botocore.exceptions import ClientError

TABLE = os.environ["TIER_STATUS_TABLE"]
DOCUMENT = os.environ["TIER_CHECK_DOCUMENT"]
TARGET_TAG_KEY = os.environ.get("TARGET_TAG_KEY", "Role")
TARGET_TAG_VALUE = os.environ.get("TARGET_TAG_VALUE", "service-3tier")
STALE_AFTER_SECONDS = int(os.environ["TIER_STALE_AFTER_SECONDS"])
WAIT_SECONDS = int(os.environ.get("TIER_WAIT_SECONDS", "60"))
POLL_SECONDS = 2

TIERS = ("web", "app", "db")
STATUSES = {"healthy", "degraded", "unhealthy", "unknown"}
SSM_PENDING = {"Pending", "InProgress", "Delayed"}
SOURCE = "ssm:" + DOCUMENT

ssm = boto3.client("ssm")
ec2 = boto3.client("ec2")
dynamodb = boto3.resource("dynamodb")


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def parse_output(text):
    """문서 출력 → {web|app|db: (status, detail)}. 형식이 다르거나 알 수 없는 상태의 줄은 무시한다(=결과 없음)."""
    found = {}
    for line in str(text or "").splitlines():
        parts = line.strip().split("|", 3)
        if len(parts) != 4 or parts[0] != "TIER":
            continue
        _, tier, status, detail = parts
        if tier in TIERS and status in STATUSES:
            found[tier] = (status, detail.strip()[:300])
    return found


def build_rows(parsed, failure, instance_id, command_id, checked_at):
    """계층 3건의 저장 행. failure 가 있으면(점검 자체를 못 함) 전부 unknown. 출력에 없는 계층도 unknown."""
    rows = []
    for tier in TIERS:
        if failure:
            status, detail = "unknown", failure
        elif tier in parsed:
            status, detail = parsed[tier]
        else:
            status, detail = "unknown", "점검 출력에 이 계층의 결과가 없습니다"
        rows.append({"tier_id": f"tier/{tier}", "status": status, "detail": detail[:300], "checked_at": checked_at,
                     "source": SOURCE, "instance_id": instance_id or "", "command_id": command_id or "",
                     "stale_after_seconds": STALE_AFTER_SECONDS})
    return rows


def find_instance():
    """(instance_id | None, 실패 사유 | None). 실행 중이고 태그가 맞는 인스턴스가 정확히 1대일 때만 대상으로 삼는다."""
    found = []
    pages = ec2.get_paginator("describe_instances").paginate(Filters=[
        {"Name": f"tag:{TARGET_TAG_KEY}", "Values": [TARGET_TAG_VALUE]},
        {"Name": "instance-state-name", "Values": ["running"]}])
    for page in pages:
        for reservation in page.get("Reservations", []):
            found.extend(i["InstanceId"] for i in reservation.get("Instances", []))
    if not found:
        return None, "점검 대상(실행 중인 docker-host) 인스턴스를 찾지 못했습니다"
    if len(found) > 1:
        return None, f"점검 대상이 {len(found)}대로 하나로 정해지지 않습니다"
    return found[0], None


def run_check(instance_id):
    """(stdout | None, command_id | None, 실패 사유 | None)."""
    try:
        sent = ssm.send_command(InstanceIds=[instance_id], DocumentName=DOCUMENT, TimeoutSeconds=60,
                                Comment="dashboard 3-tier status check (read-only)")
    except ClientError as error:
        return None, None, "점검 명령을 시작하지 못했습니다(" + error.response.get("Error", {}).get("Code", "오류") + ")"
    command_id = sent["Command"]["CommandId"]
    deadline = time.monotonic() + WAIT_SECONDS
    while True:
        time.sleep(POLL_SECONDS)
        try:
            got = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code")
            if code != "InvocationDoesNotExist":  # 시작 직후에는 아직 없을 수 있다
                return None, command_id, "점검 결과를 읽지 못했습니다(" + str(code) + ")"
        else:
            status = got.get("Status")
            if status == "Success":
                return got.get("StandardOutputContent", ""), command_id, None
            if status not in SSM_PENDING:
                return None, command_id, f"점검 명령이 성공하지 못했습니다({status})"
        if time.monotonic() >= deadline:
            return None, command_id, f"점검 결과를 {WAIT_SECONDS}초 안에 받지 못했습니다"


def store(rows):
    """행마다 checked_at 이 더 새로울 때만 덮어쓴다. 저장한 건수를 돌려준다."""
    table = dynamodb.Table(TABLE)
    saved = 0
    for row in rows:
        try:
            table.put_item(Item=row, ConditionExpression="attribute_not_exists(checked_at) OR checked_at <= :at",
                           ExpressionAttributeValues={":at": row["checked_at"]})
            saved += 1
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
                raise
    return saved


def handler(event, context):
    instance_id, failure = find_instance()
    stdout, command_id = None, None
    if instance_id:
        stdout, command_id, failure = run_check(instance_id)
    rows = build_rows(parse_output(stdout), failure, instance_id, command_id, _now())
    saved = store(rows)
    summary = {row["tier_id"]: row["status"] for row in rows}
    print(f"tier_check saved={saved} instance={instance_id} command={command_id} failure={failure} result={summary}")
    return {"ok": failure is None, "saved": saved, "tiers": summary, "failure": failure}
