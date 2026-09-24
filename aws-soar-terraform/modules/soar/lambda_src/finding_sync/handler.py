"""
finding_sync — Security Hub 탐지·Inspector 취약점을 DynamoDB 에 적재합니다 (v21, PR-4).

입력
  - Security Hub Findings - Imported (Inspector 제외)   → findings 테이블
  - Inspector2 Finding                                → vulnerabilities 테이블
  - 스케줄(aws.events) 또는 {"action": "reconcile"}   → 두 원본 전체 대조 (= 최초 백필)

규칙
  - finding 1건 = 1행. 원본의 갱신 시각(version)이 저장값보다 새로울 때만 덮어쓴다(조건부 쓰기).
    이벤트가 늦게·순서가 바뀌어 도착해도 옛 정보가 새 정보를 덮지 않는다.
  - view_state: 대시보드 목록에 보일 행 = OPEN(탐지) / ACTIVE(취약점), 그 밖은 CLOSED.
    OPEN 기준은 대시보드가 Security Hub 를 직접 읽을 때의 필터와 같다
    (RecordState ACTIVE, Workflow 가 RESOLVED·SUPPRESSED 아님, 심각도 INFORMATIONAL 아님).
  - 대조: 원본에 열려 있는데 표에 없거나 낡은 행만 쓴다(= 이벤트로 못 받은 것, corrected 로 센다).
    표에는 열려 있는데 원본에서 사라진 행은 CLOSED 로 바꾼다. 원본이 0건이면 닫기를 건너뛴다(오조회 방지).
  - CLOSED 행은 expires_at(TTL)으로 FINDING_TTL_DAYS 뒤 DynamoDB 가 지운다 → 해결 이력 보존 기간.
  - 대조 결과는 각 표의 동기화 상태 행(키 "__sync__", view_state 없음 → 인덱스에 안 들어감)에 남긴다.
    대시보드 asOf·지연 경고, 배포 후 원본/저장 건수 대조에 쓴다.
  - 실패는 예외로 올린다 → Lambda 재시도 후 DLQ(SQS), 오류 알람(SNS).
  - 원본 전체를 저장하지 않는다. 대시보드 변환 코드가 읽는 필드만 원본 이름 그대로 raw 에 둔다.
"""
import json
import os
import time
import datetime
from decimal import Decimal

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

FINDINGS_TABLE = os.environ["FINDINGS_TABLE"]
VULNERABILITIES_TABLE = os.environ["VULNERABILITIES_TABLE"]
TTL_DAYS = int(os.environ.get("FINDING_TTL_DAYS", "30"))
SYNC_KEY = "__sync__"
FINDING_INDEX = "view_state-updated_at"
VULN_INDEX = "view_state-last_observed_at"

_config = Config(retries={"mode": "adaptive", "max_attempts": 10})
securityhub = boto3.client("securityhub", config=_config)
inspector = boto3.client("inspector2", config=_config)
dynamodb = boto3.resource("dynamodb", config=_config)


def log(message, **fields):
    print(json.dumps({"message": message, **fields}, ensure_ascii=False, default=str))


def _now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def iso(value):
    """AWS 시각 → 'YYYY-MM-DDTHH:MM:SS.mmmZ'(UTC). 같은 형식이라야 문자열 비교가 시각 비교가 된다.
    ASFF ISO 문자열, boto3 datetime, epoch(초·밀리초), Inspector 이벤트 예시의
    'Wed Sep 04 16:59:44.356 UTC 2024' 형식을 받는다. 읽을 수 없으면 None."""
    if value is None or value == "":
        return None
    moment = None
    if isinstance(value, datetime.datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=datetime.timezone.utc)
    elif isinstance(value, (int, float, Decimal)):
        number = float(value)
        moment = datetime.datetime.fromtimestamp(number / 1000 if number > 1e11 else number, datetime.timezone.utc)
    elif isinstance(value, str):
        text = value.strip()
        try:
            moment = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            for pattern in ("%a %b %d %H:%M:%S.%f UTC %Y", "%a %b %d %H:%M:%S UTC %Y"):
                try:
                    moment = datetime.datetime.strptime(text, pattern).replace(tzinfo=datetime.timezone.utc)
                    break
                except ValueError:
                    continue
        if moment is not None and moment.tzinfo is None:
            moment = moment.replace(tzinfo=datetime.timezone.utc)
    if moment is None:
        return None
    return moment.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _expires():
    return int(time.time()) + TTL_DAYS * 86400


def _clean(value):
    """DynamoDB 가 받는 타입으로(float → Decimal, 빈 값 제거)."""
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items() if v is not None and v != "" and v != {} and v != []}
    if isinstance(value, (list, tuple)):
        return [_clean(v) for v in value if v is not None]
    return value


# --- 원본 → 저장 행 ---------------------------------------------------------

def finding_item(finding):
    """Security Hub ASFF → findings 행. raw 는 대시보드 repositories/findings.py 가 읽는 필드만."""
    workflow = (finding.get("Workflow") or {}).get("Status") or finding.get("WorkflowState")
    severity = (finding.get("Severity") or {}).get("Label")
    updated = iso(finding.get("UpdatedAt")) or iso(finding.get("CreatedAt")) or _now_iso()
    is_open = (finding.get("RecordState") == "ACTIVE" and workflow not in {"RESOLVED", "SUPPRESSED"}
               and severity != "INFORMATIONAL")
    remote = {k: v for k, v in (finding.get("ProductFields") or {}).items() if "remoteIpDetails" in k}
    raw = {
        "Id": finding.get("Id"), "ProductArn": finding.get("ProductArn"), "ProductName": finding.get("ProductName"),
        "GeneratorId": finding.get("GeneratorId"), "Title": finding.get("Title"),
        "Description": (finding.get("Description") or "")[:1000], "Region": finding.get("Region"),
        "AwsAccountId": finding.get("AwsAccountId"), "Severity": {"Label": severity},
        "UpdatedAt": updated, "CreatedAt": iso(finding.get("CreatedAt")),
        "Resources": [{"Id": r.get("Id"), "Type": r.get("Type")} for r in (finding.get("Resources") or [])[:5]],
        "ProductFields": remote, "RecordState": finding.get("RecordState"), "Workflow": {"Status": workflow},
        "Compliance": {"Status": (finding.get("Compliance") or {}).get("Status")},
    }
    item = {"finding_id": finding["Id"], "view_state": "OPEN" if is_open else "CLOSED", "updated_at": updated,
            "version": updated, "region": finding.get("Region"), "account_id": finding.get("AwsAccountId"),
            "product_name": finding.get("ProductName"), "severity": severity, "raw": raw,
            "ingested_at": _now_iso(), "record_version": 1}
    if not is_open:
        item["expires_at"] = _expires()
    return _clean(item)


def vulnerability_item(finding, region=None):
    """Inspector finding(ListFindings·이벤트 detail 같은 모양) → vulnerabilities 행."""
    first_resource = (finding.get("resources") or [{}])[0]
    package_details = finding.get("packageVulnerabilityDetails") or {}
    package = (package_details.get("vulnerablePackages") or [{}])[0]
    first_seen = iso(finding.get("firstObservedAt"))
    last_seen = iso(finding.get("lastObservedAt")) or first_seen or _now_iso()
    updated = iso(finding.get("updatedAt")) or last_seen
    status = finding.get("status") or "ACTIVE"
    cvss = ((finding.get("inspectorScoreDetails") or {}).get("adjustedCvss") or {}).get("score")
    resource_region = first_resource.get("region") or finding.get("region") or region
    raw = {
        "findingArn": finding.get("findingArn"), "awsAccountId": finding.get("awsAccountId"),
        "severity": finding.get("severity"), "status": status, "region": resource_region,
        "firstObservedAt": first_seen, "lastObservedAt": last_seen, "updatedAt": updated,
        "resourceId": finding.get("resourceId") or first_resource.get("id"),
        "resources": [{"id": first_resource.get("id"), "type": first_resource.get("type"),
                       "tags": {"Name": (first_resource.get("tags") or {}).get("Name")}}],
        "packageVulnerabilityDetails": {"vulnerabilityId": package_details.get("vulnerabilityId"),
                                        "vulnerablePackages": [{"name": package.get("name"),
                                                                "version": package.get("version"),
                                                                "fixedInVersion": package.get("fixedInVersion")}]},
        "inspectorScoreDetails": {"adjustedCvss": {"score": cvss}},
    }
    item = {"finding_arn": finding["findingArn"], "view_state": "ACTIVE" if status == "ACTIVE" else "CLOSED",
            "last_observed_at": last_seen, "version": max(last_seen, updated), "region": resource_region,
            "account_id": finding.get("awsAccountId"), "severity": finding.get("severity"),
            "cve_id": package_details.get("vulnerabilityId"), "raw": raw, "ingested_at": _now_iso(),
            "record_version": 1}
    if item["view_state"] == "CLOSED":
        item["expires_at"] = _expires()
    return _clean(item)


# --- 쓰기 ----------------------------------------------------------------------

def put_if_newer(table, key, item):
    """저장값보다 새 정보면 쓴다. 같은 version 인데 상태만 다르면(대조가 잘못 닫은 경우 등) 쓴다.
    옛 정보는 버린다. 썼으면 True."""
    try:
        table.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(#k) OR #v < :v OR (#v = :v AND #s <> :s)",
            ExpressionAttributeNames={"#k": key, "#v": "version", "#s": "view_state"},
            ExpressionAttributeValues={":v": item["version"], ":s": item["view_state"]})
        return True
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return False
        raise


def close_if_unchanged(table, key, key_value, seen_version, open_state):
    """대조 중 원본에서 사라진 행을 닫는다. 그 사이 새 이벤트로 바뀌었으면(version 다름) 두지 않는다."""
    now = _now_iso()
    try:
        table.update_item(
            Key={key: key_value},
            UpdateExpression="SET #s = :closed, closed_at = :now, expires_at = :exp, ingested_at = :now",
            ConditionExpression="#s = :open AND #v = :seen",
            ExpressionAttributeNames={"#s": "view_state", "#v": "version"},
            ExpressionAttributeValues={":closed": "CLOSED", ":open": open_state, ":seen": seen_version,
                                       ":now": now, ":exp": _expires()})
        return True
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return False
        raise


def stored_open(table, index, open_state, key):
    """표에 열려 있는 행 {키: version}. 인덱스 Query(열린 행만)."""
    rows, kwargs = {}, {"IndexName": index, "KeyConditionExpression": "#s = :s",
                        "ExpressionAttributeNames": {"#s": "view_state", "#k": key, "#v": "version"},
                        "ExpressionAttributeValues": {":s": open_state}, "ProjectionExpression": "#k, #v"}
    while True:
        page = table.query(**kwargs)
        for row in page.get("Items", []):
            rows[row[key]] = row.get("version")
        if not page.get("LastEvaluatedKey"):
            return rows
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]


def count_open(table, index, open_state):
    total, kwargs = 0, {"IndexName": index, "KeyConditionExpression": "#s = :s", "Select": "COUNT",
                        "ExpressionAttributeNames": {"#s": "view_state"},
                        "ExpressionAttributeValues": {":s": open_state}}
    while True:
        page = table.query(**kwargs)
        total += page.get("Count", 0)
        if not page.get("LastEvaluatedKey"):
            return total
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]


# --- 원본 목록 ------------------------------------------------------------------

def list_securityhub():
    """대조용 원본. Inspector 는 취약점 표에서 따로 다룬다. 상한 없음(대시보드의 500건 상한이 없어지는 곳)."""
    filters = {"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
               "ProductName": [{"Value": "Inspector", "Comparison": "NOT_EQUALS"}]}
    rows = []
    for page in securityhub.get_paginator("get_findings").paginate(
            Filters=filters, PaginationConfig={"PageSize": 100}):
        rows.extend(page.get("Findings", []))
    return rows


def list_inspector():
    rows = []
    for page in inspector.get_paginator("list_findings").paginate(
            filterCriteria={"findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}]},
            PaginationConfig={"PageSize": 100}):
        rows.extend(page.get("findings", []))
    return rows


# --- 대조 -----------------------------------------------------------------------

def reconcile_table(name, table, key, index, open_state, source_items):
    """source_items: 이미 저장 행 모양으로 바꾼 원본 목록."""
    started = _now_iso()
    stored = stored_open(table, index, open_state, key)
    source_open = {item[key]: item for item in source_items if item["view_state"] == open_state}
    corrected = 0
    for item in source_items:
        known = stored.get(item[key])
        if item["view_state"] == open_state:
            if known == item["version"]:
                continue  # 이미 같다 — 쓰지 않는다(비용)
        elif item[key] not in stored:
            continue  # 원본에서도 닫힌 건이고 표에도 열려 있지 않다
        if put_if_newer(table, key, item):
            corrected += 1
    closed, skipped = 0, False
    missing = [k for k in stored if k not in source_open]
    if not source_open and stored:
        skipped = True  # 원본이 0건: 조회 이상일 수 있어 한꺼번에 닫지 않는다
    else:
        for key_value in missing:
            if close_if_unchanged(table, key, key_value, stored[key_value], open_state):
                closed += 1
    table_open = count_open(table, index, open_state)
    status = {key: SYNC_KEY, "last_attempt_at": started, "last_success_at": _now_iso(),
              "source_open": len(source_open), "table_open": table_open, "corrected": corrected,
              "closed": closed, "close_skipped": skipped, "last_error": None}
    table.put_item(Item=_clean(status) | {"last_error": None})
    log("reconciled", table=name, **{k: v for k, v in status.items() if k != key})
    return status


def record_failure(table, key, error):
    table.update_item(Key={key: SYNC_KEY}, UpdateExpression="SET last_attempt_at = :now, last_error = :e",
                      ExpressionAttributeValues={":now": _now_iso(), ":e": str(error)[:500]})


def reconcile():
    results, failures = {}, []
    jobs = (("findings", FINDINGS_TABLE, "finding_id", FINDING_INDEX, "OPEN",
             lambda: [finding_item(f) for f in list_securityhub()]),
            ("vulnerabilities", VULNERABILITIES_TABLE, "finding_arn", VULN_INDEX, "ACTIVE",
             lambda: [vulnerability_item(f) for f in list_inspector()]))
    for name, table_name, key, index, open_state, load in jobs:
        table = dynamodb.Table(table_name)
        try:  # 한쪽이 실패해도 다른 쪽은 대조한다
            results[name] = reconcile_table(name, table, key, index, open_state, load())
        except Exception as error:  # noqa: BLE001 — 기록 후 아래에서 다시 올린다
            log("reconcile failed", table=name, error=str(error))
            failures.append(name)
            try:
                record_failure(table, key, error)
            except Exception as inner:  # noqa: BLE001
                log("sync status write failed", table=name, error=str(inner))
    if failures:
        raise RuntimeError("reconcile failed: " + ", ".join(failures))  # 재시도·DLQ·오류 알람
    return {k: {x: y for x, y in v.items() if x not in {"finding_id", "finding_arn"}} for k, v in results.items()}


# --- 이벤트 ---------------------------------------------------------------------

def ingest_securityhub(findings):
    table, written = dynamodb.Table(FINDINGS_TABLE), 0
    for finding in findings:
        if finding.get("ProductName") == "Inspector" or not finding.get("Id"):
            continue  # 취약점은 Inspector 이벤트로 받는다
        written += put_if_newer(table, "finding_id", finding_item(finding))
    return {"received": len(findings), "written": written}


def ingest_inspector(detail, region):
    if not detail.get("findingArn"):
        return {"received": 0, "written": 0}
    written = put_if_newer(dynamodb.Table(VULNERABILITIES_TABLE), "finding_arn", vulnerability_item(detail, region))
    return {"received": 1, "written": int(written)}


def handler(event, context):
    source = event.get("source")
    if source == "aws.securityhub":
        result = ingest_securityhub((event.get("detail") or {}).get("findings") or [])
    elif source == "aws.inspector2":
        result = ingest_inspector(event.get("detail") or {}, event.get("region"))
    elif source == "aws.events" or event.get("action") == "reconcile":
        result = reconcile()
    else:
        result = {"ignored": source}
    log("done", source=source, **{k: v for k, v in result.items() if not isinstance(v, dict)})
    return result
