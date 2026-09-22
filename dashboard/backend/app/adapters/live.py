"""실 AWS 어댑터 — 조회 구현, 쓰기는 스텁.

demo/local 과 **같은 Event 스키마**를 돌려준다. 프론트는 /health 의 mode 로
어느 쪽이 붙었는지 알 뿐, 응답 모양은 동일하다.

조회 경로
  list_events      securityhub:GetFindings + dynamodb:Scan(correlated)
  get_event        위 목록에서 단건 (상류에 단건 조회 API 가 없다)
  metrics          cloudwatch:GetMetricData (CPUUtilization · mem_used_percent)
  vulnerabilities  inspector2:ListFindings (PACKAGE_VULNERABILITY)
  scenarios        카탈로그 + 위 목록 집계
  evidence         위 전부
  execution_status ssm:GetAutomationExecution

쓰기(approve/execute/verify/cancel)는 501 스텁으로 남긴다.
`run.py:41` 이 실모드에서 WRITE_ENABLED 를 강제로 끄므로 어차피 도달하지 않는다.
읽기 전용 단계(M2)를 지나 쓰기를 열 때 구현한다 — 04-backend-design.md §3.

알아둘 것
  - **시각은 전부 epoch ms 정수로 변환한다.** correlated 테이블의 created_at 은
    ISO 문자열이라(`correlator/handler.py:76`) 그대로 내보내면 프론트 필터가 깨진다.
  - 조치 이력은 remediation_actions 를 `finding_id` 로 조인해 붙인다.
    `asr_trigger/handler.py` 가 이 값을 기록한다. DynamoDB 는 스키마리스라
    테이블 정의(`aws_dynamodb_table`)는 바꿀 필요가 없었다 — 키가 아닌 속성이다.
    테이블이 설정되지 않았을 때만 `historyNote` 로 이유를 밝힌다.
"""
from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime, timezone

from .. import enums
from ..api.errors import ApiProblem
from ..catalog import loader

# ponytail: correlated 테이블에 시간 GSI 가 없어 Scan 한다.
# 발표용 계정 규모에서 넉넉하고, 넘치면 GSI 를 파고 Query 로 바꾼다.
# 100 인 이유: securityhub:GetFindings 와 inspector2:ListFindings 의 상한이 100 이다.
# 상류 API 의 **페이지당** 상한. 총 건수 상한이 아니다 — 모두 _pages() 로 끝까지 읽는다.
# 아래 값은 각 API 가 허용하는 최대치다. 100 은 우리가 정한 값이 아니라 AWS 하드 상한이다.
#   securityhub:GetFindings        MaxResults  최대 100
#   inspector2:ListFindings        maxResults  최대 100
#   cloudwatch:DescribeAlarms      MaxRecords  최대 100
#   ec2:DescribeInstances          MaxResults  5~1000
#   s3:ListObjectsV2               MaxKeys     최대 1000
#   dynamodb:Scan                  Limit       항목 수 제한 없음(페이지당 1MB)
PAGE_SECURITYHUB = 100
PAGE_INSPECTOR = 100
PAGE_ALARMS = 100
PAGE_EC2 = 1000
PAGE_S3 = 1000
PAGE_DYNAMODB = 500
# 한 응답에 실어 보낼 최대 항목 수. 브라우저 렌더 보호용이며, 넘으면 truncated=True 로 알린다.
MAX_RESPONSE_ITEMS = 5000
# Private NACL 의 Deny 예약 구간 상한(README 1장: 1~99 Deny, 100 이상 Allow)
DENY_RULE_MAX = 99
MAX_ITEMS = 100  # 하위호환 — 새 코드는 위 상수를 쓴다

NO_ACTIONS_TABLE_NOTE = (
    "REMEDIATION_ACTIONS_TABLE 이 설정되지 않아 조치 이력을 붙이지 못했습니다. "
    "탐지 항목만 표시합니다."
)

# asr_trigger 의 decision 값 → 화면 문구
DECISION_TEXT = {
    "auto-executed": "자동 조치 실행",
    "manual-notified": "수동 조치 알림 발송 · 승인 대기",
    "dry-run": "dry-run 판정 · 실행하지 않음",
}

# 상류가 영어로 주는 제목의 한글 표기.
# 카탈로그(SEC-xx)에 분류된 건 카탈로그 제목이 우선이고, 분류가 안 된 것만 여기서 덮는다.
# 부분 일치라 컨트롤 이름이 조금 바뀌어도 계속 맞는다. 못 찾으면 원문을 그대로 둔다.
TITLE_KO = (
    ("interface endpoint for Systems Manager", "VPC에 Systems Manager 인터페이스 엔드포인트 없음"),
    ("interface endpoint for Docker Registry", "VPC에 Docker Registry(ECR) 인터페이스 엔드포인트 없음"),
    ("interface endpoint", "VPC에 필요한 인터페이스 엔드포인트 없음"),
    ("EKS Runtime Monitoring", "GuardDuty EKS 런타임 모니터링 미사용"),
    ("ECS Runtime Monitoring", "GuardDuty ECS 런타임 모니터링 미사용"),
    ("Config should be enabled", "AWS Config 미활성 또는 서비스 연결 역할 미사용"),
    ("RootCredentialUsage", "루트 계정 자격증명 사용 탐지"),
    ("invoked using root credentials", "루트 계정으로 API 호출 탐지"),
    ("restricted-common-ports", "보안 그룹에 위험 포트 공개 (Config 규칙 위반)"),
    ("restricted-ssh", "보안 그룹에 SSH(22) 전체 공개 (Config 규칙 위반)"),
    ("-cpu-high", "CPU 사용률 임계치 초과"),
    ("-mem-high", "메모리 사용률 임계치 초과"),
    ("-mysql-bruteforce", "MySQL 인증 실패 급증 (무차별 대입 의심)"),
)


import re as _re  # noqa: E402

CVE_RE = _re.compile(r"CVE-\d{4}-\d+")

# 소스별 근거 문장. 상류 영어 원문은 evidenceOriginal 로 따로 보관한다.
SOURCE_KO = {
    "Inspector": "Inspector 취약점 점검",
    "Trivy": "Trivy 이미지 점검",
    "GuardDuty": "GuardDuty 위협 탐지",
    "Config": "AWS Config 규칙 평가",
    "Security Hub": "Security Hub 보안 표준 점검",
    "CloudWatch": "CloudWatch 지표 임계치",
}


def _short(resource: str) -> str:
    """ARN 에서 사람이 읽는 부분만 남긴다."""
    text = resource or ""
    if text.startswith("arn:"):
        tail = text.split(":")[-1]
        return tail.split("/")[-1] or tail
    return text


def _remote_ip(product_fields: dict) -> dict:
    """GuardDuty finding 의 공격 출발지.

    Security Hub 는 GuardDuty 상세를 ProductFields 에 **슬래시 구분** 평평한 키로 넣는다.
    실측(2026-09-22, aws securityhub get-findings):
        aws/guardduty/service/action/awsApiCallAction/remoteIpDetails/ipAddressV4
        aws/guardduty/service/action/awsApiCallAction/remoteIpDetails/country/countryName
        aws/guardduty/service/action/awsApiCallAction/remoteIpDetails/city/cityName
        aws/guardduty/service/action/awsApiCallAction/remoteIpDetails/geoLocation/lat
        aws/guardduty/service/action/awsApiCallAction/remoteIpDetails/geoLocation/lon
    점(.) 이 아니라 슬래시(/) 다. 이전 버전은 점으로 찾아 **한 번도 매칭되지 않았다**.
    액션 종류(awsApiCallAction/networkConnectionAction 등)가 여러 가지라 키 이름을
    고정하지 않고 꼬리만 보고 찾는다.

    **위경도(geoLocation)는 GuardDuty 가 실제로 준다.** 이전 버전은 "AWS 가 좌표를
    안 준다"고 잘못 가정해 항상 None 으로 비웠다 — 실측으로 정정한다.
    """
    ip = country = city = lat = lon = ""
    for key, value in (product_fields or {}).items():
        if "remoteIpDetails" not in key or not value:
            continue
        if key.endswith("/ipAddressV4"):
            ip = str(value)
        elif key.endswith("/country/countryName"):
            country = str(value)
        elif key.endswith("/city/cityName"):
            city = str(value)
        elif key.endswith("/geoLocation/lat"):
            lat = str(value)
        elif key.endswith("/geoLocation/lon"):
            lon = str(value)
    if not ip:
        return {}
    location = None
    if country or city:
        has_coords = bool(lat and lon)
        location = {
            "city": city or country,
            "lon": float(lon) if has_coords else None,
            "lat": float(lat) if has_coords else None,
            "provenance": "GuardDuty 제공 · 실제 위치",
            "actorId": None,
            "country": country or None,
        }
    geo_status = ("위치 확인" if (location and location["lat"] is not None)
                  else "국가만 확인" if location else "위치 미상")
    return {"sourceIp": ip, "sourceLocation": location, "geoStatus": geo_status}


def _evidence_ko(source: str, title: str, resource: str, original: str, cves) -> str:
    """상류 영어 설명 대신 구조화된 사실로 한국어 근거를 만든다.

    상류 Description 은 CVE 해설처럼 길고 제각각인 영어 산문이라 번역 대상이 아니다.
    화면에 필요한 건 "무엇이 · 어디서 · 무슨 근거로" 세 가지다.
    """
    parts = [SOURCE_KO.get(source, source)]
    found = CVE_RE.findall(original or "") or CVE_RE.findall(title or "")
    if cves:
        found = list(cves) + [c for c in found if c not in cves]
    if found:
        parts.append("취약점 " + ", ".join(found[:3]) + ("  외 %d건" % (len(found) - 3) if len(found) > 3 else ""))
    if resource and resource != "n/a":
        parts.append("대상 " + _short(resource))
    return " · ".join(parts)


# 상류가 주는 권장 조치의 한글 표기. 카탈로그 note 가 없는 미분류 항목에 쓴다.
RECOMMENDATION_KO = (
    ("interface VPC endpoint", "해당 서비스용 인터페이스 VPC 엔드포인트를 생성해 프라이빗 경로를 확보하세요."),
    ("EKS Runtime Monitoring", "GuardDuty EKS 런타임 모니터링을 켜고 에이전트 자동 관리를 사용하세요. EKS 를 쓰지 않으면 해당 없음."),
    ("ECS-Fargate", "GuardDuty ECS/Fargate 런타임 모니터링용 보안 에이전트를 활성화하세요. ECS 를 쓰지 않으면 해당 없음."),
    ("Runtime Monitoring", "GuardDuty 런타임 모니터링을 활성화하세요."),
)


def _recommendation_ko(scenario: str, original: str) -> str:
    """권장 조치. 카탈로그의 한글 note 가 정본이고, 없으면 상류 원문을 쓴다."""
    item = loader.get(scenario) if scenario else None
    note = ((item or {}).get("remediation") or {}).get("note")
    if note:
        return note.strip()
    if not original or original.strip().lower() in ("none provided", "none", ""):
        return "권장 조치가 제공되지 않았습니다. 담당자 검토가 필요합니다."
    for needle, korean in RECOMMENDATION_KO:
        if needle in original:
            return korean
    return original


def _title_ko(text: str) -> str:
    for needle, korean in TITLE_KO:
        if needle in text:
            return korean
    return text


WRITE_PLAN = {
    "approve": "dynamodb:PutItem(actions, decision=approved)",
    "execute": "게이트 판정 → ssm:StartAutomationExecution + iam:PassRole → dynamodb:PutItem",
    "verify": "verify.type 별 재검사 (04 §3.4)",
    "cancel": "ssm:StopAutomationExecution — 대시보드 역할에 권한이 없다",
}


def _now_ms() -> int:
    return int(time.time() * 1000)


def _ms(value) -> int | None:
    """AWS 가 주는 여러 시각 표기를 epoch ms 정수로 통일한다."""
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        at = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return int(at.timestamp() * 1000)
    if isinstance(value, (int, float)):
        return int(value * 1000) if value < 1e12 else int(value)
    try:
        at = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        at = at if at.tzinfo else at.replace(tzinfo=timezone.utc)
        return int(at.timestamp() * 1000)
    except ValueError:
        return None


def _region_of(arn: str, default: str) -> str:
    parts = (arn or "").split(":")
    return parts[3] if len(parts) > 3 and parts[3] else default


def _round(values, index):
    if not values or index >= len(values):
        return None
    return round(float(values[index]), 1)


class LiveAdapter:
    mode = "live"

    def __init__(self, config) -> None:
        self.config = config
        self._lock = threading.RLock()
        self._clients: dict[str, object] = {}
        self._cache: dict[str, tuple[float, object]] = {}
        self._idempotency: dict[str, object] = {}

    # ── 상류 호출 ───────────────────────────────────────
    def _client(self, name: str):
        with self._lock:
            if name not in self._clients:
                try:
                    import boto3  # noqa: PLC0415
                except ImportError as exc:
                    raise ApiProblem(
                        503, "실 AWS 연동을 쓸 수 없습니다.", code="AWS_UNAVAILABLE",
                        detail="requirements.txt 의 boto3 를 설치해야 실모드가 동작합니다.",
                    ) from exc
                self._clients[name] = boto3.client(name, region_name=self.config.AWS_REGION)
            return self._clients[name]

    def _call(self, service: str, op: str, **kwargs):
        """상류 1회 호출.

        예외 메시지를 그대로 노출하지 않는다 — 권한 오류 본문에 ARN 이 섞인다
        (04-backend-design.md §4.3). 타입 이름만 detail 로 남긴다.
        """
        try:
            return getattr(self._client(service), op)(**kwargs)
        except ApiProblem:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ApiProblem(
                502, f"{service} 조회에 실패했습니다.", code="UPSTREAM_ERROR",
                detail=type(exc).__name__,
            ) from exc

    def _cached(self, key: str, ttl: int, build):
        hit = self._cache.get(key)
        if hit and time.time() - hit[0] < ttl:
            return hit[1]
        value = build()
        self._cache[key] = (time.time(), value)
        return value

    def _require_write(self, action: str) -> None:
        """쓰기 차단.

        run.py 가 app.config 로도 막지만, 어댑터를 직접 쓰는 경로가 있으므로 여기서도 본다.
        """
        if not getattr(self.config, "WRITE_ENABLED", False):
            raise ApiProblem(
                409, "쓰기가 비활성화되어 있습니다.", code="WRITE_DISABLED",
                detail=action + ": WRITE_ENABLED=true 로 기동해야 합니다.",
            )

    def _pages(self, service, operation, result_key, token='NextToken', **kwargs):
        rows, seen = [], set()
        while True:
            page = self._call(service, operation, **kwargs)
            rows.extend(page.get(result_key, []))
            next_token = page.get('LastEvaluatedKey' if token == 'ExclusiveStartKey' else token)
            if not next_token:
                return rows
            marker = repr(next_token)
            if marker in seen:
                raise ApiProblem(502, '상류 페이지 토큰이 반복되었습니다.', code='UPSTREAM_ERROR')
            seen.add(marker)
            kwargs[token] = next_token

    # ── 이벤트 조립 ─────────────────────────────────────
    def _correlated(self) -> dict[str, dict]:
        """correlator 결과를 finding_id 로 색인한다. 테이블 미설정이면 빈 dict."""
        table = self.config.CORRELATED_FINDINGS_TABLE
        if not table:
            return {}
        page = {'Items': self._pages('dynamodb', 'scan', 'Items', token='ExclusiveStartKey', TableName=table, Limit=PAGE_DYNAMODB)}
        out = {}
        for raw in page.get("Items", []):
            item = {k: next(iter(v.values())) for k, v in raw.items()}
            cves = [c.get("S", c) if isinstance(c, dict) else c
                    for c in (item.get("cve_ids") or [])]
            out[str(item.get("finding_id"))] = {
                "cveIds": cves,
                "severityBumped": str(item.get("severity_bumped")).lower() == "true",
                "finalSeverity": item.get("final_severity"),
                "instanceId": item.get("instance_id"),
                "at": _ms(item.get("created_at")),
                "guarddutyType": item.get("guardduty_type") or "",
            }
        return out

    def _actions(self) -> dict[str, list[dict]]:
        """조치 이력을 finding_id 로 묶는다. 테이블 미설정이면 빈 dict.

        asr_trigger 가 판정할 때마다 한 행씩 쌓으므로 한 finding 에 여러 건이 온다.
        오래된 것부터 정렬해 history 순서를 그대로 쓴다.
        """
        table = self.config.REMEDIATION_ACTIONS_TABLE
        if not table:
            return {}
        page = {'Items': self._pages('dynamodb', 'scan', 'Items', token='ExclusiveStartKey', TableName=table, Limit=PAGE_DYNAMODB)}
        out: dict[str, list[dict]] = {}
        for raw in page.get("Items", []):
            item = {k: next(iter(v.values())) for k, v in raw.items()}
            finding_id = str(item.get("finding_id") or "")
            # 예전 행에는 finding_id 가 없다. 조인할 수 없으므로 버린다.
            if not finding_id or finding_id == "unknown":
                continue
            out.setdefault(finding_id, []).append({
                "at": _ms(item.get("created_at")),
                "decision": str(item.get("decision") or ""),
                "beforeState": str(item.get("before_state") or ""),
                "afterState": str(item.get("after_state") or ""),
                "executionId": str(item.get("ssm_execution_id") or ""),
            })
        for rows in out.values():
            rows.sort(key=lambda r: r["at"] or 0)
        return out

    def _alarm_events(self) -> list[dict]:
        """ALARM 상태인 CloudWatch 알람을 이벤트로 만든다.

        CPU·메모리 임계치(SEC-10)와 MySQL 무차별 대입(SEC-06)이 이 경로로 화면에 뜬다.
        알람은 상류 finding 이 아니라 지표 판정이라 Security Hub 를 거치지 않는다.
        선택적 소스라 조회에 실패해도 전체 목록을 깨뜨리지 않는다.
        """
        try:
            page = {'MetricAlarms': self._pages("cloudwatch", "describe_alarms", 'MetricAlarms',
                              StateValue="ALARM", MaxRecords=PAGE_ALARMS)}
        except ApiProblem:
            return []

        events = []
        for alarm in page.get("MetricAlarms", []):
            name = alarm.get("AlarmName") or ""
            dimension = (alarm.get("Dimensions") or [{}])[0].get("Value") or "n/a"
            events.append(self._event(
                event_id="alarm:" + name,
                scenario=loader.classify(alarm=name),
                title=name,
                severity="MEDIUM",
                source="CloudWatch",
                region=self.config.AWS_REGION,
                resource=dimension,
                at=_ms(alarm.get("StateUpdatedTimestamp")) or _now_ms(),
                evidence=alarm.get("StateReason") or "",
                recommendation="",
                extra=None,
            ))
        return events

    def _build_events(self) -> list[dict]:
        correlated = self._correlated()
        actions = self._actions()
        # INFORMATIONAL 은 "평가할 리소스가 없음"(Compliance=WARNING)이다.
        # 표준을 켜면 이 계정에 없는 서비스(Redshift·SageMaker 등)까지 전부 올라와
        # 화면이 빈 결과로 뒤덮인다. 실제 탐지만 남긴다.
        page = {'Findings': self._pages(
            "securityhub", "get_findings", 'Findings',
            Filters={
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                "SeverityLabel": [{"Value": v, "Comparison": "EQUALS"}
                                  for v in ("LOW", "MEDIUM", "HIGH", "CRITICAL")],
            },
            MaxResults=PAGE_SECURITYHUB,
        )}

        events, seen = [], set()
        for f in page.get("Findings", []):
            finding_id = str(f.get("Id") or "")
            if not finding_id:
                continue
            seen.add(finding_id)
            events.append(self._from_finding(f, correlated.get(finding_id),
                                             actions.get(finding_id)))

        # correlator 만 알고 Security Hub 에 안 올라온 GuardDuty finding 도 보여준다.
        for finding_id, extra in correlated.items():
            if finding_id not in seen:
                events.append(self._from_correlated(finding_id, extra,
                                                    actions.get(finding_id)))

        events.extend(self._alarm_events())
        events.sort(key=lambda e: e["at"] or 0, reverse=True)
        return events

    def _from_finding(self, f: dict, extra: dict | None,
                      actions: list[dict] | None = None) -> dict:
        product = (f.get("ProductFields") or {}).get("aws/securityhub/ProductName", "")
        source = enums.PRODUCT_TO_SOURCE.get(product, "Security Hub")
        generator = str(f.get("GeneratorId") or "")
        gd_type = (extra or {}).get("guarddutyType") or (f.get("Types") or [""])[0]
        resource = (f.get("Resources") or [{}])[0].get("Id") or "n/a"
        origin = _remote_ip(f.get("ProductFields") or {})
        return self._event(
            origin=origin,
            event_id=str(f.get("Id")),
            scenario=loader.classify(source=source, generator=generator, gd_type=gd_type),
            title=f.get("Title") or generator or "미분류 finding",
            severity=(extra or {}).get("finalSeverity")
            or (f.get("Severity") or {}).get("Label") or "LOW",
            source=source,
            region=_region_of(resource, self.config.AWS_REGION),
            resource=resource,
            at=_ms(f.get("UpdatedAt") or f.get("CreatedAt")) or _now_ms(),
            evidence=f.get("Description") or "",
            recommendation=((f.get("Remediation") or {}).get("Recommendation") or {}).get("Text", ""),
            extra=extra,
            actions=actions,
        )

    def _from_correlated(self, finding_id: str, extra: dict,
                         actions: list[dict] | None = None) -> dict:
        gd_type = extra.get("guarddutyType") or ""
        return self._event(
            event_id=finding_id,
            scenario=loader.classify(source="GuardDuty", gd_type=gd_type),
            title=gd_type or "GuardDuty finding",
            severity=extra.get("finalSeverity") or "LOW",
            source="GuardDuty",
            region=self.config.AWS_REGION,
            resource=extra.get("instanceId") or "n/a",
            at=extra.get("at") or _now_ms(),
            evidence="GuardDuty 탐지 + Inspector CVE 상관분석 결과",
            recommendation="",
            extra=extra,
            actions=actions,
        )

    def _event(self, *, event_id, scenario, title, severity, source, region,
               resource, at, evidence, recommendation, extra, actions=None,
               origin=None) -> dict:
        """demo.py `_build_events()` 와 같은 필드 집합을 채운다."""
        extra = extra or {}
        wired = loader.is_wired(scenario) if scenario else False
        mode = ((loader.get(scenario) or {}).get('remediation') or {}).get('mode', 'MANUAL')
        # 화면은 한국어다. 카탈로그 제목이 정본, 없으면 표기표, 그것도 없으면 원문.
        # CVE 번호가 들어간 제목은 원문이 더 구체적이다(카탈로그 제목으로 덮으면
        # 88건이 전부 같은 이름이 되어 구분이 사라진다). 그 외에는 한국어를 쓴다.
        if CVE_RE.search(title or ""):
            display_title = title
        else:
            display_title = ((loader.get(scenario) or {}).get("title") if scenario else None)                 or _title_ko(title)

        # 조치 이력을 탐지 항목 뒤에 이어 붙이고, 마지막 판정으로 상태를 정한다.
        history = [{"at": at, "text": "탐지 근거 수집", "actor": None, "decision": None}]
        status = "NEW" if mode == "AUTO" else "PENDING_APPROVAL"
        execution, verification = "NOT_RUN", "NOT_RUN"
        after_at, after_value = None, None
        external_execution_id = None
        for action in actions or []:
            decision = action["decision"]
            text = DECISION_TEXT.get(decision, decision or "조치 판정")
            if action["afterState"] and action["afterState"] != "pending":
                text = f"{text} · {action['afterState']}"
            history.append({"at": action["at"], "text": text,
                            "actor": None, "decision": decision})
            if decision == "auto-executed":
                # SSM 이 실제로 끝났는지는 execution_status() 로 따로 확인한다.
                status, execution = "EXECUTING", "RUNNING"
                external_execution_id = action.get('executionId')
                after_at, after_value = action["at"], action["afterState"] or None
            elif decision == "manual-notified":
                status = "PENDING_APPROVAL"

        # 알림은 대시보드가 보내지 않는다. asr_trigger 가 게이트 불충족으로 판정할 때
        # 직접 SNS 로 발행하고(lambda_src/asr_trigger/handler.py), CloudWatch 알람은
        # alarm_actions 로 발행한다(soar/cloudwatch.tf). 화면은 "갔는지"만 보여준다.
        notified = [a for a in (actions or []) if a["decision"] == "manual-notified"]
        if notified:
            last = notified[-1]
            notification = {"at": last["at"], "channel": "SNS", "source": "asr_trigger",
                            "reason": last["beforeState"] or "자동조치 게이트 불충족",
                            "count": len(notified)}
        elif source == "CloudWatch":
            # 알람이 ALARM 상태라 화면에 올라온 것이므로 alarm_actions 가 이미 발행했다.
            notification = {"at": at, "channel": "SNS", "source": "cloudwatch-alarm",
                            "reason": title, "count": 1}
        else:
            notification = None
        return {
            "id": event_id,
            "scenario": scenario or "UNCLASSIFIED",
            "title": display_title,
            "titleOriginal": title,
            "severity": severity if severity in enums.SEVERITY_ORDER else "LOW",
            "source": source,
            "mode": mode,
            "region": region,
            "environment": "production",
            "resource": resource,
            "at": at,
            "status": status,
            "execution": execution,
            "verification": verification,
            "criterion": loader.criterion(scenario) if scenario else "",
            "unit": loader.unit(scenario) if scenario else "",
            "before": None,
            "after": None,
            "beforeAt": at,
            "afterAt": after_at,
            "afterValue": after_value,
            "evidence": _evidence_ko(source, title, resource, evidence,
                                     extra.get("cveIds") or []),
            "evidenceOriginal": evidence,
            "recommendation": _recommendation_ko(scenario, recommendation),
            # GuardDuty 가 준 값만 쓴다. GeoIP 는 호출하지 않는다(_remote_ip).
            "sourceIp": (origin or {}).get("sourceIp"),
            "sourceLocation": (origin or {}).get("sourceLocation"),
            "geoStatus": (origin or {}).get("geoStatus", "해당 없음"),
            "history": history,
            "historyNote": None if self.config.REMEDIATION_ACTIONS_TABLE else NO_ACTIONS_TABLE_NOTE,
            "notification": notification,
            "playbook": loader.playbook(scenario) if scenario else None,
            "cveIds": extra.get("cveIds") or [],
            "severityBumped": bool(extra.get("severityBumped")),
            "approver": None,
            "approvedAt": None,
            "externalExecutionId": external_execution_id,
        }

    def _events(self) -> list[dict]:
        return self._cached("events", self.config.CACHE_TTL["events"], self._build_events)

    # ── 조회 ────────────────────────────────────────────
    def list_events(self, q: dict) -> dict:
        import hashlib

        from ..storage import encode
        from ..services.filters import apply_filters, paginate, view_rows
        rows = view_rows(apply_filters(self._events(), q), q)
        result = paginate(rows, q)
        result["snapshot"] = hashlib.sha256(encode(rows).encode()).hexdigest()[:20]
        return result

    def snapshot(self, q: dict) -> dict:
        """지역 합계·차트·표가 한 판을 보도록 집계까지 같이 준다. demo 와 같은 모양."""
        from ..services.filters import build_snapshot
        return build_snapshot(self._events(), q, "live")

    def get_event(self, event_id: str):
        return next((e for e in self._events() if e["id"] == event_id), None)

    def incidents(self, q: dict) -> dict:
        from ..services.incidents import build_incidents
        return build_incidents(self._events(), q)

    def scenarios(self, q: dict) -> dict:
        from ..services.scenarios import build_coverage
        return build_coverage(self._events(), q)

    def evidence(self, event_id: str):
        from ..services.evidence import build_evidence
        event = self.get_event(event_id)
        if not event:
            return None
        ids = [a["executionId"] for a in self._actions().get(event_id, [])
               if a["executionId"] and a["executionId"] != "n/a"]
        return build_evidence(event, ssm_execution_ids=ids)

    def metrics(self, q: dict) -> dict:
        region = q.get('region') or self.config.AWS_REGION
        if region != self.config.AWS_REGION:
            return {'resource': None, 'at': None, 'cpu': None, 'memory': None,
                    'threshold': {'cpu': 80, 'memory': 80}, 'points': [], 'note': '현재 연결된 단일 리전을 선택하세요.'}
        instances = self.resources({'region': region})['items']
        instance = q.get('resource') or (instances[0]['id'] if instances else None)
        if instance and instance not in {item['id'] for item in instances}:
            raise ApiProblem(404, '선택한 리전의 자원을 찾을 수 없습니다.', code='EVENT_NOT_FOUND')
        if not instance:
            return {"resource": None, "at": None, "cpu": None, "memory": None,
                    "threshold": {"cpu": 80, "memory": 80}, "points": [],
                    "note": "지표를 조회할 EC2 인스턴스를 찾지 못했습니다."}

        period = max(300, (((q["to"] - q["from"]) // 1000 // 12 + 299) // 300) * 300)
        results = self._pages(
            "cloudwatch", "get_metric_data", 'MetricDataResults',
            MetricDataQueries=[
                _metric_query("cpu", "AWS/EC2", "CPUUtilization", instance, period),
                _metric_query("mem", *self._memory_metric(), instance, period),
            ],
            StartTime=datetime.fromtimestamp(q["from"] / 1000, tz=timezone.utc),
            EndTime=datetime.fromtimestamp(q["to"] / 1000, tz=timezone.utc),
            ScanBy="TimestampAscending",
        )
        series = {'cpu': {}, 'mem': {}}
        for result in results:
            if result.get('StatusCode') in ('InternalError', 'Forbidden'):
                raise ApiProblem(502, '일부 지표를 조회할 수 없습니다.', code='UPSTREAM_ERROR')
            for at, value in zip(result.get('Timestamps', []), result.get('Values', [])):
                series[result['Id']][_ms(at)] = round(float(value), 1)
        points = [{'at': at, 'cpu': series['cpu'].get(at), 'memory': series['mem'].get(at)}
                  for at in sorted(set(series['cpu']) | set(series['mem']))]
        return {
            "resource": instance,
            "at": points[-1]["at"] if points else None,
            "cpu": points[-1]["cpu"] if points else None,
            "memory": points[-1]["memory"] if points else None,
            "threshold": {"cpu": 80, "memory": 80},
            "points": points,
            "note": None if points else "선택한 기간에 지표 데이터가 없습니다.",
        }

    def nacls(self, q: dict) -> dict:
        """SEC-06 차단 계획용 NACL 목록.

        화면이 `acl-xxxx` 와 빈 규칙 번호를 손으로 찾지 않게 서버가 제안한다.
        Private NACL 의 **1~99 번은 Deny 예약**이다(README 1장). 이미 쓰는 번호를 주면
        prepare_plan 이 409 로 막으므로, 여기서 미리 비어 있는 가장 작은 번호를 고른다.
        """
        acls = self._pages("ec2", "describe_network_acls", "NetworkAcls", token="NextToken")
        items = []
        for acl in acls:
            inbound = sorted(entry.get("RuleNumber") for entry in acl.get("Entries", [])
                             if not entry.get("Egress") and entry.get("RuleNumber") is not None)
            reserved = [n for n in inbound if 1 <= n <= DENY_RULE_MAX]
            free = next((n for n in range(1, DENY_RULE_MAX + 1) if n not in reserved), None)
            name = next((t.get("Value") for t in acl.get("Tags", [])
                         if t.get("Key") == "Name"), None)
            items.append({
                "id": acl.get("NetworkAclId"),
                "vpcId": acl.get("VpcId"),
                "name": name,
                "isDefault": bool(acl.get("IsDefault")),
                "subnets": [a.get("SubnetId") for a in acl.get("Associations", [])],
                "usedDenyRuleNumbers": reserved,
                "suggestedRuleNumber": free,
                "mode": "live",
            })
        # 기본 NACL 은 뒤로 — 차단 규칙은 보통 Private NACL 에 넣는다.
        items.sort(key=lambda x: (x["isDefault"], x["id"] or ""))
        return {"items": items, "denyRuleRange": [1, DENY_RULE_MAX]}

    def resources(self, q):
        if q.get('region') not in (None, 'all', self.config.AWS_REGION):
            return {'items': []}
        reservations = self._pages('ec2', 'describe_instances', 'Reservations',
                                  Filters=[{'Name': 'instance-state-name', 'Values': ['running']}], MaxResults=PAGE_EC2)
        return {'items': sorted([{'id': item['InstanceId'], 'region': self.config.AWS_REGION, 'mode': 'live'}
                                for reservation in reservations for item in reservation.get('Instances', [])], key=lambda x: x['id'])}

    # ── 3계층 서비스 상태 ───────────────────────────────
    def services(self, q: dict) -> dict:
        """Nginx → Flask → MySQL 계층 상태.

        데모 어댑터와 **같은 모양**을 돌려준다(services/tiers.py 주석 참고).

        신호는 두 갈래다.
          ① ALB 가 있으면 대상 그룹 헬스체크 + ALB 지표 (가장 정확)
          ② ALB 가 없으면(`enable_alb` 기본 false) **CloudWatch Logs**
             — docker-host 의 nginx access/error 로그, db 의 mysql 로그.
             둘 다 CloudWatch Agent 가 이미 보내고 있고(compute/templates/*.tftpl),
             대시보드 역할에 `logs:FilterLogEvents` 가 있다.

        조회 실패는 502 로 올리지 않고 해당 계층만 UNKNOWN 으로 떨어뜨린다 —
        화면 전체가 죽으면 나머지 계층 상태도 못 본다.
        """
        from ..config import log_groups
        from ..services.tiers import CHECK_INTERVAL_SEC, RANK, TIERS

        region = q.get("region") or self.config.AWS_REGION
        at = q.get("to") or _now_ms()
        if region != self.config.AWS_REGION:
            return {"region": region, "checkedAt": at, "mode": "live", "overall": "UNKNOWN",
                    "target": None, "intervalSec": CHECK_INTERVAL_SEC, "items": [],
                    "note": "현재 연결된 단일 리전을 선택하세요."}

        health = self._target_health()
        latency = self._alb_latency(q) if health is not None else None
        alarms = self._alarm_states()
        nginx_group, mysql_group = log_groups(self.config)
        source = "ALB / CloudWatch" if health is not None else "CloudWatch Logs"

        # 로그는 ALB 가 없을 때만 읽는다. 호출 수를 늘리지 않기 위해서다.
        web_log = None if health is not None else self._nginx_log_signal(nginx_group, q)
        db_log = self._log_events(mysql_group, q, '?"[ERROR]" ?"Access denied"', limit=20)

        items = []
        for spec in TIERS:
            if spec["id"] == "nginx":
                status, detail, value = self._nginx_status(health, web_log, nginx_group)
            elif spec["id"] == "flask":
                status, detail, value = self._flask_status(latency, web_log, nginx_group)
            else:
                status, detail, value = self._mysql_status(alarms, db_log, mysql_group)

            items.append({
                "id": spec["id"], "name": spec["name"], "tier": spec["tier"], "port": spec["port"],
                "status": status, "detail": detail,
                "latencyMs": value, "errorRate": None,
                "checkedAt": at, "intervalSec": CHECK_INTERVAL_SEC,
                "target": nginx_group if spec["id"] != "mysql" else mysql_group,
                "probe": spec["probe"].format(host="ALB" if health is not None else "docker-host"),
                "dependsOn": spec["dependsOn"], "source": source, "blockers": [],
            })

        overall = "UP"
        for item in items:
            if RANK[item["status"]] >= RANK[overall]:
                overall = item["status"]

        note = None
        if all(item["status"] == "UNKNOWN" for item in items):
            note = ("ALB 도 로그도 읽지 못했습니다. `enable_alb=true` 로 배포하거나, "
                    "CloudWatch Agent 전송(NAT 또는 logs 엔드포인트)과 대시보드 IAM 읽기 권한을 확인하세요.")
        elif health is None:
            note = (f"ALB 가 없어 로그 기반으로 판정했습니다 (nginx: {nginx_group}, mysql: {mysql_group}). "
                    "대상 그룹 헬스체크로 보려면 `enable_alb=true` 로 배포하세요.")
        return {"region": region, "checkedAt": at, "mode": "live", "overall": overall,
                "target": self.config.AWS_REGION, "intervalSec": CHECK_INTERVAL_SEC,
                "items": items, "note": note}

    # ── 계층별 판정 ─────────────────────────────────────
    @staticmethod
    def _nginx_status(health, web_log, group):
        if health is not None:
            healthy, total = health
            if total == 0:
                return "DOWN", "ALB 대상 그룹에 등록된 대상이 없습니다.", None
            if healthy == 0:
                return "DOWN", f"정상 대상 0 / {total}", None
            if healthy < total:
                return "DEGRADED", f"정상 대상 {healthy} / {total}", None
            return "UP", f"정상 대상 {healthy} / {total}", None
        if web_log is None:
            return "UNKNOWN", f"로그 그룹을 읽지 못했습니다: {group}", None
        if web_log["errors"]:
            return "DEGRADED", f"nginx error 로그 {web_log['errors']}건 (최근 구간)", None
        if not web_log["access"]:
            return "UNKNOWN", "선택 구간에 nginx 요청 로그가 없습니다. 트래픽이 없거나 Agent 전송이 끊겼습니다.", None
        return "UP", f"nginx 요청 로그 {web_log['access']}건 · error 0건", None

    @staticmethod
    def _flask_status(latency, web_log, group):
        if latency is not None:
            response_ms, error_ratio = latency
            if error_ratio >= 5:
                return "DOWN", f"5XX 비율 {error_ratio}%", response_ms
            if error_ratio > 0 or response_ms > 1000:
                return "DEGRADED", f"응답 {response_ms}ms · 5XX {error_ratio}%", response_ms
            return "UP", f"응답 {response_ms}ms", response_ms
        if web_log is None:
            return "UNKNOWN", f"로그 그룹을 읽지 못했습니다: {group}", None
        # nginx 가 Flask 로 프록시하지 못하면 error.log 에 upstream 오류가 남는다.
        # 이게 ALB 없이 얻을 수 있는 유일한 앱 계층 신호다.
        upstream = web_log["upstream"]
        if upstream >= 5:
            return "DOWN", f"nginx upstream 오류 {upstream}건 — Flask 로 프록시되지 않습니다.", None
        if upstream:
            return "DEGRADED", f"nginx upstream 오류 {upstream}건", None
        if not web_log["access"]:
            return "UNKNOWN", "요청 로그가 없어 앱 계층을 판정할 수 없습니다.", None
        return "UP", f"upstream 오류 0건 · 요청 {web_log['access']}건 프록시 정상", None

    @staticmethod
    def _mysql_status(alarms, db_log, group):
        db_alarms = [a for a in alarms
                     if any(token in a["name"].lower() for token in ("mysql", "auth", "db"))]
        firing = [a["name"] for a in db_alarms if a["state"] == "ALARM"]
        if firing:
            return "DEGRADED", "알람: " + ", ".join(firing), None
        if db_log is None:
            if not db_alarms:
                return "UNKNOWN", f"알람도 로그({group})도 읽지 못했습니다.", None
            return "UNKNOWN", "MySQL 로그 그룹을 읽지 못했습니다.", None
        if db_log:
            return "DEGRADED", f"mysql 오류·인증실패 로그 {len(db_log)}건 (최근 구간)", None
        if db_alarms:
            return "UP", f"알람 {len(db_alarms)}건 정상 · 오류 로그 0건", None
        return "UP", "오류 로그 0건", None

    # ── 상류 신호 ───────────────────────────────────────
    def _log_events(self, group: str, q: dict, pattern: str | None = None, limit: int = 50):
        """CloudWatch Logs 조회. 그룹이 없거나 권한이 없으면 None."""
        if not group:
            return None
        kwargs = {"logGroupName": group, "startTime": int(q["from"]), "endTime": int(q["to"]),
                  "limit": limit}
        if pattern:
            kwargs["filterPattern"] = pattern
        try:
            return self._call("logs", "filter_log_events", **kwargs).get("events", [])
        except ApiProblem:
            return None

    def _nginx_log_signal(self, group: str, q: dict):
        """(요청 건수, error 건수, upstream 오류 건수). 조회 실패면 None."""
        access = self._log_events(group, q, limit=50)
        if access is None:
            return None
        errors = self._log_events(group, q, '?"[error]" ?"[crit]" ?"[emerg]"', limit=50) or []
        upstream = [e for e in errors if "upstream" in (e.get("message") or "")]
        return {"access": len(access), "errors": len(errors), "upstream": len(upstream)}

    def _target_health(self):
        """(정상 대상 수, 전체 대상 수). ALB 가 없으면 None."""
        try:
            groups = self._pages("elbv2", "describe_target_groups", "TargetGroups",
                                 token="Marker")
        except ApiProblem:
            return None
        if not groups:
            return None
        healthy = total = 0
        for group in groups:
            try:
                descriptions = self._call(
                    "elbv2", "describe_target_health",
                    TargetGroupArn=group["TargetGroupArn"]).get("TargetHealthDescriptions", [])
            except ApiProblem:
                continue
            total += len(descriptions)
            healthy += sum(1 for d in descriptions
                           if (d.get("TargetHealth") or {}).get("State") == "healthy")
        return (healthy, total)

    def _alb_latency(self, q: dict):
        """(p95 응답시간 ms, 5XX 비율 %). 지표가 없으면 None."""
        period = max(300, (((q["to"] - q["from"]) // 1000 // 12 + 299) // 300) * 300)
        queries = [
            {"Id": "rt", "MetricStat": {"Metric": {
                "Namespace": "AWS/ApplicationELB", "MetricName": "TargetResponseTime"},
                "Period": period, "Stat": "p95"}},
            {"Id": "e5", "MetricStat": {"Metric": {
                "Namespace": "AWS/ApplicationELB", "MetricName": "HTTPCode_Target_5XX_Count"},
                "Period": period, "Stat": "Sum"}},
            {"Id": "req", "MetricStat": {"Metric": {
                "Namespace": "AWS/ApplicationELB", "MetricName": "RequestCount"},
                "Period": period, "Stat": "Sum"}},
        ]
        try:
            results = self._pages(
                "cloudwatch", "get_metric_data", "MetricDataResults",
                MetricDataQueries=queries,
                StartTime=datetime.fromtimestamp(q["from"] / 1000, tz=timezone.utc),
                EndTime=datetime.fromtimestamp(q["to"] / 1000, tz=timezone.utc),
                ScanBy="TimestampDescending")
        except ApiProblem:
            return None
        series = {r["Id"]: [float(v) for v in r.get("Values", [])] for r in results}
        if not series.get("rt"):
            return None
        response_ms = round(series["rt"][0] * 1000, 1)
        errors, requests = sum(series.get("e5") or []), sum(series.get("req") or [])
        ratio = round(errors / requests * 100, 2) if requests else 0.0
        return (response_ms, ratio)

    def _alarm_states(self) -> list[dict]:
        prefix = getattr(self.config, "NAME_PREFIX", "") or ""
        kwargs = {"AlarmNamePrefix": prefix} if prefix else {}
        try:
            alarms = self._pages("cloudwatch", "describe_alarms", "MetricAlarms", **kwargs)
        except ApiProblem:
            return []
        return [{"name": a.get("AlarmName", ""), "state": a.get("StateValue", "")}
                for a in alarms]

    def _memory_metric(self) -> tuple[str, str]:
        """메모리 지표의 (네임스페이스, 지표명).

        이 프로젝트는 CloudWatch Agent 를 "<name_prefix>/host" 네임스페이스에
        MemoryUsedPercent 로 쏜다(soar/cloudwatch.tf:55-56). NAME_PREFIX 가 없으면
        Agent 기본값으로 떨어진다.
        """
        prefix = getattr(self.config, "NAME_PREFIX", "")
        if prefix:
            return f"{prefix}/host", "MemoryUsedPercent"
        return "CWAgent", "mem_used_percent"

    def _first_instance(self) -> str | None:
        """지표를 볼 EC2 를 고른다.

        finding 에서 찾지 않는다 — Security Hub 는 EC2 와 무관한 컨트롤 결과를
        대부분 올려서 EC2 가 한 건도 없을 수 있다. EC2 에 직접 묻는다.
        """
        def build():
            resp = self._call(
                "ec2", "describe_instances",
                Filters=[{"Name": "instance-state-name", "Values": ["running"]}],
                MaxResults=PAGE_EC2,
            )
            for reservation in resp.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    return instance.get("InstanceId")
            return None

        return self._cached("instance", self.config.CACHE_TTL["metrics"], build)

    def _trivy_report_key(self) -> str | None:
        """수동 점검(Trivy)의 최신 리포트 S3 키.

        본문은 파싱하지 않는다 — Trivy 출력은 형식이 고정돼 있지 않고,
        화면이 필요한 건 "언제 돌렸고 어디서 받나" 뿐이다.
        버킷 미설정이거나 조회 실패면 조용히 건너뛴다.
        """
        bucket = getattr(self.config, "SCAN_RESULTS_BUCKET", "")
        if not bucket:
            return None
        try:
            page = self._call("s3", "list_objects_v2", Bucket=bucket,
                              Prefix="trivy/", MaxKeys=PAGE_S3)
        except ApiProblem:
            return None
        objects = page.get("Contents") or []
        if not objects:
            return None
        latest = max(objects, key=lambda o: o.get("LastModified") or 0)
        return latest.get("Key")

    def vulnerabilities(self, q: dict) -> dict:
        """Inspector2 CVE 목록.

        이전에는 `_call(... maxResults=100)` 한 번이라 **100건에서 잘렸다.**
        maxResults 100 은 AWS 하드 상한이라 못 늘리므로, `_pages()` 로 끝까지 읽는다.
        총량은 MAX_RESPONSE_ITEMS 에서만 자르고 그때는 truncated 로 알린다.
        """
        def build():
            report_key = self._trivy_report_key()
            findings = self._pages(
                "inspector2", "list_findings", "findings", token="nextToken",
                filterCriteria={"findingType": [
                    {"comparison": "EQUALS", "value": "PACKAGE_VULNERABILITY"}]},
                maxResults=PAGE_INSPECTOR,
            )
            items = []
            for f in findings:
                vd = f.get("packageVulnerabilityDetails") or {}
                pkg = (vd.get("vulnerablePackages") or [{}])[0]
                scores = vd.get("cvss") or []
                resource = (f.get("resources") or [{}])[0].get("id") or ""
                items.append({
                    "id": f.get("findingArn") or vd.get("vulnerabilityId") or "",
                    "cveId": vd.get("vulnerabilityId"),
                    "source": "Inspector",
                    "kind": "INSTANCE",
                    "severity": f.get("severity") or "LOW",
                    "cvss": scores[0].get("baseScore") if scores else None,
                    "package": pkg.get("name"),
                    "installedVersion": pkg.get("version"),
                    "fixedVersion": pkg.get("fixedInVersion"),
                    "family": None,
                    "target": resource,
                    "resource": resource,
                    "region": _region_of(resource, self.config.AWS_REGION),
                    "foundAt": _ms(f.get("firstObservedAt")),
                    "reportKey": report_key,
                    "scenario": "SEC-04",
                    "note": None,
                })
            return items

        items = self._cached("vulns", self.config.CACHE_TTL["vulnerabilities"], build)
        return _shape_vulnerabilities(items, q, self._events())

    def execution_status(self, event_id: str, execution_id: str):
        event = self.get_event(event_id)
        if not event:
            return None
        run = self._call("ssm", "get_automation_execution",
                         AutomationExecutionId=execution_id).get("AutomationExecution") or {}
        status = enums.SSM_STATUS_TO_EXECUTION.get(run.get("AutomationExecutionStatus"), "RUNNING")
        steps = run.get("StepExecutions") or []
        execution = {
            "executionId": execution_id,
            "eventId": event_id,
            "kind": "REMEDIATION",
            "document": run.get("DocumentName"),
            "status": status,
            "startedAt": _ms(run.get("ExecutionStartTime")),
            "endedAt": _ms(run.get("ExecutionEndTime")),
            "progress": {
                "step": steps[-1].get("StepName") if steps else "실행 요청",
                "completed": sum(1 for s in steps if s.get("StepStatus") in ("Success", "Failed")),
                "total": len(steps) or 3,
            },
            "failureMessage": run.get("FailureMessage"),
        }
        event["execution"] = status
        return {"execution": execution, "event": event}

    # ── 쓰기 ────────────────────────────────────────────
    def _require(self, event_id: str) -> dict:
        event = self.get_event(event_id)
        if not event:
            raise ApiProblem(404, "이벤트를 찾을 수 없습니다.", code="EVENT_NOT_FOUND")
        return event

    def _automation_role_arn(self) -> str:
        """SSM Automation 이 떠맡을 역할.

        terraform 이 "<name_prefix>-ssm-automation-role" 로 고정 생성한다(main.tf:25).
        계정 번호만 알면 조립되므로 환경변수를 새로 만들지 않는다.
        """
        prefix = getattr(self.config, "NAME_PREFIX", "")
        if not prefix:
            raise ApiProblem(
                409, "NAME_PREFIX 가 설정되지 않았습니다.", code="CONFIG_MISSING",
                detail="dashboard.env 의 NAME_PREFIX 가 있어야 Automation 역할을 찾습니다.",
            )
        account = self._cached(
            "account", 3600,
            lambda: self._call("sts", "get_caller_identity")["Account"])
        return "arn:aws:iam::" + account + ":role/" + prefix + "-ssm-automation-role"

    def _parameters(self, event: dict, playbook: str) -> dict:
        """플레이북별 입력. 문서의 parameters 블록과 이름이 정확히 같아야 한다."""
        target = _short(event.get("resource") or "")
        if playbook == "ASR-BlockIpWithNacl":
            # 출발지 IP 가 있어야 차단할 대상이 정해진다.
            ip = event.get("sourceIp")
            if not ip:
                raise ApiProblem(
                    422, "차단할 출발지 IP 를 찾지 못했습니다.", code="NO_SOURCE_IP",
                    detail="GuardDuty finding 에 remoteIpDetails 가 없습니다.",
                )
            return {"NetworkAclId": [target], "AttackerCidr": [ip + "/32"],
                    "RuleNumber": ["50"]}
        table = {
            "ASR-RevokeSecurityGroupIngress": {"SecurityGroupId": [target]},
            "ASR-DisableExposedAccessKey": {"AccessKeyId": [target]},
            "ASR-RotateDbSecret": {"SecretId": [target]},
        }
        if playbook not in table:
            raise ApiProblem(
                501, "이 플레이북의 입력 매핑이 없습니다.", code="NOT_IMPLEMENTED",
                detail=playbook + ": documents/ 의 parameters 블록을 확인하세요.",
            )
        return table[playbook]

    def _record(self, event: dict, decision: str, actor: str,
                exec_id: str = "", before: str = "n/a", after: str = "pending") -> None:
        """asr_trigger _record() 와 같은 모양으로 남긴다(handler.py:61-70).

        finding_id 를 함께 넣어야 이벤트와 조인된다.
        """
        table = self.config.REMEDIATION_ACTIONS_TABLE
        if not table:
            return
        self._call("dynamodb", "put_item", TableName=table, Item={
            "action_id": {"S": "dash-" + uuid.uuid4().hex[:12]},
            "created_at": {"S": datetime.now(timezone.utc).isoformat()},
            "finding_id": {"S": event["id"]},
            "decision": {"S": decision},
            "finding_type": {"S": event.get("scenario") or "unknown"},
            "resource_id": {"S": event.get("resource") or "n/a"},
            "before_state": {"S": before},
            "after_state": {"S": after},
            "ssm_execution_id": {"S": exec_id or "n/a"},
            "actor": {"S": actor},
        })

    def _replay(self, key: str):
        """멱등성 — 같은 Idempotency-Key 는 같은 응답을 돌려준다.

        ponytail: 프로세스 메모리에만 둔다. 대시보드가 1대라 충분하고,
        여러 대로 늘리면 DynamoDB 조건부 쓰기로 옮긴다.
        """
        return self._idempotency.get(key)

    def approve(self, event_id, body, actor, key):
        self._require_write("approve")
        with self._lock:
            replay = self._replay(key)
            if replay:
                return replay
            event = self._require(event_id)
            self._record(event, "approved", actor)
            event["approver"] = actor
            event["approvedAt"] = _now_ms()
            event["history"].append({"at": _now_ms(), "text": "승인 (" + actor + ")",
                                     "actor": actor, "decision": "approved"})
            if event["status"] == "PENDING_APPROVAL":
                event["status"] = "APPROVED"
            self._idempotency[key] = event
            return event

    def execute(self, event_id, body, actor, key):
        self._require_write("execute")
        with self._lock:
            replay = self._replay(key)
            if replay:
                return replay
            event = self._require(event_id)

            from ..services.gates import evaluate
            dry_run = bool(body.get("dry_run"))
            decision = evaluate(event, dry_run=dry_run,
                                sg_has_auto_tag=self._sg_has_auto_tag)
            if not decision.allowed and self.config.ENFORCE_GATES:
                raise ApiProblem(422, decision.title, code=decision.code,
                                 detail=decision.detail)

            playbook = loader.playbook(event.get("scenario") or "")
            if dry_run or not playbook:
                # 게이트만 판정. SSM 을 부르지 않는다.
                kind = "dry-run" if dry_run else "manual-notified"
                text = ("dry-run 판정 통과" if dry_run
                        else "사람이 수행하는 조치 · 승인 기록됨")
                self._record(event, kind, actor)
                event["history"].append({"at": _now_ms(), "text": text,
                                         "actor": actor, "decision": kind})
                return {"execution": None, "event": event}

            exec_id = self._call(
                "ssm", "start_automation_execution",
                DocumentName=playbook,
                Parameters=dict(self._parameters(event, playbook),
                                AutomationAssumeRole=[self._automation_role_arn()]),
            )["AutomationExecutionId"]

            self._record(event, "auto-executed", actor, exec_id=exec_id,
                         before=str(event.get("before") or "n/a"))
            event["status"] = "EXECUTING"
            event["execution"] = "RUNNING"
            event["history"].append({"at": _now_ms(),
                                     "text": "조치 실행 요청 (" + playbook + ")",
                                     "actor": actor, "decision": "auto-executed"})
            result = {"execution": {
                "executionId": exec_id, "eventId": event_id, "kind": "REMEDIATION",
                "document": playbook, "status": "RUNNING", "startedAt": _now_ms(),
                "endedAt": None, "failureMessage": None,
                "progress": {"step": "실행 요청", "completed": 0, "total": 3},
            }, "event": event}
            self._idempotency[key] = result
            return result

    def _sg_has_auto_tag(self, group_id: str) -> bool:
        """게이트 ② — asr_trigger 와 같은 판정을 대시보드에서도 한다."""
        resp = self._call("ec2", "describe_security_groups", GroupIds=[group_id])
        return any(t.get("Key") == "AutoRemediation" and t.get("Value") == "true"
                   for g in resp.get("SecurityGroups", []) for t in g.get("Tags", []))

    def verify(self, event_id, body, actor, key):
        self._require_write("verify")
        with self._lock:
            replay = self._replay(key)
            if replay:
                return replay
            event = self._require(event_id)
            scenario = event.get("scenario") or ""

            if loader.needs_send_command(scenario):
                raise ApiProblem(
                    501, "이 재검증은 실행할 수 없습니다.", code="NOT_IMPLEMENTED",
                    detail="대시보드 역할에 ssm:SendCommand 가 없습니다(compute/iam.tf:250).",
                )

            spec = (loader.get(scenario) or {}).get("verify") or {}
            checker = {
                "sg_ingress_count": self._verify_sg_ingress,
                "inspector_cve_count": self._verify_cve_count,
                "iam_key_status": self._verify_iam_key,
            }.get(spec.get("type"))
            if not checker:
                raise ApiProblem(
                    501, "이 재검증 유형은 아직 구현되지 않았습니다.", code="NOT_IMPLEMENTED",
                    detail=str(spec.get("type") or "미지정") + ": 카탈로그 verify.type 확인",
                )

            value = checker(event, spec)
            passed = value == 0
            now = _now_ms()
            event["afterValue"] = value
            event["afterAt"] = now
            event["verification"] = "PASSED" if passed else "FAILED"
            event["status"] = "RESOLVED" if passed else "VERIFICATION_FAILED"
            event["history"].append({
                "at": now,
                "text": ("재검증 " + ("통과" if passed else "실패") + " · "
                         + str(spec.get("type")) + " = " + str(value)),
                "actor": actor, "decision": "verified"})
            self._record(event, "verified", actor,
                         before=str(event.get("before") or "n/a"), after=str(value))

            result = {"execution": {
                "executionId": "verify-" + uuid.uuid4().hex[:12], "eventId": event_id,
                "kind": "VERIFICATION", "document": None, "status": "SUCCEEDED",
                "startedAt": now, "endedAt": now,
                "failureMessage": None if passed else "미해결 항목이 남아 있습니다.",
                "progress": {"step": "동일 기준 재검사", "completed": 1, "total": 1},
            }, "event": event}
            self._idempotency[key] = result
            return result

    def _verify_sg_ingress(self, event: dict, spec: dict) -> int:
        """0.0.0.0/0 에 열린 해당 포트 규칙 수. 0 이면 통과."""
        resp = self._call("ec2", "describe_security_groups",
                          GroupIds=[_short(event.get("resource") or "")])
        port, cidr = spec.get("port"), spec.get("cidr")
        if not resp.get('SecurityGroups'):
            raise ApiProblem(422, '재검증 대상 보안 그룹이 없습니다.', code='EVIDENCE_REQUIRED')
        return sum(1
                   for g in resp.get("SecurityGroups", [])
                   for rule in g.get("IpPermissions", [])
                   if str(rule.get('IpProtocol', 'tcp')) == '-1' or
                   (str(rule.get('IpProtocol', 'tcp')) in ('6', 'tcp') and
                    rule.get('FromPort', -1) <= port <= rule.get('ToPort', rule.get('FromPort', -1)))
                   for r in rule.get("IpRanges", []) + rule.get('Ipv6Ranges', [])
                   if r.get("CidrIp") == cidr or r.get('CidrIpv6') == '::/0')

    def _verify_cve_count(self, event: dict, spec: dict) -> int:
        """대상의 미해결 CVE 수.

        이전에는 `_call(maxResults=100)` 한 번이라 **100건을 넘으면 그 이상을 못 셌다.**
        재검증 수치가 실제보다 작게 나와 "개선됐다"로 잘못 읽히는 경로였다.
        maxResults 100 은 inspector2 하드 상한이므로 `_pages()` 로 끝까지 읽는다.

        심각도 필터는 카탈로그의 `verify.min_severity` 를 따른다. SEC-04 는 criterion 이
        '전체 심각도'라 None 이다. 여기서 임의로 HIGH 이상을 걸면 criterion 과 어긋난다.
        """
        criteria = {
            "resourceId": [{"comparison": "EQUALS",
                            "value": _short(event.get("resource") or "")}],
            "findingType": [{"comparison": "EQUALS",
                             "value": "PACKAGE_VULNERABILITY"}],
        }
        floor = (spec or {}).get("min_severity")
        if floor:
            order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
            keep = order[: order.index(floor) + 1] if floor in order else [floor]
            criteria["severity"] = [{"comparison": "EQUALS", "value": v} for v in keep]
        findings = self._pages(
            "inspector2", "list_findings", "findings", token="nextToken",
            filterCriteria=criteria, maxResults=PAGE_INSPECTOR,
        )
        return len(findings)

    def _verify_iam_key(self, event: dict, spec: dict) -> int:
        """키가 아직 Active 면 1.

        **대시보드 역할에 iam:ListAccessKeys 가 없다.** 권한을 넣기 전까지 502 가 난다.
        조용히 0(통과)으로 떨어뜨리지 않는다 — 조치 안 됐는데 해결로 보이면 안 된다.
        """
        key_id = _short(event.get("resource") or "")
        user = self._call('iam', 'get_access_key_last_used', AccessKeyId=key_id).get('UserName')
        if not user:
            raise ApiProblem(422, '키 소유자를 확인할 수 없습니다.', code='EVIDENCE_REQUIRED')
        keys, marker = [], None
        while True:
            resp = self._call('iam', 'list_access_keys', UserName=user, **({'Marker': marker} if marker else {}))
            keys.extend(resp.get('AccessKeyMetadata', []))
            if not resp.get('IsTruncated'):
                break
            next_marker = resp.get('Marker')
            if not next_marker or next_marker == marker:
                raise ApiProblem(502, '키 목록이 불완전합니다.', code='UPSTREAM_ERROR')
            marker = next_marker
        matches = [item for item in keys if item.get('AccessKeyId') == key_id]
        if len(matches) != 1 or matches[0].get('Status') not in ('Active', 'Inactive'):
            raise ApiProblem(422, '키 상태를 확인할 수 없습니다.', code='EVIDENCE_REQUIRED')
        return int(matches[0]['Status'] == 'Active')

    def cancel(self, event_id, body, actor, key):
        self._require_write("cancel")
        raise ApiProblem(
            501, "실행 취소는 지원하지 않습니다.", code="NOT_IMPLEMENTED",
            detail=WRITE_PLAN["cancel"],
        )

    # ── 상태 점검 ───────────────────────────────────────
    def health_checks(self) -> dict:
        """실모드에서 어떤 상류가 살아 있는지 알려준다.

        예외 메시지를 그대로 노출하지 않는다 — 권한 오류 본문에 ARN 이 섞인다
        (04-backend-design.md §4.3).
        """
        try:
            import boto3  # noqa: F401,PLC0415
        except ImportError:
            return {k: "skipped" for k in ("dynamodb", "cloudwatch", "securityhub", "ssm")}

        probes = {
            "dynamodb": lambda: self._client("dynamodb").describe_table(
                TableName=self.config.CORRELATED_FINDINGS_TABLE),
            "cloudwatch": lambda: self._client("cloudwatch").describe_alarms(MaxRecords=1),
            "securityhub": lambda: self._client("securityhub").describe_hub(),
            "ssm": lambda: self._client("ssm").describe_automation_executions(MaxResults=1),
        }
        checks = {}
        for name, probe in probes.items():
            try:
                probe()
                checks[name] = "ok"
            except Exception:  # noqa: BLE001 — 상세는 서버 로그에만
                checks[name] = "error"
        return checks


def _metric_query(qid: str, namespace: str, name: str, instance: str, period: int) -> dict:
    return {"Id": qid, "MetricStat": {
        "Metric": {"Namespace": namespace, "MetricName": name,
                   "Dimensions": [{"Name": "InstanceId", "Value": instance}]},
        "Period": period, "Stat": "Average"}}


def _shape_vulnerabilities(items: list[dict], q: dict, events: list[dict]) -> dict:
    """데모 어댑터(services/vulns.py)와 **같은 응답 모양**으로 맞춘다.

    프론트가 모드별 분기 없이 같은 화면을 그리려면 groups·summary 가 반드시 있어야 한다.
    """
    from ..services.vulns import SEVERITY_RANK

    severity, source = q.get("severity"), q.get("source")
    needle = (q.get("q") or "").lower()
    target = q.get("resource")
    fixable_only = bool(q.get("fixableOnly"))

    rows = []
    for item in items:
        if severity and item["severity"] != severity:
            continue
        if source and item["source"] != source:
            continue
        if target and item["target"] != target:
            continue
        if fixable_only and not item.get("fixedVersion"):
            continue
        if needle:
            hay = " ".join(str(item.get(f) or "")
                           for f in ("cveId", "package", "target", "resource")).lower()
            if needle not in hay:
                continue
        rows.append(item)

    rows.sort(key=lambda x: (SEVERITY_RANK.get(x["severity"], 9), -(x.get("cvss") or 0),
                             x.get("cveId") or ""))
    truncated = len(rows) > MAX_RESPONSE_ITEMS
    rows = rows[:MAX_RESPONSE_ITEMS]

    by_target: dict[str, list[dict]] = {}
    for item in rows:
        by_target.setdefault(item["target"], []).append(item)

    def link(target_id: str):
        pool = [e for e in events if e.get("resource") == target_id]
        return max(pool, key=lambda e: e["at"]) if pool else None

    groups = []
    for target_id, mine in sorted(by_target.items()):
        event = link(target_id)
        groups.append({
            "target": target_id, "source": mine[0]["source"], "kind": mine[0]["kind"],
            "note": None, "scannedAt": max((x["foundAt"] or 0) for x in mine) or None,
            "total": len(mine),
            "bySeverity": {s: sum(1 for x in mine if x["severity"] == s)
                           for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
            "fixable": sum(1 for x in mine if x.get("fixedVersion")),
            "eventId": event["id"] if event else None,
            "eventStatus": event["status"] if event else None,
            "actionable": bool(event and event.get("actionable")),
        })

    return {
        "items": rows, "nextCursor": None, "total": len(rows), "truncated": truncated,
        "groups": groups,
        "summary": {
            "total": len(rows),
            "bySeverity": {s: sum(1 for x in rows if x["severity"] == s)
                           for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
            "fixable": sum(1 for x in rows if x.get("fixedVersion")),
            "uniqueCves": len({x["cveId"] for x in rows if x.get("cveId")}),
            "targets": len(groups),
        },
        "catalogVersion": None, "timeFiltered": False,
    }
