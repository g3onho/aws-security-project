"""SSM Automation 실행 요약 → 조치 전/후 증거.

이 값은 조치 문서가 실행 직후 스스로 보고한 값(실행 결과)이다. 같은 조건으로 다시 확인한 재검증이 아니다
(용어집: 실행 응답을 재검증 증거로 쓰지 않는다). 화면은 "조치 직후 SSM 보고값 · 재검증 전"으로 표시한다.
ASR 문서의 before·after 는 JSON 문자열(보안그룹 규칙·NACL 규칙·설정 사전) 또는 짧은 문장이다.
사람이 읽을 줄 목록으로 바꾸고, 전후에서 없어진 줄·생긴 줄을 따로 뽑는다.
"""
import json

LINE_LIMIT, TEXT_LIMIT = 40, 300
PLACEHOLDERS = {"(규칙 없음)", "(설정 없음)"}  # 빈 목록 표시용 — 바뀐 줄로 세지 않는다
PROTOCOLS = {"-1": "전체", "6": "TCP", "17": "UDP", "1": "ICMP", "tcp": "TCP", "udp": "UDP", "icmp": "ICMP"}


def _ports(start, end):
    if start in (None, -1) and end in (None, -1):
        return "전체 포트"
    return str(start) if start == end else f"{start}-{end}"


def _permission(rule):
    """보안그룹 규칙 1개 → 줄 목록(출발지마다 한 줄)."""
    protocol = PROTOCOLS.get(str(rule.get("IpProtocol")), str(rule.get("IpProtocol")))
    where = "" if protocol == "전체" else " " + _ports(rule.get("FromPort"), rule.get("ToPort"))
    sources = ([r.get("CidrIp") for r in rule.get("IpRanges") or []]
               + [r.get("CidrIpv6") for r in rule.get("Ipv6Ranges") or []]
               + [r.get("GroupId") for r in rule.get("UserIdGroupPairs") or []]
               + [r.get("PrefixListId") for r in rule.get("PrefixListIds") or []])
    return [f"{protocol}{where} ← {source}" for source in sources if source] or [f"{protocol}{where}"]


def _nacl(entry):
    number = entry.get("RuleNumber")
    if number == 32767:
        return None  # 모든 NACL 에 있는 기본 거부(*) 규칙 — 매번 같아서 뺀다
    protocol = PROTOCOLS.get(str(entry.get("Protocol")), str(entry.get("Protocol")))
    ports = entry.get("PortRange") or {}
    where = "" if protocol == "전체" else " " + _ports(ports.get("From"), ports.get("To"))
    action = "허용" if entry.get("RuleAction") == "allow" else "차단"
    return f"규칙 {number} {action} {protocol}{where} ← {entry.get('CidrBlock') or entry.get('Ipv6CidrBlock')}"


def describe(text):
    """before·after 문자열 → 사람이 읽을 줄 목록. None 이면 None."""
    if text is None:
        return None
    try:
        value = json.loads(text)
    except (TypeError, ValueError):
        value = None
    if isinstance(value, list) and all(isinstance(item, dict) for item in value):
        if any("IpProtocol" in item for item in value):
            lines = [line for item in value for line in _permission(item)]
        elif any("RuleNumber" in item for item in value):
            lines = [line for line in (_nacl(item) for item in sorted(value, key=lambda e: e.get("RuleNumber") or 0)) if line]
        else:
            lines = [json.dumps(item, ensure_ascii=False, sort_keys=True) for item in value]
        return lines[:LINE_LIMIT] or ["(규칙 없음)"]
    if isinstance(value, dict):
        if {"inbound", "outbound"} <= set(value):  # ASR-RemoveDefaultSgRules
            lines = ([f"인바운드 {line}" for rule in value["inbound"] for line in _permission(rule)]
                     + [f"아웃바운드 {line}" for rule in value["outbound"] for line in _permission(rule)])
            return lines[:LINE_LIMIT] or ["(규칙 없음)"]
        return [f"{key} = {json.dumps(value[key], ensure_ascii=False)}" for key in sorted(value)][:LINE_LIMIT] or ["(설정 없음)"]
    return [line[:TEXT_LIMIT] for line in str(text).splitlines() if line.strip()][:LINE_LIMIT] or [str(text)[:TEXT_LIMIT]]


def _first(values):
    return values[0] if values else None


def _payload(outputs):
    try:
        return json.loads(_first(outputs.get("OutputPayload")) or "{}").get("Payload") or {}
    except (TypeError, ValueError, AttributeError):
        return {}


def evidence(execution):
    """실행 요약 → {status, document, before, after, removed, added, changed, failureMessage, startedAt, endedAt}.
    실행 기록이 없으면 None."""
    if not execution:
        return None
    steps = execution.get("steps") or []
    step = next((s for s in steps if {"before", "after", "OutputPayload"} & set(s.get("outputs") or {})), None)
    outputs = (step or {}).get("outputs") or {}
    payload = _payload(outputs)
    before_text = _first(outputs.get("before")) or payload.get("before")
    after_text = _first(outputs.get("after")) or payload.get("after")
    before, after = describe(before_text), describe(after_text)
    changed = _first(outputs.get("changed"))
    changed = payload.get("changed") if changed is None else str(changed).lower() == "true"
    revoked = _first(outputs.get("revoked_count"))
    if changed is None and revoked is not None:
        changed = str(revoked) not in {"0", "0.0"}
    failure = execution.get("failureMessage") or next((s.get("failureMessage") for s in steps if s.get("failureMessage")), None)
    return {"status": execution.get("status"), "document": execution.get("document"),
            "step": (step or {}).get("name"), "before": before, "after": after,
            "removed": [line for line in before if line not in (after or []) and line not in PLACEHOLDERS]
                       if before and after is not None else [],
            "added": [line for line in after if line not in (before or []) and line not in PLACEHOLDERS]
                     if after and before is not None else [],
            "changed": changed if isinstance(changed, bool) else None,
            "failureMessage": str(failure)[:TEXT_LIMIT] if failure else None,
            "startedAt": execution.get("startedAt"), "endedAt": execution.get("endedAt")}
