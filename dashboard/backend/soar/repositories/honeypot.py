"""허니팟 세션 로그(CloudWatch Logs, JSON 한 줄 = 이벤트 하나) → 세션·통계·관계 그래프.

이 모듈은 순수 변환이다(AWS·Flask 호출 없음). 입력은 integrations/aws/honeypot.py 가 읽어 온 원본 로그 행
`{timestamp(ms), logStreamName, message}` 이다.

**로그의 모든 문자열은 공격자가 조종할 수 있다**(명령·사용자명·비밀번호·미끼 응답, 그리고 AI 가 만든 요약·IOC 까지).
그래서 여기서는 (1) 형식이 다르면 버리고(skipped 로 센다), (2) 길이를 자르고, (3) 값이 정해진 집합(의도·위험도)이면
그 집합 밖의 값은 unknown 으로 바꾼다. 화면은 이 값을 반드시 텍스트로만 그려야 한다(HTML 로 넣지 않는다).
"""
import ipaddress
import json
import re
from collections import Counter

INTENTS = ("recon", "credential-access", "lateral-movement", "exfiltration", "impact", "unknown")
SEVERITIES = ("low", "medium", "high", "critical")
SESSION_ID = re.compile(r"^[0-9a-f]{12}$")  # honeypot.py 가 uuid4().hex[:12] 로 만든다
NOT_APPLIED = "AI 분석 미적용"                 # honeypot.py 의 규칙 기반 대체 요약에 들어가는 문구
LIMITS = {"command": 4000, "response": 2000, "user": 128, "password": 256, "summary": 500, "ioc": 200}
MAX_IOCS = 20


def _text(value, limit):
    return value[:limit] if isinstance(value, str) else ""


def _ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    return str(address) if address.version == 4 else None


def parse(raw_events):
    """원본 로그 행 → (이벤트 목록, 해석하지 못해 버린 행 수). 시각 순(같은 시각은 도착 순서 유지)."""
    events, skipped = [], 0
    for row in raw_events:
        try:
            body = json.loads(row.get("message") or "")
        except (TypeError, ValueError):
            skipped += 1
            continue
        session_id = body.get("session_id") if isinstance(body, dict) else None
        if not isinstance(session_id, str) or not SESSION_ID.match(session_id) or not isinstance(body.get("event"), str):
            skipped += 1
            continue
        events.append({"at": int(row.get("timestamp") or 0), "session": session_id, "kind": body["event"], "body": body})
    events.sort(key=lambda e: e["at"])
    return events, skipped


def _analysis(raw):
    """세션 종료 시 AI(또는 규칙)가 만든 분석. 정해진 집합·길이로 정리한다."""
    if not isinstance(raw, dict):
        return None
    summary = _text(raw.get("summary"), LIMITS["summary"])
    iocs = [_text(item, LIMITS["ioc"]) for item in (raw.get("iocs") if isinstance(raw.get("iocs"), list) else [])
            if isinstance(item, str)][:MAX_IOCS]
    intent = raw.get("intent") if raw.get("intent") in INTENTS else "unknown"
    severity = raw.get("severity") if raw.get("severity") in SEVERITIES else None
    return {"summary": summary, "iocs": iocs, "intent": intent, "severity": severity,
            "aiApplied": bool(summary) and NOT_APPLIED not in summary}


def sessions(events):
    """이벤트 → {sessionId: 세션}. connect 가 없는 세션(창이 중간에 걸림)은 첫 이벤트 시각을 시작으로 본다."""
    out = {}
    for event in events:
        body, sid = event["body"], event["session"]
        ip = _ip(body.get("src_ip"))
        s = out.setdefault(sid, {"sessionId": sid, "srcIp": None, "srcPort": None, "startedAt": event["at"],
                                 "hasConnect": False, "endedAt": None, "authAttempts": [], "commands": [],
                                 "analysis": None, "pendingCommand": None})
        if ip and not s["srcIp"]:
            s["srcIp"] = ip
        kind = event["kind"]
        if kind == "connect":
            s["hasConnect"], s["startedAt"] = True, event["at"]
            port = body.get("src_port")
            s["srcPort"] = port if isinstance(port, int) and 0 <= port <= 65535 else None
        elif kind == "auth":
            s["authAttempts"].append({"at": event["at"], "user": _text(body.get("user"), LIMITS["user"]),
                                      "password": _text(body.get("password"), LIMITS["password"])})
        elif kind == "command":
            entry = {"at": event["at"], "command": _text(body.get("command"), LIMITS["command"]), "response": None}
            s["commands"].append(entry)
            s["pendingCommand"] = entry
        elif kind == "response":
            if s["pendingCommand"] is not None and s["pendingCommand"]["response"] is None:
                s["pendingCommand"]["response"] = _text(body.get("response"), LIMITS["response"])
        elif kind == "session_end":
            s["endedAt"] = event["at"]
            s["analysis"] = _analysis(body.get("analysis"))
    for s in out.values():
        s.pop("pendingCommand")
    return out


def summary(s):
    """목록용 요약 한 줄."""
    a = s["analysis"] or {}
    return {"sessionId": s["sessionId"], "srcIp": s["srcIp"], "startedAt": s["startedAt"], "endedAt": s["endedAt"],
            "authCount": len(s["authAttempts"]), "commandCount": len(s["commands"]),
            "intent": a.get("intent"), "severity": a.get("severity"), "aiApplied": a.get("aiApplied"),
            "analyzed": s["analysis"] is not None}


BUCKET_CHOICES = (60, 300, 900, 1800, 3600, 10800, 21600, 86400)


def bucket_seconds(start_ms, end_ms, target=24):
    span = max(1, (end_ms - start_ms) // 1000)
    return next((b for b in BUCKET_CHOICES if span / b <= target), BUCKET_CHOICES[-1])


def _top(counter, n=10):
    return [{"key": key, "count": count} for key, count in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[:n]]


def stats(by_id, start_ms, end_ms):
    """③ 통계 차트 자료. 시간대별·IP별·명령별·의도·위험도·사용자명. 비밀번호는 집계하지 않는다."""
    rows = list(by_id.values())
    step = bucket_seconds(start_ms, end_ms) * 1000
    first = (start_ms // step) * step
    buckets = {t: {"sessions": 0, "commands": 0} for t in range(first, end_ms + 1, step)}
    ips, commands, users = {}, Counter(), Counter()
    intents, severities = Counter({k: 0 for k in INTENTS}), Counter({k: 0 for k in SEVERITIES})
    unanalyzed = 0
    for s in rows:
        slot = buckets.get((s["startedAt"] // step) * step)
        if slot is not None:
            slot["sessions"] += 1
            slot["commands"] += len(s["commands"])
        if s["srcIp"]:
            row = ips.setdefault(s["srcIp"], {"ip": s["srcIp"], "sessions": 0, "commands": 0, "auth": 0,
                                              "firstSeen": s["startedAt"], "lastSeen": s["startedAt"]})
            row["sessions"] += 1
            row["commands"] += len(s["commands"])
            row["auth"] += len(s["authAttempts"])
            row["firstSeen"], row["lastSeen"] = min(row["firstSeen"], s["startedAt"]), max(row["lastSeen"], s["startedAt"])
        commands.update(c["command"].strip()[:200] for c in s["commands"] if c["command"].strip())
        users.update(a["user"] for a in s["authAttempts"] if a["user"])
        if s["analysis"]:
            intents[s["analysis"]["intent"]] += 1
            if s["analysis"]["severity"]:
                severities[s["analysis"]["severity"]] += 1
        else:
            unanalyzed += 1
    return {
        "bucketSeconds": step // 1000,
        "timeline": [{"at": t, **buckets[t]} for t in sorted(buckets)],
        "topIps": sorted(ips.values(), key=lambda r: (-r["sessions"], -r["commands"], r["ip"]))[:10],
        "topCommands": _top(commands), "topUsers": _top(users),
        "intents": [{"key": k, "count": intents[k]} for k in INTENTS],
        "severities": [{"key": k, "count": severities[k]} for k in SEVERITIES],
        "totals": {"sessions": len(rows), "commands": sum(len(s["commands"]) for s in rows),
                   "uniqueIps": len(ips), "unanalyzed": unanalyzed},
    }


GRAPH_LIMITS = {"ips": 15, "sessionsPerIp": 4, "commands": 20}


def graph(by_id):
    """④ 관계 그래프: 출발지 IP → 세션 → 명령. 노드가 많아지면 상위 N개만 남기고 나머지는 개수로 알린다."""
    rows = [s for s in by_id.values() if s["srcIp"]]
    per_ip = {}
    for s in rows:
        per_ip.setdefault(s["srcIp"], []).append(s)
    ranked = sorted(per_ip.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    shown_ips = ranked[:GRAPH_LIMITS["ips"]]
    command_count = Counter()
    for _, group in shown_ips:
        for s in group:
            command_count.update({c["command"].strip()[:200] for c in s["commands"] if c["command"].strip()})
    keep = {c for c, _ in sorted(command_count.items(), key=lambda kv: (-kv[1], kv[0]))[:GRAPH_LIMITS["commands"]]}
    nodes, links, hidden_sessions = [], [], 0
    for ip, group in shown_ips:
        nodes.append({"id": f"ip:{ip}", "type": "ip", "label": ip, "sessions": len(group)})
        group = sorted(group, key=lambda s: (-s["startedAt"], s["sessionId"]))
        for s in group[:GRAPH_LIMITS["sessionsPerIp"]]:
            a = s["analysis"] or {}
            nodes.append({"id": f"s:{s['sessionId']}", "type": "session", "label": s["sessionId"],
                          "intent": a.get("intent") or "unknown", "severity": a.get("severity"),
                          "commands": len(s["commands"])})
            links.append({"source": f"ip:{ip}", "target": f"s:{s['sessionId']}"})
            for command in {c["command"].strip()[:200] for c in s["commands"]} & keep:
                links.append({"source": f"s:{s['sessionId']}", "target": f"c:{command}"})
        hidden_sessions += max(0, len(group) - GRAPH_LIMITS["sessionsPerIp"])
    linked = {link["target"] for link in links}
    nodes += [{"id": f"c:{c}", "type": "command", "label": c[:60], "count": command_count[c]}
              for c in sorted(keep) if f"c:{c}" in linked]
    return {"nodes": nodes, "links": links,
            "hidden": {"ips": max(0, len(ranked) - len(shown_ips)), "sessions": hidden_sessions,
                       "commands": max(0, len(command_count) - len(keep))}}


def by_ip(by_id, ip):
    """한 IP 의 세션 요약(차단 IP 근거·보고서용)."""
    rows = [s for s in by_id.values() if s["srcIp"] == ip]
    if not rows:
        return {"sessionCount": 0, "commandCount": 0, "authCount": 0, "lastSeenAt": None, "intents": [],
                "topCommands": [], "sessionIds": []}
    commands = Counter(c["command"].strip()[:200] for s in rows for c in s["commands"] if c["command"].strip())
    intents = sorted({s["analysis"]["intent"] for s in rows if s["analysis"]})
    rows.sort(key=lambda s: (-s["startedAt"], s["sessionId"]))
    return {"sessionCount": len(rows), "commandCount": sum(len(s["commands"]) for s in rows),
            "authCount": sum(len(s["authAttempts"]) for s in rows), "lastSeenAt": rows[0]["startedAt"],
            "intents": intents, "topCommands": _top(commands, 5), "sessionIds": [s["sessionId"] for s in rows[:20]]}


def csv_safe(value):
    """CSV·스프레드시트 수식 주입 방지: 수식 문자로 시작하면 앞에 작은따옴표를 붙인다."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text
