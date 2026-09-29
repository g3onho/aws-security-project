"""허니팟 화면 조회 서비스 — 동작 상태·세션·통계·관계 그래프·파이프라인 타임라인.

조회 전용이다(미끼 서버·NACL·SSM 을 바꾸지 않는다). 원천을 읽지 못하면 빈 값이나 정상으로 바꾸지 않고
`unknown`(읽지 못함)으로 표시한다. 미배포(HONEYPOT_LOG_GROUP 없음)는 상태 API 만 200(`deployed=false`)이고
나머지는 409 HONEYPOT_NOT_DEPLOYED 이다.

AI 분석(요약·의도·위험도)은 참고용이다. 어떤 차단·해제 판단에도 쓰지 않는다.
"""
import base64
import hashlib
import json
import logging

from .contracts import iso, parse_date
from .errors import Problem
from .repositories import honeypot as hp
from .store import now_ms

LOG = logging.getLogger(__name__)
DAY = 86_400_000
DEFAULT_WRITER_ROLES = frozenset({"operator"})  # 비밀번호 원문 보기·차단 변경이 가능한 역할 기본값(설정 BLOCKLIST_WRITE_ROLES)


def parse_window(raw, now):
    """from·to(UTC ISO 8601). 기본은 최근 24시간, 최대 31일."""
    values = {}
    if set(raw) - {"from", "to"}:
        raise Problem(400, "지원하지 않는 조회 필터입니다.", "INVALID_FILTER")
    for field, value in raw.items():
        if isinstance(value, list):
            if len(value) != 1:
                raise Problem(400, "같은 필터를 여러 번 지정할 수 없습니다.", "INVALID_FILTER")
            value = value[0]
        values[field] = value
    if ("from" in values) != ("to" in values):
        raise Problem(400, "from과 to는 함께 지정해야 합니다.", "INVALID_FILTER")
    start = parse_date(values["from"], "from") if "from" in values else now - DAY
    end = parse_date(values["to"], "to") if "to" in values else now
    if not 0 < end - start <= 31 * DAY:
        raise Problem(400, "조회 구간은 0보다 크고 31일 이하여야 합니다.", "INVALID_FILTER")
    return start, end, values


def authorize(provider, principal):
    """허니팟·차단 목록은 계정 전체 자료다 — 범위가 제한된 계정(특정 자원·다른 계정·리전만)은 볼 수 없다."""
    scope = principal.get("scope") or {}
    accounts, regions = scope.get("accounts"), scope.get("regions")
    if (scope.get("resources") is not None
            or (accounts is not None and getattr(provider, "account_id", None) not in accounts)
            or (regions is not None and getattr(provider, "region", None) not in regions)):
        raise Problem(403, "범위가 제한된 계정은 허니팟 자료를 볼 수 없습니다.", "FORBIDDEN")


class HoneypotService:
    def __init__(self, provider, workflow, settings):
        self.provider, self.workflow = provider, workflow
        self.writer_roles = frozenset(settings.get("BLOCKLIST_WRITE_ROLES") or DEFAULT_WRITER_ROLES)
        self.sources = getattr(provider, "honeypot", None)
        self.blocklist = getattr(provider, "blocklist", None)
        self.auto_controls = {c.strip() for c in (settings.get("AUTO_REMEDIABLE_CONTROLS") or "").split(",") if c.strip()}
        self.auto_configured = settings.get("AUTO_REMEDIABLE_CONTROLS") is not None
        self.auto_enabled = settings.get("ENABLE_AUTO_REMEDIATION")
        self.writes_enabled = settings.get("WRITE_ENABLED", False)

    # --- 공통 ---------------------------------------------------------------------------
    def deployed(self):
        return bool(self.sources and self.sources.log_group)

    def _guard(self, actor, need_deployed=True):
        self.provider.require_ready()
        principal = self.workflow.principal(actor)
        authorize(self.provider, principal)
        if need_deployed and not self.deployed():
            raise Problem(409, "허니팟이 배포되지 않았습니다(enable_honeypot).", "HONEYPOT_NOT_DEPLOYED")
        return principal

    def load(self, start, end):
        """(세션 {id: 세션}, 경고 목록, partial). 로그를 읽지 못하면 502."""
        try:
            raw, truncated = self.sources.events(start, end)
        except Exception as error:  # noqa: BLE001 — 원인 이름만 남기고 세부는 응답에 싣지 않는다
            LOG.exception("honeypot log read failed")
            raise Problem(502, "허니팟 로그를 읽지 못했습니다.", "HONEYPOT_LOG_UNAVAILABLE",
                          detail=type(error).__name__) from error
        events, skipped = hp.parse(raw)
        warnings = []
        if truncated:
            warnings.append(f"로그가 많아 앞쪽 {len(raw)}행까지만 읽었습니다. 기간을 줄여 다시 조회하세요.")
        if skipped:
            warnings.append(f"형식이 맞지 않는 로그 {skipped}행은 건너뛰었습니다.")
        return hp.sessions(events), warnings, bool(truncated or skipped)

    # --- ① 동작 상태 ---------------------------------------------------------------------
    def status(self, raw_query, actor):
        principal = self._guard(actor, need_deployed=False)
        now = now_ms()
        if not self.deployed():
            return {"deployed": False, "verdict": {"state": "not_deployed", "label": "허니팟 미배포", "reasons": []},
                    "cards": {}, "canWrite": False}, [], False
        cards, reasons, warnings = {}, [], []
        # 미끼 인스턴스
        try:
            found = self.sources.instances()
            running = [i for i in found if i["state"] == "running"]
            if running:
                cards["instance"] = {"state": "ok", "text": "running", "at": running[0]["launchedAt"],
                                     "detail": f"{running[0]['id']} · {running[0]['privateIp']}"}
            elif found:
                cards["instance"] = {"state": "bad", "text": found[0]["state"], "at": found[0]["launchedAt"],
                                     "detail": found[0]["id"]}
                reasons.append(f"미끼 인스턴스가 {found[0]['state']} 상태")
            else:
                cards["instance"] = {"state": "bad", "text": "없음", "at": None, "detail": "태그 Scenario=HONEYPOT 인스턴스 없음"}
                reasons.append("미끼 인스턴스를 찾지 못함")
        except Exception as error:  # noqa: BLE001
            cards["instance"] = {"state": "unknown", "text": "읽지 못함", "at": None, "detail": type(error).__name__}
            reasons.append("미끼 인스턴스 상태를 읽지 못함")
        # 로그·AI 응답 (최근 24시간 세션)
        sessions = None
        try:
            sessions, warn, _ = self.load(now - DAY, now)
            warnings += warn
        except Problem as error:
            cards["logs"] = {"state": "unknown", "text": "읽지 못함", "at": None, "detail": error.detail or error.title}
            cards["ai"] = {"state": "unknown", "text": "읽지 못함", "at": None, "detail": ""}
            reasons.append("허니팟 로그를 읽지 못함")
        if sessions is not None:
            last = max((s["endedAt"] or s["startedAt"] for s in sessions.values()), default=None)
            if last:
                cards["logs"] = {"state": "ok", "text": "수신 중", "at": last, "detail": f"최근 24시간 세션 {len(sessions)}개"}
            else:
                cards["logs"] = {"state": "info", "text": "최근 24시간 관측 없음", "at": None,
                                 "detail": "접속이 없으면 로그도 없다 — 시험 접속으로 확인하세요"}
            with_commands = [s for s in sessions.values() if s["commands"] and s["analysis"]]
            applied = [s for s in with_commands if s["analysis"]["aiApplied"]]
            if not with_commands:
                cards["ai"] = {"state": "unknown", "text": "확인할 세션 없음", "at": None,
                               "detail": "명령이 있고 분석이 끝난 세션이 없다"}
            elif applied:
                cards["ai"] = {"state": "ok", "text": f"{len(applied)}/{len(with_commands)}", "at": None,
                               "detail": "AI 분석이 적용된 세션 / 분석된 세션(명령 있음)"}
            else:
                cards["ai"] = {"state": "warn", "text": f"0/{len(with_commands)}", "at": None,
                               "detail": "AI 분석이 한 번도 적용되지 않음 — 모델 ID·Bedrock 모델 액세스 확인"}
                reasons.append("AI 분석이 적용되지 않음")
        # 탐지 알람
        try:
            alarm = self.sources.alarm()
            if alarm is None:
                cards["alarm"] = {"state": "bad", "text": "알람 없음", "at": None, "detail": self.sources.alarm_name or "이름 설정 없음"}
                reasons.append("탐지 알람을 찾지 못함")
            else:
                cards["alarm"] = {"state": "info" if alarm["state"] == "INSUFFICIENT_DATA" else "ok",
                                  "text": alarm["state"], "at": alarm["updatedAt"], "detail": alarm["name"]}
        except Exception as error:  # noqa: BLE001
            cards["alarm"] = {"state": "unknown", "text": "읽지 못함", "at": None, "detail": type(error).__name__}
            reasons.append("탐지 알람 상태를 읽지 못함")
        # 자동 차단
        cards["block"], block_reasons = self._block_card(now)
        reasons += block_reasons
        states = [c["state"] for c in cards.values()]
        if "unknown" in (cards["instance"]["state"], cards["logs"]["state"]):
            verdict = {"state": "unknown", "label": "확인 불가"}
        elif reasons:
            verdict = {"state": "partial", "label": "일부 동작"}
        elif "info" in states or "unknown" in states:
            verdict = {"state": "waiting", "label": "동작 확인 중(관측 필요)"}
            reasons.append("아직 접속·분석·차단 관측이 부족해 끝까지 확인되지 않음")
        else:
            verdict = {"state": "ok", "label": "정상 동작"}
        return {"deployed": True, "verdict": {**verdict, "reasons": reasons}, "cards": cards,
                "canWrite": principal["role"] in self.writer_roles and bool(self.writes_enabled),
                "asOf": iso(now)}, warnings, bool(warnings)

    def _block_card(self, now):
        reasons = []
        if not self.auto_configured or self.auto_enabled is None:
            return {"state": "unknown", "text": "설정 확인 불가", "at": None,
                    "detail": "자동 조치 설정 환경변수가 없다"}, reasons
        listed = "HONEYPOT" in self.auto_controls
        enabled = str(self.auto_enabled).lower() == "true"
        if not listed or not enabled:
            reasons.append("HONEYPOT 자동 차단이 꺼져 있음(수동 대응으로만 기록)")
            return {"state": "warn", "text": "자동 차단 꺼짐", "at": None,
                    "detail": "auto_remediable_controls 에 HONEYPOT 없음" if not listed else "전체 dry-run"}, reasons
        try:
            actions = self.provider.actions()
        except Exception as error:  # noqa: BLE001
            return {"state": "unknown", "text": "조치 이력 읽지 못함", "at": None, "detail": type(error).__name__}, reasons
        if not actions.get("configured"):
            return {"state": "unknown", "text": "조치 이력 설정 없음", "at": None, "detail": ""}, reasons
        rows = sorted((r for r in actions["items"] if r.get("controlId") == "HONEYPOT"), key=lambda r: -r["createdAt"])
        if not rows:
            return {"state": "info", "text": "자동 차단 켜짐 · 아직 실행 없음", "at": None, "detail": "미끼 접속이 알람을 울려야 실행된다"}, reasons
        last = rows[0]
        ok = last["status"] in {"SUCCESS", "IN_PROGRESS", "NO_CHANGE"}
        if not ok:
            reasons.append(f"최근 HONEYPOT 조치가 {last['status']}")
        return {"state": "ok" if ok else "bad", "text": last["status"], "at": last["createdAt"],
                "detail": last.get("reason") or ""}, reasons

    # --- ⑤ 세션 ------------------------------------------------------------------------------
    def sessions(self, raw_query, actor):
        self._guard(actor)
        now = now_ms()
        raw = dict(raw_query)
        limit_raw = (raw.pop("limit", ["50"]) or ["50"])[0]
        cursor = (raw.pop("cursor", [None]) or [None])[0]
        ip = (raw.pop("ip", [None]) or [None])[0]
        intent = (raw.pop("intent", [None]) or [None])[0]
        start, end, _ = parse_window(raw, now)
        if not limit_raw.isdigit() or not 1 <= int(limit_raw) <= 200:
            raise Problem(400, "limit은 1~200 정수여야 합니다.", "INVALID_FILTER")
        if intent is not None and intent not in hp.INTENTS:
            raise Problem(400, "intent 필터가 올바르지 않습니다.", "INVALID_FILTER")
        by_id, warnings, partial = self.load(start, end)
        rows = [hp.summary(s) for s in by_id.values() if (not ip or s["srcIp"] == ip)
                and (not intent or (s["analysis"] or {}).get("intent") == intent)]
        rows.sort(key=lambda r: (-r["startedAt"], r["sessionId"]))
        binding = hashlib.sha256(json.dumps([start // 60000, end // 60000, ip, intent]).encode()).hexdigest()[:16]
        offset = 0
        if cursor:
            try:
                decoded = json.loads(base64.urlsafe_b64decode(cursor.encode()))
                if decoded.get("b") != binding or type(decoded.get("o")) is not int or decoded["o"] < 0:
                    raise ValueError
                offset = decoded["o"]
            except (ValueError, TypeError):
                raise Problem(400, "cursor가 올바르지 않거나 필터가 바뀌었습니다.", "INVALID_CURSOR") from None
        page = rows[offset:offset + int(limit_raw)]
        nxt = None
        if offset + len(page) < len(rows):
            nxt = base64.urlsafe_b64encode(json.dumps({"o": offset + len(page), "b": binding}).encode()).decode()
        return {"items": page, "nextCursor": nxt, "total": len(rows)}, warnings, partial

    def session(self, session_id, raw_query, actor, reveal=False):
        principal = self._guard(actor)
        if reveal and principal["role"] not in self.writer_roles:
            raise Problem(403, "비밀번호 원문은 조치 담당자만 볼 수 있습니다.", "FORBIDDEN")
        start, end, _ = parse_window(raw_query, now_ms())
        by_id, warnings, partial = self.load(start, end)
        s = by_id.get(session_id)
        if s is None:
            raise Problem(404, "선택한 기간에서 세션을 찾지 못했습니다.", "SESSION_NOT_FOUND")
        detail = hp.summary(s) | {
            "srcPort": s["srcPort"], "hasConnect": s["hasConnect"],
            "authAttempts": [{"at": a["at"], "user": a["user"], "passwordLength": len(a["password"]),
                              "password": a["password"] if reveal else None} for a in s["authAttempts"]],
            "commands": s["commands"], "analysis": s["analysis"],
            "analysisNote": "AI 분석은 참고용이며 차단·해제 판단에 쓰지 않는다."}
        return detail, warnings, partial

    # --- ③④ 통계·그래프 ----------------------------------------------------------------------
    def stats(self, raw_query, actor):
        self._guard(actor)
        start, end, _ = parse_window(raw_query, now_ms())
        by_id, warnings, partial = self.load(start, end)
        return {"from": iso(start), "to": iso(end), **hp.stats(by_id, start, end), "graph": hp.graph(by_id)}, warnings, partial

    # --- ② 파이프라인 타임라인 ------------------------------------------------------------------
    def timeline(self, raw_query, actor):
        self._guard(actor)
        raw = dict(raw_query)
        ip = (raw.pop("ip", [None]) or [None])[0]
        from .repositories.blocklist import valid_ip
        if not valid_ip(ip):
            raise Problem(400, "ip는 IPv4 주소여야 합니다.", "INVALID_FILTER")
        start, end, _ = parse_window(raw, now_ms())
        by_id, warnings, partial = self.load(start, end)
        mine = sorted((s for s in by_id.values() if s["srcIp"] == ip), key=lambda s: s["startedAt"])
        steps = []

        def step(key, label, state, at=None, detail="", source=None):
            steps.append({"key": key, "label": label, "state": state, "at": at, "detail": detail, "source": source})

        if not mine:
            step("connect", "접속(connect)", "missing", detail="이 기간에 이 IP 의 미끼 접속 기록이 없다", source="허니팟 로그")
            return {"ip": ip, "steps": steps, "sessions": []}, warnings, partial
        first = mine[0]
        auth = [a for s in mine for a in s["authAttempts"]]
        commands = [c for s in mine for c in s["commands"]]
        ended = [s for s in mine if s["analysis"]]
        step("connect", "접속(connect)", "done", first["startedAt"], f"세션 {len(mine)}개", "허니팟 로그")
        step("auth", "로그인 시도(auth)", "done" if auth else "missing", auth[0]["at"] if auth else None,
             f"{len(auth)}회" if auth else "기록 없음", "허니팟 로그")
        step("command", "명령(command)", "done" if commands else "missing", commands[0]["at"] if commands else None,
             f"{len(commands)}개" if commands else "기록 없음", "허니팟 로그")
        last_end = max(ended, key=lambda s: s["endedAt"]) if ended else None
        step("analysis", "세션 종료·AI 분석", "done" if last_end else "missing", last_end["endedAt"] if last_end else None,
             (f"{last_end['analysis']['intent']} · " + ("AI 적용" if last_end["analysis"]["aiApplied"] else "AI 미적용(규칙 판정)"))
             if last_end else "session_end 기록 없음(진행 중이거나 종료 기록 실패)", "허니팟 로그")
        # 알람 ALARM (접속 이후 첫 전이)
        try:
            transitions = self.sources.alarm_transitions(first["startedAt"], min(end + 3_600_000, now_ms()))
            alarms = sorted((t for t in transitions if t["to"] == "ALARM" and t["at"] >= first["startedAt"]), key=lambda t: t["at"])
            step("alarm", "알람 ALARM", "done" if alarms else "missing", alarms[0]["at"] if alarms else None,
                 (f"접속 후 {(alarms[0]['at'] - first['startedAt']) // 1000}초" if alarms else "접속 이후 ALARM 전이 기록 없음"),
                 self.sources.alarm_name)
        except Exception as error:  # noqa: BLE001
            step("alarm", "알람 ALARM", "unknown", detail=f"읽지 못함({type(error).__name__})", source=self.sources.alarm_name)
        # asr_trigger 판정 · SSM 실행
        judge, run = self._judgement(ip)
        steps += [judge, run]
        step_nacl = self._nacl_step(ip)
        steps.append(step_nacl)
        return {"ip": ip, "steps": steps, "sessions": [hp.summary(s) for s in mine[-20:]]}, warnings, partial

    def _judgement(self, ip):
        cell = lambda key, label, state, at=None, detail="", source=None: {  # noqa: E731
            "key": key, "label": label, "state": state, "at": at, "detail": detail, "source": source}
        try:
            actions = self.provider.actions()
        except Exception as error:  # noqa: BLE001
            unknown = cell("judge", "asr_trigger 판정", "unknown", detail=f"읽지 못함({type(error).__name__})")
            return unknown, cell("ssm", "SSM 실행", "unknown", detail="판정을 읽지 못함")
        if not actions.get("configured"):
            return (cell("judge", "asr_trigger 판정", "unknown", detail="조치 이력 표 설정 없음"),
                    cell("ssm", "SSM 실행", "unknown"))
        rows = sorted((r for r in actions["items"] if r.get("controlId") == "HONEYPOT"
                       and (r.get("resource") or "").endswith(f"{ip}/32")), key=lambda r: -r["createdAt"])
        if not rows:
            return (cell("judge", "asr_trigger 판정", "missing", detail="이 IP 의 HONEYPOT 판정 기록 없음", source="조치 이력"),
                    cell("ssm", "SSM 실행", "missing", detail="판정이 없어 실행도 없다"))
        row = rows[0]
        judge = cell("judge", "asr_trigger 판정", "done", row["createdAt"], f"{row['decision']} · {row.get('reason') or ''}"[:200],
                     f"조치 이력 {row['actionId']}")
        if not row.get("executionId"):
            return judge, cell("ssm", "SSM 실행", "missing", detail="실행 없음(수동 대응 필요·dry-run 등)", source=row["actionId"])
        try:
            found, evidence = self.provider.execution(row["executionId"])
        except Exception as error:  # noqa: BLE001
            return judge, cell("ssm", "SSM 실행", "unknown", detail=f"읽지 못함({type(error).__name__})", source=row["executionId"])
        if not found or evidence is None:
            return judge, cell("ssm", "SSM 실행", "missing", detail="실행 기록을 찾지 못함(보존 기간 경과)", source=row["executionId"])
        state = "done" if evidence["status"] in {"Success", "CompletedWithSuccess"} else (
            "failed" if evidence["status"] in {"Failed", "TimedOut", "Cancelled", "CompletedWithFailure"} else "pending")
        return judge, cell("ssm", "SSM 실행", state, evidence.get("endedAt") or evidence.get("startedAt"),
                           evidence["status"], row["executionId"])

    def _nacl_step(self, ip):
        base = {"key": "nacl", "label": "NACL Deny 확인", "at": None, "source": "NACL 1~99"}
        if self.blocklist is None:
            return {**base, "state": "unknown", "detail": "차단 목록 설정 없음"}
        try:
            denies = self.blocklist.nacl_denies()
        except Exception as error:  # noqa: BLE001
            return {**base, "state": "unknown", "detail": f"NACL 을 읽지 못함({type(error).__name__})"}
        if ip in denies:
            return {**base, "state": "done", "detail": f"규칙 {denies[ip]} Deny {ip}/32 존재"}
        return {**base, "state": "missing", "detail": "현재 NACL 에 이 IP 의 Deny 없음(미차단·만료·해제)"}
