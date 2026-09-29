"""허니팟 화면·차단 IP 관리 라우트(v25). 라우트는 입력 검증과 응답 변환만 하고 업무 규칙은 서비스가 맡는다.

조회 6개(GET)와 변경 2개(POST·PATCH). 변경은 앱 공통 가드가 인증·CSRF·viewer 차단을 먼저 하고,
서비스가 역할(operator)·WRITE_ENABLED·Idempotency-Key·expectedVersion 을 다시 검사한다.
"""
import re
from datetime import datetime, timezone

from flask import Blueprint, Response, current_app, g, jsonify, request

from .contracts import envelope
from .errors import Problem
from .store import now_ms

bp = Blueprint("honeypot_api", __name__)
SESSION_ID = re.compile(r"^[0-9a-f]{12}$")


def honeypot():
    return current_app.extensions["honeypot_service"]


def blocklist():
    return current_app.extensions["blocklist_service"]


def answer(result, status=200):
    data, warnings, partial = result
    return jsonify(envelope(data, g.request_id, partial=partial, warnings=warnings)), status


def json_body():
    if not request.is_json:
        raise Problem(400, "Content-Type: application/json이 필요합니다.", "INVALID_PARAMETER")
    return request.get_json(silent=True)


@bp.get("/api/honeypot/status")
def honeypot_status():
    return answer(honeypot().status(dict(request.args.lists()), g.actor))


@bp.get("/api/honeypot/sessions")
def honeypot_sessions():
    return answer(honeypot().sessions(dict(request.args.lists()), g.actor))


@bp.get("/api/honeypot/sessions/<string:session_id>")
def honeypot_session(session_id):
    if not SESSION_ID.match(session_id):
        raise Problem(404, "세션을 찾을 수 없습니다.", "SESSION_NOT_FOUND")
    query = dict(request.args.lists())
    reveal = (query.pop("revealPasswords", ["false"]) or ["false"])[0]
    if reveal not in {"true", "false"}:
        raise Problem(400, "revealPasswords는 true 또는 false여야 합니다.", "INVALID_FILTER")
    result = honeypot().session(session_id, query, g.actor, reveal == "true")
    if reveal == "true":  # 비밀번호 원문을 본 기록(누가·어느 세션)
        store = current_app.extensions["store"]
        with store.connect(write=True) as db:
            store.audit(db, g.actor, None, "honeypot-reveal-passwords", {"sessionId": session_id, "requestId": g.request_id})
    return answer(result)


@bp.get("/api/honeypot/stats")
def honeypot_stats():
    return answer(honeypot().stats(dict(request.args.lists()), g.actor))


@bp.get("/api/honeypot/timeline")
def honeypot_timeline():
    return answer(honeypot().timeline(dict(request.args.lists()), g.actor))


@bp.get("/api/blocklist")
def blocklist_list():
    query = dict(request.args.lists())
    fmt = (query.pop("format", ["json"]) or ["json"])[0]
    if fmt not in {"json", "csv", "download"}:
        raise Problem(400, "format은 json, csv 중 하나여야 합니다.", "INVALID_FILTER")
    result = blocklist().list(query, g.actor)
    if fmt == "json":
        return answer(result)
    data, warnings, partial = result
    stamp = datetime.fromtimestamp(now_ms() / 1000, timezone.utc).strftime("%Y%m%d-%H%M")
    if fmt == "csv":
        body = blocklist().report_csv(data)
        response = Response(body, mimetype="text/csv")
        response.headers["Content-Disposition"] = f'attachment; filename="blocklist-{stamp}.csv"'
        return response
    response = jsonify(envelope(data, g.request_id, partial=partial, warnings=warnings))
    response.headers["Content-Disposition"] = f'attachment; filename="blocklist-{stamp}.json"'
    return response


def _write_gate():
    if not current_app.config["WRITE_ENABLED"]:
        raise Problem(403, "현재 조회 전용 모드입니다.", "WRITE_DISABLED")


@bp.post("/api/blocklist/<string:ip>/release")
def blocklist_release(ip):
    _write_gate()
    body = json_body()
    data, status = blocklist().release(ip, body, g.actor, request.headers.get("Idempotency-Key"), g.request_id)
    return jsonify(envelope(data, g.request_id)), status


@bp.patch("/api/blocklist/<string:ip>")
def blocklist_patch(ip):
    _write_gate()
    body = json_body()
    data, status = blocklist().patch(ip, body, g.actor, request.headers.get("Idempotency-Key"), g.request_id)
    return jsonify(envelope(data, g.request_id)), status
