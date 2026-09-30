"""대시보드 도우미 라우트(v27): 상태 조회(GET)와 대화(POST). 둘 다 읽기만 한다.

대화는 POST 라 CSRF 를 요구하지만, 조회 전용 도구만 쓰므로 viewer 도 쓸 수 있다(auth.py 가드의 예외 경로).
질문·답변 원문은 감사 기록에 남기지 않는다 — 누가 언제 어떤 도구를 몇 토큰으로 썼는지만 남긴다.
"""
from flask import Blueprint, current_app, g, jsonify, request

from .contracts import envelope
from .errors import Problem

bp = Blueprint("assistant_api", __name__)


def assistant():
    return current_app.extensions["assistant_service"]


def reports():
    return current_app.extensions["report_service"]


@bp.get("/api/assistant/status")
def assistant_status():
    return jsonify(envelope({**assistant().status(), "report": reports().status()}, g.request_id))


@bp.post("/api/assistant/chat")
def assistant_chat():
    if not request.is_json:
        raise Problem(400, "Content-Type: application/json이 필요합니다.", "INVALID_PARAMETER")
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise Problem(400, "요청 본문이 올바르지 않습니다.", "INVALID_PARAMETER")
    result = assistant().chat(body.get("messages"), g.actor)
    store = current_app.extensions["store"]
    with store.connect(write=True) as db:
        store.audit(db, g.actor, None, "assistant-chat", {"requestId": g.request_id, "role": g.role,
                                                         "tools": [t["name"] for t in result["toolsUsed"]],
                                                         "usage": result["usage"]})
    return jsonify(envelope(result, g.request_id))


@bp.post("/api/assistant/report")
def assistant_report():
    """화면별 AI 요약 보고서. 숫자는 서버가 집계하고 모델은 문장만 쓴다. 본문·집계 원문은 감사 기록에 남기지 않는다."""
    if not request.is_json:
        raise Problem(400, "Content-Type: application/json이 필요합니다.", "INVALID_PARAMETER")
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise Problem(400, "요청 본문이 올바르지 않습니다.", "INVALID_PARAMETER")
    result = reports().generate(body.get("view"), body, g.actor)
    store = current_app.extensions["store"]
    with store.connect(write=True) as db:
        store.audit(db, g.actor, None, "assistant-report", {"requestId": g.request_id, "role": g.role, "view": result["view"],
                                                          "cached": result["cached"], "usage": result["usage"],
                                                          "warnings": len(result["warnings"])})
    return jsonify(envelope(result, g.request_id))


@bp.post("/api/drills/run-all/<string:run_id>/summary")
def drills_run_summary(run_id):
    """실행 이력에 붙는 AI 한 줄 요약. 끝난 실행에 한 번만 만들어 저장하고, 이후는 저장된 값을 돌려준다."""
    result = reports().summarize_run_line(run_id, g.actor)
    if result["created"]:
        store = current_app.extensions["store"]
        with store.connect(write=True) as db:
            store.audit(db, g.actor, None, "run-summary-line", {"requestId": g.request_id, "role": g.role,
                                                               "runId": run_id, "source": result["source"]})
    return jsonify(envelope(result, g.request_id))
