"""The ten authenticated schema-v1 routes; /health belongs to the app factory."""
from flask import Blueprint, current_app, g, jsonify, request

from .contracts import envelope
from .errors import Problem

bp = Blueprint("standard_api", __name__)


def service():
    return current_app.extensions["standard_service"]


def read(kind):
    data = service().read(kind, dict(request.args.lists()), g.actor)
    # 서비스가 붙인 경고·부분 결과 표시를 meta 로 옮긴다(설계 2.3 원칙 6).
    warnings = data.pop("_warnings", []) if isinstance(data, dict) else []
    partial = data.pop("_partial", False) if isinstance(data, dict) else False
    return jsonify(envelope(data, g.request_id, partial=partial, warnings=warnings))


def command(action, event_id=None):
    if not request.is_json:
        raise Problem(400, "Content-Type: application/json이 필요합니다.", "INVALID_PARAMETER")
    if not current_app.config["WRITE_ENABLED"]:
        raise Problem(403, "현재 조회 전용 모드입니다.", "WRITE_DISABLED")
    data, status = service().command(action, event_id, request.get_json(silent=True), g.actor,
                                     request.headers.get("Idempotency-Key"), g.request_id)
    return jsonify(envelope(data, g.request_id)), status


@bp.get("/api/events")
def events():
    return read("events")


@bp.get("/api/summary")
def summary():
    return read("summary")


@bp.get("/api/metrics")
def metrics():
    return read("metrics")


@bp.get("/api/vulnerabilities")
def vulnerabilities():
    return read("vulnerabilities")


@bp.get("/api/infra/status")
def infrastructure():
    return read("infra")


@bp.get("/api/history")
def history():
    return read("history")


@bp.post("/api/events/<string:event_id>/approve")
def approve(event_id):
    return command("approve", event_id)


@bp.post("/api/events/<string:event_id>/cancel")
def cancel(event_id):
    return command("cancel", event_id)


@bp.post("/execute")
def execute():
    return command("execute")


@bp.post("/verify")
def verify():
    return command("verify")
