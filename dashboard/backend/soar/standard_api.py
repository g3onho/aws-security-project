"""The ten authenticated schema-v1 routes; /health belongs to the app factory."""
from flask import Blueprint, current_app, g, jsonify, request

from .contracts import envelope
from .errors import Problem

bp = Blueprint("standard_api", __name__)


def service():
    return current_app.extensions["standard_service"]


def drills():
    return current_app.extensions["drill_service"]


def read(kind):
    data = service().read(kind, dict(request.args.lists()), g.actor)
    # 서비스가 붙인 경고·부분 결과 표시를 meta 로 옮긴다(설계 2.3 원칙 6).
    warnings = data.pop("_warnings", []) if isinstance(data, dict) else []
    partial = data.pop("_partial", False) if isinstance(data, dict) else False
    as_of = data.pop("_asOf", None) if isinstance(data, dict) else None  # 적재 데이터면 마지막 대조 시각
    return jsonify(envelope(data, g.request_id, as_of=as_of, partial=partial, warnings=warnings))


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


@bp.get("/api/drills/catalog")
def drills_catalog():
    return jsonify(envelope(drills().catalog(), g.request_id))


@bp.get("/api/drills")
def drills_list():
    return jsonify(envelope(drills().run_list(), g.request_id))


@bp.post("/api/drills/web-scan/start")
def drills_web_scan_start():
    # 실제 공격(SSM SendCommand)을 실행한다 → 조회 전용 게이트를 적용한다.
    if not current_app.config["WRITE_ENABLED"]:
        raise Problem(403, "현재 조회 전용 모드입니다.", "WRITE_DISABLED")
    params = request.get_json(silent=True) if request.is_json else {}
    result = drills().start_web_scan(params or {}, g.actor)
    return jsonify(envelope(result, g.request_id)), 202


@bp.get("/api/drills/web-scan/<string:run_id>/status")
def drills_web_scan_status(run_id):
    return jsonify(envelope(drills().web_scan_status(run_id), g.request_id))


@bp.post("/api/drills/run-all/start")
def drills_run_all_start():
    # 준비된 모든 실습(SEC-02/07/08/06B/10)을 실행 → 조회 전용 게이트 적용.
    if not current_app.config["WRITE_ENABLED"]:
        raise Problem(403, "현재 조회 전용 모드입니다.", "WRITE_DISABLED")
    params = request.get_json(silent=True) if request.is_json else {}
    result = drills().start_all(params or {}, g.actor)
    return jsonify(envelope(result, g.request_id)), 202


@bp.get("/api/drills/run-all/<string:run_id>/status")
def drills_run_all_status(run_id):
    return jsonify(envelope(drills().all_status(run_id), g.request_id))


@bp.get("/api/drills/<string:run_id>")
def drills_detail(run_id):
    return jsonify(envelope(drills().run_detail(run_id), g.request_id))

