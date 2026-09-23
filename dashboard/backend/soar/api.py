"""Compatibility routes only. Business decisions live in Dashboard/Workflow."""
import uuid

from flask import Blueprint, Response, current_app, g, request

from . import readmodel
from .errors import Problem
from .queries import legacy_query

bp = Blueprint("legacy", __name__, url_prefix="/api/legacy")


def dashboard():
    return current_app.extensions["legacy_dashboard"]


def query():
    return legacy_query(request.args, current_app.extensions["provider"].as_of)


@bp.get("/config")
def config():
    return dashboard().config(g.actor)


@bp.get("/health")
def health():
    return dashboard().health()


@bp.get("/audit")
def audit():
    return dashboard().audit(g.actor)


@bp.get("/export/events.csv")
def export():
    return Response(dashboard().read("csv", query(), g.actor), content_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="events.csv"'})


@bp.get("/events/<string:event_id>")
def event(event_id):
    return dashboard().event(event_id, g.actor)


@bp.get("/events/<string:event_id>/evidence")
def evidence(event_id):
    return readmodel.evidence(dashboard().event(event_id, g.actor))


@bp.get("/events/<string:event_id>/executions/<string:job_id>")
def execution(event_id, job_id):
    dashboard().event(event_id, g.actor)
    result = current_app.extensions["workflow"].execution(event_id, job_id)
    result["event"] = dashboard().event(event_id, g.actor)
    return result


@bp.post("/events/<string:event_id>/<string:action>")
def change(event_id, action):
    if not current_app.config["WRITE_ENABLED"]:
        raise Problem(409, "조치 기능이 비활성화되어 있습니다.", "WRITE_DISABLED")
    key = request.headers.get("Idempotency-Key", "")
    try:
        if str(uuid.UUID(key)) != key.lower():
            raise ValueError
    except ValueError as error:
        raise Problem(400, "UUID 형식의 Idempotency-Key가 필요합니다.") from error
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise Problem(400, "JSON 객체 본문이 필요합니다.")
    body["request_id"] = g.request_id
    return current_app.extensions["workflow"].change(event_id, action, body, g.actor, key)


def register_reads():
    for name in ("events", "snapshot", "summary", "metrics", "services", "resources", "nacls",
                 "scenarios", "incidents", "vulnerabilities"):
        def read(kind=name):
            return dashboard().read(kind, query(), g.actor)
        bp.add_url_rule("/" + name, endpoint="read_" + name, view_func=read, methods=["GET"])


register_reads()
