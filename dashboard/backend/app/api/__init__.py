"""API 블루프린트 — 03-api-spec.yaml 의 12개 엔드포인트.

주의: run.py 의 전역 `@app.after_request` 가 모든 응답에 no-store 를 붙인다
(run.py:11-14). API 는 블루프린트 전용 after_request 로 이를 덮어쓴다.
"""
from __future__ import annotations

import re
import time
import uuid

from flask import Blueprint, Response, current_app, g, request

from .. import enums
from ..config import Config
from ..services.csv_export import to_csv
from .errors import ApiProblem

bp = Blueprint("api", __name__, url_prefix="/api")

REGION_RE = re.compile(r"^(?:[a-z]{2}-[a-z]+-\d|all|global)$")
UUID_RE = re.compile(r"^[0-9a-fA-F-]{8,64}$")


# ── 공통 ──────────────────────────────────────────────────
def adapter():
    return current_app.extensions["dashboard_adapter"]


def _now_ms() -> int:
    return int(time.time() * 1000)


def _int(name: str, default=None):
    raw = request.args.get(name)
    if raw in (None, ""):
        return default
    try:
        return int(raw)
    except ValueError:
        raise ApiProblem(400, f"{name} 은(는) 정수여야 합니다.", code="INVALID_PARAMETER")


def _enum(name: str, allowed: set[str], default=None):
    raw = request.args.get(name)
    if raw in (None, ""):
        return default
    if raw not in allowed:
        raise ApiProblem(
            400, f"{name} 값이 올바르지 않습니다.", code="INVALID_PARAMETER",
            detail=f"허용값: {', '.join(sorted(allowed))}",
        )
    return raw


def query() -> dict:
    """공통 질의 파라미터 파싱 + 검증 (04-backend-design.md §4.4)."""
    region = request.args.get("region") or "all"
    if not REGION_RE.match(region):
        raise ApiProblem(400, "리전 값이 올바르지 않습니다.", code="INVALID_PARAMETER")

    from ..adapters.demo import DEMO_NOW
    now = DEMO_NOW if adapter().mode == 'demo' else _now_ms()
    to = _int("to", now)
    frm = _int("from", to - 24 * 3600 * 1000)
    if frm > to:
        raise ApiProblem(400, "from 이 to 보다 늦습니다.", code="INVALID_PARAMETER")
    if to - frm > Config.MAX_RANGE_MS:
        raise ApiProblem(400, "조회 기간이 31일을 넘습니다.", code="INVALID_PARAMETER")
    if to > now + 5 * 60 * 1000:
        raise ApiProblem(400, "to 가 미래입니다.", code="INVALID_PARAMETER")

    needle = request.args.get("q") or ""
    if len(needle) > 200:
        raise ApiProblem(400, "검색어가 너무 깁니다.", code="INVALID_PARAMETER")
    limit = _int('limit', Config.DEFAULT_LIMIT)
    if not 1 <= limit <= Config.MAX_LIMIT:
        raise ApiProblem(400, f'limit은 1~{Config.MAX_LIMIT} 이어야 합니다.', code='INVALID_PARAMETER')

    return {
        "region": region,
        "view": request.args.get('view') or 'overview',
        "ignoreRegion": request.args.get("ignoreRegion", "").lower() in ("1", "true"),
        "environment": request.args.get("environment") or None,
        "resource": request.args.get("resource") or None,
        "from": frm,
        "to": to,
        "severity": _enum("severity", set(enums.SEVERITY_ORDER)),
        "status": _enum("status", set(enums.STATUS_TO_KO)),
        "source": _enum("source", set(enums.SOURCES)),
        "scenario": request.args.get("scenario") or None,
        "q": needle,
        "cursor": request.args.get("cursor") or None,
        "limit": limit,
        "includeDemoOnly": request.args.get("includeDemoOnly", "").lower() in ("1", "true"),
        # 취약점 화면 전용 — 수정 버전이 있는 항목만 본다.
        "fixableOnly": request.args.get("fixableOnly", "").lower() in ("1", "true"),
        # 인프라 화면이 리전의 모든 호스트 시계열을 한 번에 받는다.
        "scope": "all" if request.args.get("scope") == "all" else "one",
    }


def body() -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiProblem(400, "JSON 본문이 필요합니다.", code="INVALID_PARAMETER")
    expected = data.get("expected_status")
    if expected and expected not in enums.STATUS_TO_KO:
        raise ApiProblem(400, "expected_status 값이 올바르지 않습니다.", code="INVALID_PARAMETER")
    return data


def idempotency_key() -> str:
    key = request.headers.get("Idempotency-Key", "")
    if not key or not UUID_RE.match(key):
        raise ApiProblem(
            400, "Idempotency-Key 헤더가 필요합니다.", code="INVALID_PARAMETER",
            detail="중복 실행을 막기 위해 UUID 형식의 키를 보내야 합니다.",
        )
    return key


def require_write() -> None:
    if not current_app.config["WRITE_ENABLED"]:
        raise ApiProblem(
            409, "쓰기가 비활성화되어 있습니다.", code="WRITE_DISABLED",
            detail="WRITE_ENABLED=true 로 기동해야 승인·실행·재검증을 할 수 있습니다.",
        )


def actor() -> str:
    # B0 단계에서는 인증을 붙이지 않는다. flask-login 도입 시 current_user 로 교체.
    return g.actor


@bp.after_request
def _cache_headers(response: Response) -> Response:
    if request.method == "GET" and response.status_code == 200:
        ttl = 0
        response.headers["Cache-Control"] = (
            f"private, max-age={ttl}" if ttl else "no-store, max-age=0"
        )
    else:
        response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


# ── 조회 ──────────────────────────────────────────────────
@bp.get("/events")
def list_events():
    g.cache_ttl = Config.CACHE_TTL["events"]
    return adapter().list_events(query())


@bp.get("/events/<path:event_id>")
def get_event(event_id: str):
    g.cache_ttl = Config.CACHE_TTL["events"]
    event = adapter().get_event(event_id)
    if not event:
        raise ApiProblem(404, "이벤트를 찾을 수 없습니다.", code="EVENT_NOT_FOUND")
    return event


@bp.get("/metrics")
def metrics():
    g.cache_ttl = Config.CACHE_TTL["metrics"]
    return adapter().metrics(query())


@bp.get("/vulnerabilities")
def vulnerabilities():
    g.cache_ttl = Config.CACHE_TTL["vulnerabilities"]
    return adapter().vulnerabilities(query())


@bp.get("/scenarios")
def scenarios():
    g.cache_ttl = Config.CACHE_TTL["scenarios"]
    return adapter().scenarios(query())


@bp.get("/incidents")
def incidents():
    # 침해사례 탭 — 시나리오별 "공격 → 탐지 → 승인 → 조치 → 재검증" (README 2장·12장)
    g.cache_ttl = Config.CACHE_TTL["scenarios"]
    return adapter().incidents(query())


@bp.get("/events/<path:event_id>/evidence")
def evidence(event_id: str):
    result = adapter().evidence(event_id)
    if not result:
        raise ApiProblem(404, "이벤트를 찾을 수 없습니다.", code="EVENT_NOT_FOUND")
    return result


@bp.get("/export/events.csv")
def export_csv():
    q = query()
    if adapter().mode == 'demo':
        return Response(to_csv(adapter().snapshot(q)['items']),mimetype='text/csv',
                        headers={'Content-Disposition':'attachment; filename="aws-events.csv"'})
    q["limit"] = Config.MAX_LIMIT
    rows, cursor = [], None
    # 필터 전체를 내보낸다. 화면 페이지네이션과 무관하게 "총 N건"과 일치해야 한다.
    while True:
        q["cursor"] = cursor
        page = adapter().list_events(q)
        rows.extend(page["items"])
        cursor = page.get("nextCursor")
        if not cursor:
            break
    text = to_csv(rows)
    filename = f"aws-events-{q['region']}-events.csv"
    return Response(
        text,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── 쓰기 ──────────────────────────────────────────────────
@bp.post("/events/<path:event_id>/approve")
def approve(event_id: str):
    require_write()
    return adapter().approve(event_id, body(), actor(), idempotency_key())


@bp.post("/events/<path:event_id>/execute")
def execute(event_id: str):
    require_write()
    result = adapter().execute(event_id, body(), actor(), idempotency_key())
    return result, 202


@bp.get("/events/<path:event_id>/executions/<execution_id>")
def execution_status(event_id: str, execution_id: str):
    result = adapter().execution_status(event_id, execution_id)
    if not result:
        raise ApiProblem(404, "실행 기록을 찾을 수 없습니다.", code="EVENT_NOT_FOUND")
    return result


@bp.post("/events/<path:event_id>/verify")
def verify(event_id: str):
    require_write()
    result = adapter().verify(event_id, body(), actor(), idempotency_key())
    return result, 202


def new_idempotency_key() -> str:
    return str(uuid.uuid4())


@bp.post('/events/<path:event_id>/cancel')
def cancel(event_id):
    require_write()
    return adapter().cancel(event_id, body(), actor(), idempotency_key())


@bp.get('/snapshot')
def snapshot():
    return adapter().snapshot(query())


@bp.get('/summary')
def summary():
    data=adapter().snapshot(query())
    return {**data['summary'],'asOf':data['asOf'],'snapshot':data['snapshot']}


@bp.get('/config')
def config():
    from ..adapters.demo import DEMO_NOW,REGIONS
    return dict(mode=adapter().mode,asOf=DEMO_NOW if adapter().mode=='demo' else _now_ms(),
                writeEnabled=current_app.config['WRITE_ENABLED'],role=g.role,regions=REGIONS,
                statuses=enums.STATUS_TO_KO,sources=enums.SOURCES,awsConnected=None if adapter().mode=='live' else False)


@bp.get('/audit')
def audit_log():
    from ..storage import connect
    with connect(current_app.config['DATABASE']) as db:
        rows=db.execute('SELECT id,at,actor,event_id,action,detail FROM audit ORDER BY id DESC LIMIT 1000').fetchall()
    return {'items':[dict(row) for row in rows]}


@bp.get('/resources')
def resources():
    # 데모도 어댑터에 맡긴다. 서울 리전은 Terraform 의 EC2 5대를 그대로 돌려주므로
    # 인프라 화면에서 호스트를 골라 지표를 볼 수 있다.
    return adapter().resources(query())


@bp.get('/nacls')
def nacls():
    # SEC-06 차단 계획 폼이 쓰는 목록. 규칙 번호 1~99 는 Deny 예약 구간이다.
    g.cache_ttl = Config.CACHE_TTL["metrics"]
    return adapter().nacls(query())


@bp.get('/services')
def services():
    # 3계층(Nginx→Flask→MySQL) 상태. 화면 하드코딩을 대체하는 경로다.
    g.cache_ttl = Config.CACHE_TTL["metrics"]
    return adapter().services(query())


@bp.post('/events/<path:event_id>/plan')
def prepare_plan(event_id):
    require_write()
    if adapter().mode != 'live':
        raise ApiProblem(409, '실모드에서만 대상 계획을 설정할 수 있습니다.', code='WRITE_DISABLED')
    return adapter().prepare_plan(event_id, body(), actor(), idempotency_key())
