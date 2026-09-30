"""Application factory. Construction has no network calls or background threads."""
import gzip
import uuid
from pathlib import Path

from flask import Flask, g, redirect, render_template, request, send_from_directory
from jinja2 import ChoiceLoader, FileSystemLoader

from .auth import current_user, install_auth
from .contracts import StandardService, envelope
from .blocklist_service import BlocklistService
from .remediation_service import RemediationService
from .drills import DrillService
from .assistant_api import bp as assistant_api
from .assistant_service import AssistantService, Tools
from .report_service import ReportService
from .honeypot_api import bp as honeypot_api
from .honeypot_service import HoneypotService
from .guidance import AutoPolicy
from .provider import AwsProvider, UnconfiguredProvider
from .errors import install_errors
from .settings import configure
from .standard_api import bp as standard_api
from .store import Store
from .worker import Worker
from .workflow import Workflow


def _attack_config(settings):
    """지리별 웹보안검사 실행 설정. 값이 없으면 실행 경로는 409(미배포)로 남는다."""
    regions = [r.strip() for r in (settings.get("ATTACK_REGIONS") or "").split(",") if r.strip()]
    return {
        "documentName": settings.get("ATTACK_DOCUMENT_NAME"),
        "targetIp": settings.get("DVWA_TARGET_IP"),
        "webUrl": settings.get("DVWA_WEB_URL"),
        "scanBucket": settings.get("SCAN_RESULTS_BUCKET"),
        "regions": regions,
        # 파리(홈 리전) 로컬 실습(SEC-02/07/10)이 도는 리전. geo 공격 리전과 별개.
        "homeRegion": settings.get("AWS_REGION"),
    }


COMPRESSIBLE = {"application/json", "application/javascript", "text/javascript", "image/svg+xml", "application/geo+json"}
COMPRESS_MIN_BYTES = 1024


def _compress(response):
    """텍스트·JSON·지도 데이터를 gzip 으로 보낸다(외부 의존성 없음). 이미 압축됐거나 작거나 부분 응답이면 건드리지 않는다."""
    if (response.status_code != 200 or response.headers.get("Content-Encoding") or "Content-Range" in response.headers
            or "gzip" not in request.headers.get("Accept-Encoding", "").lower()):
        return response
    kind = (response.mimetype or "").lower()
    if not (kind.startswith("text/") or kind in COMPRESSIBLE or request.path.endswith(".geojson")):
        return response
    response.direct_passthrough = False
    body = response.get_data()
    if len(body) < COMPRESS_MIN_BYTES:
        return response
    response.set_data(gzip.compress(body, compresslevel=5, mtime=0))
    response.headers["Content-Encoding"] = "gzip"
    response.headers.add("Vary", "Accept-Encoding")
    etag = response.get_etag()[0]
    if etag:
        response.set_etag(etag, weak=True)  # 본문이 압축본이라 바이트 단위로는 같지 않다
    return response


def _demo_provider(settings):
    """DATA_PROVIDER=demo — 실제 AWS 를 호출하지 않는 모의 공급자(soar/demo.py). 시연·화면 확인 전용."""
    from .demo import DemoProvider
    return DemoProvider(settings["AWS_REGION"])


def create_app(overrides=None):
    settings = configure(overrides)
    frontend = Path(settings["FRONTEND_PATH"]).resolve()
    if not (frontend / "templates" / "index.html").is_file():
        raise ValueError(f"Frontend templates were not found at {frontend}")
    app = Flask(__name__, template_folder=str(frontend / "templates"), static_folder=None)
    app.jinja_loader = ChoiceLoader([FileSystemLoader(Path(__file__).with_name("templates")),
                                    app.jinja_loader])
    app.config.update(settings)
    store = Store(settings["DATABASE"])
    provider = (AwsProvider(settings["AWS_REGION"], actions_table=settings["REMEDIATION_ACTIONS_TABLE"],
                            correlated_table=settings["CORRELATED_FINDINGS_TABLE"],
                            findings_table=settings["FINDINGS_TABLE"],
                            vulnerabilities_table=settings["VULNERABILITIES_TABLE"],
                            event_source=settings["EVENT_SOURCE"],
                            vulnerability_source=settings["VULNERABILITY_SOURCE"],
                            auto_policy=AutoPolicy.from_settings(settings),
                            name_prefix=settings["NAME_PREFIX"],
                            honeypot_log_group=settings["HONEYPOT_LOG_GROUP"],
                            honeypot_alarm_name=settings["HONEYPOT_ALARM_NAME"],
                            blocklist_table=settings["IP_BLOCKLIST_TABLE"],
                            private_nacl_id=settings["PRIVATE_NACL_ID"],
                            unblock_document=settings["DOC_UNBLOCK_IP"],
                            automation_role_arn=settings["AUTOMATION_ROLE_ARN"],
                            tier_status_table=settings["TIER_STATUS_TABLE"])
                if settings["DATA_PROVIDER"] == "aws" else _demo_provider(settings) if settings["DATA_PROVIDER"] == "demo"
                else UnconfiguredProvider())
    if provider.connected and not settings.get("TESTING"):
        provider.warm()  # 취약점 목록(Inspector 수천 건)을 기동 직후 미리 받아 둔다
    workflow = Workflow(store, provider, settings["APPROVAL_TTL_SECONDS"])
    worker = Worker(store, provider, settings["WORKER_LEASE_SECONDS"])
    honeypot_service = HoneypotService(provider, workflow, settings)
    blocklist_service = BlocklistService(provider, workflow, store, honeypot_service, settings)
    standard_service = StandardService(store, workflow, provider, settings["SECRET_KEY"], settings["WRITE_ENABLED"])
    # 대시보드 원클릭 조치: 계획은 탐지에서 서버가 만들고, 실행 뒤 같은 기준으로 자동 재검증한다.
    remediation_service = RemediationService(provider, workflow, store, settings, standard_service.visible_events)
    standard_service.remediations = remediation_service
    standard_service.project_vpc_id = settings.get("PROJECT_VPC_ID")
    # 대시보드 도우미(v27): 조회 전용 도구만 준다. 꺼져 있거나 AWS 연결이 없으면 model=None → "사용 불가".
    assistant_model = (provider.assistant_model(settings["ASSISTANT_MODEL_ID"], settings["ASSISTANT_REGION"])
                       if settings["ASSISTANT_ENABLED"] and hasattr(provider, "assistant_model") else None)
    assistant_service = AssistantService(assistant_model, Tools(standard_service, honeypot_service, blocklist_service), settings)
    drill_service = DrillService(store, provider, attack_config=_attack_config(settings))
    # 화면별 AI 요약 보고서(v28): 같은 모델·같은 하루 토큰 예산을 도우미와 나눠 쓴다. 도구는 없다.
    report_service = ReportService(standard_service, honeypot_service, blocklist_service, drill_service,
                                   assistant_model, settings, assistant=assistant_service)
    app.extensions.update(store=store, provider=provider, workflow=workflow,
                          honeypot_service=honeypot_service,
                          blocklist_service=blocklist_service,
                          worker=worker, remediation_service=remediation_service,
                          standard_service=standard_service,
                          assistant_service=assistant_service, report_service=report_service,
                          drill_service=drill_service)

    @app.before_request
    def request_context():
        g.request_id = str(uuid.uuid4())

    install_errors(app)
    install_auth(app)
    app.register_blueprint(standard_api)
    app.register_blueprint(honeypot_api)
    app.register_blueprint(assistant_api)

    @app.get("/")
    def index():
        if not current_user():
            return redirect("/login")
        return render_template("index.html")

    @app.get("/login")
    def login():
        return render_template("login.html")

    @app.get("/health")
    def health():
        status = provider.status()
        # 생존 확인 전용. 공급자 상태·리전 같은 내부 구성은 노출하지 않는다(설계 3.3 #1, openapi HealthEnvelope).
        return envelope({"status": "ok", "dataSourceConnected": status["connected"]}, g.request_id)

    @app.get("/static/<path:filename>")
    def static(filename):
        # 정적 파일만 캐시를 허용한다(파일 이름의 ?v= 버전이 바뀌면 새로 받는다). ETag 로 만료 후에도 304 로 재검증한다.
        return send_from_directory(frontend / "static", filename, max_age=settings["STATIC_MAX_AGE_SECONDS"])

    @app.after_request
    def response_headers(response):
        response.headers.update({
            "X-Request-ID": g.request_id,
            "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
            "Referrer-Policy": "same-origin",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                                       "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
                                       "base-uri 'self'; form-action 'self'",
        })
        if not request.path.startswith("/static/") or response.status_code >= 400:
            response.headers["Cache-Control"] = "no-store"   # API·HTML·오류는 저장하지 않는다(인증·CSRF)
        return _compress(response)

    return app
