"""Application factory. Construction has no network calls or background threads."""
import uuid
from pathlib import Path

from flask import Flask, g, redirect, render_template, send_from_directory
from jinja2 import ChoiceLoader, FileSystemLoader

from .auth import current_user, install_auth
from .contracts import StandardService, envelope
from .drills import DrillService
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
        "scanBucket": settings.get("SCAN_RESULTS_BUCKET"),
        "regions": regions,
    }


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
                            vulnerability_source=settings["VULNERABILITY_SOURCE"])
                if settings["DATA_PROVIDER"] == "aws" else UnconfiguredProvider())
    if provider.connected and not settings.get("TESTING"):
        provider.warm()  # 취약점 목록(Inspector 수천 건)을 기동 직후 미리 받아 둔다
    workflow = Workflow(store, provider, settings["APPROVAL_TTL_SECONDS"])
    worker = Worker(store, provider, settings["WORKER_LEASE_SECONDS"])
    app.extensions.update(store=store, provider=provider, workflow=workflow,
                          worker=worker,
                          standard_service=StandardService(store, workflow, provider, settings["SECRET_KEY"], settings["WRITE_ENABLED"]),
                          drill_service=DrillService(store, provider, attack_config=_attack_config(settings)))

    @app.before_request
    def request_context():
        g.request_id = str(uuid.uuid4())

    install_errors(app)
    install_auth(app)
    app.register_blueprint(standard_api)

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
        return send_from_directory(frontend / "static", filename)

    @app.after_request
    def response_headers(response):
        response.headers.update({
            "Cache-Control": "no-store", "X-Request-ID": g.request_id,
            "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
            "Referrer-Policy": "same-origin",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                                       "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
                                       "base-uri 'self'; form-action 'self'",
        })
        return response

    return app
