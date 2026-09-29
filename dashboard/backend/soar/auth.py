"""Local accounts, signed sessions, CSRF and role checks in one boundary."""
import secrets
import sqlite3

from flask import Blueprint, current_app, g, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from .errors import Problem
from .store import now_ms

bp = Blueprint("auth", __name__, url_prefix="/api/auth")
MIN_PASSWORD = 8
DUMMY_HASH = generate_password_hash("no-such-local-account")


def create_user(store, name, password, role="operator", scope=None):
    if not isinstance(name, str) or not name.strip() or len(name) > 64 or name != name.strip():
        raise ValueError("User name must contain 1–64 characters without surrounding spaces")
    if not isinstance(password, str) or not MIN_PASSWORD <= len(password) <= 256:
        raise ValueError("Password must contain 8–256 characters")
    if role not in {"operator", "approver", "viewer"}:
        raise ValueError("Role must be operator, approver or viewer")
    password_hash = generate_password_hash(password)
    try:
        with store.connect(write=True) as db:
            db.execute("INSERT INTO users(name,password_hash,role) VALUES (?,?,?)",
                       (name, password_hash, role))
            if scope is not None:
                from .store import encode
                for key in ("accounts", "regions", "resources"):
                    values = scope.get(key)
                    if values is not None and (not isinstance(values, list) or not all(isinstance(v, str) for v in values)):
                        raise ValueError("Scope values must be a list of strings or null")
                db.execute("UPDATE users SET scope=? WHERE name=?", (encode(scope), name))
            store.audit(db, "local-cli", None, "user-created", {"name": name, "role": role})
    except sqlite3.IntegrityError as error:
        raise ValueError("User already exists") from error


def set_password(store, name, password):
    if not isinstance(password, str) or not MIN_PASSWORD <= len(password) <= 256:
        raise ValueError("Password must contain 8–256 characters")
    password_hash = generate_password_hash(password)
    with store.connect(write=True) as db:
        result = db.execute("UPDATE users SET password_hash=?, auth_version=auth_version+1 WHERE name=?",
                            (password_hash, name))
        if not result.rowcount:
            raise ValueError("User does not exist")
        store.audit(db, "local-cli", None, "password-changed", {"name": name})


def store():
    return current_app.extensions["store"]


def current_user():
    with store().connect() as db:
        user = db.execute("SELECT name,role,auth_version FROM users WHERE name=?",
                          (session.get("user"),)).fetchone()
    if user and user["auth_version"] == session.get("auth_version"):
        return {"name": user["name"], "role": user["role"]}
    return None


def csrf_required():
    supplied = request.headers.get("X-CSRF-Token", "")
    expected = session.get("csrf", "")
    if not expected or not supplied or not secrets.compare_digest(supplied, expected):
        raise Problem(403, "요청 확인 토큰이 일치하지 않습니다. 화면을 새로고침해주세요.", "CSRF_INVALID")


def install_auth(app):
    app.register_blueprint(bp)

    @app.before_request
    def guard():
        if not request.path.startswith("/api/") and request.path not in {"/execute", "/verify"}:
            return
        if request.path in {"/api/auth/session", "/api/auth/login"}:
            return
        user = current_user()
        if user is None:
            raise Problem(401, "로그인이 필요합니다.", "AUTH_REQUIRED")
        g.actor, g.role = user["name"], user["role"]
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            csrf_required()
            # 도우미 대화·요약 보고서는 POST 지만 읽기만 한다 → viewer 도 허용(CSRF 는 위에서 검사한다).
            if request.path not in {"/api/auth/logout", "/api/assistant/chat", "/api/assistant/report"} and user["role"] == "viewer":
                raise Problem(403, "조회 전용 계정입니다.", "FORBIDDEN")


@bp.get("/session")
def get_session():
    session.setdefault("csrf", secrets.token_urlsafe(32))
    return {"user": current_user(), "csrfToken": session["csrf"]}


@bp.post("/login")
def login():
    csrf_required()
    body = request.get_json(silent=True)
    if (not isinstance(body, dict) or not isinstance(body.get("username"), str)
            or not isinstance(body.get("password"), str)
            or not 1 <= len(body["username"]) <= 64 or not 1 <= len(body["password"]) <= 256):
        raise Problem(400, "아이디와 암호를 확인해주세요.")
    limit_key = (request.remote_addr or "local") + ":" + body["username"]
    timestamp = now_ms()
    with store().connect(write=True) as db:
        # Cleanup is bounded by login traffic and does not remove active lockouts.
        db.execute("DELETE FROM login_limits WHERE until_ms < ?", (timestamp,))
        limit = db.execute("SELECT * FROM login_limits WHERE key=?", (limit_key,)).fetchone()
        if limit and limit["failures"] >= 5:
            raise Problem(429, "로그인 시도가 많습니다. 1분 후 다시 시도해주세요.", "RATE_LIMITED")
        user = db.execute("SELECT * FROM users WHERE name=?", (body["username"],)).fetchone()
        valid = check_password_hash(user["password_hash"] if user else DUMMY_HASH, body["password"])
        if not user or not valid:
            failures = limit["failures"] + 1 if limit else 1
            until = limit["until_ms"] if limit else timestamp + 60000
            db.execute("INSERT OR REPLACE INTO login_limits VALUES (?,?,?)", (limit_key, failures, until))
            authenticated = None
        else:
            db.execute("DELETE FROM login_limits WHERE key=?", (limit_key,))
            authenticated = dict(user)
            store().audit(db, user["name"], None, "login")
    if not authenticated:
        raise Problem(401, "아이디 또는 암호가 올바르지 않습니다.", "AUTH_REQUIRED")
    session.clear()
    session.permanent = True
    session.update(user=authenticated["name"], auth_version=authenticated["auth_version"],
                   csrf=secrets.token_urlsafe(32))
    return {"user": {"name": authenticated["name"], "role": authenticated["role"]},
            "csrfToken": session["csrf"]}


@bp.post("/logout")
def logout():
    with store().connect(write=True) as db:
        store().audit(db, g.actor, None, "logout")
    session.clear()
    return {"ok": True}
