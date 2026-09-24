"""Errors at the HTTP boundary; internal exception messages are never returned."""
from flask import current_app, g, jsonify, request
from werkzeug.exceptions import HTTPException


class Problem(Exception):
    def __init__(self, status, title, code="INVALID_PARAMETER", detail=""):
        super().__init__(title)
        self.status = status
        self.title = title
        self.code = code
        self.detail = detail


def install_errors(app):
    def response(status, title, code, detail=""):
        from .contracts import metadata
        if request.path.startswith("/api/auth/"):
            result = jsonify(type="about:blank", title=title, status=status,
                             code=code, detail=detail, instance=request.path,
                             requestId=g.request_id)
            result.content_type = "application/problem+json"
        else:
            result = jsonify(error={"code": code, "message": title, "details": {"detail": detail} if detail else {}},
                             meta=metadata(g.request_id))
        result.status_code = status
        if status == 429:
            result.headers["Retry-After"] = "60"
        return result

    @app.errorhandler(Problem)
    def known_error(error):
        return response(error.status, error.title, error.code, error.detail)

    @app.errorhandler(HTTPException)
    def http_error(error):
        return response(error.code, error.name, "HTTP_ERROR")

    @app.errorhandler(Exception)
    def unexpected_error(error):
        current_app.logger.exception("Unhandled dashboard request error requestId=%s", g.request_id)
        return response(500, "요청을 처리하지 못했습니다.", "INTERNAL_ERROR")
