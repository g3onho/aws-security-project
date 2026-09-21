"""RFC 9457 problem+json 오류.

제목(title)은 한국어로, 코드(code)는 기계 판독용으로 둘 다 싣는다.
프론트는 code 로 분기하고 title 을 토스트에 그대로 띄운다.
"""
from __future__ import annotations

from flask import jsonify

CODES = {
    "AUTH_REQUIRED", "CSRF_INVALID", "FORBIDDEN", "RATE_LIMITED",
    "INVALID_PARAMETER", "EVENT_NOT_FOUND", "STATE_CONFLICT", "DUPLICATE_EXECUTION",
    "GATE_WHITELIST", "GATE_RESOURCE_TAG", "GATE_IRREVERSIBLE", "APPROVAL_REQUIRED",
    "WRITE_DISABLED", "AWS_UPSTREAM", "NOT_IMPLEMENTED",
}


class ApiProblem(Exception):
    def __init__(self, status: int, title: str, code: str = "", detail: str = "",
                 instance: str = "") -> None:
        super().__init__(title)
        self.status = status
        self.title = title
        self.code = code
        self.detail = detail
        self.instance = instance

    def to_response(self):
        body = {
            "type": "about:blank",
            "title": self.title,
            "status": self.status,
        }
        if self.detail:
            body["detail"] = self.detail
        if self.instance:
            body["instance"] = self.instance
        if self.code:
            body["code"] = self.code
        response = jsonify(body)
        response.status_code = self.status
        response.mimetype = "application/problem+json"
        return response


def register(app) -> None:
    @app.errorhandler(ApiProblem)
    def _handle(exc: ApiProblem):  # noqa: ANN202
        return exc.to_response()
