"""어댑터 인터페이스.

demo.py(고정 데이터)와 live.py(실 AWS)가 같은 시그니처를 구현한다.
프론트는 /health 의 mode 로 어느 쪽이 붙었는지 알 뿐, 응답 모양은 동일하다.
"""
from __future__ import annotations

from typing import Protocol, Any


class Adapter(Protocol):
    mode: str  # "demo" | "live"

    def list_events(self, q: dict) -> dict:
        """-> {"items": [Event], "nextCursor": str|None, "total": int, "truncated": bool}"""

    def get_event(self, event_id: str) -> dict | None:
        ...

    def metrics(self, q: dict) -> dict:
        ...

    def vulnerabilities(self, q: dict) -> dict:
        ...

    def scenarios(self, q: dict) -> dict:
        ...

    def evidence(self, event_id: str) -> dict | None:
        ...

    def approve(self, event_id: str, body: dict, actor: str, key: str) -> dict:
        ...

    def execute(self, event_id: str, body: dict, actor: str, key: str) -> dict:
        """-> {"execution": Execution, "event": Event}"""

    def execution_status(self, event_id: str, execution_id: str) -> dict | None:
        ...

    def verify(self, event_id: str, body: dict, actor: str, key: str) -> dict:
        ...

    def health_checks(self) -> dict[str, Any]:
        ...
