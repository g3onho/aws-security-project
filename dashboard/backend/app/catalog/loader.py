"""시나리오 카탈로그 로더.

카탈로그를 DynamoDB 가 아니라 저장소의 YAML 에 두는 이유는
04-backend-design.md §2.3 에 적혀 있다 — 발표 전까지 계속 바뀌고,
증적양식 9번("파일:라인 / Git Commit")이 Git diff 추적을 요구한다.
"""
from __future__ import annotations

import functools
from pathlib import Path

import yaml

CATALOG_PATH = Path(__file__).with_name("scenarios.yaml")


@functools.lru_cache(maxsize=1)
def load() -> dict:
    raw = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))
    scenarios = raw.get("scenarios") or {}
    for key, item in scenarios.items():
        item.setdefault("demo_only", False)
        item.setdefault("detection", [])
        item.setdefault("remediation", {})
        item.setdefault("verify", {})
        item["id"] = key
    return {
        "version": raw.get("version"),
        "updated": str(raw.get("updated", "")),
        "scenarios": scenarios,
    }


def get(scenario_id: str) -> dict | None:
    return load()["scenarios"].get(scenario_id)


def ids(include_demo_only: bool = False) -> list[str]:
    items = load()["scenarios"]
    return [
        k for k, v in items.items()
        if include_demo_only or not v.get("demo_only")
    ]


def criterion(scenario_id: str) -> str:
    item = get(scenario_id)
    return item.get("criterion", "") if item else ""


def unit(scenario_id: str) -> str:
    item = get(scenario_id)
    return item.get("unit", "") if item else ""


def playbook(scenario_id: str) -> str | None:
    item = get(scenario_id)
    return (item.get("remediation") or {}).get("playbook") if item else None


def is_wired(scenario_id: str) -> bool:
    item = get(scenario_id)
    return bool((item.get("remediation") or {}).get("wired")) if item else False


def is_reversible(scenario_id: str) -> bool:
    """게이트 ④ — 되돌릴 수 없는 조치는 실행을 막는다 (04 §3.2).

    카탈로그에 명시가 없으면 **안전한 쪽으로 False** 를 돌려준다.
    """
    item = get(scenario_id)
    if not item:
        return False
    return bool((item.get("remediation") or {}).get("reversible"))


def needs_send_command(scenario_id: str) -> bool:
    """재검증에 ssm:SendCommand 가 필요한지.

    현재 대시보드 실행 정책은 StartAutomationExecution 만 허용하므로
    (compute/iam.tf:248-252) True 인 항목은 실모드에서 501 을 돌려준다.
    """
    item = get(scenario_id)
    return bool((item.get("verify") or {}).get("needs_send_command")) if item else False
