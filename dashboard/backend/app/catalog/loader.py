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
INCIDENT_PATH = Path(__file__).with_name("incidents.yaml")
VULN_PATH = Path(__file__).with_name("vulnerabilities.yaml")


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


@functools.lru_cache(maxsize=1)
def load_incidents() -> dict:
    """침해사례 서술 카탈로그.

    scenarios.yaml 과 분리돼 있다 — 이 파일을 고쳐도 탐지 분류·재검증 동작은 바뀌지 않는다.
    파일이 없으면 빈 카탈로그를 돌려준다(침해사례 탭만 비고 나머지는 정상 동작).
    """
    if not INCIDENT_PATH.exists():
        return {"version": None, "updated": "", "incidents": {}}
    raw = yaml.safe_load(INCIDENT_PATH.read_text(encoding="utf-8")) or {}
    return {
        "version": raw.get("version"),
        "updated": str(raw.get("updated", "")),
        "incidents": raw.get("incidents") or {},
    }


def incident(scenario_id: str) -> dict:
    return load_incidents()["incidents"].get(scenario_id) or {}


@functools.lru_cache(maxsize=1)
def load_vulnerabilities() -> dict:
    """데모 CVE 카탈로그. 실모드는 쓰지 않는다(Inspector2·Trivy 리포트가 정본)."""
    if not VULN_PATH.exists():
        return {"version": None, "targets": [], "vulnerabilities": []}
    raw = yaml.safe_load(VULN_PATH.read_text(encoding="utf-8")) or {}
    return {
        "version": raw.get("version"),
        "updated": str(raw.get("updated", "")),
        "targets": raw.get("targets") or [],
        "vulnerabilities": raw.get("vulnerabilities") or [],
    }


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


def classify(source: str = "", generator: str = "", gd_type: str = "",
             config_rule: str = "", alarm: str = "") -> str | None:
    """실 AWS finding 을 SEC-xx 로 분류한다.

    카탈로그의 `match:` 블록이 정본이다. 우선순위는 좁은 것부터 —
    GuardDuty 유형 > Config 규칙 > Security Hub generator > 소스.
    어디에도 걸리지 않으면 None 이고, 호출부가 미분류로 처리한다.
    """
    items = load()["scenarios"]

    def matched(key, test):
        for sid, item in items.items():
            if item.get("demo_only"):
                continue
            for value in (item.get("match") or {}).get(key, []):
                if test(value):
                    return sid
        return None

    return (
        (gd_type and matched("guardduty_type_prefix", lambda v: gd_type.startswith(v)))
        or (config_rule and matched("config_rules", lambda v: v == config_rule))
        or (generator and matched("securityhub_generator_contains", lambda v: v in generator))
        or (alarm and matched("cloudwatch_alarm_suffix", lambda v: alarm.endswith(v)))
        or (source and matched("sources", lambda v: v == source))
        or None
    )
