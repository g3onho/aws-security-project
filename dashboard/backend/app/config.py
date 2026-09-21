"""런타임 설정.

user_data(`modules/compute/templates/dashboard.sh.tftpl:16-22`)가 만드는
/opt/dashboard/dashboard.env 의 값을 그대로 읽는다.

기본값은 **데모 + 읽기 전용**이다. 발표 당일 AWS 계정이 불안정해도 화면은 뜬다.
실모드는 dashboard.env 에 명시적으로 넣어야 켜진다.
"""
from __future__ import annotations

import os
from pathlib import Path

# app/ → backend/ → dashboard/ ; VERSION 파일은 frontend 쪽에 있다
BACKEND = Path(__file__).resolve().parents[1]
FRONTEND = BACKEND.parent / "frontend"


def _flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def read_version() -> str:
    try:
        return (FRONTEND / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        return "unknown"


class Config:
    # 데모 ↔ 실 AWS
    USE_DEMO_DATA = _flag("USE_DEMO_DATA", True)
    # 승인/실행/재검증 허용 여부. 실모드 읽기 전용 단계(M2)를 위해 분리했다.
    WRITE_ENABLED = _flag("WRITE_ENABLED", False)
    # 게이트를 데모에서도 강제한다. 미배선 플레이북(ASR-HardenNginx)이 화면에서
    # 그대로 막히는 편이 발표에 정직하다. 끄면 판정만 하고 통과시킨다.
    ENFORCE_GATES = _flag("ENFORCE_GATES", True)

    AWS_REGION = os.getenv("AWS_REGION", "ap-northeast-2")
    CORRELATED_FINDINGS_TABLE = os.getenv("CORRELATED_FINDINGS_TABLE", "")
    REMEDIATION_ACTIONS_TABLE = os.getenv("REMEDIATION_ACTIONS_TABLE", "")
    SCAN_RESULTS_BUCKET = os.getenv("SCAN_RESULTS_BUCKET", "")
    SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN", "")

    VERSION = read_version()

    # 응답 캐시 TTL (초) — 04-backend-design.md §4.6
    CACHE_TTL = {
        "events": 15,
        "metrics": 30,
        "vulnerabilities": 120,
        "scenarios": 300,
    }

    # 조회 상한
    MAX_LIMIT = 200
    DEFAULT_LIMIT = 50
    MAX_RANGE_MS = 31 * 24 * 3600 * 1000  # 31일


def as_dict() -> dict:
    return {
        k: getattr(Config, k)
        for k in dir(Config)
        if k.isupper()
    }
