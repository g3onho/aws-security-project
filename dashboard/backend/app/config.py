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
    # 메모리는 CloudWatch Agent 커스텀 지표다 — 네임스페이스가 배포마다 다르다
    # (soar/cloudwatch.tf:56 의 "${name_prefix}/host"). 비면 표준 CWAgent 로 본다.
    NAME_PREFIX = os.getenv("NAME_PREFIX", "")

    # 3계층 상태의 로그 기반 판정에 쓴다(adapters/live.py services()).
    # ALB 가 꺼져 있으면(enable_alb 기본 false) 대상 그룹 헬스체크가 없으므로
    # docker-host 의 nginx 로그와 db 의 mysql 로그가 유일한 실측 신호다.
    # 이름 정본은 aws-soar-terraform/main.tf:16-17 의 locals 다.
    LOG_GROUP_NGINX = os.getenv("LOG_GROUP_NGINX", "")
    LOG_GROUP_MYSQL = os.getenv("LOG_GROUP_MYSQL", "")

    VERSION = read_version()

    # 응답 캐시 TTL (초) — 04-backend-design.md §4.6
    # events 는 15 -> 60. Security Hub GetFindings 계정당 요청 제한이 낮은데
    # 지금 계정 ACTIVE finding 이 2,241건까지 늘어 15초마다 재조회하면
    # TooManyRequestsException 이 바로 남(2026-09-22 확인). 호출 빈도를 줄인다.
    CACHE_TTL = {
        "events": 60,
        "metrics": 30,
        "vulnerabilities": 120,
        "scenarios": 300,
    }

    # 조회 상한.
    # MAX_LIMIT 은 /api/events 의 페이지 크기 상한이다. 취약점 목록이 대상당 수십 건이라
    # 200 이면 한 이미지도 다 못 본다. 1000 으로 올리고, 응답 총량은 어댑터의
    # MAX_RESPONSE_ITEMS(5000)에서만 자른다.
    MAX_LIMIT = 1000
    DEFAULT_LIMIT = 200
    MAX_RANGE_MS = 31 * 24 * 3600 * 1000  # 31일


def log_groups(config=None) -> tuple[str, str]:
    """(nginx, mysql) 로그 그룹 이름.

    `config` 를 주면 그 객체의 값을 먼저 본다 — 실모드 어댑터는 app.config 스냅샷을
    들고 다니므로 모듈 전역 Config 와 값이 다를 수 있다.

    환경변수가 비어 있으면 NAME_PREFIX("<project>-<env>")에서 유도한다.
    Terraform 은 `/<project>/<env>/web/nginx` 로 만든다 — 접두사와 구분자가 다르므로
    마지막 하이픈에서 한 번만 쪼갠다. 유도에 실패하면 빈 문자열이고, 그때는
    해당 계층이 UNKNOWN 으로 떨어진다(추측해서 틀린 그룹을 읽지 않는다).
    """
    source = config if config is not None else Config
    nginx = getattr(source, "LOG_GROUP_NGINX", "") or Config.LOG_GROUP_NGINX
    mysql = getattr(source, "LOG_GROUP_MYSQL", "") or Config.LOG_GROUP_MYSQL
    if nginx and mysql:
        return nginx, mysql
    prefix = getattr(source, "NAME_PREFIX", "") or Config.NAME_PREFIX
    if "-" not in prefix:
        return nginx, mysql
    project, env = prefix.rsplit("-", 1)
    return (nginx or f"/{project}/{env}/web/nginx",
            mysql or f"/{project}/{env}/db/mysql")


def as_dict() -> dict:
    return {
        k: getattr(Config, k)
        for k in dir(Config)
        if k.isupper()
    }
