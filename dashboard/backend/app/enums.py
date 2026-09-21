"""API enum ↔ 화면 국문 매핑.

설계 근거: 02-frontend-redesign.md §2.5
  - API/저장소는 안정적 영문 enum
  - 화면과 **CSV 는 국문 그대로** (CSV 는 증적 산출물이고 store.js:16 의 계약이다)

정본 국문 목록: static/js/data.js:71 (statuses), data.js:69 (severityColors 키),
data.js:70 (sources).
"""
from __future__ import annotations

# ── 처리 상태 ─────────────────────────────────────────────
STATUS_TO_KO = {
    "APPROVED": "승인됨",
    "EXECUTION_FAILED": "실행 실패",
    "NEW": "신규",
    "PENDING_APPROVAL": "승인 대기",
    "EXECUTING": "조치 실행 중",
    "PENDING_VERIFICATION": "재검증 대기",
    "VERIFYING": "재검증 중",
    "RESOLVED": "해결",
    "VERIFICATION_FAILED": "재검증 실패",
}
KO_TO_STATUS = {v: k for k, v in STATUS_TO_KO.items()}

# store.js:12 의 실행 허용 상태와 동일
EXECUTABLE_STATUSES = {"NEW", "PENDING_APPROVAL", "VERIFICATION_FAILED"}
# store.js:13 의 재검증 허용 상태
VERIFIABLE_STATUSES = {"PENDING_VERIFICATION"}
# 쓰기가 막히는 진행 중 상태
BUSY_STATUSES = {"EXECUTING", "VERIFYING"}

# ── 실행 결과 ─────────────────────────────────────────────
EXECUTION_TO_KO = {
    "NOT_RUN": "미실행",
    "RUNNING": "실행 중",
    "SUCCEEDED": "성공",
    "FAILED": "실패",
}

# SSM AutomationExecutionStatus → 내부 enum
SSM_STATUS_TO_EXECUTION = {
    "Pending": "RUNNING",
    "InProgress": "RUNNING",
    "Waiting": "RUNNING",
    "Cancelling": "RUNNING",
    "Success": "SUCCEEDED",
    "TimedOut": "FAILED",
    "Cancelled": "FAILED",
    "Failed": "FAILED",
}

# ── 재검증 결과 ───────────────────────────────────────────
VERIFICATION_TO_KO = {
    "NOT_RUN": "미실행",
    "CHECKING": "검사 중",
    "PASSED": "통과",
    "FAILED": "실패",
}

# ── 대응 방식 ─────────────────────────────────────────────
MODE_TO_KO = {"AUTO": "자동", "MANUAL": "수동"}
KO_TO_MODE = {v: k for k, v in MODE_TO_KO.items()}

# ── 위험도 ────────────────────────────────────────────────
# 화면은 'Critical' 같은 파스칼 표기를 쓴다(data.js:69 의 severityColors 키).
SEVERITY_TO_DISPLAY = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
}
DISPLAY_TO_SEVERITY = {v: k for k, v in SEVERITY_TO_DISPLAY.items()}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# GuardDuty 는 숫자 severity 를 쓴다. correlator/handler.py:50-57 과 동일 규칙.
def severity_from_number(value) -> str:
    try:
        num = float(value)
    except (TypeError, ValueError):
        return "LOW"
    if num >= 7:
        return "HIGH"
    if num >= 4:
        return "MEDIUM"
    return "LOW"


# ── 탐지 소스 ─────────────────────────────────────────────
# data.js:70 과 정확히 같은 6종. 필터 드롭다운이 이 배열로 만들어진다(app.js:144).
SOURCES = ["GuardDuty", "Security Hub", "Config", "Inspector", "Trivy", "CloudWatch"]

# Security Hub ProductName → 화면 소스
PRODUCT_TO_SOURCE = {
    "GuardDuty": "GuardDuty",
    "Inspector": "Inspector",
    "Security Hub": "Security Hub",
    "Config": "Config",
    "IAM Access Analyzer": "Security Hub",
}


def status_ko(value: str) -> str:
    return STATUS_TO_KO.get(value, value)


def execution_ko(value: str) -> str:
    return EXECUTION_TO_KO.get(value, value)


def verification_ko(value: str) -> str:
    return VERIFICATION_TO_KO.get(value, value)


def mode_ko(value: str) -> str:
    return MODE_TO_KO.get(value, value)


def severity_display(value: str) -> str:
    return SEVERITY_TO_DISPLAY.get(value, value)
