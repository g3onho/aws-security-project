"""Shared vocabulary and approval fingerprint, independent of Flask/SQLite."""
import copy
import hashlib

from .store import encode

STATUSES = {
    "NEW": "신규", "PENDING_APPROVAL": "승인 대기", "APPROVED": "승인됨",
    "EXECUTING": "조치 실행 중", "EXECUTION_FAILED": "실행 실패",
    "PENDING_VERIFICATION": "재검증 대기", "VERIFYING": "재검증 중",
    "RESOLVED": "해결", "VERIFICATION_FAILED": "재검증 실패",
}
SOURCES = ["GuardDuty", "Security Hub", "Config", "Inspector", "Trivy", "CloudWatch"]
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def plan_hash(event):
    """Approval covers target, scope, procedure and the verification criterion."""
    plan = {key: event.get(key) for key in (
        "resource", "region", "environment", "scenario", "criterion", "criterionVersion", "unit", "plan")}
    return hashlib.sha256(encode(plan).encode()).hexdigest()


def public_event(event):
    result = copy.deepcopy({key: value for key, value in event.items() if not key.startswith("_")})
    result["planHash"] = plan_hash(event)
    return result
