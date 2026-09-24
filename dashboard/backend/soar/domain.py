"""Shared vocabulary and approval fingerprint, independent of Flask/SQLite."""
import copy
import hashlib

from .store import encode

def plan_hash(event):
    """Approval covers target, scope, procedure and the verification criterion."""
    plan = {key: event.get(key) for key in (
        "resource", "region", "environment", "scenario", "criterion", "criterionVersion", "unit", "plan")}
    return hashlib.sha256(encode(plan).encode()).hexdigest()


def public_event(event):
    result = copy.deepcopy({key: value for key, value in event.items() if not key.startswith("_")})
    result["planHash"] = plan_hash(event)
    return result
