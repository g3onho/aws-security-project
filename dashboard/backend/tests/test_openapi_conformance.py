"""실제 응답이 03-api-spec.yaml 의 스키마와 맞는지 확인한다.

명세와 구현이 갈라지는 걸 막는 게 목적이다. jsonschema 가 없으면 필수 필드만 본다.
"""
from __future__ import annotations

from pathlib import Path

import pytest

# .../<repo>/dashboard/backend/tests/  →  parents[3] 가 저장소 루트
SPEC = Path(__file__).resolve().parents[3] / "docs" / "backend" / "03-api-spec.yaml"


@pytest.fixture(scope="module")
def spec():
    if not SPEC.exists():
        pytest.skip(f"명세 파일이 없습니다: {SPEC}")
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load(SPEC.read_text(encoding="utf-8"))


def _required(spec, name):
    return spec["components"]["schemas"][name]["required"]


def test_spec_is_valid_openapi(spec):
    validator = pytest.importorskip("openapi_spec_validator")
    validator.validate(spec)


def test_event_has_all_required_fields(client, spec):
    from app.adapters import demo as demo_mod
    body = client.get("/api/events", query_string={
        "from": demo_mod.DEMO_NOW - 30 * 24 * 3600 * 1000, "to": demo_mod.DEMO_NOW}).json
    event = body["items"][0]
    missing = [f for f in _required(spec, "Event") if f not in event]
    assert not missing, f"Event 에 빠진 필수 필드: {missing}"


def test_event_page_required_fields(client, spec):
    from app.adapters import demo as demo_mod
    body = client.get("/api/events", query_string={
        "from": demo_mod.DEMO_NOW - 30 * 24 * 3600 * 1000, "to": demo_mod.DEMO_NOW}).json
    missing = [f for f in _required(spec, "EventPage") if f not in body]
    assert not missing, f"EventPage 에 빠진 필수 필드: {missing}"


def test_enums_match_spec(spec):
    from app import enums
    schemas = spec["components"]["schemas"]
    assert set(schemas["EventStatus"]["enum"]) == set(enums.STATUS_TO_KO)
    assert set(schemas["ExecutionStatus"]["enum"]) == set(enums.EXECUTION_TO_KO)
    assert set(schemas["VerificationStatus"]["enum"]) == set(enums.VERIFICATION_TO_KO)
    assert set(schemas["RemediationMode"]["enum"]) == set(enums.MODE_TO_KO)
    assert set(schemas["Severity"]["enum"]) == set(enums.SEVERITY_ORDER)
    assert schemas["DetectionSource"]["enum"] == enums.SOURCES


def test_every_spec_path_is_routed(demo_app, spec):
    rules = {str(r) for r in demo_app.url_map.iter_rules()}
    for path in spec["paths"]:
        flask_path = (path.replace("{id}", "<path:event_id>")
                          .replace("{executionId}", "<execution_id>"))
        assert flask_path in rules, f"명세의 {path} 에 대응하는 라우트가 없습니다"


def test_problem_codes_match_spec(spec):
    from app.api.errors import CODES
    spec_codes = set(spec["components"]["schemas"]["Problem"]["properties"]["code"]["enum"])
    extra = CODES - spec_codes
    assert not extra, f"명세에 없는 오류 코드: {extra}"
