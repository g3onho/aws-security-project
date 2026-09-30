"""전부 실행 1회 결과 AI 요약 보고서(v39.3) 자가 점검.

실제 Bedrock·AWS 는 부르지 않는다. 가짜 원천과 가짜 모델을 쓴다.
- 결과 JSON(단계 출력)에서 코드가 사실만 뽑는다(열린 포트·발견 건수·경고 건수). 자격증명 값은 facts 로 넘기지 않는다.
- 사람이 파일을 올리지 않는다: runId 하나로 서버가 상태와 결과를 읽는다.
"""
import json

import pytest

from soar.errors import Problem
from soar.report_service import REQUIRED, ReportService
from soar.run_report import build_run_facts, summarize_step

SETTINGS = {"ASSISTANT_ENABLED": True, "ASSISTANT_REPORT_RATE_PER_10MIN": 6, "ASSISTANT_REPORT_CACHE_SECONDS": 300,
            "ASSISTANT_DAILY_TOKEN_BUDGET": 100000, "ASSISTANT_RATE_PER_10MIN": 20}
RUN_ID = "3f2b1c4e-5a6d-4e7f-8a9b-0c1d2e3f4a5b"

NMAP = "Starting Nmap\n22/tcp open  ssh\n80/tcp open  http\n443/tcp closed https\nNmap done: 1 IP address (1 host up)"
HYDRA_HIT = "[22][ssh] host: 10.0.0.1   login: victim   password: Sup3rSecret!\n1 of 1 target successfully completed, 1 valid password found"
HYDRA_MISS = "1 of 1 target completed, 0 valid passwords found"
ZAP = "WARN-NEW: Missing Anti-clickjacking Header [10020] x 2\nWARN-NEW: Cookie No HttpOnly Flag [10010] x 1\nFAIL-NEW: 0\tFAIL-INFORM: 0\tWARN-NEW: 2\tWARN-INFORM: 0"
SQLMAP_HIT = "Parameter: id (GET)\n    Type: boolean-based blind\nthe back-end DBMS is MySQL\nParameter 'id' is vulnerable"
SQLMAP_MISS = "all tested parameters do not appear to be injectable"


class FakeModel:
    model_id = "fake-haiku"

    def __init__(self, text="## 1. 요약\n본문"):
        self.text, self.calls = text, []

    def converse(self, system, messages, tool_config, max_tokens, temperature=0.2):
        self.calls.append({"system": system, "messages": messages, "tool_config": tool_config})
        return {"output": {"message": {"role": "assistant", "content": [{"text": self.text}]}}, "stopReason": "end_turn",
                "usage": {"inputTokens": 40, "outputTokens": 12}}


class FakeDrills:
    def __init__(self, run_type="run-all", ready=True, status_fails=False):
        self.run_type, self.ready, self.status_fails = run_type, ready, status_fails

    def run_detail(self, run_id):
        if run_id != RUN_ID:
            raise Problem(404, "없음", "DRILL_NOT_FOUND")
        return {"runId": run_id, "type": self.run_type, "createdAt": "2026-09-30T06:00:00.000Z", "startedAt": 1_790_000_000_000,
                "skipped": ["SEC-05 대상 없음"]}

    def all_status(self, run_id):
        if self.status_fails:
            raise Problem(502, "x", "X")
        return {"runId": run_id, "skipped": ["SEC-05 대상 없음"], "items": [
            {"sec": "SEC-08", "label": "SEC-08 · 도쿄", "status": "Success", "output": "uploaded"},
            {"sec": "SEC-02", "label": "SEC-02", "status": "Success", "output": "line1\nline2\nline3\nline4"},
            {"sec": "SEC-10", "label": "SEC-10 · docker-host", "status": "Failed", "detail": "AccessDenied"}]}

    def report(self, run_id):
        if not self.ready:
            return {"runId": run_id, "regions": {"mumbai": {"ready": False, "reason": "아직 업로드 안 됨"}}}
        steps = [{"step": "nmap", "output": NMAP}, {"step": "hydra-ssh", "output": HYDRA_HIT},
                 {"step": "hydra-web", "output": HYDRA_MISS}, {"step": "zap", "output": ZAP}, {"step": "sqlmap", "output": SQLMAP_HIT}]
        return {"runId": run_id, "regions": {"tokyo": {"ready": True, "steps": steps},
                                             "mumbai": {"ready": False, "reason": "아직 업로드 안 됨"}}}


def service(model=None, drills=None, assistant=None, **settings):
    return ReportService(object(), object(), object(), drills or FakeDrills(), model or FakeModel(), {**SETTINGS, **settings},
                         assistant=assistant)


# -- 사실 추출 -----------------------------------------------------------------------------------------------

def test_step_summaries_extract_facts_only():
    assert summarize_step("nmap", NMAP)["결과"] == "열린 포트 2개"
    assert summarize_step("nmap", NMAP)["핵심 줄"] == ["22/tcp ssh", "80/tcp http"]
    assert summarize_step("hydra-ssh", HYDRA_HIT)["결과"] == "유효 자격증명 1건 발견"
    assert summarize_step("hydra-web", HYDRA_MISS)["발견"] is False
    zap = summarize_step("zap", ZAP)
    assert zap["결과"] == "경고 2건 · 실패 0건" and len(zap["핵심 줄"]) == 2
    assert summarize_step("sqlmap", SQLMAP_HIT)["발견"] is True
    assert summarize_step("sqlmap", SQLMAP_MISS)["발견"] is False
    assert summarize_step("nmap", "")["결과"] == "출력 없음"


def test_credential_values_never_reach_facts():
    run = FakeDrills().run_detail(RUN_ID)
    facts = build_run_facts(run, FakeDrills().all_status(RUN_ID), FakeDrills().report(RUN_ID))
    dumped = json.dumps(facts, ensure_ascii=False)
    assert "Sup3rSecret" not in dumped
    assert "유효 자격증명 1건 발견" in dumped


def test_required_values_are_computed_by_code():
    run = FakeDrills().run_detail(RUN_ID)
    facts = build_run_facts(run, FakeDrills().all_status(RUN_ID), FakeDrills().report(RUN_ID))
    assert set(facts["필수 항목 값"]) == set(REQUIRED["drill-run"])
    assert facts["필수 항목 값"]["실패 항목"] == ["SEC-10 · docker-host"]
    assert facts["필수 항목 값"]["결과 없는 리전"] == ["mumbai"]
    assert facts["필수 항목 값"]["열린 포트 발견 리전"] == ["tokyo"]
    assert set(facts["필수 항목 값"]["취약 지점 발견 단계"]) == {"tokyo/hydra-ssh", "tokyo/zap", "tokyo/sqlmap"}


def test_unreadable_sources_are_reported_as_unreadable_not_empty():
    run = FakeDrills().run_detail(RUN_ID)
    facts = build_run_facts(run, None, None)
    assert facts["필수 항목 값"] == {k: "읽지 못함" for k in REQUIRED["drill-run"]}


# -- 서비스 --------------------------------------------------------------------------------------------------

def test_generate_run_reads_server_side_and_calls_model_once():
    model = FakeModel()
    result = service(model=model).generate("drill-run", {"runId": RUN_ID}, "op")
    assert result["view"] == "drill-run" and result["cached"] is False and len(model.calls) == 1
    sent = model.calls[0]["messages"][0]["content"][0]["text"]
    assert "<data>" in sent and "열린 포트 2개" in sent and "Sup3rSecret" not in sent
    assert model.calls[0]["tool_config"] is None
    assert "추가 규칙(전부 실행 결과 보고서)" in model.calls[0]["system"]


def test_generate_run_caches_same_run_for_same_user():
    model = FakeModel()
    svc = service(model=model)
    svc.generate("drill-run", {"runId": RUN_ID}, "op")
    again = svc.generate("drill-run", {"runId": RUN_ID}, "op")
    assert again["cached"] is True and len(model.calls) == 1


def test_generate_run_rejects_bad_run_id_and_unknown_run_and_wrong_type():
    with pytest.raises(Problem) as e:
        service().generate("drill-run", {"runId": "../etc/passwd"}, "op")
    assert e.value.status == 400
    with pytest.raises(Problem) as e:
        service().generate("drill-run", {"runId": "00000000-0000-4000-8000-000000000000"}, "op")
    assert e.value.status == 404
    with pytest.raises(Problem) as e:
        service(drills=FakeDrills(run_type="web-scan")).generate("drill-run", {"runId": RUN_ID}, "op")
    assert e.value.status == 400


def test_generate_run_needs_ai_enabled():
    with pytest.raises(Problem) as e:
        service(ASSISTANT_ENABLED=False).generate("drill-run", {"runId": RUN_ID}, "op")
    assert e.value.status == 503


def test_generate_run_survives_one_unreadable_source_and_lists_it():
    result = service(drills=FakeDrills(status_fails=True)).generate("drill-run", {"runId": RUN_ID}, "op")
    assert result["unavailable"] == ["실행 상태"]
    assert result["facts"]["필수 항목 값"]["실패 항목"] == "읽지 못함"


def test_new_default_daily_token_budget_is_doubled():
    from soar.settings import configure
    import os, tempfile
    os.environ["DASHBOARD_INSTANCE"] = tempfile.mkdtemp()
    os.environ.pop("ASSISTANT_DAILY_TOKEN_BUDGET", None)
    assert configure({"SECRET_KEY": "x" * 32})["ASSISTANT_DAILY_TOKEN_BUDGET"] == 1_000_000
