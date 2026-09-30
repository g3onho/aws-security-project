"""실행 이력 AI 한 줄 요약(v44): 끝난 실행에만, 한 번만 만들고 저장 · 원천에 없는 수치는 버리고 집계 문장으로 대신한다."""
import pytest

from soar.errors import Problem
from soar.report_service import ReportService

RID = "11111111-2222-3333-4444-555555555555"
SETTINGS = {"ASSISTANT_ENABLED": True, "ASSISTANT_REPORT_RATE_PER_10MIN": 6, "ASSISTANT_DAILY_TOKEN_BUDGET": 100000}


class Model:
    model_id = "fake"

    def __init__(self, text):
        self.text, self.calls = text, 0

    def converse(self, system, messages, tool_config, max_tokens, temperature=0.2):
        self.calls += 1
        return {"output": {"message": {"content": [{"text": self.text}]}}, "usage": {"inputTokens": 5, "outputTokens": 5}}


class Runs:
    def __init__(self):
        self.saved = None

    def set_summary(self, run_id, line, source):
        self.saved = {"summaryLine": line, "summarySource": source}
        return self.saved


class Drills:
    def __init__(self, items, stored=None):
        self.items, self.runs, self.stored = items, Runs(), stored

    def run_detail(self, run_id):
        return {"runId": run_id, "type": "run-all", "createdAt": "x", **(self.stored or {})}

    def all_status(self, run_id):
        return {"runId": run_id, "items": self.items, "skipped": ["SEC-05: 대상 없음"]}


DONE = [{"sec": "SEC-02", "status": "Success"}, {"sec": "SEC-04", "status": "Failed"}, {"sec": "SEC-10", "status": "Success"}]


def svc(model, drills):
    return ReportService(None, None, None, drills, model, SETTINGS)


def test_ai_line_saved_once():
    d, m = Drills(DONE), Model("3개 항목 중 성공 2, 실패 1, 건너뜀 1.")
    out = svc(m, d).summarize_run_line(RID, "op")
    assert out["source"] == "ai" and out["created"] and d.runs.saved["summaryLine"].startswith("3개")
    d2 = Drills(DONE, stored={"summaryLine": "저장됨", "summarySource": "ai"})
    m2 = Model("x")
    out2 = svc(m2, d2).summarize_run_line(RID, "op")
    assert out2["summaryLine"] == "저장됨" and not out2["created"] and m2.calls == 0


def test_running_run_is_not_summarized():
    with pytest.raises(Problem) as err:
        svc(Model("x"), Drills(DONE + [{"sec": "SEC-08", "status": "InProgress"}])).summarize_run_line(RID, "op")
    assert err.value.status == 409


def test_invented_number_falls_back_to_rule_line():
    d = Drills(DONE)
    out = svc(Model("성공 9건, 실패 1건."), d).summarize_run_line(RID, "op")
    assert out["source"] == "rule" and "항목 3개" in d.runs.saved["summaryLine"]


def test_model_failure_falls_back():
    class Broken(Model):
        def converse(self, *a, **k):
            raise RuntimeError("boom")
    out = svc(Broken("x"), Drills(DONE)).summarize_run_line(RID, "op")
    assert out["source"] == "rule"


def test_bad_run_id():
    with pytest.raises(Problem):
        svc(Model("x"), Drills(DONE)).summarize_run_line("../x", "op")
