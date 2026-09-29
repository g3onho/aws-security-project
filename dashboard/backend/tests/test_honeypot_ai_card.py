"""허니팟 'AI 응답' 카드(v29, DEC-037): ai_call 호출 기록으로 판정한다. 기록이 없으면 정상으로 보지 않는다."""
from tests.test_honeypot import AI, NOW, build, login, log, session_events, status  # noqa: F401


def with_calls(calls, analysis=None, commands=(("whoami", "root"),)):
    rows = session_events("a00000000001", "10.0.2.55", NOW - 600_000, list(commands), analysis)
    for i, call in enumerate(calls):
        rows.append(log(NOW - 590_000 + i, event="ai_call", src_ip="10.0.2.55", session_id="a00000000001", **call))
    return rows


def card(tmp_path, rows):
    app, *_ = build(tmp_path, rows)
    return status(login(app))


def test_success_records_make_the_card_ok_and_show_model_and_latency(tmp_path):
    data = card(tmp_path, with_calls([{"kind": "shell", "ok": True, "model": "apac.amazon.nova-lite-v1:0", "ms": 470, "error": ""}], AI))
    ai = data["cards"]["ai"]
    assert ai["state"] == "ok" and "성공 1 / 실패 0" == ai["text"]
    assert "nova-lite" in ai["detail"] and "470ms" in ai["detail"]


def test_failures_only_show_the_exception_class_not_ok(tmp_path):
    data = card(tmp_path, with_calls([{"kind": "shell", "ok": False, "model": "m", "ms": 90, "error": "ValidationException"}]))
    ai = data["cards"]["ai"]
    assert ai["state"] == "bad" and "ValidationException" in ai["detail"]
    assert data["verdict"]["state"] == "partial" and "ValidationException" in " ".join(data["verdict"]["reasons"])


def test_success_after_failure_is_ok_and_mentions_the_failures(tmp_path):
    data = card(tmp_path, with_calls([{"kind": "shell", "ok": False, "model": "m", "ms": 10, "error": "AccessDeniedException"},
                                      {"kind": "analysis", "ok": True, "model": "m", "ms": 900, "error": ""}], AI))
    ai = data["cards"]["ai"]
    assert ai["state"] == "ok" and "AccessDeniedException" in ai["detail"]


def test_no_records_is_unknown_waiting_not_healthy(tmp_path):
    rows = [r for r in with_calls([]) if '"session_end"' not in r["message"]]   # 명령은 있으나 분석도 호출 기록도 없음
    ai = card(tmp_path, rows)["cards"]["ai"]
    assert ai["state"] == "unknown" and "기록 없음" in ai["text"]


def test_hostile_ai_call_fields_are_sanitised(tmp_path):
    evil = "<img src=x onerror=alert(1)>"
    data = card(tmp_path, with_calls([{"kind": evil, "ok": False, "model": evil * 40, "ms": "x", "error": evil}]))
    ai = data["cards"]["ai"]
    assert "<" not in ai["detail"] and ai["state"] == "bad" and "unknown" in ai["detail"]
