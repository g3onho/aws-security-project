"""전부 실행 1회의 결과(단계 출력)를 AI 요약 보고서의 근거(facts)로 바꾸는 순수 함수 모음(v39.3).

왜 따로 두는가
- 결과 JSON 안의 단계 출력은 매우 길다(포트 스캔·웹 스캐너·SQL 주입 도구의 원문). 그대로 모델에 넣으면 토큰이 크게 늘고,
  그 안의 문장(공격 대상이 돌려준 글)이 지시문처럼 읽힐 수 있다. 그래서 코드가 핵심 사실만 뽑아 숫자·짧은 줄로 줄인다.
- 인증 정보 값(비밀번호 등)은 어떤 경우에도 facts 로 넘기지 않는다. '발견 건수'만 넘긴다.
- 이 모듈은 boto3·Flask 를 import 하지 않는다. 입력은 DrillService.all_status()/report()가 이미 돌려준 dict 이다.
"""
import re

LINE_MAX = 180          # 핵심 줄 하나의 길이 상한
LINES_PER_STEP = 5      # 단계당 핵심 줄 수 상한
FAILED = {"Failed", "TimedOut"}
RUNNING = {"Pending", "InProgress", "Delayed", "Cancelling"}
STATUS_KO = {"Success": "완료", "Failed": "실패", "TimedOut": "시간 초과", "Cancelled": "취소", "Pending": "대기",
             "InProgress": "진행 중", "Delayed": "지연", "Cancelling": "취소 중"}

# 값이 붙는 자격증명 표기는 값만 가린다(로그인 이름은 남긴다). 키·토큰류 긴 문자열도 가린다.
_SECRET_VALUE = re.compile(r"(pass(?:word)?\s*[:=]\s*)\S+", re.I)
_LONG_TOKEN = re.compile(r"\b[A-Za-z0-9+/_\-]{32,}\b")
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

_NMAP_OPEN = re.compile(r"^\s*(\d{1,5})/(tcp|udp)\s+open\s+(\S+)", re.M)
_HYDRA_VALID = re.compile(r"(\d+)\s+valid\s+passwords?\s+found", re.I)
_ZAP_SUMMARY = re.compile(r"FAIL-NEW:\s*(\d+).*?WARN-NEW:\s*(\d+)", re.S)
_ZAP_WARN = re.compile(r"^WARN-NEW:\s*(.+?)\s*\[\d+\]", re.M)
_SQLMAP_PARAM = re.compile(r"^\s*Parameter:\s*(.+)$", re.M)
_SQLMAP_TYPE = re.compile(r"^\s*Type:\s*(.+)$", re.M)


def _clean(text):
    text = _ANSI.sub("", str(text or ""))
    text = _SECRET_VALUE.sub(r"\1[가림]", text)
    return _LONG_TOKEN.sub("[가림]", text)


def _line(text):
    text = " ".join(_clean(text).split())
    return text if len(text) <= LINE_MAX else text[:LINE_MAX] + "…"


def _tail(output, n=3):
    rows = [ln for ln in _clean(output).splitlines() if ln.strip()]
    return [_line(ln) for ln in rows[-n:]]


def summarize_step(step, output):
    """단계 이름과 원문 출력 → {결과: 한 줄, 핵심 줄: [...], 발견: bool|None}. 발견=None 은 판정 근거 없음."""
    name = str(step or "").lower()
    text = _clean(output)
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return {"결과": "출력 없음", "핵심 줄": [], "발견": None}
    if "nmap" in name:
        ports = [f"{p}/{proto} {svc}" for p, proto, svc in _NMAP_OPEN.findall(text)]
        return {"결과": f"열린 포트 {len(ports)}개", "핵심 줄": ports[:LINES_PER_STEP * 2], "발견": bool(ports)}
    if "hydra" in name:
        found = sum(int(n) for n in _HYDRA_VALID.findall(text))
        return {"결과": f"유효 자격증명 {found}건 발견" if found else "유효 자격증명 발견 없음",
                "핵심 줄": _tail(text, 2), "발견": found > 0}
    if "zap" in name:
        warns = list(dict.fromkeys(_ZAP_WARN.findall(text)))
        summary = _ZAP_SUMMARY.search(text)
        fail_new, warn_new = (int(summary.group(1)), int(summary.group(2))) if summary else (None, len(warns))
        label = f"경고 {warn_new}건" + (f" · 실패 {fail_new}건" if fail_new is not None else "")
        return {"결과": label, "핵심 줄": [_line(w) for w in warns[:LINES_PER_STEP]],
                "발견": bool((fail_new or 0) or warn_new)}
    if "sqlmap" in name:
        # "do not appear to be injectable" 같은 부정문에도 'injectable' 이 들어 있다 → 단어 하나로 판정하지 않는다.
        found = bool(re.search(r"identified the following injection point|is vulnerable|^\s*Parameter:\s.+\(", text, re.I | re.M)
                     or (re.search(r"appears to be .*injectable", text, re.I) and not re.search(r"(?:do|does)(?:n't| not)\s+(?:appear|seem)", text, re.I)))
        params = [_line(p) for p in dict.fromkeys(_SQLMAP_PARAM.findall(text))][:2]
        types = [_line(t) for t in dict.fromkeys(_SQLMAP_TYPE.findall(text))][:LINES_PER_STEP - len(params)]
        return {"결과": "주입 가능 지점 발견" if found else "주입 가능 지점 발견 없음",
                "핵심 줄": params + types if found else _tail(text, 2), "발견": found}
    return {"결과": f"출력 {len(lines)}줄", "핵심 줄": _tail(text, LINES_PER_STEP), "발견": None}


def build_run_facts(run, status, report):
    """run: DrillService.run_detail(), status: all_status() 또는 None, report: report() 또는 None.
    -> facts dict. 실패 항목·결과 없는 리전·발견 여부를 코드가 판정해 '필수 항목 값'에 넣는다."""
    facts, failed, running = {}, [], 0
    items = (status or {}).get("items") or []
    if status is not None:
        rows = []
        for it in items:
            st = it.get("status") or "Unknown"
            label = it.get("label") or it.get("sec") or "항목"
            if st in FAILED:
                failed.append(str(label))
            if st in RUNNING:
                running += 1
            row = {"항목": str(label), "상태": STATUS_KO.get(st, st)}
            # SEC-08 은 아래 '공격 로그'에서 단계별로 다룬다. 나머지는 출력 끝 몇 줄만.
            if it.get("sec") != "SEC-08" and it.get("output"):
                row["출력 끝"] = _tail(it["output"], 3)
            if it.get("detail"):
                row["상세"] = _line(it["detail"])
            rows.append(row)
        facts["항목 수"] = len(items)
        facts["항목 상태별"] = {STATUS_KO.get(k, k): v for k, v in _count(i.get("status") for i in items).items()}
        facts["항목별 결과"] = rows
        facts["진행 중 항목"] = running
        facts["건너뜀"] = [_line(s) for s in ((status.get("skipped") or run.get("skipped") or []))][:10]
    facts["접수 시각"] = run.get("createdAt")

    records, regions_missing, ports_regions, found_steps = [], [], [], []
    if report is not None:
        for label, region in sorted((report.get("regions") or {}).items()):
            if not region.get("ready"):
                regions_missing.append(str(label))
                records.append({"리전": str(label), "단계": "-", "결과": "결과 없음", "사유": _line(region.get("reason") or "")})
                continue
            open_ports = False
            for st in region.get("steps") or []:
                s = summarize_step(st.get("step"), st.get("output"))
                records.append({"리전": str(label), "단계": str(st.get("step") or "?"), "결과": s["결과"], "핵심 줄": s["핵심 줄"]})
                if s["발견"]:
                    if "nmap" in str(st.get("step") or "").lower():
                        open_ports = True
                    else:
                        found_steps.append(f"{label}/{st.get('step')}")
            if open_ports:
                ports_regions.append(str(label))
        facts["공격 리전 수"] = len(report.get("regions") or {})
    facts["공격 로그"] = records
    facts["필수 항목 값"] = {
        "실패 항목": failed if status is not None else "읽지 못함",
        "결과 없는 리전": regions_missing if report is not None else "읽지 못함",
        "열린 포트 발견 리전": ports_regions if report is not None else "읽지 못함",
        "취약 지점 발견 단계": found_steps if report is not None else "읽지 못함",
    }
    return facts


def _count(values):
    out = {}
    for v in values:
        key = v or "Unknown"
        out[key] = out.get(key, 0) + 1
    return out
