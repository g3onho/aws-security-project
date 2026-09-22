"""프론트엔드 JS 가 파싱되는지 본다.

왜 있나 — `static/js/app.js` 에 작은따옴표 문자열 안에 `${...}` 를 넣은 줄이 커밋돼
파일 전체가 SyntaxError 로 죽어 있었다. 모듈이 통째로 로드되지 않으니 화면은 빈
껍데기만 떴고, 파이썬 테스트 114개는 전부 통과했다. 파서를 한 번 돌리는 것만으로
이 부류를 다 잡는다. Node 가 없으면 skip 한다.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"
SCRIPTS = sorted(FRONTEND.glob("static/js/*.js"))


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_javascript_parses(script, tmp_path):
    if not shutil.which("node"):
        pytest.skip("node 가 없어 JS 파싱 검사를 건너뜁니다")
    # node --check 는 확장자로 모듈 여부를 판단한다. .mjs 로 복사해서 ESM 으로 읽힌다.
    copy = tmp_path / (script.stem + ".mjs")
    copy.write_text(script.read_text(encoding="utf-8"), encoding="utf-8")
    proc = subprocess.run(["node", "--check", str(copy)], capture_output=True, text=True,
                          encoding="utf-8", timeout=30)
    assert proc.returncode == 0, f"{script.name} 파싱 실패:\n{proc.stderr[:800]}"


def test_template_defines_every_id_app_js_queries():
    """app.js 가 `$('#id')` 로 찾는 요소가 템플릿에 있어야 한다."""
    import re

    app = (FRONTEND / "static/js/app.js").read_text(encoding="utf-8")
    html = (FRONTEND / "templates/index.html").read_text(encoding="utf-8")
    # app.js 가 innerHTML 로 직접 만들어 넣는 id 는 템플릿에 없어도 정상이다.
    dynamic = {
        "region-spark", "severity-chart", "metrics-chart", "coverage", "audit-log",
        "bulk-count", "pick-all", "host", "close-region", "dialog-title", "incidents",
        "evidence-content", "manual-note", "manual-reference", "manual-value", "retry",
        "vulns", "vuln-size", "vuln-fixable",
        "block-plan", "nacl-id", "nacl-ip", "nacl-rule", "nacl-evidence",
    }
    queried = set(re.findall(r"""\$\('#([a-zA-Z0-9_-]+)'\)""", app))
    defined = set(re.findall(r'id="([^"]+)"', html))
    assert not (queried - defined - dynamic)


def test_url_state_keys_cover_every_shared_filter():
    """주소에 담는 키가 빠지면 새로고침 때 그 필터만 조용히 초기화된다."""
    import re

    app = (FRONTEND / "static/js/app.js").read_text(encoding="utf-8")
    defaults = re.search(r"const URL_DEFAULTS=\{([^}]*)\}", app).group(1)
    keys = set(re.findall(r"(\w+):", defaults))
    assert keys == {"view", "region", "resource", "hours", "endOffset",
                    "severity", "status", "source", "search", "page"}
    # 주소 파라미터 이름도 같은 수여야 한다(누락 시 조용히 안 담긴다).
    params = re.search(r"const URL_KEYS=\{([^}]*)\}", app).group(1)
    assert len(re.findall(r"(\w+):", params)) == len(keys)


def test_history_is_pushed_only_for_view_and_dialog():
    """검색어 한 글자마다 히스토리가 쌓이면 뒤로가기를 못 쓴다."""
    app = (FRONTEND / "static/js/app.js").read_text(encoding="utf-8")
    assert "refresh({push:true})" in app          # 화면 전환
    assert "activeId=id;approval=ask;syncUrl(true)" in app   # 상세 열기
    # 필터·검색은 push 없이 refresh() 만 부른다.
    assert "state.search=e.target.value;state.page=1;clearTimeout(searchTimer);" in app
