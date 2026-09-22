"""dom-check.mjs 가 쓸 API 응답 픽스처를 만든다.

실제 Flask 응답을 그대로 떠서 저장하므로, 계약이 바뀌면 화면 테스트도 같이 따라온다.
사용: python tools/dump_fixtures.py [출력경로]
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.auth import create_user  # noqa: E402
from run import create_app  # noqa: E402

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT.parent / "frontend" / "tests" / "fixtures.json"


def main() -> None:
    database = Path(tempfile.mkdtemp()) / "fixtures.sqlite3"
    app = create_app({"DATABASE": str(database), "TESTING": True,
                      "USE_DEMO_DATA": True, "WRITE_ENABLED": True})
    create_user(str(database), "operator", "fixture-password-123", "operator")
    client = app.test_client()
    token = client.get("/api/auth/session").json["csrfToken"]
    login = client.post("/api/auth/login",
                        json={"username": "operator", "password": "fixture-password-123"},
                        headers={"X-CSRF-Token": token})
    client.environ_base["HTTP_X_CSRF_TOKEN"] = login.json["csrfToken"]

    from app.adapters.demo import DEMO_NOW  # noqa: PLC0415
    query = f"region=ap-northeast-2&from={DEMO_NOW - 24 * 3600000}&to={DEMO_NOW}"
    fixtures = {
        "/api/auth/session": client.get("/api/auth/session").json,
        "/api/config": client.get("/api/config").json,
        "/api/snapshot": client.get("/api/snapshot?" + query).json,
        "/api/metrics": client.get("/api/metrics?" + query + "&scope=all").json,
        "/api/vulnerabilities": client.get("/api/vulnerabilities?" + query).json,
        "/api/services": client.get("/api/services?" + query).json,
        "/api/scenarios": client.get("/api/scenarios?" + query).json,
        "/api/incidents": client.get("/api/incidents?" + query).json,
        "/api/audit": client.get("/api/audit").json,
        "/health": client.get("/health").json,
        # 지도 데이터는 화면 검사와 무관하므로 빈 컬렉션으로 둔다.
        "/static/data/countries.geojson": {"type": "FeatureCollection", "features": []},
    }
    fixtures["/api/auth/session"]["user"] = {"name": "operator"}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(fixtures, ensure_ascii=False, indent=1), encoding="utf-8")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
