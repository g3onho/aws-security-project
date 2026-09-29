"""모의 데이터로 대시보드를 띄운다(시연·화면 확인 전용). 실제 AWS 를 호출하지 않는다.

    python tools/run_demo.py [--host 127.0.0.1] [--port 5052]

- 임시 폴더의 별도 DB 를 쓴다(실제 instance/ DB 와 섞이지 않는다). 종료 후에도 남지 않는다.
- 로그인: admin / demo-password-1 (조치 담당), viewer / demo-password-1 (조회 전용). 로컬 전용 모의 계정이다.
- WRITE_ENABLED 를 켠다: 대시보드 원클릭 조치를 화면에서 눌러 볼 수 있게. 모의 공급자가 메모리에서만 흉내 내며
  실제 AWS 를 호출하지 않는다. viewer 계정은 실행할 수 없다.
"""
import argparse
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

PASSWORD = "demo-password-1"


def main():
    parser = argparse.ArgumentParser(description="Dashboard with mock data")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5052)
    args = parser.parse_args()
    os.environ["DATA_PROVIDER"] = "demo"
    os.environ["WRITE_ENABLED"] = "true"
    os.environ.setdefault("PROJECT_VPC_ID", "vpc-0demo00000000001")  # 모의 VPC. 실제 값이 아니다
    os.environ["DASHBOARD_INSTANCE"] = tempfile.mkdtemp(prefix="dashboard-demo-")
    from soar import create_app
    from soar.auth import create_user
    app = create_app()
    store = app.extensions["store"]
    full = {"accounts": None, "regions": None, "resources": None}
    create_user(store, "admin", PASSWORD, "operator", scope=full)
    create_user(store, "viewer", PASSWORD, "viewer", scope=full)
    from waitress import serve
    print(f"[demo] http://{args.host}:{args.port}/login  (admin / {PASSWORD})", flush=True)
    serve(app, host=args.host, port=args.port, threads=4)


if __name__ == "__main__":
    main()
