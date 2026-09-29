"""Local CLI. The default server runs its durable worker in the same process."""
import argparse
import getpass
import logging
import os
from pathlib import Path

from soar import create_app
from soar.auth import create_user, set_password


def main():
    parser = argparse.ArgumentParser(description="Security operations dashboard")
    parser.add_argument("--host", default=os.getenv("DASHBOARD_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("DASHBOARD_PORT", "5051")))
    operations = parser.add_mutually_exclusive_group()
    operations.add_argument("--init-admin", action="store_true")
    operations.add_argument("--add-user", metavar="NAME")
    operations.add_argument("--set-password", metavar="NAME")
    operations.add_argument("--worker", action="store_true")
    parser.add_argument("--role", choices=["operator", "approver", "viewer"], default="viewer")
    parser.add_argument("--full-scope", action="store_true",
                        help="With --add-user: allow all accounts, regions and resources (default: sees nothing)")
    parser.add_argument("--once", action="store_true", help="Process at most one job (requires --worker)")
    parser.add_argument("--no-worker", action="store_true", help="Run HTTP only; use a separate --worker process")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if args.once and not args.worker:
        parser.error("--once requires --worker")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    app = create_app()
    store, worker = app.extensions["store"], app.extensions["worker"]
    if args.init_admin:
        with store.connect() as db:
            exists = db.execute("SELECT 1 FROM users LIMIT 1").fetchone()
        if exists:
            print("Existing accounts preserved; use --set-password if needed.")
            return
        # 팀 공용 고정 계정: 조치 담당(operator) + 조회 전용(viewer). 환경변수로 덮어쓸 수 있다.
        # 기본 scope 는 accounts=[](아무 계정도 못 봄)라 그대로 두면 모든 화면이 0건이다 — 전체 범위로 만든다.
        accounts = [(os.getenv("DASHBOARD_ADMIN_USER", "admin"), os.getenv("DASHBOARD_ADMIN_PASSWORD", "rapa6074!"), "operator"),
                    (os.getenv("DASHBOARD_VIEWER_USER", "user"), os.getenv("DASHBOARD_VIEWER_PASSWORD", "rapa6074!"), "viewer")]
        for name, password, role in accounts:
            create_user(store, name, password, role, scope={"accounts": None, "regions": None, "resources": None})
        path = Path(app.config["DATABASE"]).parent / "initial-login.txt"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(f"URL: http://127.0.0.1:{args.port}/login\n")
            for name, password, role in accounts:
                handle.write(f"{role}: {name} / {password}\n")
        print(f"Initial login details: {path}")
    elif args.add_user:
        scope = {"accounts": None, "regions": None, "resources": None} if args.full_scope else None
        create_user(store, args.add_user, getpass.getpass("Password (8-256 characters): "), args.role, scope=scope)
        print("Account created.")
    elif args.set_password:
        set_password(store, args.set_password, getpass.getpass("New password (8-256 characters): "))
        print("Password updated; previous sessions invalidated.")
    elif args.worker:
        app.extensions["provider"].require_ready()
        if args.once:
            worker.run_once()
        else:
            try:
                worker._loop()
            except KeyboardInterrupt:
                pass
    else:
        from waitress import serve
        if not args.no_worker and app.extensions["provider"].connected:
            worker.start()
        print(f"Dashboard: http://127.0.0.1:{args.port}", flush=True)
        try:
            serve(app, host=args.host, port=args.port, threads=4)
        except KeyboardInterrupt:
            pass
        finally:
            worker.stop()


if __name__ == "__main__":
    main()
