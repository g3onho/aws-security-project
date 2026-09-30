"""서비스 계층 Flask 대체 앱 — compose 계약(5000 포트, DB_* 환경변수)만 만족하는 최소 구현."""
import os

import pymysql
from flask import Flask, jsonify

app = Flask(__name__)


def db_ping():
    conn = pymysql.connect(
        host=os.environ["DB_HOST"], user=os.environ["DB_USER"], password=os.environ["MYSQL_PASSWORD"],
        database=os.environ["DB_NAME"], connect_timeout=3,
    )
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
    finally:
        conn.close()


@app.get("/")
def index():
    # DB 실패를 정상으로 숨기지 않는다: 연결 실패면 503.
    try:
        db_ping()
    except Exception as exc:  # noqa: BLE001
        return jsonify(service="web", db="unreachable", error=type(exc).__name__), 503
    return jsonify(service="web", db="ok")
