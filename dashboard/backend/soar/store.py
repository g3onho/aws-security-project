"""One SQLite database for accounts, event state, durable jobs and audit history.

Each command commits its event, job, audit and idempotent response together.
No database transaction is held while executing a job.
"""
import json
import sqlite3
import time
from contextlib import contextmanager


def now_ms():
    return int(time.time() * 1000)


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


class Store:
    def __init__(self, path):
        self.path = str(path)
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version > 1:
                raise ValueError("Database was created by a newer backend")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    name TEXT PRIMARY KEY, password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('operator','approver','viewer')),
                    scope TEXT NOT NULL DEFAULT '{"accounts":[],"regions":null,"resources":null}',
                    auth_version INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, event_id TEXT NOT NULL REFERENCES events(id),
                    kind TEXT NOT NULL CHECK(kind IN ('execute','verify')),
                    state TEXT NOT NULL, payload TEXT NOT NULL, result TEXT,
                    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
                    lease_until INTEGER NOT NULL DEFAULT 0, lease_token TEXT
                );
                CREATE UNIQUE INDEX IF NOT EXISTS one_active_job ON jobs(event_id)
                    WHERE state IN ('QUEUED','RUNNING');
                CREATE TABLE IF NOT EXISTS requests (
                    key TEXT PRIMARY KEY, actor TEXT NOT NULL, fingerprint TEXT NOT NULL,
                    status INTEGER NOT NULL, response TEXT NOT NULL, created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL,
                    actor TEXT NOT NULL, event_id TEXT, action TEXT NOT NULL, detail TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS login_limits (
                    key TEXT PRIMARY KEY, failures INTEGER NOT NULL, until_ms INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS drills (
                    run_id TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                -- 대시보드 원클릭 조치 실행 기록. 탐지(events)는 실환경에서 이 DB 에 없으므로 FK 를 걸지 않는다.
                CREATE TABLE IF NOT EXISTS remediations (
                    id TEXT PRIMARY KEY, event_id TEXT NOT NULL, actor TEXT NOT NULL, request_key TEXT NOT NULL UNIQUE,
                    state TEXT NOT NULL, execution_id TEXT, payload TEXT NOT NULL,
                    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS one_active_remediation ON remediations(event_id)
                    WHERE state IN ('STARTING','RUNNING','VERIFYING');
                CREATE INDEX IF NOT EXISTS remediations_created_at ON remediations(created_at);
                -- 열린 탐지를 완전히 읽을 때마다 기록하는 관찰 장부. 사라진 탐지 중 우리 조치 기록이 없는 것을 '외부 해결'로 추정한다.
                CREATE TABLE IF NOT EXISTS event_seen (
                    event_id TEXT PRIMARY KEY, snapshot TEXT NOT NULL, first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL, gone_at INTEGER
                );
                PRAGMA user_version=1;
            """)

    @contextmanager
    def connect(self, write=False):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            if write:
                db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()


    @staticmethod
    def save_event(db, event):
        db.execute("INSERT INTO events(id,payload) VALUES (?,?) "
                   "ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", (event["id"], encode(event)))

    @staticmethod
    def event(db, event_id):
        row = db.execute("SELECT payload FROM events WHERE id=?", (event_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def events(self):
        with self.connect() as db:
            return [json.loads(row[0]) for row in db.execute("SELECT payload FROM events ORDER BY id")]

    def observe_events(self, events, at, keep_ms):
        """완전히 읽은 '지금 열린 탐지' 목록을 장부에 반영한다. 보이면 last_seen 갱신(사라졌다 돌아오면 gone_at 해제),
        장부에 있는데 이번에 안 보이면 gone_at 기록. keep_ms 보다 오래된 사라짐 기록은 지운다."""
        with self.connect(write=True) as db:
            present = set()
            for event in events:
                present.add(event["id"])
                snapshot = encode({key: event.get(key) for key in (
                    "id", "title", "resource", "severity", "source", "region", "accountId", "controlId", "externalFindingId")})
                db.execute("INSERT INTO event_seen(event_id,snapshot,first_seen,last_seen,gone_at) VALUES (?,?,?,?,NULL) "
                           "ON CONFLICT(event_id) DO UPDATE SET snapshot=excluded.snapshot,last_seen=excluded.last_seen,gone_at=NULL",
                           (event["id"], snapshot, at, at))
            for (event_id,) in db.execute("SELECT event_id FROM event_seen WHERE gone_at IS NULL").fetchall():
                if event_id not in present:
                    db.execute("UPDATE event_seen SET gone_at=? WHERE event_id=?", (at, event_id))
            db.execute("DELETE FROM event_seen WHERE gone_at IS NOT NULL AND gone_at<?", (at - keep_ms,))

    def gone_events(self, start, end):
        with self.connect() as db:
            rows = db.execute("SELECT * FROM event_seen WHERE gone_at IS NOT NULL AND gone_at>=? AND gone_at<? "
                              "ORDER BY gone_at DESC", (start, end)).fetchall()
        return [{**json.loads(row["snapshot"]), "firstSeen": row["first_seen"], "lastSeen": row["last_seen"],
                 "goneAt": row["gone_at"]} for row in rows]

    @staticmethod
    def audit(db, actor, event_id, action, detail=None):
        db.execute("INSERT INTO audit(at,actor,event_id,action,detail) VALUES (?,?,?,?,?)",
                   (now_ms(), actor, event_id, action, encode(detail or {})))
