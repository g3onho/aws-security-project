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
                CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
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

    @staticmethod
    def audit(db, actor, event_id, action, detail=None):
        db.execute("INSERT INTO audit(at,actor,event_id,action,detail) VALUES (?,?,?,?,?)",
                   (now_ms(), actor, event_id, action, encode(detail or {})))

    def audit_log(self):
        with self.connect() as db:
            return {"items": [dict(row) for row in db.execute(
                "SELECT id,at,actor,event_id,action,detail FROM audit ORDER BY id DESC LIMIT 1000")]}
