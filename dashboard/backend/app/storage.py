"""Single-host SQLite storage. Transactions serialize web and worker mutations."""
import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path


def ms():
    return int(time.time()*1000)


def encode(value):
    return json.dumps(value,ensure_ascii=False,sort_keys=True)


@contextmanager
def connect(path, write=False):
    db=sqlite3.connect(path,timeout=20)
    db.row_factory=sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    try:
        if write:
            db.execute('BEGIN IMMEDIATE')
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def migrate(path):
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    with connect(path) as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript('''
        CREATE TABLE IF NOT EXISTS schema_versions(version INTEGER PRIMARY KEY, at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, payload TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY,password TEXT NOT NULL,role TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,event_id TEXT NOT NULL,kind TEXT NOT NULL,
          state TEXT NOT NULL,payload TEXT NOT NULL);
        CREATE UNIQUE INDEX IF NOT EXISTS active_job ON jobs(event_id) WHERE state='RUNNING';
        CREATE TABLE IF NOT EXISTS requests(key TEXT PRIMARY KEY,hash TEXT NOT NULL,response TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,at INTEGER NOT NULL,
          actor TEXT NOT NULL,event_id TEXT,action TEXT NOT NULL,detail TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS login_limits(key TEXT PRIMARY KEY,failures INTEGER NOT NULL,until REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        ''')
        db.execute('INSERT OR IGNORE INTO schema_versions VALUES(1,?)',(ms(),))


def save(db,event):
    db.execute('INSERT INTO events VALUES(?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload',
               (event['id'],encode(event)))


def audit(db,actor,event_id,action,detail):
    db.execute('INSERT INTO audit(at,actor,event_id,action,detail) VALUES(?,?,?,?,?)',
               (ms(),actor,event_id,action,encode(detail)))
