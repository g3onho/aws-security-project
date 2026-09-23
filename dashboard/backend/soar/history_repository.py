"""Read durable audit records and jobs without exposing SQLite to HTTP routes."""
import json


class HistoryRepository:
    def __init__(self, store):
        self.store = store

    def snapshot(self):
        with self.store.connect() as db:
            # Both lists use one read transaction, so a completion cannot appear
            # halfway through this repository snapshot.
            db.execute("BEGIN")
            audits = [dict(row) for row in db.execute("SELECT * FROM audit WHERE event_id IS NOT NULL")]
            jobs = [dict(row) for row in db.execute("SELECT * FROM jobs")]
        for row in audits:
            row["detail"] = json.loads(row["detail"])
        for row in jobs:
            row["payload"] = json.loads(row["payload"])
            row["result"] = json.loads(row["result"]) if row["result"] else None
        return audits, jobs
