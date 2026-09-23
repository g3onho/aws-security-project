"""Read use cases for the existing frontend; no Flask or SQL dependencies."""
from . import readmodel
from .domain import SOURCES, STATUSES
from .errors import Problem
from .store import now_ms


class Dashboard:
    def __init__(self, workflow, provider, store, worker, writes_enabled):
        self.workflow, self.provider = workflow, provider
        self.store, self.worker = store, worker
        self.writes_enabled = writes_enabled

    def event(self, event_id, actor):
        self.provider.require_ready()
        if getattr(self.provider, "connected", False):
            event = next((row for row in self.provider.observations({}) if row["id"] == event_id), None)
            if event is None:
                raise Problem(404, "吏?먰븯吏 ?딅뒗 ?대깽?멸낫?낮?덈떎.", "EVENT_NOT_FOUND")
        else:
            event = self.workflow.get_event(event_id)
            self.workflow.authorize_event(event, actor)
        event["allowedActions"] = self.workflow.allowed_actions(event, actor) if self.writes_enabled else []
        return event

    def read(self, kind, query, actor):
        self.provider.require_ready()
        events = (self.provider.observations(query) if getattr(self.provider, "connected", False)
                  else self.workflow.visible_events(actor))
        if not self.writes_enabled:
            for event in events:
                event["allowedActions"] = []
        query = {**query, "collectedAt": now_ms()}
        projections = {"events": readmodel.paginate, "snapshot": readmodel.snapshot}
        if kind in {"scenarios", "incidents", "vulnerabilities"}:
            return getattr(self.provider, kind)(query, events)
        if kind in projections:
            return projections[kind](events, query)
        if kind == "summary":
            data = readmodel.snapshot(events, query)
            return {**data["summary"], "asOf": data["asOf"], "snapshot": data["snapshot"]}
        if kind == "csv":
            return readmodel.to_csv(readmodel.snapshot(events, query)["items"])
        principal = self.workflow.principal(actor)
        scope = principal["scope"]
        for name, key in (("regions", "region"), ("resources", "resource")):
            allowed = scope.get(name)
            if allowed is not None and query.get(key) not in (None, "all", *allowed):
                raise Problem(404, "허용 범위에서 자원을 찾을 수 없습니다.", "RESOURCE_NOT_FOUND")
        if scope.get("regions") is not None and query["region"] == "all":
            query["region"] = scope["regions"][0] if scope["regions"] else "unknown"
        if scope.get("resources") is not None and not query.get("resource"):
            query["resource"] = scope["resources"][0] if scope["resources"] else "__no_authorized_resource__"
        if kind == "services":
            return self.provider.services(query, events)
        if kind == "metrics":
            data = self.provider.metrics(query)
            if scope.get("resources") is not None:
                data["hosts"] = [host for host in data.get("hosts", []) if host["id"] in scope["resources"]]
                data["series"] = [series for series in data.get("series", []) if series["resource"] in scope["resources"]]
                for series in data["series"]:
                    series["hosts"] = [host for host in series.get("hosts", []) if host["id"] in scope["resources"]]
            return data
        if kind in {"resources", "nacls"}:
            data = getattr(self.provider, kind)(query)
            if scope.get("resources") is not None:
                data["items"] = [item for item in data["items"] if item["id"] in scope["resources"]]
                data["total"] = len(data["items"])
            return data
        raise ValueError("Unknown read model")

    def config(self, actor):
        principal = self.workflow.principal(actor)
        status = self.provider.status()
        return {"mode": "live", "asOf": now_ms(), "writeEnabled": False,
                "role": principal["role"], "regions": list(getattr(self.provider, "regions", ())), "statuses": STATUSES,
                "sources": SOURCES, "awsConnected": status["connected"],
                "dataSourceConnected": status["connected"], "provider": status}

    def health(self):
        status = self.provider.status()
        return {"mode": "live", "status": "ok" if status["connected"] else "degraded",
                "aws_connected": status["connected"],
                "checks": {"database": "ok", "dataSource": status["state"], "worker": "disabled"},
                "write_enabled": False, "version": "0.1.0"}

    def audit(self, actor):
        self.provider.require_ready()
        ids = {event["id"] for event in self.workflow.visible_events(actor)}
        return {"items": [item for item in self.store.audit_log()["items"]
                          if item["event_id"] in ids or (item["event_id"] is None and item["actor"] == actor)]}
