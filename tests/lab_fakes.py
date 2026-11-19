"""Test doubles: no Mininet, traffic, root, model loading, or database access."""

import copy


class MemoryRepository:
    def __init__(self):
        self.project_rows = {}
        self.run_rows = {}
        self.event_rows = {}
        self.failed = False

    def health(self):
        if self.failed:
            raise OSError("database unavailable")
        return True

    def recover_runs(self):
        for row in self.run_rows.values():
            row["status"] = "interrupted"

    def save_project(self, topology, project_id=None):
        self.health()
        identifier = project_id or "project"
        self.project_rows[identifier] = {"id": identifier, "topology": topology}
        return identifier

    def projects(self):
        self.health()
        return list(self.project_rows.values())

    def create_run(self, run):
        self.health()
        self.run_rows[run["id"]] = copy.deepcopy(run)

    def finish_run(self, run_id, status):
        self.health()
        self.run_rows[run_id]["status"] = status

    def runs(self):
        self.health()
        return list(self.run_rows.values())

    def run(self, run_id):
        self.health()
        return self.run_rows.get(run_id)

    def append_event(self, event):
        self.health()
        self.event_rows.setdefault(event["run_id"], []).append(copy.deepcopy(event))

    def events(self, run_id, after, limit=500):
        self.health()
        return [row for row in self.event_rows.get(run_id, []) if row["seq"] > after][
            :limit
        ]


class FakeRuntime:
    def __init__(
        self,
        topology,
        run_id,
        mitigation,
        emit,
        detection=None,
        forwarding="per_port",
        protected_hosts=(),
    ):
        self.emit = emit
        self.protected_hosts = tuple(protected_hosts)
        self.detection = detection
        self.forwarding = forwarding
        self.closed = False

    def start(self):
        self.emit("versions", {"runtime": "test double"})

    def sample(self):
        self.emit("links", {"links": []})

    def start_probe(self, client, target, started_at):
        self.probe(client, target)

    def probe(self, client, target):
        return None

    def start_pings(self, experiment):
        return None

    def stop_pings(self):
        return None

    def close(self):
        self.closed = True

    def drain(self):
        pass

    def diagnostic(self, request):
        self.emit("command", {"argv": ["test"], "node": request.node})

    def capture(self, request):
        self.emit("capture_started", {"link_id": request.link_id})
