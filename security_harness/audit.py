"""Minimal evidence exists before configuration parsing or external tool calls."""
import uuid
from datetime import datetime, timezone
from pathlib import Path
from .results import EVIDENCE_VERSION, SUBJECT_FORMAT, result, write_json


class AuditRun:
    def __init__(self, root: Path, operation: str):
        self.output = root / "artifacts" / str(uuid.uuid4())
        self.data = {"schema_version": EVIDENCE_VERSION, "subject_digest_format": SUBJECT_FORMAT,
                     "run_id": self.output.name,
                     "operation": operation, "created_at": datetime.now(timezone.utc).isoformat(),
                     "subject_digest": None, "policy_digest": None, "records": [],
                     "execution": "RUNNING", "decision": "BLOCK", "reasons": ["run incomplete"],
                     "stage": "initialization", "errors": []}
        self.save()

    def save(self):
        write_json(self.output / "report.json", self.data)

    def stage(self, name):
        self.data['stage'] = name
        self.save()

    def add(self, gate, status, kind, count, findings, detail, **extra):
        self.data["records"].append(result(gate, status, kind, count, findings,
            self.data["subject_digest"], self.data["policy_digest"], detail,
            run_id=self.data["run_id"], **extra))
        self.save()

    def fail(self, exc):
        # Never serialize exception text, subprocess output, DSNs or URLs.
        self.data["errors"].append({"stage": self.data["stage"], "error_type": type(exc).__name__})
        self.data.update(execution="ERROR", decision="BLOCK", reasons=["run failed; see redacted errors"])

    def finish(self, required=()):
        seen = {r["gate"] for r in self.data["records"]}
        for gate, kind in required:
            if gate not in seen:
                self.add(gate, "NOT_RUN", kind, 0, 0, "run interrupted before gate completion")
        if self.data["execution"] == "RUNNING":
            self.data["execution"] = "COMPLETED"
        self.save()
        pointer = "latest.txt" if self.data["operation"] == "security" else self.data["operation"] + "-latest.txt"
        (self.output.parent / pointer).write_text(self.data["run_id"] + "\n")
        return 0 if self.data["decision"] == "ALLOW" else 1
