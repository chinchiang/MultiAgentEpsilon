"""設定解析或外部工具呼叫前即保留最小證據。

Minimal evidence exists before configuration parsing or external tool calls."""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from .results import EVIDENCE_VERSION, SUBJECT_FORMAT, result, write_json, write_text_atomic


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

    @classmethod
    def resume(cls, root: Path, run_id: str):
        """接續 supervisor 已建立的執行，不重新產生 run ID。 / Continue a run the supervisor created, keeping its run ID."""
        audit = cls.__new__(cls)
        audit.output = Path(root) / "artifacts" / run_id
        audit.data = json.loads((audit.output / "report.json").read_text())
        if audit.data.get("run_id") != run_id:
            raise ValueError("resumed run identity mismatch")
        return audit

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
        # 不序列化例外文字、子程序輸出、DSN 或 URL。 / Never serialize exception text, subprocess output, DSNs or URLs.
        self.data["errors"].append({"stage": self.data["stage"], "error_type": type(exc).__name__})
        self.data.update(execution="ERROR", decision="BLOCK", reasons=["run failed; see redacted errors"])
        self.save()

    def finish(self, required=(), *, update_pointer=True):
        seen = {r["gate"] for r in self.data["records"]}
        for gate, kind in required:
            if gate not in seen:
                self.add(gate, "NOT_RUN", kind, 0, 0, "run interrupted before gate completion")
                # 缺少必要 gate 時不可保留先前的 ALLOW。 / A missing required gate can never keep an earlier ALLOW.
                self.data.update(decision="BLOCK", reasons=[*self.data.get("reasons", []), f"{gate}: not run"])
        if self.data["execution"] == "RUNNING":
            self.data["execution"] = "COMPLETED"
        self.save()
        if update_pointer:
            pointer = "latest.txt" if self.data["operation"] == "security" else self.data["operation"] + "-latest.txt"
            write_text_atomic(self.output.parent / pointer, self.data["run_id"] + "\n")
        return 0 if self.data["decision"] == "ALLOW" else 1
