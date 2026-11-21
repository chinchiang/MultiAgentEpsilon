"""設定解析或外部工具呼叫前即保留最小證據。

Minimal evidence exists before configuration parsing or external tool calls."""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from .results import EVIDENCE_VERSION, SUBJECT_FORMAT, read_regular, result, write_json, write_text_atomic

# security 證據的大小上限；正常報告遠小於此。 / Size limit for security evidence; a normal report is far smaller.
REPORT_LIMIT = 8 * 1024 * 1024


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
    def from_evidence(cls, output: Path, data: dict):
        """以既有輸出目錄與證據資料建立實例，供接續執行與回收收尾共用。 / Build an instance from an existing output
        directory and evidence dictionary, shared by worker resumption and recovery closing."""
        audit = cls.__new__(cls)
        audit.output = Path(output)
        audit.data = data
        return audit

    @classmethod
    def resume(cls, root: Path, run_id: str):
        """接續 supervisor 已建立的執行，不重新產生 run ID。 / Continue a run the supervisor created, keeping its run ID."""
        output = Path(root) / "artifacts" / run_id
        data = json.loads(read_regular(output / "report.json", REPORT_LIMIT))
        if not isinstance(data, dict) or data.get("run_id") != run_id:
            raise ValueError("resumed run identity mismatch")
        return cls.from_evidence(output, data)

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

    def finish(self, required=(), *, update_pointer=True, defer_final=False):
        if defer_final:
            self.data["pending_decision"] = self.data["decision"]
            self.data["pending_execution"] = self.data["execution"]
            self.data.update(decision="BLOCK", execution="AWAITING_CLEANUP")
        seen = {r["gate"] for r in self.data["records"]}
        for gate, kind in required:
            if gate not in seen:
                self.add(gate, "NOT_RUN", kind, 0, 0, "run interrupted before gate completion")
                # 缺少必要 gate 時不可保留先前的 ALLOW。 / A missing required gate can never keep an earlier ALLOW.
                self.data.update(decision="BLOCK", reasons=[*self.data.get("reasons", []), f"{gate}: not run"])
                if defer_final:
                    self.data["pending_decision"] = "BLOCK"
        if self.data["execution"] == "RUNNING":
            self.data["execution"] = "COMPLETED"
        self.save()
        if update_pointer:
            pointer = "latest.txt" if self.data["operation"] == "security" else self.data["operation"] + "-latest.txt"
            write_text_atomic(self.output.parent / pointer, self.data["run_id"] + "\n")
        if defer_final:
            return 0 if self.data.get("pending_decision") == "ALLOW" else 1
        return 0 if self.data["decision"] == "ALLOW" else 1
