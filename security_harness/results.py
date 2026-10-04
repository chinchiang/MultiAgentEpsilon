"""Small, strict result contract. These are local evidence records, not attestations."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def digest_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def subject_digest(root: Path) -> str:
    """Bind the complete input worktree, including docs and untracked source files.

    Generated environments/state/run evidence are explicitly outside this subject.
    This content digest does not establish signer identity or immutable storage.
    """
    excluded = {".git", ".venv", ".tools", ".state", "artifacts", "__pycache__", ".pytest_cache"}
    selected = [p for p in root.rglob("*")
                if not excluded.intersection(p.relative_to(root).parts) and p.is_file()]
    digest = hashlib.sha256()
    for p in sorted(set(selected)):
        if p.is_symlink():
            raise ValueError("symlink subject requires explicit review")
        digest.update(p.relative_to(root).as_posix().encode() + b"\0")
        digest.update(p.read_bytes() + b"\0")
    return digest.hexdigest()


def result(gate: str, status: str, kind: str, count: int, findings: int,
           subject: str, policy: str, detail: str, **extra) -> dict:
    return {
        "schema_version": 1, "gate": gate, "execution": status,
        "kind": kind, "coverage_count": count, "findings": findings,
        "subject_digest": subject, "policy_digest": policy,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "detail": detail, **extra,
    }


def decide(records: list[dict], policy: dict, subject: str, policy_digest: str,
           now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    reasons = []
    seen = set()
    required = policy.get("required_gates")
    if (not isinstance(required, list) or not required or
            any(not isinstance(g, str) or not g for g in required) or
            len(set(required)) != len(required) or
            type(policy.get("max_evidence_age_seconds")) is not int or
            policy["max_evidence_age_seconds"] <= 0):
        return {"decision": "BLOCK", "reasons": ["invalid trusted policy"]}
    for record in records:
        if not isinstance(record, dict):
            reasons.append("malformed evidence")
            continue
        gate = record.get("gate", "INVALID")
        if not isinstance(gate, str) or gate not in required:
            reasons.append("unexpected gate")
            continue
        if gate in seen:
            reasons.append(f"{gate}: duplicate evidence")
        seen.add(gate)
        try:
            valid = (type(record["schema_version"]) is int and record["schema_version"] == 1
                     and record["subject_digest"] == subject
                     and record["policy_digest"] == policy_digest
                     and record["kind"] in ("scan", "test")
                     and record["execution"] in ("COMPLETED", "ERROR", "TIMEOUT", "NOT_RUN")
                     and type(record["coverage_count"]) is int and record["coverage_count"] > 0
                     and type(record["findings"]) is int and record["findings"] >= 0)
            if not valid:
                raise ValueError("invalid contract")
            when = datetime.fromisoformat(record["created_at"])
            age = (now - when).total_seconds()
            if not 0 <= age <= policy["max_evidence_age_seconds"]:
                raise ValueError("stale or future evidence")
        except (KeyError, ValueError, TypeError):
            reasons.append(f"{gate}: invalid, missing, stale or mismatched evidence")
            continue
        if record["execution"] != "COMPLETED":
            reasons.append(f"{gate}: {record['execution']}")
        if record["findings"]:
            reasons.append(f"{gate}: confirmed findings")
    for gate in policy["required_gates"]:
        if gate not in seen:
            reasons.append(f"{gate}: missing required gate")
    return {"decision": "BLOCK" if reasons else "ALLOW", "reasons": reasons,
            "scope": "local milestone only; no release attestation or full ASVS claim"}


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
