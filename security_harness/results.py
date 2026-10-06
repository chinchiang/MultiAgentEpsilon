"""Small, strict result contract. These are local evidence records, not attestations."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from .inputs import input_files

EVIDENCE_VERSION = 3
SUBJECT_FORMAT = "worktree-manifest-v1"


def file_identity(path: Path) -> tuple[os.stat_result, str]:
    """Stream regular files without following a final symlink; detect read-time changes."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("non-regular input")
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
    current = path.lstat()
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if identity(before) != identity(after) or identity(after) != identity(current):
        raise ValueError("input changed while hashing")
    return before, digest


def digest_file(path: Path) -> str:
    return file_identity(path)[1]


def subject_digest(root: Path) -> str:
    """Bind the complete input worktree, including docs and untracked source files.

    Generated environments/state/run evidence are explicitly outside this subject.
    This content digest does not establish signer identity or immutable storage.
    """
    paths = input_files(root)
    files = []
    for p in paths:
        info, content = file_identity(p)
        files.append({"path": p.relative_to(root).as_posix(), "type": "file",
                      "executable_bits": info.st_mode & 0o111, "size": info.st_size,
                      "sha256": content})
    if paths != input_files(root):
        raise ValueError("input inventory changed while hashing")
    encoded = json.dumps({"format": SUBJECT_FORMAT, "files": files},
                         sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()
    return SUBJECT_FORMAT + ":sha256:" + hashlib.sha256(encoded).hexdigest()


def result(gate: str, status: str, kind: str, count: int, findings: int,
           subject: str | None, policy: str | None, detail: str, *, run_id: str, **extra) -> dict:
    return {
        **extra, "schema_version": EVIDENCE_VERSION, "subject_digest_format": SUBJECT_FORMAT,
        "run_id": run_id, "gate": gate, "execution": status,
        "kind": kind, "coverage_count": count, "findings": findings,
        "subject_digest": subject, "policy_digest": policy,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "detail": detail,
    }


def validate_policy(policy: dict) -> None:
    required = policy.get("required_gates")
    contracts = policy.get("gate_contracts")
    if (not isinstance(required, list) or not required or
            any(not isinstance(g, str) or not g for g in required) or
            len(set(required)) != len(required) or
            type(policy.get("max_evidence_age_seconds")) is not int or
            policy["max_evidence_age_seconds"] <= 0 or not isinstance(contracts, dict) or
            set(contracts) != set(required)):
        raise ValueError("invalid trusted policy")
    for contract in contracts.values():
        if not isinstance(contract, dict) or contract.get("kind") not in ("scan", "test"):
            raise ValueError("invalid gate contract")
        if contract["kind"] == "test":
            validate_cases([{"case": c, "passed": True} for c in contract.get("case_ids", [])], contract)
            seeded_defects(contract)


def seeded_defects(contract: dict) -> set[str]:
    """Exact cases the seeded vulnerable variant must fail; a count alone would let a
    regression trade one detected violation for another."""
    seeded = contract.get("seeded_defect_case_ids")
    if (not isinstance(seeded, list) or not seeded or
            any(not isinstance(x, str) or not x for x in seeded) or len(set(seeded)) != len(seeded) or
            not set(seeded) < set(contract.get("case_ids", []))):
        raise ValueError("invalid seeded defect manifest")
    return set(seeded)


def validate_cases(cases: list[dict], contract: dict) -> None:
    expected = contract.get("case_ids")
    if (not isinstance(expected, list) or not expected or
            any(not isinstance(x, str) or not x for x in expected) or
            len(set(expected)) != len(expected)):
        raise ValueError("invalid required case manifest")
    if (not isinstance(cases, list) or len(cases) != len(expected) or
            any(not isinstance(c, dict) or not isinstance(c.get("case"), str) or
                type(c.get("passed")) is not bool for c in cases)):
        raise ValueError("invalid case coverage")
    names = [c["case"] for c in cases]
    if len(set(names)) != len(names) or set(names) != set(expected):
        raise ValueError("missing, duplicate or unknown case ID")


def decide(records: list[dict], policy: dict, subject: str, policy_digest: str,
           now: datetime | None = None, *, run_id: str) -> dict:
    now = now or datetime.now(timezone.utc)
    reasons = []
    seen = set()
    try:
        validate_policy(policy)
    except (ValueError, TypeError, AttributeError):
        return {"decision": "BLOCK", "reasons": ["invalid trusted policy"]}
    required = policy["required_gates"]
    if not subject or not policy_digest or not isinstance(run_id, str) or not run_id:
        return {"decision": "BLOCK", "reasons": ["missing run or subject binding"]}
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
            valid = (type(record["schema_version"]) is int and record["schema_version"] == EVIDENCE_VERSION
                     and record["subject_digest_format"] == SUBJECT_FORMAT
                     and record["run_id"] == run_id
                     and record["subject_digest"] == subject
                     and record["policy_digest"] == policy_digest
                     and record["kind"] == policy["gate_contracts"][gate]["kind"]
                     and record["execution"] in ("COMPLETED", "ERROR", "TIMEOUT", "CANCELLED", "NOT_RUN")
                     and type(record["coverage_count"]) is int and record["coverage_count"] > 0
                     and type(record["findings"]) is int and record["findings"] >= 0)
            if not valid:
                raise ValueError("invalid contract")
            if policy['gate_contracts'][gate].get('coverage_required'):
                coverage = record['evidence']['coverage']
                counts = ('selected_files', 'selected_bytes', 'scanned_leaves', 'scanned_bytes',
                          'expanded_bytes', 'archives', 'history_blobs', 'unsupported_files')
                if (coverage['status'] != 'COMPLETE' or
                        any(type(coverage[key]) is not int or coverage[key] < 0 for key in counts) or
                        coverage['selected_files'] != record['coverage_count'] or coverage['unsupported_files'] != 0):
                    raise ValueError('incomplete scan coverage')
            if record["kind"] == "test":
                validate_cases(record["cases"], policy["gate_contracts"][gate])
                if (record["coverage_count"] != len(record["cases"]) or
                        record["findings"] != sum(not c["passed"] for c in record["cases"])):
                    raise ValueError("case summary mismatch")
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
    fd, temporary = tempfile.mkstemp(prefix=".report-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
