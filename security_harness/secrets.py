"""Execute verified Gitleaks and retain only redacted, normalized findings."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from .results import digest_file

EXCLUDED = {".git", ".venv", ".tools", ".state", "artifacts", "__pycache__", ".pytest_cache"}


def scan(root: Path, binary: Path, config: Path, expected_hash: str, *, history=True) -> dict:
    if digest_file(binary) != expected_hash:
        raise ValueError("scanner integrity mismatch")
    paths = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if EXCLUDED.intersection(relative.parts):
            continue
        if path.is_symlink():
            raise ValueError("symlink scan scope needs explicit review")
        if path.is_file():
            if path.stat().st_size > 20 * 1024 * 1024:
                raise ValueError("oversize file would leave incomplete coverage")
            paths.append(path)
    if not paths or len(paths) > 20_000:
        raise ValueError("empty or excessive scan scope")
    findings = []
    scopes = ["worktree (explicit build/cache/state exclusions)"]
    with tempfile.TemporaryDirectory(prefix="epsilon-gitleaks-") as temp:
        temp = Path(temp)
        snapshot = temp / "snapshot"
        snapshot.mkdir()
        for path in paths:
            target = snapshot / path.relative_to(root)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
        commands = [["dir", str(snapshot)]]
        if history:
            head = subprocess.run(["git", "-C", str(root), "rev-parse", "--verify", "HEAD"], capture_output=True, timeout=10)
            if head.returncode == 0:
                shallow = subprocess.run(["git", "-C", str(root), "rev-parse", "--is-shallow-repository"], capture_output=True, text=True, check=True, timeout=10)
                if shallow.stdout.strip() != "false":
                    raise ValueError("shallow repository cannot establish history coverage")
                commands.append(["git", str(root), "--log-opts=--all"])
                scopes.append("all locally available Git refs; remote dangling objects not covered")
            else:
                scopes.append("history NOT_AVAILABLE: unborn repository")
        else:
            scopes.append("history NOT_REQUESTED: synthetic acceptance fixture")
        for i, command in enumerate(commands):
            report = temp / f"scan-{i}.json"
            run = subprocess.run([str(binary), *command, "--config", str(config), "--redact=100",
                                  "--no-banner", "--report-format=json", "--report-path", str(report)],
                                 capture_output=True, timeout=90)
            if run.returncode not in (0, 1) or not report.exists():
                raise RuntimeError("scanner did not produce a valid report")
            records = json.loads(report.read_text())
            if not isinstance(records, list) or bool(records) != (run.returncode == 1):
                raise ValueError("scanner exit code/report mismatch")
            for item in records:
                if not isinstance(item, dict) or not item.get("RuleID") or not item.get("File"):
                    raise ValueError("malformed scanner finding")
                name = item["File"].removeprefix(str(snapshot) + "/")
                findings.append({"rule": item["RuleID"], "file": name,
                                 "line": item.get("StartLine"), "scope": "worktree" if i == 0 else "history"})
    return {"targets": len(paths), "findings": findings, "scopes": scopes,
            "scanner": "gitleaks", "redacted": True}
