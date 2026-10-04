"""Execute verified Gitleaks and retain only redacted, normalized findings."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from .results import digest_file
from .inputs import input_files


def scan(root: Path, binary: Path, config: Path, expected_hash: str, *, history=True) -> dict:
    if digest_file(binary) != expected_hash:
        raise ValueError("scanner integrity mismatch")
    paths = input_files(root)
    if any(path.stat().st_size > 20 * 1024 * 1024 for path in paths):
        raise ValueError("oversize file would leave incomplete coverage")
    if not paths or len(paths) > 20_000:
        raise ValueError("empty or excessive scan scope")
    findings = []
    scopes = ["worktree (explicit build/cache/state exclusions)"]
    with tempfile.TemporaryDirectory(prefix="epsilon-gitleaks-") as temp:
        temp = Path(temp)
        snapshot = temp / "snapshot"
        snapshot.mkdir()
        names = {}
        for index, path in enumerate(paths):
            # Scanner-internal .git / ignore-file rules must not shrink our scope.
            target = snapshot / f"input-{index:06d}.txt"
            names[target.name] = path.relative_to(root).as_posix()
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
                                  "--ignore-gitleaks-allow",
                                  "--gitleaks-ignore-path", str(temp),
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
                if i == 0:
                    name = names[Path(name).name]
                findings.append({"rule": item["RuleID"], "file": name,
                                 "line": item.get("StartLine"), "scope": "worktree" if i == 0 else "history"})
    return {"targets": len(paths), "findings": findings, "scopes": scopes,
            "scanner": "gitleaks", "redacted": True}
