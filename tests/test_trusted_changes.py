from scripts.check_trusted_changes import protected_changes
import json
import subprocess
import sys
from pathlib import Path


def test_candidate_cannot_silently_lower_policy_or_replace_evaluator():
    paths = ["security/policy.json", "security/gitleaks.toml", "scripts/run_security.py",
             "security_harness/results.py", ".github/workflows/security.yml",
             "requirements.lock", "fixture_app/app.py", "docs/README.md"]
    assert protected_changes(paths) == paths[:6]


def test_guard_retains_sha_bound_evidence_even_when_it_blocks(tmp_path):
    repo = tmp_path / "candidate"
    repo.mkdir()
    def git(*args):
        return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()
    git("init", "-q")
    git("config", "user.name", "Synthetic fixture")
    git("config", "user.email", "fixture@example.invalid")
    (repo / "README.md").write_text("baseline\n")
    git("add", ".")
    git("commit", "-qm", "baseline")
    base = git("rev-parse", "HEAD")
    output = tmp_path / "audit/trusted-guard.json"
    script = Path(__file__).resolve().parents[1] / "scripts/check_trusted_changes.py"
    command = [sys.executable, str(script), "--base", base, "--candidate", str(repo), "--output", str(output)]
    allowed = subprocess.run(command, capture_output=True)
    assert allowed.returncode == 0
    assert json.loads(output.read_text())["decision"] == "ALLOW"
    (repo / "security").mkdir()
    (repo / "security/policy.json").write_text('{}\n')
    git("add", ".")
    git("commit", "-qm", "policy change")
    blocked = subprocess.run(command, capture_output=True)
    evidence = json.loads(output.read_text())
    assert blocked.returncode == 1
    assert evidence["decision"] == "BLOCK"
    assert evidence["base_sha"] == base
    assert evidence["candidate_sha"] == git("rev-parse", "HEAD")
    assert evidence["protected_changes"] == ["security/policy.json"]
