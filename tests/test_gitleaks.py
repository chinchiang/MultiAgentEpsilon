import json
import secrets
import subprocess
from pathlib import Path

import pytest

from security_harness.secrets import scan

ROOT = Path(__file__).resolve().parents[1]
LOCK = json.loads((ROOT / "security/tools.lock.json").read_text())["gitleaks"]


def run(path, history=False):
    return scan(path, ROOT / ".tools/gitleaks", ROOT / "security/gitleaks.toml", LOCK["binary_sha256"], history=history)


def test_real_scanner_detects_then_clears_and_redacts(tmp_path):
    canary = "VIBE_TEST_" + "SECRET_" + secrets.token_hex(16)
    file = tmp_path / "settings.txt"
    file.write_text('credential="' + canary + '"\n')
    found = run(tmp_path)
    assert any(x["rule"] == "epsilon-acceptance-canary" for x in found["findings"])
    assert canary not in json.dumps(found)
    file.write_text("credential supplied at runtime\n")
    clean = run(tmp_path)
    assert clean["targets"] == 1 and clean["findings"] == []


def test_secret_removed_from_tree_still_found_in_history(tmp_path):
    def git(*args):
        subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True)
    git("init")
    git("config", "user.name", "Synthetic fixture")
    git("config", "user.email", "fixture@example.invalid")
    file = tmp_path / "settings.txt"
    file.write_text("VIBE_TEST_" + "SECRET_" + secrets.token_hex(16))
    git("add", ".")
    git("commit", "-m", "synthetic canary")
    file.write_text("redacted configuration")
    git("add", ".")
    git("commit", "-m", "remove canary")
    found = run(tmp_path, history=True)
    assert any(x["scope"] == "history" for x in found["findings"])


def test_missing_tampered_scanner_and_empty_scope_fail(tmp_path):
    with pytest.raises(ValueError):
        run(tmp_path)
    (tmp_path / "data").write_text("safe")
    with pytest.raises(ValueError):
        scan(tmp_path, ROOT / ".tools/gitleaks", ROOT / "security/gitleaks.toml", "incorrect")


def test_candidate_inline_allow_comment_cannot_suppress_canary(tmp_path):
    canary = "VIBE_TEST_" + "SECRET_" + secrets.token_hex(16)
    (tmp_path / "settings.py").write_text('token = "' + canary + '" # gitleaks:allow\n')
    assert len(run(tmp_path)["findings"]) == 1
