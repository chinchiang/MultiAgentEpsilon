import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from scripts import bootstrap, preflight, run_security
from security_harness import isolation

ROOT = Path(__file__).resolve().parents[1]


def fixture_root(tmp_path):
    (tmp_path / "security").mkdir()
    for name in ("roe.json", "policy.json", "tools.lock.json"):
        (tmp_path / "security" / name).write_bytes((ROOT / "security" / name).read_bytes())
    return tmp_path


def report(root):
    reports = list((root / "artifacts").glob("*/report.json"))
    assert len(reports) == 1
    return json.loads(reports[0].read_text())


@pytest.mark.parametrize("cases", [[{"case": "fake", "passed": True}], [{"case": "fake", "passed": True}] * 14])
def test_orchestrator_blocks_incomplete_worker_output(tmp_path, monkeypatch, cases):
    monkeypatch.setattr(run_security, "ROOT", fixture_root(tmp_path))
    monkeypatch.setattr(sys, "argv", ["run_security"])
    monkeypatch.setattr(run_security, "verify", lambda *a: ["synthetic"])
    monkeypatch.setattr(run_security, "scan", lambda *a: {"targets": 1, "findings": []})
    monkeypatch.setattr(isolation, "cleanup_run", lambda *a: None)
    with patch.object(run_security.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps({"cases": cases, "isolation": {}}), "")):
        assert run_security.main() == 1
    data = report(tmp_path)
    assert data["decision"] == "BLOCK"
    assert data["records"][-1]["execution"] == "ERROR"


@pytest.mark.parametrize("module", [run_security, bootstrap, preflight])
def test_invalid_configuration_retains_redacted_early_evidence(tmp_path, monkeypatch, module):
    fixture_root(tmp_path)
    for name in ("roe.json", "policy.json"):
        (tmp_path / "security" / name).write_text('{"secret": "never-print-this"')
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(sys, "argv", ["command"])
    assert module.main() != 0
    data = report(tmp_path)
    assert data["decision"] == "BLOCK" and data["execution"] == "ERROR"
    assert data["subject_digest"] is None
    assert data["errors"][0]["error_type"] == "JSONDecodeError"
    assert all(r["execution"] == "NOT_RUN" for r in data["records"])
    assert "never-print-this" not in json.dumps(data)


def test_cancellation_retains_incomplete_gates(tmp_path, monkeypatch):
    monkeypatch.setattr(bootstrap, "ROOT", tmp_path)
    def interrupt(audit):
        raise KeyboardInterrupt()
    monkeypatch.setattr(bootstrap, "install", interrupt)
    assert bootstrap.main() == 1
    assert report(tmp_path)["errors"][0]["error_type"] == "KeyboardInterrupt"


def test_timeout_cleans_owned_isolation_and_records_timeout(tmp_path, monkeypatch):
    monkeypatch.setattr(run_security, "ROOT", fixture_root(tmp_path))
    monkeypatch.setattr(sys, "argv", ["run_security"])
    monkeypatch.setattr(run_security, "verify", lambda *a: ["synthetic"])
    monkeypatch.setattr(run_security, "scan", lambda *a: {"targets": 1, "findings": []})
    cleaned = []
    monkeypatch.setattr(isolation, "cleanup_run", cleaned.append)
    with patch.object(run_security.subprocess, "run", side_effect=subprocess.TimeoutExpired("worker", 120)):
        assert run_security.main() == 1
    data = report(tmp_path)
    assert cleaned == [data["run_id"]]
    assert data["records"][-1]["execution"] == "TIMEOUT"
