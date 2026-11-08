import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from scripts import bootstrap, preflight, run_security
from security_harness import isolation
from security_harness.audit import AuditRun

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
    audit = AuditRun(tmp_path, "security")
    run_security.plan(audit, tmp_path, "fixed")
    monkeypatch.setattr(run_security, "verify", lambda *a: ["synthetic"])
    monkeypatch.setattr(run_security, "dependency_scan", lambda *a: {"findings": [], "sbom": {}})
    monkeypatch.setattr(run_security, "scan", lambda *a, **k: {"targets": 1, "findings": []})
    monkeypatch.setattr(isolation, "cleanup_run", lambda *a: None)
    with patch.object(run_security.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps({"cases": cases, "isolation": {}}), "")):
        assert run_security.main(audit) == 1
    data = report(tmp_path)
    assert data["decision"] == "BLOCK"
    assert data["records"][-1]["execution"] == "ERROR"


@pytest.mark.parametrize("changed", ["roe.json", "policy.json", "tools.lock.json"])
def test_configuration_changed_after_planning_blocks_before_any_gate(tmp_path, monkeypatch, changed):
    # 換行不影響 JSON 或 RoE 是否合法，只改變雜湊；tools.lock.json 只屬於評估者摘要。 / A trailing newline keeps the
    # JSON and the RoE valid and changes only the digest; tools.lock.json is covered by the evaluator digest alone.
    root = fixture_root(tmp_path)
    monkeypatch.setattr(run_security, "ROOT", root)
    audit = AuditRun(root, "security")
    run_security.plan(audit, root, "fixed")
    target = root / "security" / changed
    target.write_bytes(target.read_bytes() + b"\n")
    assert run_security.main(audit) == 1
    data = report(root)
    assert data["decision"] == "BLOCK" and data["execution"] == "ERROR"
    assert data["errors"] == [{"stage": "configuration", "error_type": "PlanMismatch"}]
    assert all(r["execution"] == "NOT_RUN" for r in data["records"])


@pytest.mark.parametrize("field", ["roe_sha256", "policy_digest"])
def test_plan_naming_other_configuration_bytes_blocks_before_any_gate(tmp_path, monkeypatch, field):
    # 評估者摘要仍相符，但 supervisor 規劃時讀到的位元組與 worker 讀到的不同（檔案在兩次讀取之間被換掉）。 / The
    # evaluator digest still matches, but the bytes the supervisor planned with differ from those the worker reads
    # (the file was swapped between the two reads).
    root = fixture_root(tmp_path)
    monkeypatch.setattr(run_security, "ROOT", root)
    audit = AuditRun(root, "security")
    run_security.plan(audit, root, "fixed")
    audit.data[field] = "0" * 64
    assert run_security.main(audit) == 1
    data = report(root)
    assert data["errors"] == [{"stage": "configuration", "error_type": "PlanMismatch"}]
    assert all(r["execution"] == "NOT_RUN" for r in data["records"])


@pytest.mark.parametrize("module", [run_security, bootstrap, preflight])
def test_invalid_configuration_retains_redacted_early_evidence(tmp_path, monkeypatch, module):
    fixture_root(tmp_path)
    for name in ("roe.json", "policy.json"):
        (tmp_path / "security" / name).write_text('{"secret": "never-print-this"')
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(sys, "argv", ["command"])
    # run_security 在規劃時讀取設定；worker 的 main 只接受已規劃的執行。 / run_security reads its configuration while
    # planning; the worker's main only accepts a planned run.
    entry = module.supervised_main if module is run_security else module.main
    assert entry() != 0
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
    assert bootstrap.main([]) == 1
    assert report(tmp_path)["errors"][0]["error_type"] == "KeyboardInterrupt"


def test_timeout_cleans_owned_isolation_and_records_timeout(tmp_path, monkeypatch):
    monkeypatch.setattr(run_security, "ROOT", fixture_root(tmp_path))
    audit = AuditRun(tmp_path, "security")
    run_security.plan(audit, tmp_path, "fixed")
    monkeypatch.setattr(run_security, "verify", lambda *a: ["synthetic"])
    monkeypatch.setattr(run_security, "dependency_scan", lambda *a: {"findings": [], "sbom": {}})
    monkeypatch.setattr(run_security, "scan", lambda *a, **k: {"targets": 1, "findings": []})
    cleaned = []
    monkeypatch.setattr(isolation, "cleanup_run", cleaned.append)
    with patch.object(run_security.subprocess, "run", side_effect=subprocess.TimeoutExpired("worker", 120)):
        assert run_security.main(audit) == 1
    data = report(tmp_path)
    assert cleaned == [data["run_id"]]
    assert data["records"][-1]["execution"] == "TIMEOUT"


def test_bootstrap_known_vulnerability_blocks_before_installation(tmp_path, monkeypatch):
    monkeypatch.setattr(bootstrap, 'ROOT', fixture_root(tmp_path))
    monkeypatch.setattr(bootstrap, 'verify', lambda *a: [{'name': 'example', 'version': '1.0'}])
    monkeypatch.setattr(bootstrap, 'dependency_scan', lambda *a: {
        'sbom': {}, 'findings': [{'advisory_id': 'CVE-2026-12345'}]})
    def forbidden(*args, **kwargs):
        raise AssertionError('installation must not start')
    monkeypatch.setattr(bootstrap.subprocess, 'run', forbidden)
    assert bootstrap.main([]) == 1
    data = report(tmp_path)
    assert data['decision'] == 'BLOCK' and data['stage'] == 'G1'
    assert data['records'][0]['gate'] == 'G1' and data['records'][0]['findings'] == 1
    assert not (tmp_path / '.venv').exists()


def test_bootstrap_partial_query_keeps_error_and_findings_without_installing(tmp_path, monkeypatch):
    from security_harness.dependencies import DependencyError
    monkeypatch.setattr(bootstrap, 'ROOT', fixture_root(tmp_path))
    monkeypatch.setattr(bootstrap, 'verify', lambda *a: [{'name': 'example', 'version': '1.0'}])
    partial = {'status': 'INCOMPLETE', 'sbom': {}, 'findings': [{'advisory_id': 'CVE-2026-12345'}],
               'queries': [{'status': 'ERROR', 'error_type': 'TimeoutError'}]}
    def incomplete(*args):
        raise DependencyError('incomplete query', partial)
    monkeypatch.setattr(bootstrap, 'dependency_scan', incomplete)
    assert bootstrap.main([]) == 1
    data = report(tmp_path)
    assert data['records'][0]['execution'] == 'ERROR' and data['records'][0]['findings'] == 1
    assert data['records'][0]['sca']['queries'][0]['error_type'] == 'TimeoutError'
    assert not (tmp_path / '.venv').exists()


def test_ci_provenance_is_built_once_for_writer_and_self_check():
    from scripts import check_publishable_evidence, write_ci_provenance
    root = Path(__file__).resolve().parents[1]
    environ = {"GITHUB_REPOSITORY": "owner/repo", "GITHUB_REPOSITORY_ID": "10", "GITHUB_RUN_ID": "20",
               "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "pull_request_target",
               "GITHUB_WORKFLOW_REF": "owner/repo/.github/workflows/security.yml@refs/heads/main",
               "GITHUB_WORKFLOW_SHA": "a" * 40, "PR_NUMBER": "7"}
    value = write_ci_provenance.provenance(root, root, environ)
    assert value["base_sha"] == value["candidate_sha"] and len(value["base_sha"]) == 40
    assert value["pr_number"] == 7 and value["run_id"] == 20
    assert check_publishable_evidence.ci_provenance is write_ci_provenance.provenance


@pytest.mark.parametrize("stdout, expected", [
    ('{"error_type": "IsolationMismatch", "failed_checks": ["network", "tmpfs"]}',
     {"error_type": "IsolationMismatch", "failed_checks": ["network", "tmpfs"]}),
    ('{"error_type": "CalledProcessError", "failed_checks": []}', {"error_type": "CalledProcessError", "failed_checks": []}),
    # 夾帶例外文字或 DSN 的欄位一律丟棄。 / Anything carrying exception text or a DSN is dropped.
    ('{"error_type": "postgresql://user:pw@host", "failed_checks": []}', {"error_type": "Unknown", "failed_checks": []}),
    ('{"error_type": "OSError", "failed_checks": ["Permission denied: /secret"]}', {"error_type": "OSError", "failed_checks": []}),
    ('Traceback (most recent call last)', {"error_type": "Unknown", "failed_checks": []}),
    ('["IsolationMismatch"]', {"error_type": "Unknown", "failed_checks": []}),
    ('{"error_type": "A", "failed_checks": []}' + " " * 5000, {"error_type": "Unknown", "failed_checks": []}),
])
def test_worker_failure_keeps_only_identifier_shaped_fields(stdout, expected):
    assert run_security.worker_failure(stdout) == expected


def test_failed_authorization_worker_records_its_error_type_and_failed_checks(tmp_path, monkeypatch):
    monkeypatch.setattr(run_security, "ROOT", fixture_root(tmp_path))
    audit = AuditRun(tmp_path, "security")
    run_security.plan(audit, tmp_path, "fixed")
    monkeypatch.setattr(run_security, "verify", lambda *a: ["synthetic"])
    monkeypatch.setattr(run_security, "dependency_scan", lambda *a: {"findings": [], "sbom": {}})
    monkeypatch.setattr(run_security, "scan", lambda *a, **k: {"targets": 1, "findings": []})
    monkeypatch.setattr(isolation, "cleanup_run", lambda *a: None)
    failure = json.dumps({"error_type": "IsolationMismatch", "failed_checks": ["mounts"]})
    with patch.object(run_security.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, failure, "")):
        assert run_security.main(audit) == 1
    record = report(tmp_path)["records"][-1]
    assert record["gate"] == "AUTH" and record["execution"] == "ERROR"
    assert record["detail"] == "AuthorizationWorkerFailed"
    assert record["worker_failure"] == {"error_type": "IsolationMismatch", "failed_checks": ["mounts"]}


def test_isolation_worker_reports_failed_checks_as_json(tmp_path):
    process = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/isolation_worker.py"), str(tmp_path), "bogus", "x"],
                             capture_output=True, text=True, timeout=30)
    assert process.returncode == 1
    assert json.loads(process.stdout) == {"error_type": "ValueError", "failed_checks": []}
