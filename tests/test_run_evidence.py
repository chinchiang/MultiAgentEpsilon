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
    with patch.object(run_security, "run_isolation_worker", return_value=subprocess.CompletedProcess([], 0, json.dumps({"cases": cases, "isolation": {}}), "")):
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
    with patch.object(run_security, "run_isolation_worker", side_effect=subprocess.TimeoutExpired("worker", 120)):
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
    with patch.object(run_security, "run_isolation_worker", return_value=subprocess.CompletedProcess([], 1, failure, "")):
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


def test_timed_out_isolation_worker_takes_its_children_with_it(tmp_path):
    # 先前 subprocess.run 逾時只殺直接子程序，docker CLI 孫程序仍會在清理後建立容器。 / A timeout used to kill only the
    # direct child; its docker CLI grandchildren could still create containers after cleanup.
    marker = tmp_path / "grandchild.pid"
    script = ("import subprocess,sys,time;"
              f"p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']);"
              f"open({str(marker)!r},'w').write(str(p.pid));time.sleep(60)")
    with pytest.raises(subprocess.TimeoutExpired):
        run_security.run_isolation_worker([sys.executable, "-c", script], 1)
    grandchild = int(marker.read_text())
    import os
    import time
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            os.kill(grandchild, 0)
        except ProcessLookupError:
            break
        state = Path(f"/proc/{grandchild}/stat").read_text().rsplit(")", 1)[1].split()[0] if Path(f"/proc/{grandchild}").exists() else "X"
        if state == "Z":
            break
        time.sleep(0.05)
    else:
        pytest.fail("grandchild survived the timeout")


def test_isolation_worker_output_is_returned_when_it_finishes():
    done = run_security.run_isolation_worker([sys.executable, "-c", "print('ok')"], 10)
    assert (done.returncode, done.stdout) == (0, "ok\n")


class LateDocker:
    """第一次清理後才出現另一個容器的 docker 假實作。 / A fake docker where a second container appears after the
    first sweep."""

    def __init__(self, rounds):
        self.rounds = list(rounds)
        self.removed = []

    def __call__(self, *args, check=True, timeout=45):
        if args[:2] == ("ps", "-aq"):
            out = "".join(i + "\n" for i in (self.rounds.pop(0) if self.rounds else []))
        elif args[:2] == ("rm", "--force"):
            self.removed.extend(args[2:])
            out = ""
        else:
            pytest.fail("unexpected docker call: " + " ".join(args))
        return subprocess.CompletedProcess(args, 0, out, "")


def test_cleanup_repeats_until_no_container_of_the_run_remains(monkeypatch):
    fake = LateDocker([["first"], ["late"], []])
    monkeypatch.setattr(isolation, "docker", fake)
    monkeypatch.setattr(isolation, "CLEANUP_INTERVAL", 0)
    monkeypatch.setattr(isolation, "CLEANUP_SETTLE", 0)
    isolation.cleanup_run("a" * 32)
    assert fake.removed == ["first", "late"]


def test_cleanup_waits_for_a_settled_empty_listing(monkeypatch):
    # 先前第一次列出空清單就返回；被終止的 docker CLI 稍後才建立的容器會被遺留。 / Cleanup used to return on the first
    # empty listing, leaking a container that a terminated docker CLI created a moment later.
    fake = LateDocker([[], ["late"], [], []])
    monkeypatch.setattr(isolation, "docker", fake)
    monkeypatch.setattr(isolation, "CLEANUP_INTERVAL", 0)
    monkeypatch.setattr(isolation, "CLEANUP_SETTLE", 0)
    isolation.cleanup_run("a" * 32)
    assert fake.removed == ["late"]
    assert fake.rounds == []


def test_cleanup_sleeps_between_empty_listings(monkeypatch):
    fake = LateDocker([])
    slept = []
    monkeypatch.setattr(isolation, "docker", fake)
    monkeypatch.setattr(isolation.time, "sleep", slept.append)
    isolation.cleanup_run("a" * 32)
    assert slept == [isolation.CLEANUP_SETTLE] and isolation.CLEANUP_SETTLE >= 1


def test_security_release_relies_on_the_settling_cleanup(tmp_path):
    from security_harness.lifecycle import SecurityContainers
    calls = []
    SecurityContainers(tmp_path, "a" * 32, calls.append).release("a" * 32)
    assert calls == ["a" * 32]


def test_cleanup_fails_when_containers_keep_appearing(monkeypatch):
    fake = LateDocker([["again"]] * 10)
    monkeypatch.setattr(isolation, "docker", fake)
    monkeypatch.setattr(isolation, "CLEANUP_INTERVAL", 0)
    monkeypatch.setattr(isolation, "CLEANUP_SETTLE", 0)
    with pytest.raises(RuntimeError, match="isolated containers remain after cleanup"):
        isolation.cleanup_run("a" * 32)


def _gone(pid):
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
    except FileNotFoundError:
        return True
    return state == "Z"


def test_supervised_isolation_worker_is_registered_and_stopped_with_the_run(tmp_path, monkeypatch):
    # 先前 worker 從未登記，supervisor 逾時或取消時 stop_registered 看不到它，worker 與 docker CLI 成為孤兒。 /
    # The worker used to be unregistered: on a supervisor timeout or cancel, stop_registered could not see it and the
    # worker and its docker CLI were orphaned.
    import shutil
    import threading
    import uuid
    from security_harness import supervision
    monkeypatch.setattr(run_security, "ROOT", tmp_path)
    run_id = str(uuid.uuid4())
    work = supervision.prepare_run(tmp_path, run_id, "security")
    marker = tmp_path / "worker.pid"
    script = ("import os,subprocess,sys,time;"
              "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']);"
              f"open({str(marker)!r},'w').write(str(os.getpid())+' '+str(p.pid));time.sleep(60)")
    outcome = {}

    def run():
        try:
            outcome["done"] = run_security.run_isolation_worker([sys.executable, "-c", script], 30, run_id)
        except BaseException as exc:  # noqa: BLE001 - 交回主執行緒檢查。 / Handed back to the main thread.
            outcome["error"] = exc

    thread = threading.Thread(target=run)
    thread.start()
    try:
        import time
        deadline = time.monotonic() + 10
        while not marker.exists() or " " not in marker.read_text():
            assert time.monotonic() < deadline, "worker never started"
            time.sleep(0.02)
        worker, grandchild = map(int, marker.read_text().split())
        assert (work / "groups" / f"{worker}.json").exists()
        supervision.stop_registered(work)
        thread.join(10)
        assert not thread.is_alive()
        assert outcome["done"].returncode != 0
        assert _gone(worker) and _gone(grandchild)
    finally:
        thread.join(10)
        shutil.rmtree(supervision.temporary_directory(run_id), ignore_errors=True)


def test_unsupervised_isolation_worker_runs_without_registration(tmp_path, monkeypatch):
    import uuid
    monkeypatch.setattr(run_security, "ROOT", tmp_path)
    done = run_security.run_isolation_worker([sys.executable, "-c", "print('ok')"], 10, str(uuid.uuid4()))
    assert (done.returncode, done.stdout) == (0, "ok\n")
    assert not (tmp_path / ".state").exists()


def test_isolation_worker_never_runs_when_registration_fails(tmp_path, monkeypatch):
    import shutil
    import uuid
    from security_harness import supervision
    monkeypatch.setattr(run_security, "ROOT", tmp_path)
    run_id = str(uuid.uuid4())
    supervision.prepare_run(tmp_path, run_id, "security")
    marker = tmp_path / "ran"

    def refuse(*args, **kwargs):
        raise ValueError("invalid run owner")

    monkeypatch.setattr(supervision, "register_group", refuse)
    try:
        with pytest.raises(ValueError, match="^invalid run owner$"):
            run_security.run_isolation_worker([sys.executable, "-c", f"open({str(marker)!r},'w')"], 10, run_id)
        assert not marker.exists()
    finally:
        shutil.rmtree(supervision.temporary_directory(run_id), ignore_errors=True)


def test_bridge_deadline_in_the_authorization_worker_is_recorded_as_a_timeout(tmp_path, monkeypatch):
    # 橋接逾時是基礎設施逾時，不是一般錯誤，也不是證據不符。 / A bridge deadline is an infrastructure timeout, not a
    # generic error and not mismatched evidence.
    monkeypatch.setattr(run_security, "ROOT", fixture_root(tmp_path))
    audit = AuditRun(tmp_path, "security")
    run_security.plan(audit, tmp_path, "fixed")
    monkeypatch.setattr(run_security, "verify", lambda *a: ["synthetic"])
    monkeypatch.setattr(run_security, "dependency_scan", lambda *a: {"findings": [], "sbom": {}})
    monkeypatch.setattr(run_security, "scan", lambda *a, **k: {"targets": 1, "findings": []})
    monkeypatch.setattr(isolation, "cleanup_run", lambda *a: None)
    failure = json.dumps({"error_type": "DeadlineExceeded", "failed_checks": []})
    with patch.object(run_security, "run_isolation_worker", return_value=subprocess.CompletedProcess([], 1, failure, "")):
        assert run_security.main(audit) == 1
    data = report(tmp_path)
    record = data["records"][-1]
    assert (record["gate"], record["execution"], record["coverage_count"]) == ("AUTH", "TIMEOUT", 0)
    assert record["worker_failure"] == {"error_type": "DeadlineExceeded", "failed_checks": []}
    assert data["decision"] == "BLOCK" and "AUTH: TIMEOUT" in data["reasons"]
    assert not any("AUTH: invalid" in reason for reason in data["reasons"])
