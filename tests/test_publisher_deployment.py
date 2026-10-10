import hashlib
import io
import json
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

from scripts.prepare_publisher_deployment import prepare
from security_harness.results import subject_digest
from security_harness.trusted_publisher import Denied, validate_settings

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def evaluator(tmp_path):
    root = tmp_path / "evaluator"
    (root / "security").mkdir(parents=True)
    for name in ("policy.json", "trusted-publisher.example.json", "trust-policy.json"):
        shutil.copyfile(ROOT / "security" / name, root / "security" / name)
    (root / "README.md").write_text("synthetic deployment fixture\n")
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(["git", "-C", str(root), "-c", "user.name=Synthetic", "-c",
                    "user.email=synthetic@example.invalid", "commit", "-qm", "synthetic"], check=True)
    sha = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    return root, sha


def test_preparation_pins_exact_clean_tree_policy_and_archive_without_claiming_deployment(evaluator, tmp_path):
    root, sha = evaluator
    output = tmp_path / "bundle"
    report = prepare(root, output, sha, 42, 12)
    settings = json.loads((output / "publisher.json").read_text())
    policy = (output / "gate-policy.json").read_bytes()
    validate_settings(settings, json.loads(policy))
    assert settings["evaluator_sha"] == sha and settings["evaluator_digest"] == subject_digest(root)
    assert settings["policy_digest"] == hashlib.sha256(policy).hexdigest()
    assert report["configuration_complete"] and not report["deployed"] and not report["approval_verified"]
    with tarfile.open(fileobj=io.BytesIO((output / "app.tar").read_bytes())) as archive:
        assert sorted(archive.getnames()) == ["README.md", "security", "security/policy.json",
                                            "security/trust-policy.json", "security/trusted-publisher.example.json"]
    for line in (output / "SHA256SUMS").read_text().splitlines():
        expected, name = line.split("  ", 1)
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == expected


def test_missing_app_identifiers_stay_missing_and_live_configuration_is_rejected(evaluator, tmp_path):
    root, sha = evaluator
    output = tmp_path / "bundle"
    report = prepare(root, output, sha)
    assert report["missing"] == ["app_id", "installation_id"] and not report["configuration_complete"]
    with pytest.raises(Denied, match="SETTINGS_INCOMPLETE"):
        validate_settings(json.loads((output / "publisher.json").read_text()),
                          json.loads((output / "gate-policy.json").read_text()))


@pytest.mark.parametrize("attribute", ["export-ignore", "export-subst"])
def test_archive_attributes_cannot_change_the_pinned_deployment(evaluator, tmp_path, attribute):
    root, _ = evaluator
    (root / ".gitattributes").write_text("README.md " + attribute + "\n")
    (root / "README.md").write_text("$Format:%H$\n")
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(["git", "-C", str(root), "-c", "user.name=Synthetic", "-c",
                    "user.email=synthetic@example.invalid", "commit", "-qm", "archive attribute"], check=True)
    sha = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    with pytest.raises(Denied, match="ARCHIVE_MANIFEST"):
        prepare(root, tmp_path / "bundle", sha, 42, 12)


@pytest.mark.parametrize("attack", ["wrong_sha", "dirty", "untracked", "internal_output", "shared_app", "invalid_id",
                                    "policy_reviewers", "existing_output"])
def test_preparation_rejects_unsafe_inputs_without_overwriting_existing_files(evaluator, tmp_path, attack):
    root, sha = evaluator
    output = tmp_path / "bundle"
    app_id, installation_id = 42, 12
    if attack == "wrong_sha": sha = "a" * 40
    if attack == "dirty": (root / "README.md").write_text("changed")
    if attack == "untracked": (root / "surprise.py").write_text("raise RuntimeError('never execute')")
    if attack == "internal_output": output = root / "bundle"
    if attack == "shared_app": app_id = 15368
    if attack == "invalid_id": installation_id = -1
    if attack == "policy_reviewers":
        p = root / "security/trust-policy.json"
        policy = json.loads(p.read_text())
        policy["baseline_reviewers"] = ["other"]
        p.write_text(json.dumps(policy))
        subprocess.run(["git", "-C", str(root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(root), "-c", "user.name=Synthetic", "-c",
                        "user.email=synthetic@example.invalid", "commit", "-qm", "changed trust"], check=True)
        sha = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    if attack == "existing_output":
        output.mkdir()
        (output / "publisher.json").write_text("existing pin")
    with pytest.raises((Denied, FileExistsError)):
        prepare(root, output, sha, app_id, installation_id)
    if attack == "existing_output":
        assert (output / "publisher.json").read_text() == "existing pin"
    else:
        assert not output.exists()


def test_shared_lock_queues_then_reports_busy_instead_of_failing_immediately(tmp_path):
    import fcntl
    import os
    from scripts import publish_trusted_check as cli
    from security_harness.trusted_publisher import Denied
    path = tmp_path / 'publisher.lock'
    holder = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    waiter = os.open(path, os.O_RDWR)
    try:
        fcntl.flock(holder, fcntl.LOCK_EX)
        now = [0.0]
        released = []
        def sleep(seconds):
            now[0] += seconds
            if now[0] >= 5 and not released:
                fcntl.flock(holder, fcntl.LOCK_UN)
                released.append(True)
        cli.acquire_lock(waiter, wait=60, clock=lambda: now[0], sleep=sleep)
        assert released and now[0] < 60
        fcntl.flock(waiter, fcntl.LOCK_UN)
        fcntl.flock(holder, fcntl.LOCK_EX)
        now[0] = 0.0
        with pytest.raises(Denied, match='LOCK_BUSY'):
            cli.acquire_lock(waiter, wait=3, clock=lambda: now[0], sleep=lambda s: now.__setitem__(0, now[0] + s))
    finally:
        os.close(waiter)
        os.close(holder)


def test_timer_spreads_instances_and_unit_documents_python_requirement():
    base = Path(__file__).resolve().parents[1] / 'deploy/trusted-publisher'
    timer = (base / 'epsilon-publisher@.timer').read_text()
    service = (base / 'epsilon-publisher@.service').read_text()
    assert 'RandomizedDelaySec=' in timer
    assert 'ExecStart=/usr/bin/python3 -I ' in service and 'Python 3.12' in service
    assert service.count('--lock-file /var/lib/epsilon-publisher/publisher.lock') == 1
