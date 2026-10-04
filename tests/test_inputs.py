import secrets
import subprocess
import os
import hashlib

import pytest
from security_harness.inputs import input_files
from security_harness.results import subject_digest
from tests.test_gitleaks import run


@pytest.mark.parametrize("name", ["artifacts", ".state", ".tools", ".venv", ".git"])
def test_nested_generated_name_is_real_input(tmp_path, name):
    path = tmp_path / "fixture_app" / name / "source.py"
    path.parent.mkdir(parents=True)
    path.write_text('token = "VIBE_TEST_' + 'SECRET_' + secrets.token_hex(16) + '"\n')
    before = subject_digest(tmp_path)
    assert path in input_files(tmp_path)
    assert len(run(tmp_path)["findings"]) == 1
    path.write_text("value = 1\n")
    assert subject_digest(tmp_path) != before
    assert run(tmp_path)["findings"] == []


def test_generated_root_does_not_change_subject(tmp_path):
    (tmp_path / "app.py").write_text("value = 1\n")
    before = subject_digest(tmp_path)
    (tmp_path / "artifacts").mkdir()
    (tmp_path / "artifacts/report.json").write_text('{}')
    assert subject_digest(tmp_path) == before


def test_symlink_directory_is_rejected(tmp_path):
    (tmp_path / "source").symlink_to(tmp_path.parent, target_is_directory=True)
    with pytest.raises(ValueError):
        subject_digest(tmp_path)


def test_tracked_reserved_input_is_not_silently_omitted(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "artifacts").mkdir()
    (tmp_path / "artifacts/app.py").write_text("value = 1")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    with pytest.raises(ValueError, match="reserved"):
        subject_digest(tmp_path)


def test_digest_frames_binary_contents_with_same_paths_and_count(tmp_path):
    left, right = tmp_path / "left", tmp_path / "right"
    left.mkdir(); right.mkdir()
    (left / "a").write_bytes(b"\0".join([b"x", b"b", b"0", b"y"]))
    (left / "b").write_bytes(b"z")
    (right / "a").write_bytes(b"x")
    (right / "b").write_bytes(b"\0".join([b"y", b"b", b"0", b"z"]))
    def legacy(root):
        data = b"".join(p.name.encode() + b"\x000\x00" + p.read_bytes() + b"\0"
                        for p in sorted(root.iterdir()))
        return hashlib.sha256(data).hexdigest()
    assert legacy(left) == legacy(right)  # This fixture exercised the old collision.
    assert subject_digest(left) != subject_digest(right)
    assert subject_digest(left).startswith("worktree-manifest-v1:sha256:")


def test_digest_binds_path_and_executable_mode(tmp_path):
    path = tmp_path / "a"
    path.write_text("same")
    first = subject_digest(tmp_path)
    path.chmod(0o755)
    assert subject_digest(tmp_path) != first
    second = subject_digest(tmp_path)
    path.rename(tmp_path / "b")
    assert subject_digest(tmp_path) != second


def test_unreadable_directory_blocks_inventory_digest_and_scan(tmp_path, monkeypatch):
    hidden = tmp_path / "hidden"
    hidden.mkdir()
    (hidden / "source.py").write_text("hidden source")
    hidden.chmod(0)
    real_scandir = os.scandir
    # Root can read mode 000; model the kernel denial there too, without skips.
    if os.geteuid() == 0:
        def scandir(path):
            if os.fspath(path) == str(hidden):
                raise PermissionError("synthetic inaccessible directory")
            return real_scandir(path)
        monkeypatch.setattr(os, "scandir", scandir)
    try:
        for operation in (input_files, subject_digest, run):
            with pytest.raises(PermissionError):
                operation(tmp_path)
    finally:
        hidden.chmod(0o700)
