import secrets
import subprocess

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
