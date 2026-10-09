import subprocess
from pathlib import Path

import pytest
from security_harness import candidate_git
from security_harness.inputs import input_files
from security_harness.secrets import history_blobs

ROOT = Path(__file__).resolve().parents[1]


def git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def repository(path):
    path.mkdir(parents=True, exist_ok=True)
    git(path, "init", "-q")
    git(path, "config", "user.email", "fixture@example.invalid")
    git(path, "config", "user.name", "Fixture")
    (path / "app.py").write_text("print('synthetic')\n")
    git(path, "add", ".")
    git(path, "commit", "-qm", "fixture")
    return path


@pytest.mark.parametrize("key", ["core.fsmonitor", "core.hooksPath"])
def test_candidate_repository_config_never_runs_host_programs(tmp_path, key):
    repo = repository(tmp_path / "candidate")
    marker = tmp_path / "executed"
    hook = tmp_path / "hook"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\nexit 1\n")
    hook.chmod(0o755)
    if key == "core.hooksPath":
        hooks = tmp_path / "hooks"
        hooks.mkdir()
        for name in ("post-index-change", "reference-transaction", "post-checkout"):
            (hooks / name).write_bytes(hook.read_bytes())
            (hooks / name).chmod(0o755)
        git(repo, "config", key, str(hooks))
    else:
        git(repo, "config", key, str(hook))
    # 對照：強化前的命令會執行儲存庫設定指定的程式。 / Control: the unhardened command used before would execute the configured program.
    if key == "core.fsmonitor":
        subprocess.run(["git", "-C", str(repo), "ls-files", "-z"], capture_output=True)
        assert marker.exists()
        marker.unlink()
    input_files(repo)
    head, blobs = history_blobs(repo, required=True)
    assert head == candidate_git.head(repo) and blobs
    assert not marker.exists()


def test_inherited_git_environment_cannot_redirect_the_repository(tmp_path, monkeypatch):
    repo = repository(tmp_path / "candidate")
    other = repository(tmp_path / "other")
    (other / "extra.py").write_text("x = 1\n")
    git(other, "add", ".")
    git(other, "commit", "-qm", "other")
    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(other))
    assert candidate_git.head(repo) != candidate_git.head(other)


def test_nested_directory_does_not_inherit_enclosing_repository_history(tmp_path):
    outer = repository(tmp_path / "outer")
    nested = outer / "candidate"
    nested.mkdir()
    (nested / "app.py").write_text("print('nested')\n")
    assert history_blobs(nested) == (None, [])
    with pytest.raises(ValueError, match="not a repository"):
        history_blobs(nested, required=True)


def test_repository_without_commits_cannot_claim_required_history(tmp_path):
    repo = tmp_path / "candidate"
    repo.mkdir()
    git(repo, "init", "-q")
    (repo / "app.py").write_text("print('synthetic')\n")
    assert history_blobs(repo) == (None, [])
    with pytest.raises(ValueError, match="no commits"):
        history_blobs(repo, required=True)


@pytest.mark.parametrize("kind", ["gitfile", "symlink"])
def test_redirected_repository_metadata_is_refused(tmp_path, kind):
    other = repository(tmp_path / "other")
    repo = tmp_path / "candidate"
    repo.mkdir()
    (repo / "app.py").write_text("print('synthetic')\n")
    if kind == "gitfile":
        (repo / ".git").write_text(f"gitdir: {other / '.git'}\n")
    else:
        (repo / ".git").symlink_to(other / ".git")
    for call in (lambda: input_files(repo), lambda: history_blobs(repo), lambda: candidate_git.head(repo)):
        with pytest.raises(ValueError, match="real .git directory"):
            call()


def test_every_candidate_git_call_uses_the_hardened_helper():
    sources = [*ROOT.glob("security_harness/*.py"), *ROOT.glob("scripts/*.py")]
    offenders = [p.relative_to(ROOT).as_posix() for p in sources
                 if p.name != "candidate_git.py" and ('["git"' in p.read_text() or "['git'" in p.read_text())]
    assert offenders == []
