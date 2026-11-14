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


def test_forged_commit_graph_cannot_hide_history_from_the_scan(tmp_path):
    # git 預設信任 commit-graph 記的父 commit，不與 commit 物件核對；候選可藉此讓舊提交的內容不被列出。 /
    # Git trusts the parents recorded in the commit-graph without checking the commit objects, so a candidate
    # could hide what earlier commits contained.
    import struct
    repo = repository(tmp_path / "repo")
    (repo / "old.txt").write_text("removed-later\n")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "adds old.txt")
    git(repo, "rm", "-q", "old.txt")
    git(repo, "commit", "-qm", "removes old.txt")
    git(repo, "commit-graph", "write", "--reachable")
    graph = repo / ".git/objects/info/commit-graph"
    data = bytearray(graph.read_bytes())
    assert data[:4] == b"CGPH" and data[5] == 1, "SHA-1 commit-graph expected"
    chunks = {bytes(data[8 + 12 * i:12 + 12 * i]): struct.unpack(">Q", data[12 + 12 * i:20 + 12 * i])[0]
              for i in range(data[6] + 1)}
    lookup, commits = chunks[b"OIDL"], chunks[b"CDAT"]
    oids = [bytes(data[lookup + 20 * i:lookup + 20 * i + 20]).hex() for i in range((commits - lookup) // 20)]
    entry = commits + oids.index(candidate_git.head(repo)) * 36
    data[entry + 20:entry + 24] = struct.pack(">I", 0x70000000)  # 「沒有父 commit」 / "no parent"
    # git 把 commit-graph 寫成唯讀；非 root 執行（如 CI runner）須先開寫入權限才能竄改。 / Git writes the
    # commit-graph read-only, so a non-root run (a CI runner, say) must make it writable before tampering.
    graph.chmod(0o644)
    graph.write_bytes(bytes(data))
    # 未加防護的 git 2.43 實測會漏掉 old.txt；較新的版本若自行核對或拒絕這份檔案也無妨，所以這裡不作斷言。 /
    # An unhardened git 2.43 was observed to drop old.txt; a newer one that checks or rejects the file is fine
    # too, so nothing is asserted about it here.
    subprocess.run(["git", "-C", str(repo), "rev-list", "--objects", "HEAD"], capture_output=True)
    # 加固後的呼叫不讀 commit-graph，任何版本都必須列出舊提交的檔案。 / The hardened call never reads the
    # commit-graph, so on every version it must list the earlier commit's file.
    assert "core.commitGraph=false" in candidate_git.command(repo, "rev-list")
    _, blobs = history_blobs(repo, required=True)
    assert any(name == "old.txt" for _, name, _ in blobs)
