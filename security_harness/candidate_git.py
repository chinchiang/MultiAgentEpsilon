"""以標準函式庫操作不可信儲存庫，安裝前亦可使用。儲存庫設定屬候選資料；命令列 -c 優先覆寫，防止 fsmonitor、hooks、transport 執行程式，明確 git 目錄亦避免誤用外層儲存庫。

Git over untrusted repositories; stdlib only so pre-install scripts can use it.

Repository config is candidate data. Command-line `-c` outranks it, so programs it
names (fsmonitor, hooks, transports) never run, and the explicit git dir stops
discovery from reaching an enclosing repository.
"""
import os
import subprocess
from pathlib import Path

OVERRIDES = (
    "core.fsmonitor=false",
    "core.hooksPath=/dev/null",
    "core.untrackedCache=false",
    "protocol.allow=never",
    # 候選不可把提交中繼資料轉成掃描器讀不懂的編碼。 / The candidate cannot re-encode commit metadata away from the scanner.
    "i18n.logOutputEncoding=UTF-8",
)


def environment() -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_OPTIONAL_LOCKS="0",
               GIT_TERMINAL_PROMPT="0", GIT_NO_LAZY_FETCH="1", GIT_NO_REPLACE_OBJECTS="1",
               GIT_ATTR_NOSYSTEM="1", LC_ALL="C",
               # 候選的 .git/info/grafts 不能截斷要掃描的歷史。 / A candidate's .git/info/grafts cannot truncate scanned history.
               GIT_GRAFT_FILE=os.devnull)
    return env


def git_dir(root: Path) -> Path | None:
    """只接受候選自身的 .git 目錄；gitfile 與符號連結可能指向任意位置。

The candidate's own `.git` directory; gitfiles and symlinks could point anywhere."""
    dot = Path(root) / ".git"
    if not os.path.lexists(dot):
        return None
    if dot.is_symlink() or not dot.is_dir():
        raise ValueError("repository metadata must be a real .git directory")
    return dot


def command(root: Path, *args: str) -> list[str]:
    dot = git_dir(root)
    if dot is None:
        raise ValueError("no repository at input root")
    pairs = [part for item in OVERRIDES for part in ("-c", item)]
    return ["git", *pairs, "--git-dir", str(dot), "--work-tree", str(root), *args]


def run(root: Path, *args: str, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command(root, *args), env=environment(), **kwargs)


def head(root: Path) -> str:
    return run(root, "rev-parse", "--verify", "HEAD", capture_output=True, text=True,
               check=True, timeout=10).stdout.strip()
