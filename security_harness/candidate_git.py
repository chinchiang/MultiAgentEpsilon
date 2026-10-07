"""Git over untrusted repositories; stdlib only so pre-install scripts can use it.

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
)


def environment() -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_OPTIONAL_LOCKS="0",
               GIT_TERMINAL_PROMPT="0", GIT_NO_LAZY_FETCH="1", GIT_NO_REPLACE_OBJECTS="1",
               GIT_ATTR_NOSYSTEM="1", LC_ALL="C")
    return env


def git_dir(root: Path) -> Path | None:
    """The candidate's own `.git` directory; gitfiles and symlinks could point anywhere."""
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
