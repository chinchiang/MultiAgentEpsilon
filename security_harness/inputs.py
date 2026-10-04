"""One worktree scope for scanning and subject binding; never follow symlinks."""
import os
import subprocess
from pathlib import Path

ROOT_GENERATED = {".git", ".venv", ".tools", ".state", "artifacts", ".pytest_cache"}
CACHES = {"__pycache__", ".pytest_cache"}


def excluded(relative: Path) -> bool:
    return relative.parts[0] in ROOT_GENERATED or any(p in CACHES for p in relative.parts)


def input_files(root: Path) -> list[Path]:
    # A tracked file in a reserved generated area is not silently omitted.
    if (root / ".git").exists():
        tracked = subprocess.run(["git", "-C", str(root), "ls-files", "-z"],
                                 capture_output=True, check=True, timeout=10)
        if any(excluded(Path(n)) for n in tracked.stdout.decode().split("\0") if n):
            raise ValueError("tracked input uses a reserved generated path")
    paths = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        parent = Path(directory)
        for name in list(dirs) + files:
            path = parent / name
            relative = path.relative_to(root)
            if excluded(relative):
                if name in dirs:
                    dirs.remove(name)
                continue
            if path.is_symlink() or (name in files and not path.is_file()):
                raise ValueError("non-regular input requires explicit review")
            if name in files:
                paths.append(path)
    return sorted(paths)
