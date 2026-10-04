"""One worktree scope for scanning and subject binding; never follow symlinks."""
import os
import subprocess
from pathlib import Path
from .limits import LIMITS, ResourceLimit

ROOT_GENERATED = {".git", ".venv", ".tools", ".state", "artifacts", ".pytest_cache"}
CACHES = {"__pycache__", ".pytest_cache"}


def excluded(relative: Path) -> bool:
    return relative.parts[0] in ROOT_GENERATED or any(p in CACHES for p in relative.parts)


def input_files(root: Path) -> list[Path]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("input root must be a real directory")
    # A tracked file in a reserved generated area is not silently omitted.
    if (root / ".git").exists():
        tracked = subprocess.run(["git", "-C", str(root), "ls-files", "-z"],
                                 capture_output=True, check=True, timeout=10)
        if any(excluded(Path(n)) for n in tracked.stdout.decode().split("\0") if n):
            raise ValueError("tracked input uses a reserved generated path")
    paths = []
    total = 0
    entries = 0
    def failed(exc):
        raise exc
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=failed):
        parent = Path(directory)
        for name in list(dirs) + files:
            entries += 1
            if entries > LIMITS.max_files * 2:
                raise ResourceLimit("input directory inventory exceeds limit")
            path = parent / name
            relative = path.relative_to(root)
            if excluded(relative):
                if name in dirs:
                    dirs.remove(name)
                continue
            if path.is_symlink() or (name in files and not path.is_file()):
                raise ValueError("non-regular input requires explicit review")
            if name in files:
                size = path.stat().st_size
                total += size
                if size > LIMITS.max_file_bytes or total > LIMITS.max_input_bytes or len(paths) >= LIMITS.max_files:
                    raise ResourceLimit("input byte or file limit exceeded")
                paths.append(path)
    return sorted(paths)
