#!/usr/bin/env python3
"""Bounded model worker; only its parent may publish COMPLETE after cleanup."""
import asyncio
import resource
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from security_harness.lifecycle import run_directory
from scripts.model_smoke import run_worker

if __name__ == '__main__':
    root, run_id = Path(sys.argv[1]), sys.argv[2]
    run_directory(root, run_id)
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    resource.setrlimit(resource.RLIMIT_DATA, (512 * 1024**2, 512 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CPU, (30, 35))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024**2, 1024**2))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    raise SystemExit(asyncio.run(run_worker(root, run_id)))
