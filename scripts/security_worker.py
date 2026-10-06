#!/usr/bin/env python3
"""Trusted whole-pipeline worker; the parent owns deadlines and cleanup."""
import json
import resource
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from security_harness.audit import AuditRun
from security_harness.lifecycle import run_directory
from scripts.run_security import main


if __name__ == '__main__':
    run_id, candidate, variant = sys.argv[1:]
    run_directory(ROOT, run_id)  # validate before resolving evidence paths
    resource.setrlimit(resource.RLIMIT_AS, (8*1024**3, 8*1024**3))
    resource.setrlimit(resource.RLIMIT_DATA, (512*1024**2, 512*1024**2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64*1024**2, 64*1024**2))
    resource.setrlimit(resource.RLIMIT_CPU, (120, 125))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    audit = AuditRun.__new__(AuditRun)
    audit.output = ROOT / 'artifacts' / run_id
    audit.data = json.loads((audit.output / 'report.json').read_text())
    sys.argv = ['run_security', '--candidate', candidate, '--variant', variant]
    raise SystemExit(main(audit=audit, defer_final=True))
