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
from security_harness.limits import WORKER_RLIMITS
from scripts.run_security import main


if __name__ == '__main__':
    run_id, candidate, variant = sys.argv[1:]
    run_directory(ROOT, run_id)  # validate before resolving evidence paths
    limits = WORKER_RLIMITS
    resource.setrlimit(resource.RLIMIT_AS, (limits["address_space_bytes"],) * 2)
    resource.setrlimit(resource.RLIMIT_DATA, (limits["per_process_data_bytes"],) * 2)
    resource.setrlimit(resource.RLIMIT_FSIZE, (limits["per_file_output_bytes"],) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (limits["per_process_cpu_seconds"], limits["per_process_cpu_seconds"] + 5))
    resource.setrlimit(resource.RLIMIT_NOFILE, (limits["file_descriptors"],) * 2)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    audit = AuditRun.__new__(AuditRun)
    audit.output = ROOT / 'artifacts' / run_id
    audit.data = json.loads((audit.output / 'report.json').read_text())
    sys.argv = ['run_security', '--candidate', candidate, '--variant', variant]
    raise SystemExit(main(audit=audit, defer_final=True))
