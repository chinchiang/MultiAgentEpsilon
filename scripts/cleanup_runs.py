#!/usr/bin/env python3
"""Reap only dead supervisor runs owned by this UID; never clear another live run."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from security_harness.lifecycle import sweep_stale

if __name__ == '__main__':
    print(json.dumps({'cleaned_run_ids': sweep_stale(ROOT)}))
