"""盲審受監督執行相容入口；實作統一收斂於 security_harness.llm.lifecycle。

Compatibility facade for blind-review supervised runs; the implementation lives in security_harness.llm.lifecycle."""
from .benchmark import CASES_PATH, ORACLE_PATH
from .lifecycle import (archived_cases, deadline_policy, digest_bytes, implementation_sha256,
                        implementation_unchanged, initial_review_report as initial_report,
                        record, run_worker, snapshot_inputs)

INPUT_FILES = {'catalog.json': CASES_PATH, 'oracle.json': ORACLE_PATH}

__all__ = (
    'CASES_PATH',
    'INPUT_FILES',
    'ORACLE_PATH',
    'archived_cases',
    'deadline_policy',
    'digest_bytes',
    'implementation_sha256',
    'implementation_unchanged',
    'initial_report',
    'record',
    'run_worker',
    'snapshot_inputs',
)
