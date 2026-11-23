"""盲審受監督執行相容入口；實作統一收斂於 security_harness.llm.lifecycle。

Compatibility facade for blind-review supervised runs; the implementation lives in security_harness.llm.lifecycle."""
from .benchmark import CASES_PATH, ORACLE_PATH
from .lifecycle import (archived_cases, deadline_policy, digest_bytes, implementation_sha256,
                        implementation_unchanged, initial_review_report as initial_report,
                        record, run_worker, snapshot_inputs)

__all__ = (
    'CASES_PATH',
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
