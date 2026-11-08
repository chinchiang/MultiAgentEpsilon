"""測試用的收尾輔助：模擬 worker 已在 supervise 之外結束後，經正式收尾協定關閉證據。

Test-only finalization helpers: close the evidence through the real finalization protocol
for a worker that already ended outside supervise."""
import time

from security_harness import supervision
from security_harness.llm.lifecycle import ModelRun


def finalize(root, run_id, role, *, stop=None, returncode=None):
    """在清理鎖下以 Ended 結果收尾。 / Finalize with an Ended outcome under the cleanup lock."""
    with supervision.finalization_lock(supervision.run_directory(root, run_id)):
        return supervision.close_run(root, run_id, role, supervision.Ended(stop, returncode, time.monotonic()))[1]


def finish(root, run_id, *, providers=(), returncode=None, stop=None, expected_report=None):
    """收尾一個已在 supervise 之外結束的模型執行。 / Finalize a model run whose worker already ended outside supervise."""
    return finalize(root, run_id, ModelRun(root, run_id, providers, expected_report), stop=stop, returncode=returncode)
