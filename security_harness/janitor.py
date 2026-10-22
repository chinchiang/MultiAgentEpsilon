"""回收擁有者已死亡的受監督執行；依角色分派復原，最後清掃孤兒容器。

Reap supervised runs whose owner died, dispatching recovery by role, then sweep orphan containers."""
from . import lifecycle
from .llm import lifecycle as model_lifecycle
from .supervision import sweep_runs

RECOVERERS = {'security': lifecycle.recover, 'model-smoke': model_lifecycle.recover}


class SweepIncomplete(RuntimeError):
    """部分過期執行無法回收，其他項目仍繼續處理。

Some stale runs could not be reaped; the others were still processed."""

    def __init__(self, cleaned, failures):
        super().__init__('stale run cleanup incomplete')
        self.cleaned, self.failures = cleaned, failures


def sweep_stale(root):
    cleaned, failures = sweep_runs(root, RECOVERERS)
    try:
        lifecycle.remove_orphan_containers(root)
    except Exception as exc:
        failures.append({'containers': 'epsilon.isolated', 'error_type': type(exc).__name__})
    if failures:
        raise SweepIncomplete(cleaned, failures)
    return cleaned
