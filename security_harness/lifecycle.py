"""security 角色的受監督執行：計畫、worker 環境、容器與執行狀態清理、收尾，以及擁有者死亡後的復原。

The security role of a supervised run: its plan, worker environment, container and run-state cleanup, finalization,
and recovery after its owner died."""
import copy
import hashlib
import json
import os
import time
from datetime import datetime, timedelta, timezone
from . import supervision
from .results import EVIDENCE_VERSION, SUBJECT_FORMAT, decide, required_gate_kinds
from .supervision import PlanMismatch, child_environment, plan_changed, plan_digest

# 遠大於 RoE 的 120 秒執行上限。 / Well beyond the RoE's 120-second run limit.
ORPHAN_CONTAINER_AGE = timedelta(minutes=10)
# RoE 允許的最長整體期限。 / The longest total deadline the RoE allows.
MAX_TOTAL_SECONDS = 600


# security 證據的大小上限；正常報告遠小於此。 / Size limit for security evidence; a normal report is far smaller.
REPORT_LIMIT = 8 * 1024 * 1024


def remove_run_containers(run_id):
    from .isolation import cleanup_run
    cleanup_run(run_id)


def remove_orphan_containers(root):
    from . import isolation
    # daemon 較慢時，容器可能在 cleanup 之後才建立。 / A slow daemon can create a container after its run's cleanup.
    ids = isolation.docker('ps', '-aq', '--filter', 'label=epsilon.isolated=true', timeout=30).stdout.split()
    if not ids:
        return
    # 較新的容器可能屬於同主機另一個 checkout 仍在進行的執行。 / A younger container may belong to another checkout's live run.
    cutoff = datetime.now(timezone.utc) - ORPHAN_CONTAINER_AGE
    # 回收後仍留下目錄的執行，其擁有者仍存活。 / Runs whose directory survived the reaping still have a live owner.
    live = {work.name for work in (root / '.state' / 'runs').glob('*')}
    # 列出後才被正常移除的容器會讓 inspect 以非零結束，但其餘容器仍在輸出中；只有輸出無法解析才算失敗。 /
    # A container removed after listing makes inspect exit non-zero, yet the others are still in its output; only
    # unparsable output is a failure.
    inspected = isolation.docker('inspect', *ids, check=False, timeout=30)
    try:
        found = json.loads(inspected.stdout)
    except ValueError:
        found = None
    if not isinstance(found, list):
        raise ValueError('unparsable container inspection')
    old = [c['Id'] for c in found
           if datetime.fromisoformat(c['Created']) < cutoff
           and (c['Config']['Labels'] or {}).get('epsilon.run') not in live]
    if old:
        isolation.docker('rm', '--force', *old, timeout=30)


# supervisor 在放行 worker 前決定的計畫欄位；worker 報告中的這些欄位必須與 supervisor 持有的值相同。
# / The plan fields the supervisor decides before releasing the worker; the worker's report must keep the values
# the supervisor holds.
SECURITY_IMMUTABLE = ('run_id', 'operation', 'created_at', 'variant', 'candidate', 'resource_limits',
                      'policy_digest', 'roe_sha256', 'evaluator_digest')


def matches_plan(report, digest):
    """worker 讀回的報告是否仍是命令列摘要所指的計畫。 / Whether the report the worker read back is still the plan
    its command-line digest names."""
    return plan_digest(report, SECURITY_IMMUTABLE) == digest


# security worker 另需 docker 設定；不需權杖、供應商金鑰或 libpq 設定。 / The security worker also needs the docker
# configuration; it needs no token, provider key or libpq setting.
SECURITY_WORKER_EXTRA = frozenset({"DOCKER_CONFIG"})


def security_worker_environment(environ=os.environ):
    """security worker 的環境：基本環境加上 docker 設定。

The security worker's environment: the base environment plus the docker configuration.
    """
    return child_environment(environ, SECURITY_WORKER_EXTRA)


class SecurityContainers:
    """security 角色在接縫上的外部資源：這次執行的容器，正常收尾與 janitor 回收都經過這裡清除。

The security role's external resources at the seam: the run's containers, removed here on both live finalization
    and janitor recovery.
    """
    operation, ceiling = 'security', MAX_TOTAL_SECONDS

    def __init__(self, root, run_id, remove_containers=remove_run_containers):
        self.root, self.run_id, self.remove_containers = root, run_id, remove_containers

    def release(self, run_id):
        # CLI 終止後，daemon 仍可能正在完成請求。 / The daemon may still be finishing a request when its CLI is terminated.
        for _ in range(3):
            self.remove_containers(run_id)
            time.sleep(0.1)

    def report_path(self):
        return self.root / 'artifacts' / self.run_id / 'report.json'

    def load(self):
        """讀回 worker 最後原子保存的報告；無法解析時回傳 None 與例外型別。 / Read back the worker's last atomically
        persisted report; when it cannot be parsed, return None and the exception type."""
        try:
            # 不跟隨符號連結，並限制大小；報告目錄可被同 uid 程序改寫。 / Never follow a symlink and bound the size:
            # the report directory is writable by any process under the same uid.
            fd = os.open(self.report_path(), os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, 'rb') as handle:
                raw = handle.read(REPORT_LIMIT + 1)
            if len(raw) > REPORT_LIMIT:
                raise ValueError('evidence too large')
            data = json.loads(raw)
            if not isinstance(data, dict) or data.get('run_id') != self.run_id:
                raise ValueError('invalid evidence identity')
            return data, None
        except (OSError, ValueError) as exc:
            return None, type(exc).__name__


def closed(data, outcome):
    """關閉證據的共同部分：不留待定結果，帶上清理紀錄；回傳被移除的待定判定與執行狀態。

The part of closing shared by both security closes: no pending result stays and the cleanup record is attached.
    Return the pending decision and execution that were removed.
    """
    pending = data.pop('pending_decision', None), data.pop('pending_execution', None)
    data['cleanup'] = outcome.cleanup
    return pending


def block_unless_cleaned(data, outcome):
    if outcome.kind == supervision.CLEANUP_FAILED:
        data.update(execution='ERROR', decision='BLOCK', reasons=['cleanup incomplete'])


class SecurityRun(SecurityContainers):
    """security 角色在受監督執行中的宣告：清除這次執行的容器，並把 worker 報告關成發布用的證據。

What the security role declares to a supervised run: remove the run's containers, and close the worker's report
    into the evidence that is published.
    """

    def __init__(self, root, audit, remove_containers=remove_run_containers):
        super().__init__(root, audit.data['run_id'], remove_containers)
        self.audit = audit
        self.planned = {key: audit.data.get(key) for key in SECURITY_IMMUTABLE}

    def reproduces_allow(self, data):
        try:
            policy_bytes = (self.root / 'security/policy.json').read_bytes()
            if hashlib.sha256(policy_bytes).hexdigest() != self.planned['policy_digest']:
                return False
            return decide(data['records'], json.loads(policy_bytes), data.get('subject_digest'),
                          self.planned['policy_digest'], run_id=self.run_id)['decision'] == 'ALLOW'
        except (OSError, ValueError, KeyError, TypeError):
            return False

    def read(self):
        data, error_type = self.load()
        if data is None:
            # 報告無法讀回時，以 supervisor 持有的副本關成阻擋證據，不讓執行卡住。 / When the report cannot be read
            # back, close the supervisor's own copy as blocking evidence instead of stranding the run.
            data = copy.deepcopy(self.audit.data)
            data['errors'].append({'stage': 'supervisor', 'error_type': error_type})
        return data

    def close(self, evidence, outcome):
        audit = self.audit
        audit.data = copy.deepcopy(evidence)
        # 發布的證據只能帶 supervisor 實際使用的計畫，不採用 worker 改過的值。 / Published evidence carries only the plan
        # the supervisor actually used, never values the worker changed.
        changed = plan_changed(audit.data, self.planned)
        audit.data.update(self.planned)
        pending, execution = closed(audit.data, outcome)
        finalized = False
        if (outcome.kind == supervision.EXITED and not changed and outcome.returncode in (0, 1)
                and audit.data['execution'] == 'AWAITING_CLEANUP' and pending in ('ALLOW', 'BLOCK')):
            finalized = True
            if outcome.returncode != (0 if pending == 'ALLOW' else 1):
                audit.fail(RuntimeError('worker exit/decision mismatch'))
            elif pending == 'ALLOW' and not self.reproduces_allow(audit.data):
                # supervisor 依計畫的政策自行重算判定，不只相信 worker 寫下的 ALLOW。 / The supervisor recomputes the
                # decision under the planned policy instead of trusting the ALLOW the worker wrote.
                audit.fail(RuntimeError('worker decision not reproduced'))
            else:
                audit.data['decision'] = pending
                audit.data['execution'] = 'COMPLETED' if execution == 'RUNNING' else execution
        if outcome.error_type:
            # 保留監督程序例外型別，不保存例外文字。 / Keep the supervisor's exception type, never its text.
            audit.data['errors'].append({'stage': 'supervisor', 'error_type': outcome.error_type})
        reason = 'ERROR' if outcome.stop == supervision.SUPERVISOR_FAILED else outcome.stop
        if reason:
            stage = audit.data['stage']
            kinds = dict(required_gate_kinds(self.root))
            if stage in kinds and not any(r['gate'] == stage for r in audit.data['records']):
                audit.add(stage, reason, kinds[stage], 0, 0, 'supervisor stopped run')
            audit.data.update(execution=reason, decision='BLOCK', reasons=['supervisor ' + reason.lower()])
        elif changed or outcome.returncode == 2:
            # exit 2 表示 worker 讀回的計畫與命令列摘要不符。 / Exit 2 means the plan the worker read back did not match
            # the digest on its command line.
            audit.fail(PlanMismatch('worker report differs from the plan'))
        elif not finalized:
            # 只有完成清理交接後才能發布 worker 判定。 / Only the cleanup handoff may publish a worker decision.
            audit.fail(RuntimeError('worker did not complete'))
        block_unless_cleaned(audit.data, outcome)
        audit.data['total_seconds'] = outcome.seconds
        # 檢查點也更新最新指標，指標永遠指向已關閉的證據。 / The checkpoint moves the latest pointer too, so it always
        # names closed evidence.
        return audit.finish(required_gate_kinds(self.root))


def supervise(root, audit, command, max_seconds, remove_containers=remove_run_containers):
    return supervision.supervise(root, audit.data['run_id'], SecurityRun(root, audit, remove_containers), command,
                                 security_worker_environment(os.environ), max_seconds)


class SecurityRecovery(SecurityContainers):
    """擁有者已死亡的 security 執行：同樣清除容器，證據一律以取消關閉，且不移動最新指標。

A security run whose owner died: its containers are removed the same way, its evidence is always closed as
    cancelled, and the latest pointer stays where it is.
    """

    def read(self):
        if not self.report_path().exists():
            return None
        data, error_type = self.load()
        if data is None:
            # 無法解析的證據換成阻擋用的替代證據，janitor 才不會每輪都卡在同一次執行。 / Unparsable evidence is
            # replaced by blocking evidence, so the janitor does not stall on the same run every sweep.
            data = {'schema_version': EVIDENCE_VERSION, 'subject_digest_format': SUBJECT_FORMAT,
                    'run_id': self.run_id, 'operation': 'security', 'created_at': None, 'subject_digest': None,
                    'policy_digest': None, 'records': [], 'stage': 'janitor',
                    'errors': [{'stage': 'janitor', 'error_type': error_type}]}
        return data

    def close(self, evidence, outcome):
        if evidence is None:
            return None
        from .audit import AuditRun
        audit = AuditRun.__new__(AuditRun)
        audit.output = self.report_path().parent
        audit.data = copy.deepcopy(evidence)
        closed(audit.data, outcome)
        audit.data.update(execution='CANCELLED', decision='BLOCK', reasons=['orphaned supervisor reaped'])
        block_unless_cleaned(audit.data, outcome)
        # 回收舊執行不可覆寫較新執行的索引。 / A reaped old run must not displace the index of a newer run.
        return audit.finish(required_gate_kinds(self.root), update_pointer=False)


def recover(root, run_id, marker):
    """回收擁有者已死亡的 security 執行：經同一套收尾協定停止群組、清除容器與執行狀態，並以取消關閉證據。

Reap a security run whose owner died: stop its groups, remove its containers and run state, and close its evidence
    as cancelled, through the same finalization protocol.
    """
    supervision.recover(root, run_id, marker, SecurityRecovery(root, run_id))
