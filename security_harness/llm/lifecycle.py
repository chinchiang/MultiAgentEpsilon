"""使用共用執行清冊管理模型 supervisor 與復原，不使用 Docker。

Model supervisor and recovery using the shared run inventory, without Docker."""
import copy
import os

from .. import supervision
from ..supervision import CANCELLED, CLEANUP_FAILED, EXITED, TIMEOUT, child_environment, persist
from .gateway import ModelError
from .transport import strict_json

# 最多 16 筆審查乘以 16 KiB 原文，另加中繼資料。 / 16 reviews x 16 KiB bound raw responses, plus metadata.
REPORT_LIMIT = 1024 * 1024
# 模型 supervisor 的最長整體期限。 / The model supervisor's longest total deadline.
MAX_TOTAL_SECONDS = 130
BLIND_REVIEW_IMMUTABLE = ('plan', 'providers', 'selected_providers', 'case_ids', 'rounds', 'limits',
                          'total_timeout_seconds', 'output_tokens_per_review', 'implementation_sha256',
                          'case_catalog_sha256', 'oracle_sha256', 'model_roe_sha256')


# smoke 的計畫：supervisor 決定的供應商、fixture、實作與 RoE 雜湊、限額與時限。 / The smoke plan: the providers,
# fixture, implementation and RoE digests, limits and deadline the supervisor decided.
SMOKE_IMMUTABLE = ('schema_version', 'operation', 'run_id', 'started_at', 'providers', 'fixture',
                   'implementation_sha256', 'model_roe_sha256', 'limits', 'total_timeout_seconds',
                   'max_output_tokens_per_call')


def smoke_plan_digest(report):
    """smoke 計畫的雜湊；supervisor 經命令列交給 worker。 / Digest of a smoke plan, handed to the worker on the
    command line."""
    return supervision.plan_digest(report, SMOKE_IMMUTABLE)


def plan_digest(report):
    """盲審不可變計畫、預算、身分與逐筆請求摘要的雜湊；supervisor 經命令列交給 worker，不經磁碟。

Digest of a blind review's immutable plan, budget, identities and per-request digests. The
    supervisor hands it to the worker on the command line, never through the report on disk."""
    requests = [check.get('request_sha256') for check in report.get('checks', [])]
    return supervision.plan_digest({**report, 'request_sha256': requests}, (*BLIND_REVIEW_IMMUTABLE, 'request_sha256'))


def read_report(root, run_id):
    path = root / 'artifacts' / run_id / 'report.json'
    try:
        if path.is_symlink() or path.stat().st_size > REPORT_LIMIT:
            raise ValueError('invalid evidence')
        with path.open('rb') as handle:
            raw = handle.read(REPORT_LIMIT + 1)
        if len(raw) > REPORT_LIMIT:
            raise ValueError('invalid evidence size')
        data = strict_json(raw)
        if (data.get('run_id') != run_id or data.get('operation') != 'model-smoke' or
                data.get('schema_version') != 2):
            raise ValueError('invalid evidence identity')
        for name in ('checks', 'calls'):
            if (not isinstance(data.get(name), list) or len(data[name]) > 16 or
                    any(not isinstance(item, dict) for item in data[name])):
                raise ValueError('invalid evidence records')
        return data
    except (OSError, ValueError, TypeError, AttributeError, ModelError):
        return {'schema_version': 2, 'run_id': run_id, 'operation': 'model-smoke',
                'advisory_only': True, 'status': 'INCOMPLETE', 'code': 'EVIDENCE_INVALID',
                'evidence_error': 'EVIDENCE_INVALID',
                'providers': [], 'checks': [], 'calls': []}


def complete_worker_report(data, providers, returncode):
    # 不可因空集合、過期報告或缺少供應商嘗試而成功。 / No vacuous success, stale report or success from missing provider attempts.
    checks, calls = data.get('checks', []), data.get('calls', [])
    return (returncode == 0 and data.get('status') == 'AWAITING_CLEANUP' and
            data.get('pending_status') == 'COMPLETE' and bool(providers) and
            data.get('providers') == providers and
            [c.get('provider') for c in checks] == providers and
            all(c.get('status') == 'SUCCESS' for c in checks) and
            [c.get('provider') for c in calls] == providers and
            all(c.get('status') == 'SUCCESS' for c in calls))


class ModelRun:
    """model 角色在受監督執行中的宣告：不建立外部資源，並把 worker 報告關成評估證據。

What the model role declares to a supervised run: no external resources, and closing the worker's report into the
    evaluation evidence.
    """
    operation, ceiling = 'model-smoke', MAX_TOTAL_SECONDS

    def __init__(self, root, run_id, providers=(), expected_report=None):
        self.root, self.run_id = root, run_id
        self.providers, self.expected_report = list(providers), expected_report

    def release(self, run_id):
        """模型執行不使用 Docker 或其他外部資源。 / Model runs use no Docker or other external resource."""

    def read(self):
        return read_report(self.root, self.run_id)

    def close(self, evidence, outcome):
        data, expected_report = copy.deepcopy(evidence), self.expected_report
        reason = outcome.stop
        try:
            completed = outcome.kind == EXITED and complete_worker_report(data, self.providers, outcome.returncode)
        except (TypeError, AttributeError):
            completed = False
        previous_status = data.get('status')
        data.pop('pending_status', None)
        data.update(status='INCOMPLETE', cleanup=outcome.cleanup)
        if reason:
            data['code'] = reason
        for check in data.get('checks', []):
            if check.get('status') == 'RUNNING':
                check.update(status='CANCELLED' if reason == CANCELLED else 'ERROR', code=reason or 'WORKER_FAILED')
        if data.get('task') == 'blind-review' or (expected_report or {}).get('task') == 'blind-review':
            try:
                from .benchmark_score import summarize
                data['analysis'] = summarize(data, (expected_report or {}).get('plan'))
                # 盲審 worker 也綁定 supervisor 交付的不可變計畫、預算與請求摘要。 / Blind-review workers are bound to
                # the supervisor's immutable plan, budget and request digests too.
                if expected_report is not None and plan_digest(data) != plan_digest(expected_report):
                    raise ValueError('blind review differs from the supervisor plan')
            except Exception:
                completed = False
                data.update(analysis=None, code='EVALUATION_INVALID')
        elif expected_report is not None:
            # Smoke worker 也綁定 supervisor 不可變計畫與限額。 / Smoke workers are bound to the supervisor's immutable plan and limits too.
            calls = data.get('calls', [])
            reservations_valid = (type(data.get('reserved_calls')) is int and
                type(data.get('reserved_output_tokens')) is int and
                all(type(c.get('reserved')) is bool and c.get('reserved') is True and
                    type(c.get('reserved_output_tokens')) is int and
                    c['reserved_output_tokens'] == expected_report['max_output_tokens_per_call'] for c in calls) and
                data['reserved_calls'] == len(calls) and
                data['reserved_output_tokens'] == len(calls) * expected_report['max_output_tokens_per_call'])
            if smoke_plan_digest(data) != smoke_plan_digest(expected_report) or not reservations_valid:
                completed = False
                data['code'] = 'EVALUATION_INVALID'
        if outcome.kind == CLEANUP_FAILED:
            data.update(status='ERROR', code='CLEANUP_FAILED')
        elif reason in (CANCELLED, TIMEOUT):
            data.update(status=reason, code=reason)
        elif completed:
            data.update(status='COMPLETE', code=None)
        elif outcome.returncode == 2:
            # exit 2 表示 worker 讀回的計畫與命令列摘要不符，一次呼叫都沒發。 / Exit 2 means the plan the worker read back
            # did not match the digest on its command line, and it made no call.
            data.update(status='INCOMPLETE', code='EVALUATION_INVALID')
        else:
            data.update(status='INCOMPLETE', code=data.get('code') or
                        ('WORKER_FAILED' if previous_status != 'AWAITING_CLEANUP' else 'PROVIDER_INCOMPLETE'))
        persist(self.root / 'artifacts' / self.run_id / 'report.json', data)
        return data


def finish(root, run_id, *, providers=(), returncode=None, stop=None, expected_report=None):
    """收尾一個 worker 已在 supervise 之外結束的模型執行。 / Finalize a model run whose worker already ended outside
    supervise."""
    return supervision.finalize(root, run_id, ModelRun(root, run_id, providers, expected_report), stop=stop,
                                returncode=returncode)


def recover(root, run_id, marker):
    """回收擁有者已死亡的模型執行：經同一套收尾協定以 CANCELLED 關閉證據並移除執行狀態。

Reap a model run whose owner died: close its evidence as CANCELLED and remove its run state through the same
    finalization protocol.
    """
    supervision.recover(root, run_id, marker, ModelRun(root, run_id))


def model_worker_environment(environ, providers):
    """model worker 的環境：基本程序、代理與 CA 變數，加上所選供應商的設定；mock 不需要任何設定。

The model worker's environment: basic process, proxy and CA variables plus the
    selected providers' settings. Mock providers need none.
    """
    from .config import PROVIDER_ENV
    return child_environment(environ, frozenset().union(*(PROVIDER_ENV.get(p, ()) for p in providers)))


def supervise(root, report, command, max_seconds):
    run_id = report['run_id']
    return supervision.supervise(root, run_id, ModelRun(root, run_id, report['providers'], report), command,
                                 model_worker_environment(os.environ, set(report['providers'])), max_seconds)
