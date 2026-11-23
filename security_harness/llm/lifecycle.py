"""使用共用執行清冊管理模型受監督執行、計畫封存與復原，不使用 Docker。

Model supervised runs, plan archiving and recovery using the shared run inventory, without Docker."""
import asyncio
import copy
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import os
import signal
import sys
import tempfile
import time
import uuid

from .. import supervision
from ..results import read_regular
from ..scope import MODEL_RUN_CEILING, call_seconds, load_model_roe, run_seconds, valid_deadline_policy
from ..supervision import (CANCELLED, CLEANUP_FAILED, EXITED, TIMEOUT, child_environment,
                           persist, prepare_run, run_directory)
from . import benchmark as bench
from . import config
from .benchmark import (OUTPUT_BUDGETS, OUTPUT_TOKENS, SUITES, MockReviewer, load_cases,
                        make_plan, parse_review, request_digest, review_request)
from .gateway import Gateway, Limits, ModelError, Request, digest
from .transport import JsonHTTP, strict_json

# 最多 16 筆審查乘以 16 KiB 原文，另加中繼資料。 / 16 reviews x 16 KiB bound raw responses, plus metadata.
REPORT_LIMIT = 1024 * 1024
# 模型 supervisor 的最長整體期限。 / The model supervisor's longest total deadline.
MAX_TOTAL_SECONDS = MODEL_RUN_CEILING
# 報告版本：3 起記錄期限政策並封存評分輸入。 / Report versions: from 3 the deadline policy is recorded and the scoring
# inputs are archived.
REPORT_VERSIONS = (2, 3)
REPORT_VERSION = 3
# 封存輸入的檔名與上限；與報告同目錄、同權限。 / Archived input names and their bound; beside the report, same mode.
INPUTS = 'inputs'
INPUT_LIMIT = 65536
INPUT_NAMES = ('catalog.json', 'oracle.json', 'model-roe.json')
BLIND_REVIEW_IMMUTABLE = ('plan', 'providers', 'selected_providers', 'case_ids', 'rounds', 'limits',
                          'total_timeout_seconds', 'output_tokens_per_review', 'implementation_sha256',
                          'case_catalog_sha256', 'oracle_sha256', 'model_roe_sha256', 'deadline_policy')

# smoke 的計畫：supervisor 決定的供應商、fixture、實作與 RoE 雜湊、限額與時限。 / The smoke plan: the providers,
# fixture, implementation and RoE digests, limits and deadline the supervisor decided.
SMOKE_IMMUTABLE = ('schema_version', 'operation', 'run_id', 'started_at', 'providers', 'fixture',
                   'implementation_sha256', 'model_roe_sha256', 'limits', 'total_timeout_seconds',
                   'max_output_tokens_per_call', 'deadline_policy')

FIXTURE = Request(
    system="You are running a synthetic transport check. Follow the user's exact output instruction.",
    user="Reply with exactly EPSILON_SYNTHETIC_OK and no other text.", max_output_tokens=256)


def digest_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def file_digest(path):
    return digest_bytes(path.read_bytes())


def smoke_plan_digest(report):
    """smoke 計畫的雜湊；supervisor 經命令列交給 worker。 / Digest of a smoke plan, handed to the worker on the
    command line."""
    return supervision.plan_digest(report, SMOKE_IMMUTABLE)


def plan_digest(report):
    """統一計算模型受監督執行的不可變計畫、預算、身分與逐筆請求雜湊；supervisor 經命令列交給 worker，不經磁碟報告。

    Unified digest of a model supervised run's immutable plan, budget, identities and per-request digests.
    The supervisor hands it to the worker on the command line, never through the report on disk."""
    if report.get('task') != 'blind-review' and 'plan' not in report:
        return smoke_plan_digest(report)
    requests = [check.get('request_sha256') for check in report.get('checks', [])]
    return supervision.plan_digest({**report, 'request_sha256': requests}, (*BLIND_REVIEW_IMMUTABLE, 'request_sha256'))


current_plan_digest = plan_digest


def snapshot_inputs():
    """一次讀取案例目錄、標準答案與模型 RoE 的位元組；計畫的雜湊與封存副本都取自這份快照。

    Read the case catalog, reference and model RoE bytes once; both the plan's digests and the
    archived copies come from this snapshot."""
    return {'catalog.json': bench.CASES_PATH.read_bytes(),
            'oracle.json': bench.ORACLE_PATH.read_bytes(),
            'model-roe.json': (config.ROOT / 'security/model-roe.json').read_bytes()}


def deadline_policy(roe_raw):
    policy = strict_json(roe_raw).get('deadline_policy')
    if not valid_deadline_policy(policy):
        raise ValueError('invalid model deadline policy')
    return policy


def deadline_warning(report):
    """付費呼叫前提醒：真實供應商依 RoE 期限政策的逐次期限總和超過整輪上限時，慢回應會留下 INCOMPLETE。

    Before paid calls: if the live providers' per-call deadlines under the RoE deadline policy can exceed
    the run cap, slow replies leave INCOMPLETE."""
    worst = sum(call_seconds(report['deadline_policy'], p) for p in report['providers'] if not p.startswith('mock'))
    total_seconds = report['total_timeout_seconds']
    if worst <= total_seconds:
        return None
    return (f'最壞情況 {worst} 秒超過整輪上限 {total_seconds} 秒；回應較慢時結果會是 INCOMPLETE / '
            f'worst case {worst}s exceeds the {total_seconds}s run cap; slow replies will leave the run INCOMPLETE')


def require_model_roe(parser, providers, planned_calls):
    try:
        load_model_roe(config.ROOT, providers, planned_calls)
    except (OSError, ValueError):
        parser.error('live model calls are outside the approved model RoE (security/model-roe.json)')


def implementation_sha256():
    """盲審計畫綁定的實作雜湊：模型層實作與兩支盲審腳本。計畫與 worker 都以此計算。 / The implementation digest a
    blind-review plan binds: the model layer plus the two blind-review scripts. The plan and the worker both use it."""
    return digest(json.dumps([config.implementation_digest(), file_digest(config.ROOT / 'scripts/model_review.py'),
                              file_digest(config.ROOT / 'scripts/review_adjudicate.py')]))


def implementation_unchanged(report):
    """worker 讀到的實作是否仍是計畫綁定的那一份；無法讀取即視為已變更。 / Whether the implementation the worker reads is
    still the one the plan bound; an unreadable implementation counts as changed."""
    try:
        expected = implementation_sha256() if report.get('task') == 'blind-review' else config.implementation_digest()
        return expected == report['implementation_sha256']
    except OSError:
        return False


def read_report(root, run_id):
    path = root / 'artifacts' / run_id / 'report.json'
    try:
        # 不跟隨符號連結、只讀一般檔案（FIFO 不會卡住）並限制大小。 / Never follow a symlink, read only a regular
        # file (a FIFO cannot block) and bound the size.
        data = strict_json(read_regular(path, REPORT_LIMIT))
        if (data.get('run_id') != run_id or data.get('operation') != 'model-smoke' or
                data.get('schema_version') not in REPORT_VERSIONS):
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


def archive_inputs(run_dir, inputs):
    """把評分輸入的原始位元組封存在報告旁，供日後以報告內雜湊重驗；同名檔案不得覆寫。

    Archive the scoring inputs' raw bytes beside the report, so later validation checks
    the report's digests against these copies; an existing copy is never replaced."""
    folder = run_dir / INPUTS
    folder.mkdir(mode=0o700)
    for name, raw in inputs.items():
        if len(raw) > INPUT_LIMIT:
            raise ValueError('archived input too large')
        fd, temporary = tempfile.mkstemp(prefix='.input-', dir=folder)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temporary, folder / name)
        finally:
            os.unlink(temporary)
    descriptor = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def record(path, report, inputs=None):
    """寫入計畫報告並封存其評分輸入，於 supervisor 啟動 worker 前呼叫；inputs 須與建立初始報告所用快照一致。

    Write the planned report and archive its scoring inputs before the supervisor starts the
    worker. inputs must be the same snapshot the initial report used."""
    persist(path, report)
    if inputs is None:
        inputs = (snapshot_inputs() if report.get('task') == 'blind-review'
                  else {'model-roe.json': (config.ROOT / 'security/model-roe.json').read_bytes()})
    archive_inputs(path.parent, inputs)


def read_inputs(run_dir, names):
    """讀回封存輸入：不跟隨符號連結、限大小、只收一般檔案。 / Read archived inputs back without following
    symlinks, within the bound and only as regular files."""
    folder = run_dir / INPUTS
    if folder.is_symlink() or not folder.is_dir():
        raise ValueError('archived inputs missing')
    return {name: read_regular(folder / name, INPUT_LIMIT) for name in names}


def archived_cases(run_dir, report):
    """計畫封存的案例目錄；封存缺失、被竄改或無法解析時回傳 None。 / The case catalog the plan archived, or None when the
    archive is missing, tampered with or unparsable."""
    try:
        inputs = read_inputs(run_dir, INPUT_NAMES)
        if any(digest_bytes(inputs[name]) != report[key] for name, key in (
                ('catalog.json', 'case_catalog_sha256'), ('oracle.json', 'oracle_sha256'),
                ('model-roe.json', 'model_roe_sha256'))):
            return None
        return load_cases(inputs['catalog.json'])
    except (OSError, ValueError):
        return None


def validate_reservations(report, output_tokens, *, require_all=False):
    """統一核對模型報告的呼叫預留與詞元帳目。 / Unified validation of call reservations and token accounting."""
    calls = report.get('calls', [])
    for call in calls:
        if (type(call.get('reserved')) is not bool or type(call.get('reserved_output_tokens')) is not int or
                (require_all and not call['reserved']) or
                call['reserved_output_tokens'] != (output_tokens if call['reserved'] else 0) or
                (not call['reserved'] and (call.get('status') != 'ERROR' or
                    call.get('code') not in ('ROUTING_DENIED', 'INPUT_LIMIT', 'BUDGET_EXHAUSTED')))):
            raise ValueError('invalid call reservation')
    if (type(report.get('reserved_calls')) is not int or
            type(report.get('reserved_output_tokens')) is not int or
            report['reserved_calls'] != sum(c['reserved'] for c in calls) or
            report['reserved_output_tokens'] != sum(c['reserved_output_tokens'] for c in calls)):
        raise ValueError('reservation accounting mismatch')
    return True


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


def initial_smoke_report(providers, run_id, roe_raw=None):
    """建立 smoke 初始報告；roe_raw 是計畫綁定並封存的模型 RoE 位元組。 / Build the initial smoke report; roe_raw is the
    model RoE bytes the plan binds and archives."""
    roe_raw = (config.ROOT / 'security/model-roe.json').read_bytes() if roe_raw is None else roe_raw
    policy = deadline_policy(roe_raw)
    limits = Limits(max_calls=len(providers), reserved_output_tokens=FIXTURE.max_output_tokens * len(providers),
                    timeout_seconds=max(call_seconds(policy, p) for p in providers))
    return {'schema_version': REPORT_VERSION, 'operation': 'model-smoke', 'run_id': run_id, 'advisory_only': True,
            'data_class': 'synthetic', 'fixture': 'fixed-ack-v1', 'providers': list(providers),
            'started_at': datetime.now(timezone.utc).isoformat(),
            'implementation_sha256': config.implementation_digest(), 'status': 'INCOMPLETE', 'code': None,
            'limits': asdict(limits), 'total_timeout_seconds': run_seconds(policy, providers),
            'deadline_policy': policy,
            'max_output_tokens_per_call': FIXTURE.max_output_tokens,
            'checks': [{'provider': p, 'live': p != 'mock', 'status': 'NOT_RUN', 'code': None} for p in providers],
            'calls': [], 'reserved_calls': 0, 'reserved_output_tokens': 0,
            'model_roe_sha256': digest_bytes(roe_raw),
            'cleanup': {'completed': False}}


def initial_review_report(providers, case_ids, run_id, output_tokens=OUTPUT_TOKENS, rounds=1, inputs=None):
    """建立盲審初始報告與逐筆請求摘要。 / Build the initial blind-review report and per-request digests."""
    inputs = snapshot_inputs() if inputs is None else inputs
    policy = deadline_policy(inputs['model-roe.json'])
    cases = load_cases(inputs['catalog.json'])
    plan = make_plan(providers, case_ids, rounds, cases)
    if type(output_tokens) is not int or output_tokens not in OUTPUT_BUDGETS:
        raise ValueError('invalid review output budget')
    planned = [p['provider'] for p in plan]
    limits = Limits(max_calls=len(plan), reserved_output_tokens=output_tokens * len(plan),
                    timeout_seconds=max(call_seconds(policy, p) for p in planned))
    checks = [{**p, 'status': 'NOT_RUN', 'code': None, 'review': None, 'call_id': None,
               'request_sha256': request_digest(review_request(cases[p['case_id']], p['review_id'], output_tokens))}
              for p in plan]
    return {'schema_version': REPORT_VERSION, 'operation': 'model-smoke', 'task': 'blind-review', 'run_id': run_id,
            'advisory_only': True, 'data_class': 'synthetic', 'status': 'INCOMPLETE', 'code': None,
            'started_at': datetime.now(timezone.utc).isoformat(),
            'implementation_sha256': implementation_sha256(),
            'case_catalog_sha256': digest_bytes(inputs['catalog.json']),
            'oracle_sha256': digest_bytes(inputs['oracle.json']),
            'model_roe_sha256': digest_bytes(inputs['model-roe.json']), 'deadline_policy': policy,
            'rounds': rounds,
            'sampling_policy': {p: ('provider-default' if p == 'bedrock' else 'temperature=0'
                                    if not p.startswith('mock-') else 'deterministic-fixture') for p in providers},
            'selected_providers': list(providers), 'case_ids': list(case_ids), 'plan': plan,
            'providers': [p['provider'] for p in plan], 'checks': checks, 'calls': [],
            'reserved_calls': 0, 'reserved_output_tokens': 0,
            'limits': asdict(limits), 'total_timeout_seconds': run_seconds(policy, planned),
            'output_tokens_per_review': output_tokens,
            'cleanup': {'completed': False}, 'analysis': None}


async def run_worker(root, run_id, plan_digest, mode=None):
    """統一的模型受監督 worker 執行迴圈：核對計畫摘要與前置完整性，經 Gateway 執行並留下清理交接。

    Unified model supervised worker loop: verify the plan digest and pre-call integrity,
    execute through the Gateway, and leave a cleanup handoff."""
    report = read_report(root, run_id)
    path = root / 'artifacts' / run_id / 'report.json'
    task = mode or ('blind-review' if report.get('task') == 'blind-review' else 'smoke')
    # 磁碟上的報告與 supervisor 的計畫不同時，一次呼叫都不發，也不寫報告。 / Make no call and write nothing when the
    # report on disk differs from the supervisor's plan.
    if (report.get('task') == 'blind-review') != (task == 'blind-review') or current_plan_digest(report) != plan_digest:
        return 2
    # 限額只取自計畫，不另行重算。 / The limits come from the plan only and are never recomputed.
    gateway = Gateway(Limits(**report['limits']))
    report['calls'] = gateway.evidence
    current_task, loop = asyncio.current_task(), asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, current_task.cancel)
    current_check = None

    def save():
        report.update(reserved_calls=gateway.calls, reserved_output_tokens=gateway.reserved_tokens)
        persist(path, report)

    def checkpoint():
        if task == 'blind-review' and gateway.evidence and current_check is not None:
            call = gateway.evidence[-1]
            call.update(case_id=current_check['case_id'], review_id=current_check['review_id'])
            if 'round_index' in current_check:
                call['round_index'] = current_check['round_index']
            current_check['call_id'] = call['call_id']
        save()

    gateway.checkpoint = checkpoint
    try:
        cases = archived_cases(path.parent, report) if task == 'blind-review' else None
        if task == 'blind-review':
            precondition_failed = (
                cases is None
                or file_digest(config.ROOT / 'security/model-roe.json') != report['model_roe_sha256']
                or implementation_unchanged(report) is False
            )
            if precondition_failed:
                # 呼叫前須核對計畫綁定的目錄、RoE 與實作；不可先花費再偵測。 / Calls must use the catalog, RoE and
                # implementation the plan was bound to; never spend first, detect later.
                report['code'] = 'CONFIGURATION'
                for check in report['checks']:
                    check.update(status='ERROR', code='CONFIGURATION')
        else:
            # 計畫後被改的模型程式不可發出任何呼叫。 / Model code changed after planning makes no call.
            precondition_failed = not implementation_unchanged(report)

        for check in report['checks']:
            if task == 'blind-review' and check['status'] != 'NOT_RUN':
                continue
            if task == 'smoke' and precondition_failed:
                check.update(status='ERROR', code='CONFIGURATION')
                save()
                continue
            current_check = check
            check['status'] = 'RUNNING'
            save()
            provider = check['provider']
            try:
                seconds = call_seconds(report['deadline_policy'], provider)
                if task == 'blind-review':
                    adapter = (MockReviewer(provider) if provider.startswith('mock-')
                               else config.configured_adapter(provider, report['model_roe_sha256'],
                                                              run_directory(root, run_id),
                                                              JsonHTTP(timeout_seconds=seconds)))
                else:
                    adapter = config.configured_adapter(provider, report['model_roe_sha256'],
                                                        run_directory(root, run_id),
                                                        None if provider == 'mock' else JsonHTTP(timeout_seconds=seconds))
            except (KeyError, ModelError):
                check.update(status='ERROR', code='CONFIGURATION')
                save()
                continue
            if task == 'blind-review':
                case = cases[check['case_id']]
                before = len(gateway.evidence)
                try:
                    reply = await gateway.generate(
                        adapter, review_request(case, check['review_id'], report['output_tokens_per_review']), seconds)
                finally:
                    if len(gateway.evidence) > before:
                        checkpoint()
                    else:
                        save()
                if reply is None:
                    check.update(status='ERROR', code=gateway.evidence[-1]['code'],
                                 diagnostic=gateway.evidence[-1].get('diagnostic'))
                else:
                    try:
                        value = parse_review(reply.text, case, check['review_id'])
                    except ModelError as exc:
                        check.update(status='ERROR', code='REVIEW_' + exc.code, diagnostic=exc.detail)
                    else:
                        # 原始文字將此審查綁定自身呼叫的 response_sha256。 / The raw text binds this review to its own call's response_sha256.
                        check.update(status='SUCCESS', review=value,
                                     review_sha256=digest(json.dumps(value, sort_keys=True)),
                                     response_text=reply.text)
            else:
                reply = await gateway.generate(adapter, FIXTURE, seconds)
                if reply is not None and reply.text.strip() == 'EPSILON_SYNTHETIC_OK':
                    check['status'] = 'SUCCESS'
                else:
                    check['status'] = 'ERROR'
                    check['code'] = gateway.evidence[-1]['code'] or 'FIXTURE_MISMATCH'
            save()
        if all(c['status'] == 'SUCCESS' for c in report['checks']):
            report['pending_status'] = 'COMPLETE'
    except asyncio.CancelledError:
        report['code'] = 'CANCELLED'
        if task == 'blind-review':
            for check in report['checks']:
                if check['status'] == 'RUNNING':
                    check.update(status='CANCELLED', code='CANCELLED')
    finally:
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(sig)
        report['status'] = 'AWAITING_CLEANUP'
        report.setdefault('pending_status', 'INCOMPLETE')
        save()
    return 0 if report['pending_status'] == 'COMPLETE' else 1


class ModelRun:
    """model 角色在受監督執行中的生命週期控制代碼：管理計畫封存、worker 啟動與收尾證據驗證。

    Lifecycle handle for the model role in a supervised run: manages plan archiving, worker launch,
    and closing the worker's report into validated evaluation evidence.
    """
    operation, ceiling = 'model-smoke', MAX_TOTAL_SECONDS

    def __init__(self, root, run_id, providers=(), expected_report=None, *, inputs=None):
        self.root, self.run_id = root, run_id
        self.providers = list(providers or (expected_report or {}).get('providers', ()))
        self.report = expected_report
        self.expected_report = copy.deepcopy(expected_report) if expected_report is not None else None
        self.inputs = inputs
        self.extra_output = None

    @property
    def path(self):
        return self.root / 'artifacts' / self.run_id / 'report.json'

    @property
    def digest(self):
        return plan_digest(self.report)

    @property
    def deadline_warning(self):
        return deadline_warning(self.report)

    def record(self, extra_output=None):
        """寫入計畫報告並封存其評分輸入；回傳 self 供串接呼叫。 / Write the planned report and archive its inputs; return self."""
        if extra_output is not None and extra_output != self.path:
            self.extra_output = extra_output
            self.report['canonical_report'] = str(self.path)
        record(self.path, self.report, self.inputs)
        if self.extra_output is not None:
            self.extra_output.parent.mkdir(parents=True, exist_ok=True)
            with self.extra_output.open('x', encoding='utf-8') as handle:
                json.dump(self.report, handle)
        self.expected_report = copy.deepcopy(self.report)
        return self

    def supervise(self, command=None, max_seconds=None):
        """啟動受監督執行：若尚未封存且使用預設 worker 命令則先完成封存，再交由 supervision.supervise 執行。

        Start the supervised run: archive the plan first when using the default worker command,
        then delegate to supervision.supervise."""
        if command is None and not (self.path.parent / INPUTS).exists():
            self.record()
        mode = 'blind-review' if (self.report or {}).get('task') == 'blind-review' else 'smoke'
        command = ([sys.executable, '-I', str(config.ROOT / 'scripts/model_worker.py'),
                    str(self.root), self.run_id, mode, self.digest] if command is None else command)
        max_seconds = self.report['total_timeout_seconds'] if max_seconds is None else max_seconds
        return supervision.supervise(self.root, self.run_id, self, command,
                                     model_worker_environment(os.environ, set(self.providers)), max_seconds)

    def run_worker(self, plan_digest=None):
        """於同程序內準備執行清冊並執行模型 worker（供離線測試使用）。

        Prepare the run inventory and execute the model worker in-process for offline tests."""
        if not run_directory(self.root, self.run_id).exists():
            prepare_run(self.root, self.run_id, operation=self.operation)
        mode = 'blind-review' if (self.report or {}).get('task') == 'blind-review' else 'smoke'
        return asyncio.run(run_worker(self.root, self.run_id,
                                      self.digest if plan_digest is None else plan_digest, mode=mode))

    def finish(self, returncode=None, *, stop=None):
        """在清理鎖下以 Ended 監督結果完成收尾協定。 / Finalize with an Ended supervision outcome under the cleanup lock."""
        with supervision.finalization_lock(run_directory(self.root, self.run_id)):
            return supervision.close_run(self.root, self.run_id, self,
                                         supervision.Ended(stop, returncode, time.monotonic()))[1]

    def collect(self):
        """依序完成計畫封存、同程序 worker 執行與正式收尾協定。 / Record the plan, run the worker in-process and finalize."""
        if not self.path.exists():
            self.record()
        code = self.run_worker()
        return self.finish(returncode=code)

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
                data['analysis'] = summarize(data, (expected_report or {}).get('plan'),
                                             self.root / 'artifacts' / self.run_id)
                # 盲審 worker 也綁定 supervisor 交付的不可變計畫、預算與請求摘要。 / Blind-review workers are bound to
                # the supervisor's immutable plan, budget and request digests too.
                if expected_report is not None and plan_digest(data) != plan_digest(expected_report):
                    raise ValueError('blind review differs from the supervisor plan')
            except Exception:
                completed = False
                data.update(analysis=None, code='EVALUATION_INVALID')
        elif expected_report is not None:
            # Smoke worker 也綁定 supervisor 不可變計畫與限額。 / Smoke workers are bound to the supervisor's immutable plan and limits too.
            try:
                validate_reservations(data, expected_report['max_output_tokens_per_call'], require_all=True)
                reservations_valid = True
            except ValueError:
                reservations_valid = False
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
        if self.extra_output is not None:
            persist(self.extra_output, data)
        return data


def plan_smoke(providers=('mock',), run_id=None, *, root=None, roe_raw=None):
    """建立 smoke 計畫與 ModelRun 控制代碼。 / Create a smoke plan and its ModelRun handle."""
    root = config.ROOT if root is None else root
    run_id = str(uuid.uuid4()) if run_id is None else run_id
    roe_raw = (config.ROOT / 'security/model-roe.json').read_bytes() if roe_raw is None else roe_raw
    report = initial_smoke_report(providers, run_id, roe_raw)
    return ModelRun(root, run_id, report['providers'], report, inputs={'model-roe.json': roe_raw})


def plan_review(providers=('mock-review-a', 'mock-review-b'), case_ids=None, run_id=None,
                output_tokens=OUTPUT_TOKENS, rounds=1, *, root=None, inputs=None):
    """建立盲審計畫與 ModelRun 控制代碼。 / Create a blind-review plan and its ModelRun handle."""
    root = config.ROOT if root is None else root
    run_id = str(uuid.uuid4()) if run_id is None else run_id
    inputs = snapshot_inputs() if inputs is None else inputs
    case_ids = list(SUITES['injection']) if case_ids is None else list(case_ids)
    report = initial_review_report(providers, case_ids, run_id, output_tokens, rounds, inputs)
    return ModelRun(root, run_id, report['providers'], report, inputs=inputs)


def collect_review(root, providers=None, case_ids=None, *, output_tokens=OUTPUT_TOKENS, rounds=1):
    """在指定根目錄完成盲審規劃、封存、同程序 worker 執行與收尾，回傳 (報告, 路徑)。

    Plan, archive, run the worker in-process and finalize a blind review under root, returning (report, path)."""
    run = plan_review(providers or ['mock-review-a', 'mock-review-b'],
                      case_ids or list(SUITES['injection']),
                      output_tokens=output_tokens, rounds=rounds, root=root)
    return run.collect(), run.path


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
    return child_environment(environ, frozenset().union(*(config.PROVIDER_ENV.get(p, ()) for p in providers)))


def supervise(root, report, command=None, max_seconds=None):
    if isinstance(report, ModelRun):
        return report.supervise(command, max_seconds)
    run_id = report['run_id']
    return ModelRun(root, run_id, report['providers'], report).supervise(command, max_seconds)
