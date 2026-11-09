"""受監督且有限額地收集固定合成案例的獨立審查。

Supervised, bounded collection of independent reviews of fixed synthetic cases."""
import asyncio
import hashlib
import json
import signal
from dataclasses import asdict
from datetime import datetime, timezone

from .benchmark import (CASES_PATH, ORACLE_PATH, OUTPUT_BUDGETS, OUTPUT_TOKENS, MockReviewer, load_cases,
                        make_plan, review_request, request_digest, parse_review)
from .gateway import Gateway, Limits, ModelError, digest
from .lifecycle import REPORT_VERSION, archive_inputs, plan_digest as current_plan_digest, read_report
from .transport import JsonHTTP, strict_json
from ..scope import call_seconds, run_seconds, valid_deadline_policy
from ..supervision import persist, run_directory

# 封存的評分輸入：檔名對應目前路徑。 / Archived scoring inputs: each name and its current path.
INPUT_FILES = {'catalog.json': CASES_PATH, 'oracle.json': ORACLE_PATH}


def snapshot_inputs():
    """一次讀取案例目錄、標準答案與模型 RoE 的位元組；計畫的雜湊與封存副本都取自這份快照。

Read the case catalog, reference and model RoE bytes once; both the plan's digests and the
    archived copies come from this snapshot."""
    from .config import ROOT
    return {**{name: path.read_bytes() for name, path in INPUT_FILES.items()},
            'model-roe.json': (ROOT / 'security/model-roe.json').read_bytes()}


def record(path, report, inputs=None):
    """寫入計畫報告並封存其評分輸入；supervisor 啟動 worker 前呼叫。inputs 須是 initial_report 用的同一份快照。

Write the planned report and archive its scoring inputs before the supervisor starts the
    worker. inputs must be the same snapshot initial_report used."""
    persist(path, report)
    archive_inputs(path.parent, snapshot_inputs() if inputs is None else inputs)


def deadline_policy(roe_raw):
    policy = strict_json(roe_raw).get('deadline_policy')
    if not valid_deadline_policy(policy):
        raise ValueError('invalid model deadline policy')
    return policy


def digest_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def implementation_sha256():
    """盲審計畫綁定的實作雜湊：模型層實作與兩支盲審腳本。計畫與 worker 都以此計算。 / The implementation digest a
    blind-review plan binds: the model layer plus the two blind-review scripts. The plan and the worker both use it."""
    from . import config
    from .benchmark_score import file_digest
    return digest(json.dumps([config.implementation_digest(), file_digest(config.ROOT / 'scripts/model_review.py'),
                              file_digest(config.ROOT / 'scripts/review_adjudicate.py')]))


def implementation_unchanged(report):
    """worker 讀到的實作是否仍是計畫綁定的那一份；無法讀取即視為已變更。 / Whether the implementation the worker reads is
    still the one the plan bound; an unreadable implementation counts as changed."""
    try:
        return implementation_sha256() == report['implementation_sha256']
    except OSError:
        return False


def initial_report(providers, case_ids, run_id, output_tokens=OUTPUT_TOKENS, rounds=1, inputs=None):
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
            'case_catalog_sha256': digest_bytes(inputs['catalog.json']), 'oracle_sha256': digest_bytes(inputs['oracle.json']),
            'model_roe_sha256': digest_bytes(inputs['model-roe.json']), 'deadline_policy': policy,
            'rounds': rounds, 'sampling_policy': {p: ('provider-default' if p == 'bedrock' else 'temperature=0' if not p.startswith('mock-') else 'deterministic-fixture') for p in providers},
            'selected_providers': providers, 'case_ids': case_ids, 'plan': plan,
            'providers': [p['provider'] for p in plan], 'checks': checks, 'calls': [],
            'reserved_calls': 0, 'reserved_output_tokens': 0,
            'limits': asdict(limits), 'total_timeout_seconds': run_seconds(policy, planned),
            'output_tokens_per_review': output_tokens,
            'cleanup': {'completed': False}, 'analysis': None}


async def run_worker(root, run_id, plan_digest):
    from . import config
    report = read_report(root, run_id)
    cases = load_cases()
    path = root / 'artifacts' / run_id / 'report.json'
    # 磁碟上的報告與 supervisor 的計畫不同時，一次呼叫都不發。 / Make no call at all when the report on disk
    # differs from the supervisor's plan.
    if current_plan_digest(report) != plan_digest:
        return 2
    gateway = Gateway(Limits(**report['limits']))
    report['calls'] = gateway.evidence
    task, loop = asyncio.current_task(), asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, task.cancel)

    def save():
        report.update(reserved_calls=gateway.calls, reserved_output_tokens=gateway.reserved_tokens)
        persist(path, report)

    def checkpoint():
        if gateway.evidence:
            call = gateway.evidence[-1]
            call.update(case_id=check['case_id'], review_id=check['review_id'])
            if 'round_index' in check:
                call['round_index'] = check['round_index']
            check['call_id'] = call['call_id']
        save()

    gateway.checkpoint = checkpoint

    try:
        from .benchmark_score import file_digest
        if (file_digest(CASES_PATH) != report['case_catalog_sha256']
                or file_digest(config.ROOT / 'security/model-roe.json') != report['model_roe_sha256']
                or implementation_unchanged(report) is False):
            # 呼叫前須核對計畫綁定的目錄、RoE 與實作；不可先花費再偵測。 / Calls must use the catalog, RoE and
            # implementation the plan was bound to; never spend first, detect later.
            report['code'] = 'CONFIGURATION'
            for check in report['checks']:
                check.update(status='ERROR', code='CONFIGURATION')
        for check in report['checks']:
            if check['status'] != 'NOT_RUN':
                continue
            check['status'] = 'RUNNING'
            save()
            provider, case = check['provider'], cases[check['case_id']]
            try:
                seconds = call_seconds(report['deadline_policy'], provider)
                adapter = MockReviewer(provider) if provider.startswith('mock-') else config.configured_adapter(provider, report['model_roe_sha256'], run_directory(root, run_id), JsonHTTP(timeout_seconds=seconds))
            except (KeyError, ModelError):
                check.update(status='ERROR', code='CONFIGURATION')
                save()
                continue
            before = len(gateway.evidence)
            try:
                reply = await gateway.generate(adapter, review_request(case, check['review_id'], report['output_tokens_per_review']),
                                               seconds)
            finally:
                if len(gateway.evidence) > before:
                    call = gateway.evidence[-1]
                    call.update(case_id=check['case_id'], review_id=check['review_id'])
                    if 'round_index' in check:
                        call['round_index'] = check['round_index']
                    check['call_id'] = call['call_id']
                save()
            if reply is None:
                check.update(status='ERROR', code=gateway.evidence[-1]['code'], diagnostic=gateway.evidence[-1].get('diagnostic'))
            else:
                try:
                    value = parse_review(reply.text, case, check['review_id'])
                except ModelError as exc:
                    check.update(status='ERROR', code='REVIEW_' + exc.code, diagnostic=exc.detail)
                else:
                    # 原始文字將此審查綁定自身呼叫的 response_sha256。 / The raw text binds this review to its own call's response_sha256.
                    check.update(status='SUCCESS', review=value, review_sha256=digest(json.dumps(value, sort_keys=True)),
                                 response_text=reply.text)
            save()
        if all(c['status'] == 'SUCCESS' for c in report['checks']):
            report['pending_status'] = 'COMPLETE'
    except asyncio.CancelledError:
        report['code'] = 'CANCELLED'
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
