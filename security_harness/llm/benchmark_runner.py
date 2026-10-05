"""Supervised, bounded collection of independent reviews of fixed synthetic cases."""
import asyncio
import json
import signal
import uuid
from dataclasses import asdict
from datetime import datetime, timezone

from .benchmark import (CASES_PATH, ORACLE_PATH, OUTPUT_TOKENS, MockReviewer, load_cases,
                        make_plan, review_request, request_digest, parse_review)
from .gateway import Gateway, Limits, ModelError, digest
from .lifecycle import persist, read_report
from .transport import JsonHTTP
from ..lifecycle import run_directory


def initial_report(providers, case_ids, run_id, output_tokens=OUTPUT_TOKENS, rounds=1):
    from .benchmark_score import file_digest
    from scripts.model_smoke import implementation_digest, ROOT
    cases, plan = load_cases(), make_plan(providers, case_ids, rounds)
    if type(output_tokens) is not int or output_tokens not in (512, 1024):
        raise ValueError('invalid review output budget')
    limits = Limits(max_calls=len(plan), reserved_output_tokens=output_tokens * len(plan), timeout_seconds=30)
    implementation = [implementation_digest(), file_digest(ROOT / 'scripts/model_review.py'),
                      file_digest(ROOT / 'scripts/review_adjudicate.py')]
    checks = [{**p, 'status': 'NOT_RUN', 'code': None, 'review': None, 'call_id': None,
               'request_sha256': request_digest(review_request(cases[p['case_id']], p['review_id'], output_tokens))}
              for p in plan]
    return {'schema_version': 2, 'operation': 'model-smoke', 'task': 'blind-review', 'run_id': run_id,
            'advisory_only': True, 'data_class': 'synthetic', 'status': 'INCOMPLETE', 'code': None,
            'started_at': datetime.now(timezone.utc).isoformat(),
            'implementation_sha256': digest(json.dumps(implementation)),
            'case_catalog_sha256': file_digest(CASES_PATH), 'oracle_sha256': file_digest(ORACLE_PATH),
            'rounds': rounds, 'sampling_policy': {p: ('provider-default' if p == 'bedrock' else 'temperature=0' if not p.startswith('mock-') else 'deterministic-fixture') for p in providers},
            'selected_providers': providers, 'case_ids': case_ids, 'plan': plan,
            'providers': [p['provider'] for p in plan], 'checks': checks, 'calls': [],
            'limits': asdict(limits), 'total_timeout_seconds': min(130, 20 * len(plan) + 10),
            'output_tokens_per_review': output_tokens,
            'cleanup': {'completed': False}, 'analysis': None}


async def run_worker(root, run_id):
    from scripts.model_smoke import configured_adapter
    report = read_report(root, run_id)
    cases = load_cases()
    path = root / 'artifacts' / run_id / 'report.json'
    gateway = Gateway(Limits(**report['limits']))
    report['calls'] = gateway.evidence
    task, loop = asyncio.current_task(), asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, task.cancel)

    def save():
        report.update(reserved_calls=gateway.calls, reserved_output_tokens=gateway.reserved_tokens)
        persist(path, report)

    try:
        for check in report['checks']:
            check['status'] = 'RUNNING'
            save()
            provider, case = check['provider'], cases[check['case_id']]
            try:
                adapter = MockReviewer(provider) if provider.startswith('mock-') else configured_adapter(provider, run_directory(root, run_id), JsonHTTP(timeout_seconds=30))
            except (KeyError, ModelError):
                check.update(status='ERROR', code='CONFIGURATION')
                save()
                continue
            before = len(gateway.evidence)
            try:
                reply = await gateway.generate(adapter, review_request(case, check['review_id'], report['output_tokens_per_review']))
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
                    check.update(status='SUCCESS', review=value, review_sha256=digest(json.dumps(value, sort_keys=True)))
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
