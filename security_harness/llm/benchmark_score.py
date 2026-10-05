"""Local reference scoring and unsigned human review notes; no model voting gate."""
import hashlib
import itertools
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .benchmark import (CASES_PATH, ORACLE_PATH, CWES, load_cases, case_digest, review_request,
                        request_digest, validate_review, bounded_text)
from .gateway import digest
from .transport import strict_json


def file_digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def signature(review):
    return review['verdict'], tuple(sorted((f['cwe'], f['line']) for f in review['findings']))


def reference():
    data = strict_json(ORACLE_PATH.read_bytes())
    cases = load_cases()
    if data['version'] != 'synthetic-review-v1' or set(data['cases']) != set(cases):
        raise ValueError('reference does not match catalog')
    for key, value in data['cases'].items():
        if (set(value) != {'verdict', 'findings'} or value['verdict'] not in ('VULNERABLE', 'CLEAN') or
                bool(value['findings']) != (value['verdict'] == 'VULNERABLE')):
            raise ValueError('invalid reference')
        for finding in value['findings']:
            if (set(finding) != {'cwe', 'line'} or finding['cwe'] not in CWES or
                    type(finding['line']) is not int or not 1 <= finding['line'] <= len(cases[key]['source'].splitlines())):
                raise ValueError('invalid reference location')
    return data['cases']


def validate_collection(report, expected_plan=None):
    cases = load_cases()
    if (report.get('task') != 'blind-review' or report.get('advisory_only') is not True or
            report.get('case_catalog_sha256') != file_digest(CASES_PATH) or
            report.get('oracle_sha256') != file_digest(ORACLE_PATH)):
        raise ValueError('stale or invalid benchmark identity')
    plan, checks, calls = report['plan'], report['checks'], report['calls']
    output_tokens = report.get('output_tokens_per_review', 512)
    if type(output_tokens) is not int or output_tokens not in (512, 1024) or output_tokens * len(plan) > 8192:
        raise ValueError('invalid review budget')
    if expected_plan is not None and plan != expected_plan:
        raise ValueError('worker changed the review plan')
    providers, selected = report['selected_providers'], report['case_ids']
    if (not providers or len(set(providers)) != len(providers) or not selected or
            len(set(selected)) != len(selected) or not set(selected) <= set(cases) or
            not 1 <= len(plan) <= 16 or len(checks) != len(plan) or len(calls) > len(plan) or
            report['providers'] != [p['provider'] for p in plan] or
            {(p['case_id'], p['provider']) for p in plan} != set(itertools.product(selected, providers)) or
            len(plan) != len(selected) * len(providers)):
        raise ValueError('incomplete or duplicate review plan')
    tokens, used_calls = {}, set()
    call_map = {c['call_id']: c for c in calls}
    if len(call_map) != len(calls):
        raise ValueError('duplicate call evidence')
    for item, check in zip(plan, checks, strict=True):
        case = cases[item['case_id']]
        if (set(item) != {'case_id', 'provider', 'review_id', 'case_sha256'} or
                str(uuid.UUID(item['review_id'])) != item['review_id'] or
                item['case_sha256'] != case_digest(case) or any(check.get(k) != v for k, v in item.items()) or
                check['status'] not in ('SUCCESS', 'ERROR', 'NOT_RUN', 'RUNNING', 'CANCELLED')):
            raise ValueError('invalid case binding')
        if tokens.setdefault(item['case_id'], item['review_id']) != item['review_id']:
            raise ValueError('providers received different opaque identities')
        expected_request = request_digest(review_request(case, item['review_id'], output_tokens))
        if check['request_sha256'] != expected_request:
            raise ValueError('request binding mismatch')
        call_id = check.get('call_id')
        call = call_map.get(call_id)
        if call_id is not None:
            if (call is None or call_id in used_calls or call.get('provider') != item['provider'] or
                    call.get('case_id') != item['case_id'] or call.get('review_id') != item['review_id'] or
                    call.get('request_sha256') != expected_request):
                raise ValueError('call binding mismatch')
            for key in ('input_tokens', 'output_tokens', 'elapsed_ms'):
                value = call.get(key)
                if value is not None and (type(value) is not int or not 0 <= value <= 10000000):
                    raise ValueError('invalid usage evidence')
            used_calls.add(call_id)
        if check['status'] == 'SUCCESS':
            value = validate_review(check['review'], case, item['review_id'])
            if (call is None or call['status'] != 'SUCCESS' or
                    check['review_sha256'] != digest(json.dumps(value, sort_keys=True))):
                raise ValueError('unbound review')
        elif check.get('review') is not None:
            raise ValueError('failed attempt contains a trusted review')
    if used_calls != set(call_map) or len(set(tokens.values())) != len(tokens):
        raise ValueError('unexpected call or reused case identity')
    return cases


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def summarize(report, expected_plan=None):
    validate_collection(report, expected_plan)
    truth = reference()
    metrics, families = {}, set()
    lookup = {(c['case_id'], c['provider']): c for c in report['checks']}
    selected = report['case_ids']
    for provider in report['selected_providers']:
        counts = dict(tp=0, tn=0, fp=0, fn=0, abstained=0, unavailable=0,
                      matched_findings=0, reported_findings=0)
        positive_count = sum(truth[c]['verdict'] == 'VULNERABLE' for c in selected)
        expected_findings = sum(len(truth[c]['findings']) for c in selected)
        for key in selected:
            check = lookup[key, provider]
            if check['status'] != 'SUCCESS':
                counts['unavailable'] += 1
                continue
            value = check['review']
            if value['verdict'] == 'ABSTAIN':
                counts['abstained'] += 1
                continue
            actual, expected = value['verdict'] == 'VULNERABLE', truth[key]['verdict'] == 'VULNERABLE'
            counts['tp' if actual and expected else 'fp' if actual else 'fn' if expected else 'tn'] += 1
            predicted = set(signature(value)[1])
            targets = set(signature(truth[key])[1])
            counts['reported_findings'] += len(predicted)
            counts['matched_findings'] += len(predicted & targets)
        calls = [c for c in report['calls'] if c['provider'] == provider]
        if not provider.startswith('mock-'):
            families.update(c['family'] for c in calls if c['status'] == 'SUCCESS' and
                            c.get('family') not in (None, 'mock', 'unverified'))
        valid = counts['tp'] + counts['tn'] + counts['fp'] + counts['fn']
        metrics[provider] = {**counts, 'planned': len(selected), 'classified': valid,
            'coverage': ratio(valid, len(selected)),
            'false_positive_rate_valid': ratio(counts['fp'], counts['fp'] + counts['tn']),
            'false_negative_rate_valid': ratio(counts['fn'], counts['fn'] + counts['tp']),
            'positive_miss_rate_all': ratio(positive_count - counts['tp'], positive_count),
            'finding_precision': ratio(counts['matched_findings'], counts['reported_findings']),
            'finding_recall_all': ratio(counts['matched_findings'], expected_findings),
            'calls_recorded': len(calls),
            'input_tokens_reported': sum(c.get('input_tokens') or 0 for c in calls) if any(c.get('input_tokens') is not None for c in calls) else None,
            'output_tokens_reported': sum(c.get('output_tokens') or 0 for c in calls) if any(c.get('output_tokens') is not None for c in calls) else None,
            'usage_complete': bool(calls) and all(c.get('input_tokens') is not None and c.get('output_tokens') is not None for c in calls),
            'elapsed_ms_reported': sum(c.get('elapsed_ms') or 0 for c in calls),
            'monetary_cost': None}
    pairs = []
    for left, right in itertools.combinations(report['selected_providers'], 2):
        comparable, disagreed = 0, 0
        for key in selected:
            a, b = lookup[key, left], lookup[key, right]
            if any(c['status'] != 'SUCCESS' or c['review']['verdict'] == 'ABSTAIN' for c in (a, b)):
                continue
            comparable += 1
            disagreed += signature(a['review']) != signature(b['review'])
        pairs.append({'providers': [left, right], 'comparable': comparable, 'planned': len(selected),
                      'disagreements': disagreed, 'rate_comparable': ratio(disagreed, comparable)})
    decisions = []
    for key in selected:
        rows = [lookup[key, p] for p in report['selected_providers']]
        valid = [c['review'] for c in rows if c['status'] == 'SUCCESS']
        reasons = []
        if len(rows) < 2:
            reasons.append('SINGLE_REVIEWER')
        if len(valid) != len(rows):
            reasons.append('INCOMPLETE_REVIEW')
        if any(r['verdict'] == 'ABSTAIN' for r in valid):
            reasons.append('ABSTAIN')
        if len({signature(r) for r in valid}) > 1:
            reasons.append('DISAGREEMENT')
        if any(signature(r) != signature(truth[key]) for r in valid):
            reasons.append('REFERENCE_MISMATCH')
        decisions.append({'case_id': key, 'status': 'PENDING_HUMAN_REVIEW' if reasons else 'REFERENCE_MATCH',
                          'reasons': reasons, 'reference': truth[key]})
    return {'advisory_only': True, 'provider_metrics': metrics, 'pairwise': pairs,
            'adjudication': decisions, 'live_family_labels_observed': sorted(families),
            'bias_reduction': 'NOT_ESTABLISHED', 'security_gate_effect': 'NONE',
            'limits': f'{len(selected)} selected synthetic snippets in their declared scope; not product or ASVS coverage.'}


def add_adjudication(report_path, case_id, decision, reviewer, reason):
    raw = report_path.read_bytes()
    if len(raw) > 262144:
        raise ValueError('report too large')
    report = strict_json(raw)
    summarize(report)
    if (report_path.name != 'report.json' or report_path.parent.name != report['run_id'] or
            case_id not in report['case_ids'] or decision not in
            ('REFERENCE_CONFIRMED', 'REFERENCE_CHALLENGED', 'NEEDS_MORE_EVIDENCE') or
            not bounded_text(reviewer) or not bounded_text(reason)):
        raise ValueError('invalid adjudication')
    entry = {'schema_version': 1, 'note_id': str(uuid.uuid4()), 'run_id': report['run_id'],
             'report_sha256': hashlib.sha256(raw).hexdigest(), 'case_id': case_id,
             'decision': decision, 'asserted_reviewer': reviewer, 'reason': reason,
             'created_at': datetime.now(timezone.utc).isoformat(),
             'identity_verified': False, 'advisory_only': True, 'security_gate_effect': 'NONE'}
    path = report_path.parent / 'adjudications' / (entry['note_id'] + '.json')
    path.parent.mkdir(exist_ok=True)
    with path.open('x') as handle:
        json.dump(entry, handle, ensure_ascii=False, indent=2)
    return path


def note_matches_report(note, report_path):
    return (note.get('report_sha256') == file_digest(report_path) and
            note.get('run_id') == report_path.parent.name and note.get('advisory_only') is True and
            note.get('security_gate_effect') == 'NONE')
