"""跨批次參考統計；Cross-batch advisory statistics with explicit comparability checks."""
from collections import Counter
import hashlib
import math
import re
import uuid

from .benchmark_score import load_cases, reference, report_inputs, summarize, ratio
from .lifecycle import REPORT_LIMIT
from .transport import strict_json
from ..results import read_regular


def wilson(successes, total, z=1.959963984540054):
    """95% Wilson 分數區間；分母為 0 時為 None。 / The 95% Wilson score interval; None for an empty denominator."""
    if not total:
        return None
    p = successes / total
    centre = (p + z * z / (2 * total)) / (1 + z * z / total)
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / (1 + z * z / total)
    return {'low': round(max(0.0, centre - half), 4), 'high': round(min(1.0, centre + half), 4), 'n': total}


def compare(paths):
    """拒絕重播與混版；Reject replayed reports and incompatible experiment versions."""
    if not 1 <= len(paths) <= 32:
        raise ValueError('report count / 報告數量超限')
    reports, proofs, seen_runs, seen_calls, seen_reviews = [], [], set(), set(), set()
    pins = None
    labels = {}
    case_rounds = Counter()
    for path in paths:
        raw = read_regular(path, REPORT_LIMIT)
        report = strict_json(raw)
        run = report['run_id']
        if (str(uuid.UUID(run)) != run or run in seen_runs
                or report.get('status') not in ('COMPLETE', 'INCOMPLETE')
                or report.get('cleanup', {}).get('completed') is not True):
            raise ValueError('duplicate or unfinished report / 重複或未清理的報告')
        seen_runs.add(run)
        inputs = report_inputs(report, path.parent)
        analysis = summarize(report, run_dir=path.parent)
        if report.get('analysis') != analysis:
            raise ValueError('analysis mismatch / 分析內容不一致')
        fields = ('implementation_sha256', 'case_catalog_sha256', 'oracle_sha256', 'model_roe_sha256')
        if any(not re.fullmatch('[a-f0-9]{64}', report.get(k, '')) for k in fields):
            raise ValueError('missing version binding / 缺少版本綁定')
        identity = ([report[k] for k in fields], report['selected_providers'],
                    report['output_tokens_per_review'], report['sampling_policy'])
        if pins is not None and identity != pins:
            raise ValueError('incompatible experiment / 實驗設定不相容')
        pins = identity
        calls = {c['call_id'] for c in report['calls']}
        reviews = {p['review_id'] for p in report['plan']}
        if seen_calls & calls or seen_reviews & reviews:
            raise ValueError('replayed observations / 重播的觀測結果')
        seen_calls.update(calls); seen_reviews.update(reviews)
        if {c['provider'] for c in report['calls']} != set(report['selected_providers']):
            raise ValueError('missing model identity / 缺少模型識別')
        for call in report['calls']:
            label = call.get('model_label')
            provider = call['provider']
            if (not label or label == 'redacted' or label.startswith('arn-redacted:')
                    or (provider in labels and labels[provider] != label)):
                raise ValueError('model identity cannot be compared / 無法比較模型識別')
            labels[provider] = label
        for case in report['case_ids']:
            case_rounds[case] += report.get('rounds', 1)
        reports.append((report, analysis))
        proofs.append({'run_id': run, 'report_sha256': hashlib.sha256(raw).hexdigest(),
                       'status': report['status'], 'cases': report['case_ids'], 'rounds': report.get('rounds', 1)})
    if len(set(case_rounds.values())) != 1:
        raise ValueError('unbalanced case repetitions / 各案例輪次不一致')
    # 所有報告綁定同一份標準答案（版本綁定已比對），取最後一份的封存或目前輸入。 / Every report binds the same
    # reference (the version pins match), so the last report's archived or current inputs serve all.
    truth = reference(inputs['oracle.json'], load_cases(inputs['catalog.json']))
    positives = sum(n for case, n in case_rounds.items() if truth[case]['verdict'] == 'VULNERABLE')
    metrics = {}
    for provider in pins[1]:
        rows = [a['provider_metrics'][provider] for _, a in reports]
        fields = ('tp', 'tn', 'fp', 'fn', 'abstained', 'unavailable', 'planned', 'classified')
        m = {k: sum(r[k] for r in rows) for k in fields}
        m.update(coverage=ratio(m['classified'], m['planned']),
                 false_positive_rate_valid=ratio(m['fp'], m['fp'] + m['tn']),
                 false_negative_rate_valid=ratio(m['fn'], m['fn'] + m['tp']),
                 positive_miss_rate_all=ratio(positives - m['tp'], positives))
        # 每個比率附 95% Wilson 區間與分母；小樣本的點估計不能單獨解讀。 / Each rate carries a 95% Wilson interval and
        # its denominator; a point estimate from a small sample cannot be read alone.
        m['intervals_95'] = {
            'coverage': wilson(m['classified'], m['planned']),
            'false_positive_rate_valid': wilson(m['fp'], m['fp'] + m['tn']),
            'false_negative_rate_valid': wilson(m['fn'], m['fn'] + m['tp']),
            'positive_miss_rate_all': wilson(positives - m['tp'], positives)}
        metrics[provider] = m
    return {'schema_version': 1, 'advisory_only': True, 'security_gate_effect': 'NONE',
            'bias_reduction': 'NOT_ESTABLISHED', 'identity_verified': False,
            'serving_revision_consistency': 'NOT_VERIFIED_ACROSS_RUNS',
            'limitations': 'Unsigned reports; repeated observations are not independent samples. / 未簽章報告；重複觀測不是獨立樣本。',
            'reports': proofs, 'case_rounds': dict(sorted(case_rounds.items())),
            'configured_model_labels': labels, 'provider_metrics': metrics}
