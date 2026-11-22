"""跨批次版本、重播與分母回歸；Cross-batch version, replay and denominator regressions."""
import json
import pytest

from tests.test_model_benchmark import collected
from security_harness.llm.comparison import compare


def test_balanced_batches_preserve_reference_metrics_and_limits(tmp_path):
    _, a = collected(tmp_path / 'a', case_ids=['B01', 'B02'])
    _, b = collected(tmp_path / 'b', case_ids=['B03', 'B04'])
    result = compare([a, b])
    assert result['provider_metrics']['mock-review-a']['tp'] == 2
    assert result['provider_metrics']['mock-review-a']['tn'] == 2
    assert result['bias_reduction'] == 'NOT_ESTABLISHED'
    assert result['serving_revision_consistency'] == 'NOT_VERIFIED_ACROSS_RUNS'


@pytest.mark.parametrize('attack', ['duplicate', 'implementation', 'sampling', 'cleanup', 'analysis', 'replay', 'unbalanced', 'model'])
def test_incompatible_or_replayed_batches_are_rejected(tmp_path, attack):
    first, a = collected(tmp_path / 'a', case_ids=['B01', 'B02'])
    data, b = collected(tmp_path / 'b', case_ids=['B01'] if attack == 'unbalanced' else ['B01', 'B02'])
    if attack == 'duplicate': b = a
    elif attack == 'implementation': data['implementation_sha256'] = 'a' * 64
    elif attack == 'sampling': data['sampling_policy']['mock-review-a'] = 'unknown'
    elif attack == 'cleanup': data['cleanup']['completed'] = False
    elif attack == 'analysis': data['analysis']['provider_metrics']['mock-review-a']['tp'] = 999
    elif attack == 'replay': data['run_id'] = first['run_id']
    elif attack == 'model':
        for c in data['calls']: c['model_label'] = 'changed-model'
    if b != a: b.write_text(json.dumps(data))
    with pytest.raises(ValueError, match='^(?:analysis\\ mismatch\\ /\\ 分析內容不一致|duplicate\\ or\\ unfinished\\ report\\ /\\ 重複或未清理的報告|incompatible\\ experiment\\ /\\ 實驗設定不相容|model\\ identity\\ cannot\\ be\\ compared\\ /\\ 無法比較模型識別|sampling\\ policy\\ mismatch|unbalanced\\ case\\ repetitions\\ /\\ 各案例輪次不一致)$'): compare([a, b])


def test_configuration_failure_without_model_identity_cannot_be_pooled(tmp_path, monkeypatch):
    from security_harness.llm import config as model_config
    from security_harness.llm.gateway import ModelError
    def unavailable(*args):
        raise ModelError('CONFIGURATION')
    monkeypatch.setattr(model_config, 'configured_adapter', unavailable)
    report, path = collected(tmp_path, providers=['lmstudio'], case_ids=['B13', 'B14'])
    assert report['cleanup']['completed'] and report['status'] == 'INCOMPLETE'
    assert report['analysis']['provider_metrics']['lmstudio']['positive_miss_rate_all'] == 1
    with pytest.raises(ValueError, match='missing model identity'):
        compare([path])


@pytest.mark.parametrize("successes,total,low,high", [(0, 10, 0.0, 0.2775), (5, 10, 0.2366, 0.7634),
                                                      (10, 10, 0.7225, 1.0), (1, 1, 0.2065, 1.0)])
def test_wilson_interval_matches_reference_values(successes, total, low, high):
    from security_harness.llm.comparison import wilson
    assert wilson(successes, total) == {'low': low, 'high': high, 'n': total}


def test_empty_denominator_has_no_interval():
    from security_harness.llm.comparison import wilson
    assert wilson(0, 0) is None


def test_every_pooled_rate_carries_its_interval(tmp_path):
    _, a = collected(tmp_path / 'a', case_ids=['B01', 'B02'])
    _, b = collected(tmp_path / 'b', case_ids=['B03', 'B04'])
    result = compare([a, b])
    for metrics in result['provider_metrics'].values():
        assert set(metrics['intervals_95']) == {'coverage', 'false_positive_rate_valid',
                                                'false_negative_rate_valid', 'positive_miss_rate_all'}
        coverage = metrics['intervals_95']['coverage']
        assert coverage['n'] == metrics['planned'] and coverage['low'] <= metrics['coverage'] <= coverage['high']


@pytest.mark.parametrize("successes,observations,repeats,expected", [
    # 單輪：與一般 Wilson 區間相同。 / One round: the plain Wilson interval.
    (5, 10, 1, {'low': 0.2366, 'high': 0.7634, 'n': 10, 'effective_n': 10.0}),
    # 同樣的比率重複 4 輪：樣本仍是 10 個案例，區間不變窄。 / The same rate over four rounds: still ten cases, so the
    # interval is no narrower.
    (20, 40, 4, {'low': 0.2366, 'high': 0.7634, 'n': 40, 'effective_n': 10.0}),
    (0, 40, 4, {'low': 0.0, 'high': 0.2775, 'n': 40, 'effective_n': 10.0}),
    # 部分輪次沒有有效分類時，樣本數可以不是整數。 / With rounds missing a valid classification the size may be fractional.
    (3, 6, 4, {'low': 0.076, 'high': 0.924, 'n': 6, 'effective_n': 1.5}),
])
def test_interval_counts_distinct_cases_not_repeated_rounds(successes, observations, repeats, expected):
    """重複觀測不是獨立樣本：區間以觀測數除以輪數為樣本數，重複輪次不會讓區間變窄。

    Repeated observations are not independent samples: the interval uses the observations divided by the rounds, so
    repeating rounds never narrows it."""
    from security_harness.llm.comparison import case_interval, wilson
    assert case_interval(successes, observations, repeats) == expected
    naive = wilson(successes, observations)
    assert expected['high'] - expected['low'] >= naive['high'] - naive['low']
    assert case_interval(0, 0, repeats) is None


def test_pooled_intervals_of_repeated_cases_use_the_case_count(tmp_path):
    """同一組案例跨兩份報告各跑一輪：n 是觀測數，區間以案例數計算。

    The same cases run once in each of two reports: n is the observations and the interval counts the cases."""
    from security_harness.llm.comparison import wilson
    _, a = collected(tmp_path / 'a', case_ids=['B01', 'B02'])
    _, b = collected(tmp_path / 'b', case_ids=['B01', 'B02'])
    result = compare([a, b])
    assert result['case_rounds'] == {'B01': 2, 'B02': 2}
    assert 'intervals count distinct cases' in result['limitations']
    for metrics in result['provider_metrics'].values():
        coverage = metrics['intervals_95']['coverage']
        assert (coverage['n'], coverage['effective_n']) == (metrics['planned'], metrics['planned'] / 2) == (4, 2.0)
        cases = wilson(metrics['classified'] / 2, 2)
        assert (coverage['low'], coverage['high']) == (cases['low'], cases['high'])
        observations = wilson(metrics['classified'], 4)
        assert coverage['high'] - coverage['low'] > observations['high'] - observations['low']

