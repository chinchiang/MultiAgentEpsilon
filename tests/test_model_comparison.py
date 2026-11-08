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
