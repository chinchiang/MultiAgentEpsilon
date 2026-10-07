"""Regression tests for review binding, text, usage, identity and child-environment hardening."""
import asyncio
import copy
import hashlib
import json

import pytest

from security_harness.llm import benchmark as bench
from security_harness.llm import benchmark_score as score
from security_harness.llm.adapters import BedrockAdapter, GeminiAdapter
from security_harness.llm.gateway import Gateway, MockAdapter, Reply
from tests.test_model_benchmark import collected
from tests.test_model_gateway import GEMINI, cli_fixture, http_fixture, invoke


def test_reviews_cannot_be_swapped_between_providers_for_the_same_case(tmp_path):
    # B06 is where the two mock reviewers disagree, so a swap changes FP/TN metrics.
    data, _ = collected(tmp_path, ['mock-review-a', 'mock-review-b'], ['B06'])
    score.summarize(data)
    a, b = data['checks']
    assert a['review'] != b['review'] and a['review_id'] == b['review_id']
    for key in ('review', 'review_sha256'):
        a[key], b[key] = b[key], a[key]
    with pytest.raises(ValueError, match='unbound review'):
        score.summarize(data)


@pytest.mark.parametrize('tamper', ['text', 'missing-text', 'call-digest', 'failed-with-text'])
def test_review_must_be_rederived_from_its_own_provider_response(tmp_path, tamper):
    data, _ = collected(tmp_path, ['mock-review-a'], ['B01', 'B02'])
    check = data['checks'][0]
    if tamper == 'text':
        check['response_text'] = check['response_text'].replace('Offline', 'Edited')
    elif tamper == 'missing-text':
        del check['response_text']
    elif tamper == 'call-digest':
        next(c for c in data['calls'] if c['call_id'] == check['call_id'])['response_sha256'] = '0' * 64
    else:
        data['checks'][1].update(status='ERROR', code='REFUSED', review=None)
        data['checks'][1]['response_text'] = data['checks'][0]['response_text']
    with pytest.raises(ValueError):
        score.summarize(data)


@pytest.mark.parametrize('text', ['C1 control \x9b here', 'line\u2028separator', 'bidi \u202eoverride',
                                  'zero\u200bwidth', 'tab\tinside', 'private \ue000 use', 'soft\u00adhyphen'])
def test_invisible_or_reordering_characters_are_rejected(text):
    assert not bench.bounded_text(text)


@pytest.mark.parametrize('text', ['Parameterized query prevents CWE-89.', '使用參數化查詢，沒有 SQL 注入。'])
def test_ordinary_text_including_cjk_is_accepted(text):
    assert bench.bounded_text(text)


def test_adjudication_refuses_a_stored_analysis_that_differs_from_the_recomputed_one(tmp_path):
    report, path = collected(tmp_path, case_ids=['B06'])
    edited = copy.deepcopy(report)
    edited['analysis']['adjudication'][0].update(status='REFERENCE_MATCH', reasons=[])
    path.write_text(json.dumps(edited))
    with pytest.raises(ValueError, match='stored analysis'):
        score.add_adjudication(path, 'B06', 'REFERENCE_CONFIRMED', 'synthetic-reviewer', 'Checked against reference.')
    path.write_text(json.dumps(report))
    assert score.add_adjudication(path, 'B06', 'REFERENCE_CONFIRMED', 'synthetic-reviewer', 'Checked against reference.')


def test_gemini_thinking_without_visible_output_count_cannot_skip_the_budget():
    value = copy.deepcopy(GEMINI)
    value['usageMetadata'] = {'promptTokenCount': 10, 'thoughtsTokenCount': 5000}
    http, _, _ = http_fixture(value)
    result, evidence = invoke(GeminiAdapter('synthetic-model', 'synthetic-key', http))
    assert result is None and evidence['code'] == 'INVALID_RESPONSE' and evidence['diagnostic'] == 'USAGE_SCHEMA'


def test_model_identity_is_keyed_per_run_and_never_the_plain_digest():
    model = 'arn:aws:bedrock:ap-southeast-1:123456789012:inference-profile/synthetic'
    first, second = Gateway(), Gateway()
    assert first.identity(model) == first.identity(model) != second.identity(model)
    assert hashlib.sha256(model.encode()).hexdigest() not in first.identity(model)


def test_provider_reported_model_drift_is_rejected(tmp_path):
    data, _ = collected(tmp_path, ['mock-review-a'], ['B01', 'B02'])
    calls = data['calls']
    calls[0]['reported_model_sha256'] = 'hmac-sha256:' + 'a' * 64
    calls[1]['reported_model_sha256'] = 'hmac-sha256:' + 'a' * 64
    score.summarize(data)
    calls[1]['reported_model_sha256'] = 'hmac-sha256:' + 'b' * 64
    with pytest.raises(ValueError, match='provider-reported model changed'):
        score.summarize(data)


def test_gateway_records_the_reported_serving_model():
    class Reporting(MockAdapter):
        async def generate(self, _):
            return Reply('ok', 1, 1, 'synthetic-model-2026-10-01')
    _, evidence = invoke(Reporting())
    assert evidence['reported_model_sha256'].startswith('hmac-sha256:')


def test_aws_cli_child_receives_only_aws_and_basic_process_context(tmp_path, monkeypatch):
    monkeypatch.setenv('GH_TOKEN', 'synthetic-github-token')
    monkeypatch.setenv('OTHER_PROVIDER_API_KEY', 'synthetic-provider-key')
    monkeypatch.setenv('AWS_PROFILE', 'synthetic-profile')
    monkeypatch.setenv('HTTPS_PROXY', 'http://proxy.invalid:3128')
    cli = cli_fixture(tmp_path, "import json, os\n"
        "assert 'GH_TOKEN' not in os.environ and 'OTHER_PROVIDER_API_KEY' not in os.environ\n"
        "assert os.environ['AWS_PROFILE'] == 'synthetic-profile'\n"
        "assert os.environ['HTTPS_PROXY'] == 'http://proxy.invalid:3128'\n"
        "print(json.dumps({'ok': True}))\n")
    assert asyncio.run(cli.converse('ap-southeast-1', {'modelId': 'synthetic'})) == {'ok': True}


@pytest.mark.parametrize('stderr,code,detail', [
    ('An error occurred (ValidationException) when calling the Converse operation: The model returned the '
     'following errors: output_config.format: Extra inputs are not permitted', 'PROVIDER_FAILURE', 'OUTPUT_CONFIGURATION'),
    ('An error occurred (ExpiredTokenException) when calling the Converse operation: The security token '
     'included in the request is expired', 'AUTHENTICATION', None),
    ('An error occurred (AccessDeniedException) when calling the Converse operation: User: '
     'arn:aws:sts::123456789012:assumed-role/synthetic/session is not authorized', 'AUTHENTICATION', None),
    ('An error occurred (ThrottlingException) when calling the Converse operation: Too many requests', 'RATE_LIMIT', None),
    ('An error occurred (ModelErrorException) when calling the Converse operation: private detail 123456789012',
     'PROVIDER_FAILURE', None),
])
def test_bedrock_cli_failures_are_classified_without_keeping_provider_text(tmp_path, stderr, code, detail):
    # Observed live: a Claude model without Bedrock structured-output support only
    # surfaced as an unexplained PROVIDER_FAILURE before.
    cli = cli_fixture(tmp_path, 'import sys\nsys.stderr.write(' + repr(stderr) + ')\nsys.exit(254)\n')
    result, evidence = invoke(BedrockAdapter('global.anthropic.claude-synthetic', 'ap-southeast-1', cli))
    assert result is None and evidence['code'] == code and evidence['diagnostic'] == detail
    dumped = json.dumps(evidence)
    assert '123456789012' not in dumped and 'arn:aws' not in dumped and 'Extra inputs' not in dumped


def test_chatty_cli_stderr_cannot_block_the_response_or_be_stored(tmp_path):
    cli = cli_fixture(tmp_path, "import json, sys\nsys.stderr.write('x' * 1000000)\nsys.stderr.flush()\n"
                                "print(json.dumps({'ok': True}))\n")
    assert asyncio.run(cli.converse('ap-southeast-1', {'modelId': 'synthetic'})) == {'ok': True}


@pytest.mark.parametrize("provider,overrides", [
    ("glm", {"GLM_MODEL_ID": "replace-with-deployed-model-id", "GLM_CHAT_URL": "https://glm.internal.test/v1/chat/completions"}),
    ("glm", {"GLM_MODEL_ID": "synthetic-glm", "GLM_CHAT_URL": "https://local.example.invalid/v1/chat/completions"}),
    ("gemini", {"GEMINI_MODEL_ID": "gemini-synthetic", "GEMINI_API_KEY": ""}),
    ("bedrock", {"BEDROCK_MODEL_ID": "", "BEDROCK_REGION": "ap-southeast-1"}),
])
def test_example_placeholders_are_configuration_errors(monkeypatch, provider, overrides):
    from scripts.model_smoke import configured_adapter
    from security_harness.llm.gateway import ModelError
    for name, value in overrides.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(ModelError) as caught:
        configured_adapter(provider)
    assert caught.value.code == "CONFIGURATION"


def test_empty_optional_glm_key_means_no_key(monkeypatch):
    from scripts.model_smoke import configured_adapter
    monkeypatch.setenv("GLM_MODEL_ID", "synthetic-glm")
    monkeypatch.setenv("GLM_CHAT_URL", "https://glm.internal.test/v1/chat/completions")
    monkeypatch.setenv("GLM_API_KEY", "")
    assert configured_adapter("glm")._api_key is None


@pytest.mark.parametrize("model,label", [
    ("global.anthropic.claude-sonnet-4-5-20250929-v1:0", "global.anthropic.claude-sonnet-4-5-20250929-v1:0"),
    ("gemini-3.8-flash", "gemini-3.8-flash"),
    ("arn:aws:bedrock:ap-southeast-1:123456789012:inference-profile/x", "redacted"),
    ("arn:aws:bedrock:ap-southeast-1::foundation-model/x", "arn-redacted:foundation-model"),
    ("model with spaces", "redacted"),
])
def test_model_label_is_readable_without_account_identity(model, label):
    from security_harness.llm.gateway import Gateway
    assert Gateway.label(model) == label
