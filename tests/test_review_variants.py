"""Variant truth comes from real temporary file reads and isolated mock requests."""
import asyncio
import uuid
import httpx
import pytest
from tests.test_review_boundaries import fixture
from security_harness.llm import benchmark as bench, benchmark_score as score


@pytest.mark.parametrize('case_id', ['B13', 'B14'])
def test_prefix_guard_must_distinguish_sibling_directory(case_id, tmp_path):
    base = tmp_path / 'allowed'; base.mkdir()
    (base / 'ok.txt').write_text('allowed')
    sibling = tmp_path / 'allowed-other'; sibling.mkdir()
    outside = sibling / 'sentinel.txt'; outside.write_text('outside synthetic data')
    read = fixture(case_id)['read_file']
    assert read(base, 'ok.txt') == 'allowed'
    if case_id == 'B13': assert read(base, '../allowed-other/sentinel.txt') == 'outside synthetic data'
    else:
        with pytest.raises(PermissionError): read(base, '../allowed-other/sentinel.txt')


@pytest.mark.parametrize('case_id', ['B15', 'B16'])
@pytest.mark.parametrize('target', ['http://catalog.example.test/v1/status',
    'https://catalog.example.test:8443/v1/status', 'https://catalog.example.test/admin'])
def test_hostname_guard_cannot_authorize_other_protocol_port_or_path(case_id, target):
    seen = []
    def upstream(request):
        seen.append(str(request.url))
        return httpx.Response(200, text='synthetic')
    with httpx.Client(transport=httpx.MockTransport(upstream), trust_env=False) as client:
        fetch = fixture(case_id)['fetch_status']
        allowed = 'https://catalog.example.test/v1/status'
        assert fetch(client, allowed) == 'synthetic'
        seen.clear()
        if case_id == 'B15':
            assert fetch(client, target) == 'synthetic'
            assert seen == [target]
        else:
            with pytest.raises(PermissionError): fetch(client, target)
            assert seen == []


@pytest.mark.parametrize('case_id', bench.SUITES['variants'])
def test_variants_have_consistent_blind_reference_and_mock_contract(case_id):
    case = bench.load_cases()[case_id]
    token = str(uuid.uuid4())
    for provider in ('mock-review-a', 'mock-review-b'):
        response = asyncio.run(bench.MockReviewer(provider).generate(bench.review_request(case, token)))
        parsed = bench.parse_review(response.text, case, token)
        assert score.signature(parsed) == score.signature(score.reference()[case_id])


def test_variant_repetitions_fit_existing_caps_and_keep_round_identities_separate():
    plan = bench.make_plan(['gemini', 'bedrock'], ['B13', 'B14'], rounds=2)
    assert len(plan) == 8
    assert len({p['review_id'] for p in plan}) == 4
    with pytest.raises(ValueError):
        bench.make_plan(['gemini', 'bedrock'], list(bench.load_cases()), rounds=2)
