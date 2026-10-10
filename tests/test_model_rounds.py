"""錯誤分類與多輪觀察維持限額及證據綁定。

Failure categories and repeated observations remain bounded and evidence-bound."""
import asyncio
import json
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from security_harness.llm import benchmark as bench, benchmark_runner as runner, benchmark_score as score
from security_harness.llm import lifecycle as life
from security_harness.llm.gateway import Gateway, ModelError, Reply
from security_harness.llm.adapters import BedrockAdapter
from security_harness.llm.transport import strict_json
from security_harness.lifecycle import prepare_run


from tests.model_evidence import provider_answer


@pytest.fixture(autouse=True)
def _no_model_evidence_left_in_artifacts():
    from tests.model_evidence import remove_new_model_evidence
    with remove_new_model_evidence(Path(__file__).resolve().parents[1]):
        yield

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('raw,detail', [(b'{', 'JSON_SYNTAX'), (b'\xff', 'JSON_ENCODING'),
    (b'{"secret-marker":1,"secret-marker":2}', 'JSON_DUPLICATE_KEY'),
    (b'{"value":NaN}', 'JSON_NONFINITE'), (b'{"value":1e999}', 'JSON_NONFINITE'),
    (b'[]', 'ENVELOPE_SCHEMA')])
def test_parser_categories_never_expose_raw_values(raw, detail):
    with pytest.raises(ModelError) as exc:
        strict_json(raw)
    assert exc.value.code == 'INVALID_RESPONSE' and exc.value.detail == detail
    assert 'secret-marker' not in str(exc.value)


@pytest.mark.parametrize('mutation,detail,code', [('missing', 'MISSING_FIELD', 'INVALID_RESPONSE'),
    ('unknown-content', 'UNEXPECTED_CONTENT', 'INVALID_RESPONSE'),
    ('empty', 'EMPTY_TEXT', 'INVALID_RESPONSE'), ('usage', 'USAGE_SCHEMA', 'INVALID_RESPONSE'),
    ('stop', 'STOP_REASON', 'INVALID_RESPONSE'), ('truncated', None, 'TRUNCATED'),
    ('refused', None, 'REFUSED'), ('tool', None, 'TOOL_REQUEST')])
def test_provider_diagnostics_are_fixed_categories_and_keep_rejections(mutation, detail, code):
    value = {'stopReason':'end_turn','output':{'message':{'role':'assistant','content':[{'text':'ok'}]}}}
    if mutation == 'missing': value['output'].pop('message')
    elif mutation == 'unknown-content': value['output']['message']['content'] = [{'private-marker':'hidden'}]
    elif mutation == 'empty': value['output']['message']['content'] = [{'text':' '}]
    elif mutation == 'usage': value['usage'] = {'inputTokens':True}
    else: value['stopReason'] = {'stop':'private-marker','truncated':'max_tokens','refused':'content_filtered','tool':'tool_use'}[mutation]
    class CLI:
        async def converse(self, *args): return value
    gateway = Gateway()
    request = bench.review_request(bench.load_cases()['B01'], str(uuid.uuid4()))
    assert asyncio.run(gateway.generate(BedrockAdapter('synthetic','ap-southeast-1',CLI()),request)) is None
    record = gateway.evidence[0]
    assert record['code'] == code and record['diagnostic'] == detail
    assert 'private-marker' not in json.dumps(record) and 'hidden' not in json.dumps(record)


def collect(tmp_path, monkeypatch=None):
    report = runner.initial_report(['mock-review-a','mock-review-b'], ['B01','B02'], str(uuid.uuid4()), 512, 2)
    path = tmp_path/'artifacts'/report['run_id']/'report.json'
    life.persist(path,report);prepare_run(tmp_path,report['run_id'],operation='model-smoke')
    result = asyncio.run(runner.run_worker(tmp_path,report['run_id']))
    return life.finish(tmp_path,report['run_id'],providers=report['providers'],returncode=result,expected_report=report)


def test_rounds_share_one_budget_and_preserve_opaque_ids(tmp_path):
    d = collect(tmp_path)
    assert d['status']=='COMPLETE' and d['cleanup']['completed']
    assert len(d['calls']) == d['reserved_calls'] == 8
    assert d['reserved_output_tokens']==4096 and d['total_timeout_seconds']==130
    tokens = {(x['case_id'],x['round_index']):x['review_id'] for x in d['plan']}
    assert len(set(tokens.values()))==4
    assert [x['round_index'] for x in d['plan']]==[1]*4+[2]*4
    a=d['analysis'];assert len(a['rounds'])==2 and len(a['adjudication'])==4
    assert all(x['all_rounds_agree'] is True for x in a['stability'])
    assert a['provider_metrics']['mock-review-a']['planned']==4
    assert a['pairwise'][0]['planned']==4 and a['live_family_labels_observed']==[]


def test_failure_is_not_replaced_by_success_in_another_round(tmp_path):
    d=collect(tmp_path)
    c=next(c for c in d['checks'] if c['provider']=='mock-review-a' and c['case_id']=='B01' and c['round_index']==2)
    # 模擬 runner 記錄解析失敗：沒有可信審查或綁定原文。 / As the runner records a parse failure: no trusted review and no bound response text.
    c.update(status='ERROR',code='REVIEW_INVALID_RESPONSE',diagnostic='JSON_SYNTAX',review=None)
    c.pop('response_text')
    d['status']='INCOMPLETE'
    a=score.summarize(d);m=a['provider_metrics']['mock-review-a']
    assert (m['tp'],m['tn'],m['unavailable'],m['planned'])==(1,2,1,4)
    assert m['valid_response_rate']==m['coverage']==.75 and m['positive_miss_rate_all']==.5
    assert m['error_categories']=={'JSON_SYNTAX':1}
    assert a['pairwise'][0]['comparable']==3 and a['pairwise'][0]['planned']==4
    assert a['rounds'][0]['analysis']['provider_metrics']['mock-review-a']['coverage']==1
    assert a['rounds'][1]['analysis']['provider_metrics']['mock-review-a']['coverage']==.5
    row=next(x for x in a['stability'] if x['provider']=='mock-review-a' and x['case_id']=='B01')
    assert row['classified_rounds']==1 and row['all_rounds_agree'] is None


@pytest.mark.parametrize('mutation',['round-count','duplicate-round','call-round','token-reuse','raw-diagnostic','model-change'])
def test_round_substitution_and_untrusted_labels_rejected(tmp_path,mutation):
    d=collect(tmp_path)
    if mutation=='round-count': d['rounds']=3
    elif mutation=='duplicate-round': d['plan'][4]['round_index']=1
    elif mutation=='call-round': d['calls'][0]['round_index']=2
    elif mutation=='token-reuse': d['plan'][4]['review_id']=d['plan'][0]['review_id']
    elif mutation=='raw-diagnostic': d['checks'][0]['diagnostic']='secret-response-body'
    else: d['calls'][0]['model_sha256']='0'*64
    with pytest.raises(ValueError): score.summarize(d)


@pytest.mark.parametrize('rounds,tokens',[(True,512),(0,512),(5,512),(4,1024)])
def test_repetition_caps_reject_before_io(rounds,tokens):
    with pytest.raises(ValueError):
        runner.initial_report(['mock-review-a','mock-review-b'],['B01','B02'],str(uuid.uuid4()),tokens,rounds)


def test_cancellation_preserves_all_planned_rounds(tmp_path,monkeypatch):
    async def cancelled(self,request): raise asyncio.CancelledError()
    monkeypatch.setattr(bench.MockReviewer,'generate',cancelled)
    d=collect(tmp_path)
    assert d['status']=='INCOMPLETE' and d['cleanup']['completed']
    assert len(d['plan'])==8 and len(d['calls'])==1
    assert all(m['planned']==4 and m['coverage']==0 for m in d['analysis']['provider_metrics'].values())
    assert len(d['analysis']['rounds'])==2
    assert sum(m['error_categories'].get('CANCELLED',0) for m in d['analysis']['provider_metrics'].values())==1
    assert sum(m['error_categories'].get('UNASSESSED',0) for m in d['analysis']['provider_metrics'].values())==7


def test_repeated_cli_and_oversized_plan(tmp_path):
    cmd=[sys.executable,'-I',str(ROOT/'scripts/model_review.py'),'--case','B01','--case','B02','--rounds','2']
    p=subprocess.run(cmd,capture_output=True,text=True,timeout=20);assert p.returncode==0,p.stderr
    d=json.loads(Path(json.loads(p.stdout)['evidence']).read_text());assert d['rounds']==2 and d['cleanup']['completed']
    p=subprocess.run([sys.executable,'-I',str(ROOT/'scripts/model_review.py'),'--rounds','2'],capture_output=True,timeout=10)
    assert p.returncode==2


def test_changed_answers_are_not_reported_as_stable(tmp_path):
    d=collect(tmp_path)
    check=next(c for c in d['checks'] if c['provider']=='mock-review-a' and c['case_id']=='B01' and c['round_index']==2)
    check['review'].update(verdict='CLEAN',findings=[],reason='Synthetic incorrect answer')
    provider_answer(d,check)
    a=score.summarize(d)
    row=next(x for x in a['stability'] if x['provider']=='mock-review-a' and x['case_id']=='B01')
    assert row['all_rounds_agree'] is False and row['distinct_valid_answers']==2
    assert a['provider_metrics']['mock-review-a']['false_negative_rate_valid']==.5
    assert a['pairwise'][0]['disagreements']==1
    assert any('REFERENCE_MISMATCH' in x['reasons'] and x['round_index']==2 for x in a['adjudication'])


def test_abstention_is_valid_response_but_not_classification(tmp_path):
    d=collect(tmp_path)
    check=d['checks'][0]
    check['review'].update(verdict='ABSTAIN',findings=[],reason='Cannot determine')
    provider_answer(d,check)
    m=score.summarize(d)['provider_metrics'][check['provider']]
    assert m['valid_response_rate']==1 and m['coverage']==.75
    assert m['error_categories']=={'ABSTAIN':1}


def test_diagnostic_rejects_untrusted_details_and_sampling_changes(tmp_path):
    assert ModelError('INVALID_RESPONSE','private raw response').detail is None
    d=collect(tmp_path);d['sampling_policy']['mock-review-a']='private-setting'
    with pytest.raises(ValueError,match='sampling'): score.summarize(d)


def test_review_stage_limit_is_not_misclassified_as_unassessed():
    assert score.error_categories([{'status':'ERROR','code':'REVIEW_RESPONSE_LIMIT'},
                                   {'status':'ERROR','code':'private-raw-error'}]) == {'RESPONSE_LIMIT':1,'UNASSESSED':1}


def test_changed_case_catalog_spends_no_calls(tmp_path, monkeypatch):
    report = runner.initial_report(['mock-review-a'], ['B01'], str(uuid.uuid4()), 512, 1)
    report['case_catalog_sha256'] = '0' * 64  # 計畫綁定後目錄被修改。 / catalog edited after the plan was bound
    path = tmp_path/'artifacts'/report['run_id']/'report.json'
    life.persist(path, report); prepare_run(tmp_path, report['run_id'], operation='model-smoke')
    async def forbidden(self, request): raise AssertionError('call spent against an unbound catalog')
    monkeypatch.setattr(bench.MockReviewer, 'generate', forbidden)
    assert asyncio.run(runner.run_worker(tmp_path, report['run_id'])) == 1
    data = json.loads(path.read_text())
    assert data['code'] == 'CONFIGURATION' and data['calls'] == []
    assert [c['code'] for c in data['checks']] == ['CONFIGURATION']


@pytest.mark.parametrize('code', ['TIMEOUT', 'SUPERVISOR_FAILED', 'WORKER_FAILED', 'PROVIDER_INCOMPLETE'])
def test_supervisor_stop_reasons_are_known_categories(code):
    assert score.error_categories([{'status': 'ERROR', 'code': code}]) == {code: 1}


def test_live_plan_warns_when_worst_case_exceeds_the_run_cap():
    from scripts.model_review import deadline_warning
    assert deadline_warning(3, 90) is None
    message = deadline_warning(8, 130)
    assert '240' in message and '130' in message and 'INCOMPLETE' in message
