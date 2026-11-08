"""模型 RoE 期限政策與 v3 報告封存重驗。 / The model RoE deadline policy and v3 archived re-verification."""
import asyncio
import copy
import json
import os
import uuid

import pytest

from security_harness import scope
from security_harness.llm import benchmark_runner as runner
from security_harness.llm import benchmark_score as score
from security_harness.llm import lifecycle as life
from security_harness.llm.gateway import Gateway, Limits, Request
from security_harness.llm.transport import JsonHTTP
from tests.test_model_benchmark import collected

POLICY = {'version': 1, 'default_call_seconds': 30, 'max_call_seconds': {'lmstudio': 60}, 'max_total_seconds': 130}


def roe(**changes):
    value = json.loads((runner.CASES_PATH.parent / 'model-roe.json').read_text())
    value.update(changes)
    return value


def test_checked_in_model_roe_carries_a_valid_deadline_policy():
    assert roe()['deadline_policy'] == POLICY
    assert scope.validate_model_roe(roe(), ['lmstudio'], 1)


@pytest.mark.parametrize('policy', [
    None, {}, {**POLICY, 'version': 2}, {**POLICY, 'version': True},
    {**POLICY, 'default_call_seconds': 0}, {**POLICY, 'default_call_seconds': 61},
    {**POLICY, 'default_call_seconds': 30.0}, {**POLICY, 'max_call_seconds': {'lmstudio': 61}},
    {**POLICY, 'max_call_seconds': {'lmstudio': True}}, {**POLICY, 'max_call_seconds': {'mock-review-a': 30}},
    {**POLICY, 'max_call_seconds': []}, {**POLICY, 'max_total_seconds': 131},
    {**POLICY, 'max_total_seconds': 9}, {**POLICY, 'extra': 1},
    {k: v for k, v in POLICY.items() if k != 'max_total_seconds'},
], ids=['missing', 'empty', 'version', 'bool-version', 'zero-call', 'call-over-ceiling', 'float-call',
        'provider-over-ceiling', 'bool-provider', 'unknown-provider', 'list', 'run-over-ceiling', 'run-too-short',
        'extra-key', 'missing-key'])
def test_deadline_policy_outside_the_code_ceilings_is_refused(policy):
    with pytest.raises(ValueError, match='^live model calls are outside the approved model RoE$'):
        scope.validate_model_roe(roe(deadline_policy=policy), ['lmstudio'], 1)


def test_per_provider_deadlines_set_the_call_ceiling_and_the_run_cap():
    assert scope.call_seconds(POLICY, 'lmstudio') == 60
    assert scope.call_seconds(POLICY, 'gemini') == scope.call_seconds(POLICY, 'mock-review-a') == 30
    assert scope.run_seconds(POLICY, ['lmstudio']) == 70
    assert scope.run_seconds(POLICY, ['gemini', 'lmstudio']) == 100
    assert scope.run_seconds(POLICY, ['lmstudio'] * 3) == 130
    report = runner.initial_report(['lmstudio', 'gemini'], ['B13'], str(uuid.uuid4()))
    assert report['schema_version'] == 3 and report['deadline_policy'] == POLICY
    assert (report['limits']['timeout_seconds'], report['total_timeout_seconds']) == (60, 100)
    report = runner.initial_report(['mock-review-a', 'mock-review-b'], ['B01'], str(uuid.uuid4()))
    assert (report['limits']['timeout_seconds'], report['total_timeout_seconds']) == (30, 70)


def test_transport_accepts_the_call_ceiling_but_not_beyond():
    assert JsonHTTP(timeout_seconds=60).timeout_seconds == 60
    with pytest.raises(ValueError, match='^invalid HTTP timeout$'):
        JsonHTTP(timeout_seconds=61)


class Slow:
    provider, family, model = 'mock', 'mock', 'synthetic'

    async def generate(self, request):
        await asyncio.sleep(5)


@pytest.mark.parametrize('seconds,code', [(1, 'DEADLINE'), (31, 'ROUTING_DENIED'), (True, 'ROUTING_DENIED'),
                                          (0, 'ROUTING_DENIED')])
def test_a_call_deadline_may_only_tighten_the_gateway_ceiling(seconds, code, monkeypatch):
    gateway = Gateway(Limits(max_calls=1, reserved_output_tokens=256, timeout_seconds=30))
    if seconds == 1:
        # 以 0.05 秒代表 1 秒期限，避免測試等待。 / 0.05 seconds stands in for the one-second deadline.
        real = asyncio.timeout
        monkeypatch.setattr(asyncio, 'timeout', lambda value: real(0.05 if value == 1 else value))
    assert asyncio.run(gateway.generate(Slow(), Request('synthetic', 'synthetic'), seconds)) is None
    assert gateway.evidence[0]['code'] == code


def test_v3_report_validates_against_its_archive_after_the_current_inputs_change(tmp_path, monkeypatch):
    report, path = collected(tmp_path)
    assert report['status'] == 'COMPLETE'
    archived = {name: (path.parent / 'inputs' / name).read_bytes() for name in score.INPUT_NAMES}
    assert archived == runner.snapshot_inputs()
    changed = {**archived, 'model-roe.json': archived['model-roe.json'].replace(b'"max_total_seconds": 130',
                                                                                 b'"max_total_seconds": 120')}
    assert changed != archived
    monkeypatch.setattr(score, 'current_inputs', lambda: changed)
    assert score.summarize(report, run_dir=path.parent) == report['analysis']
    # 沒給報告目錄時退回目前檔案，RoE 已改就拒絕。 / Without the report directory the current files apply, and the
    # changed RoE is refused.
    with pytest.raises(ValueError, match='^model RoE binding mismatch$'):
        score.summarize(report)


@pytest.mark.parametrize('attack', ['tampered', 'symlink', 'oversized', 'missing', 'directory-symlink'])
def test_archived_inputs_that_are_tampered_or_unsafe_are_refused(tmp_path, attack):
    report, path = collected(tmp_path)
    folder = path.parent / 'inputs'
    catalog = folder / 'catalog.json'
    if attack == 'tampered':
        catalog.write_bytes(catalog.read_bytes() + b'\n')  # 仍是合法 JSON，但雜湊不同。 / Valid JSON, other digest.
        expected = '^stale or invalid benchmark identity$'
    elif attack == 'symlink':
        target = tmp_path / 'outside.json'
        target.write_bytes(catalog.read_bytes())
        catalog.unlink()
        catalog.symlink_to(target)
        expected = None
    elif attack == 'oversized':
        catalog.write_bytes(b' ' * (life.INPUT_LIMIT + 1))
        expected = '^input exceeds read limit$'
    elif attack == 'missing':
        catalog.unlink()
        expected = None
    else:
        moved = tmp_path / 'elsewhere'
        folder.rename(moved)
        folder.symlink_to(moved, target_is_directory=True)
        expected = '^archived inputs missing$'
    with pytest.raises((ValueError, OSError), match=expected):
        score.summarize(report, run_dir=path.parent)


def test_archived_inputs_are_never_replaced(tmp_path):
    life.archive_inputs(tmp_path, {'catalog.json': b'{}'})
    with pytest.raises(FileExistsError):
        life.archive_inputs(tmp_path, {'catalog.json': b'[]'})
    folder = tmp_path / 'inputs'
    assert (folder / 'catalog.json').read_bytes() == b'{}'
    assert oct(os.stat(folder / 'catalog.json').st_mode & 0o777) == '0o600'
    assert not [p for p in folder.iterdir() if p.name.startswith('.input-')]


def test_v2_reports_still_validate_against_the_current_files(tmp_path):
    report, _ = collected(tmp_path, case_ids=['B01'])
    assert (report['total_timeout_seconds'], min(130, 20 * len(report['plan']) + 10)) == (70, 50)
    old = copy.deepcopy(report)
    old['schema_version'] = 2
    del old['deadline_policy']
    old['limits']['timeout_seconds'] = 30
    old['total_timeout_seconds'] = min(130, 20 * len(old['plan']) + 10)
    assert score.summarize(old) == report['analysis']
    # v2 不能帶 v3 的期限，v3 也不能帶 v2 的期限。 / A v2 report cannot carry v3 deadlines, nor v3 the v2 ones.
    mixed = {**copy.deepcopy(old), 'total_timeout_seconds': report['total_timeout_seconds']}
    with pytest.raises(ValueError, match='^review limits mismatch$'):
        score.summarize(mixed)
    with pytest.raises(ValueError, match='^review limits mismatch$'):
        score.summarize({**copy.deepcopy(report), 'total_timeout_seconds': old['total_timeout_seconds']})


@pytest.mark.parametrize('change', [lambda p: p.update(max_total_seconds=120),
                                    lambda p: p['max_call_seconds'].update(lmstudio=30)],
                         ids=['run-cap', 'call-deadline'])
def test_v3_policy_must_match_the_archived_roe(tmp_path, change):
    report, path = collected(tmp_path)
    tampered = copy.deepcopy(report)
    change(tampered['deadline_policy'])
    with pytest.raises(ValueError, match='^review limits mismatch$'):
        score.summarize(tampered, run_dir=path.parent)


@pytest.mark.parametrize('version,valid', [(2, True), (3, True), (4, False), (True, False)])
def test_report_reader_accepts_only_known_versions(tmp_path, version, valid):
    run_id = str(uuid.uuid4())
    life.persist(tmp_path / 'artifacts' / run_id / 'report.json',
                 {'schema_version': version, 'run_id': run_id, 'operation': 'model-smoke', 'checks': [], 'calls': []})
    assert (life.read_report(tmp_path, run_id).get('code') != 'EVIDENCE_INVALID') is valid


def test_smoke_binds_and_archives_the_deadline_policy(tmp_path):
    from scripts.model_smoke import initial_report
    from security_harness.supervision import prepare_run
    from tests import model_support
    import scripts.model_smoke as smoke
    report = initial_report(['mock', 'lmstudio'], str(uuid.uuid4()))
    assert report['schema_version'] == 3 and report['deadline_policy'] == POLICY
    assert (report['limits']['timeout_seconds'], report['total_timeout_seconds']) == (60, 100)
    tampered = copy.deepcopy(report)
    tampered['deadline_policy']['max_total_seconds'] = 120
    assert life.smoke_plan_digest(tampered) != life.smoke_plan_digest(report)
    report = initial_report(['mock'], str(uuid.uuid4()))
    path = tmp_path / 'artifacts' / report['run_id'] / 'report.json'
    life.persist(path, tampered := {**copy.deepcopy(report), 'deadline_policy': {**POLICY, 'max_total_seconds': 120}})
    prepare_run(tmp_path, report['run_id'], operation='model-smoke')
    code = asyncio.run(smoke.run_worker(tmp_path, report['run_id'], life.smoke_plan_digest(tampered)))
    data = model_support.finish(tmp_path, report['run_id'], providers=report['providers'], returncode=code,
                                expected_report=report)
    assert (data['status'], data['code']) == ('INCOMPLETE', 'EVALUATION_INVALID')


def test_deadline_policy_boundaries_are_inclusive():
    # 上下限都可用，且可逐一列出全部真實供應商。 / Both bounds are usable, and every live provider may be listed.
    edges = {'version': 1, 'default_call_seconds': 1, 'max_total_seconds': 10,
             'max_call_seconds': dict.fromkeys(scope.MODEL_PROVIDERS, scope.MODEL_CALL_CEILING)}
    assert scope.validate_model_roe(roe(deadline_policy=edges), ['lmstudio'], 1)
    edges.update(default_call_seconds=scope.MODEL_CALL_CEILING, max_total_seconds=scope.MODEL_RUN_CEILING,
                 max_call_seconds=dict.fromkeys(scope.MODEL_PROVIDERS, 1))
    assert scope.validate_model_roe(roe(deadline_policy=edges), ['lmstudio'], 1)
