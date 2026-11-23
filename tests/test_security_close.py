"""SecurityRun.close 與 worker 清理交接的直接測試：supervisor 把 worker 報告關成發布用證據時，每一個條件都必須有測試。
不啟動子程序，可在突變快照內執行。

Direct tests of SecurityRun.close and the worker's cleanup handoff: every condition under which the supervisor closes a
worker's report into published evidence needs a test. No subprocess is started, so they run in the mutation
snapshot."""
import copy

import pytest

from security_harness import lifecycle, supervision
from security_harness.audit import AuditRun
from security_harness.lifecycle import SecurityRun
from security_harness.results import required_gate_kinds
from security_harness.supervision import Outcome

CLEAN = {'completed': True, 'error_type': None, 'temporary_directory_removed': True,
         'run_directory_removed': True, 'process_group_terminated': True, 'recovered_by_janitor': False}
DIRTY = {**CLEAN, 'completed': False, 'error_type': 'RuntimeError'}


def no_containers(run_id):
    """這些測試不建立容器。 / These tests create no containers."""


def handed_off(root, pending='ALLOW', pending_execution='RUNNING', reproduces=True, gates=None):
    """建立一份 worker 已完成清理交接的報告：每個必要 gate 都有紀錄，判定留在 pending 欄位。 / A report whose worker
    finished the cleanup handoff: every required gate has a record and the decision waits in the pending fields."""
    audit = AuditRun(root, 'security')
    for gate, kind in (required_gate_kinds(root) if gates is None else gates):
        audit.add(gate, 'COMPLETED', kind, 1, 0, 'ok')
    audit.stage('decision')
    audit.data.update(decision=pending, execution=pending_execution, reasons=['worker reasons'])
    audit.finish(required_gate_kinds(root) if gates is None else (), defer_final=True)
    role = SecurityRun(root, audit, no_containers)
    role.reproduces_allow = lambda data: reproduces
    return audit, role


def close(role, audit, returncode, stop=None, cleanup=CLEAN, error_type=None, evidence=None):
    evidence = copy.deepcopy(audit.data) if evidence is None else evidence
    return role.close(evidence, Outcome(stop, returncode, error_type, cleanup, 1.5))


def error_types(audit):
    return [error['error_type'] for error in audit.data['errors']]


def test_a_handed_off_allow_is_published_when_the_supervisor_reproduces_it(tmp_path):
    audit, role = handed_off(tmp_path)
    assert audit.data['execution'] == 'AWAITING_CLEANUP' and audit.data['decision'] == 'BLOCK'
    assert close(role, audit, 0) == 0
    assert (audit.data['decision'], audit.data['execution'], audit.data['errors']) == ('ALLOW', 'COMPLETED', [])
    assert 'pending_decision' not in audit.data and 'pending_execution' not in audit.data
    assert audit.data['cleanup'] == CLEAN and audit.data['total_seconds'] == 1.5
    assert audit.data['reasons'] == ['worker reasons']


def test_a_handed_off_block_is_published_without_recomputing_an_allow(tmp_path):
    # BLOCK 不需要重算；重算結果為否也不可把它變成錯誤。 / A BLOCK needs no recomputation, and a negative
    # recomputation must not turn it into an error.
    audit, role = handed_off(tmp_path, pending='BLOCK', reproduces=False)
    assert close(role, audit, 1) == 1
    assert (audit.data['decision'], audit.data['execution'], audit.data['errors']) == ('BLOCK', 'COMPLETED', [])
    assert audit.data['reasons'] == ['worker reasons']


def test_the_worker_pending_execution_is_kept_unless_it_was_still_running(tmp_path):
    audit, role = handed_off(tmp_path, pending='BLOCK', pending_execution='ERROR')
    assert close(role, audit, 1) == 1
    assert (audit.data['decision'], audit.data['execution'], audit.data['errors']) == ('BLOCK', 'ERROR', [])


@pytest.mark.parametrize('pending,returncode', [('ALLOW', 1), ('BLOCK', 0)])
def test_an_exit_code_that_contradicts_the_pending_decision_blocks(tmp_path, pending, returncode):
    audit, role = handed_off(tmp_path, pending=pending)
    assert close(role, audit, returncode) == 1
    assert (audit.data['decision'], audit.data['execution']) == ('BLOCK', 'ERROR')
    assert error_types(audit) == ['RuntimeError'] and audit.data['reasons'] == ['run failed; see redacted errors']


def test_an_allow_the_supervisor_cannot_reproduce_blocks(tmp_path):
    audit, role = handed_off(tmp_path, reproduces=False)
    assert close(role, audit, 0) == 1
    assert (audit.data['decision'], audit.data['execution']) == ('BLOCK', 'ERROR')
    assert error_types(audit) == ['RuntimeError']


@pytest.mark.parametrize('returncode', [0, 1])
def test_a_report_that_never_reached_the_cleanup_handoff_blocks(tmp_path, returncode):
    audit = AuditRun(tmp_path, 'security')
    for gate, kind in required_gate_kinds(tmp_path):
        audit.add(gate, 'COMPLETED', kind, 1, 0, 'ok')
    audit.data.update(decision='ALLOW', pending_decision='ALLOW', pending_execution='RUNNING')
    role = SecurityRun(tmp_path, audit, no_containers)
    role.reproduces_allow = lambda data: True
    assert audit.data['execution'] == 'RUNNING'
    assert close(role, audit, returncode) == 1
    assert (audit.data['decision'], audit.data['execution']) == ('BLOCK', 'ERROR')
    assert error_types(audit) == ['RuntimeError']


def test_a_handoff_without_a_recognised_pending_decision_blocks(tmp_path):
    audit, role = handed_off(tmp_path, pending='BLOCK')
    evidence = copy.deepcopy(audit.data)
    evidence['pending_decision'] = None
    assert close(role, audit, 1, evidence=evidence) == 1
    assert (audit.data['decision'], audit.data['execution']) == ('BLOCK', 'ERROR')
    assert error_types(audit) == ['RuntimeError']


def test_exit_code_two_is_a_plan_mismatch_and_nothing_else(tmp_path):
    # exit 2 表示 worker 讀回的計畫與命令列摘要不符；只記一筆 PlanMismatch。 / Exit 2 means the plan the worker read
    # back did not match its command line; exactly one PlanMismatch is recorded.
    audit, role = handed_off(tmp_path, pending='BLOCK')
    assert close(role, audit, 2) == 1
    assert (audit.data['decision'], audit.data['execution']) == ('BLOCK', 'ERROR')
    assert error_types(audit) == ['PlanMismatch']


@pytest.mark.parametrize('returncode', [0, 1])
def test_a_report_whose_plan_was_changed_is_a_plan_mismatch_and_gets_the_plan_back(tmp_path, returncode):
    audit, role = handed_off(tmp_path, pending='ALLOW' if returncode == 0 else 'BLOCK')
    planned = audit.data['created_at']
    evidence = copy.deepcopy(audit.data)
    evidence['created_at'] = 'changed by the worker'
    assert close(role, audit, returncode, evidence=evidence) == 1
    assert (audit.data['decision'], audit.data['execution']) == ('BLOCK', 'ERROR')
    assert error_types(audit) == ['PlanMismatch']
    assert audit.data['created_at'] == planned


def test_incomplete_cleanup_blocks_and_never_counts_as_a_finished_handoff(tmp_path):
    audit, role = handed_off(tmp_path)
    assert close(role, audit, 0, cleanup=DIRTY) == 1
    assert (audit.data['decision'], audit.data['execution'], audit.data['reasons']) == (
        'BLOCK', 'ERROR', ['cleanup incomplete'])
    # 清理失敗的執行不是「worker 自行結束」，所以 worker 的判定未被採用。 / A run whose cleanup failed is not a worker
    # that exited on its own, so the worker's decision was never adopted.
    assert error_types(audit) == ['RuntimeError'] and audit.data['cleanup'] == DIRTY


@pytest.mark.parametrize('stop,execution', [('TIMEOUT', 'TIMEOUT'), ('CANCELLED', 'CANCELLED'),
                                            ('SUPERVISOR_FAILED', 'ERROR')])
def test_a_stopped_run_blocks_and_records_the_gate_it_was_in(tmp_path, stop, execution):
    audit = AuditRun(tmp_path, 'security')
    first, second = required_gate_kinds(tmp_path)[:2]
    audit.add(first[0], 'COMPLETED', first[1], 1, 0, 'ok')
    audit.stage(second[0])
    role = SecurityRun(tmp_path, audit, no_containers)
    assert close(role, audit, None, stop=stop, error_type='KeyError' if stop == 'SUPERVISOR_FAILED' else None) == 1
    assert (audit.data['decision'], audit.data['execution']) == ('BLOCK', execution)
    # 停止原因排第一，其後是尚未執行的必要 gate。 / The stop reason comes first, then the required gates never run.
    later = [gate for gate, _ in required_gate_kinds(tmp_path)[2:]]
    assert audit.data['reasons'] == ['supervisor ' + execution.lower(), *[f'{gate}: not run' for gate in later]]
    stopped = [r for r in audit.data['records'] if r['gate'] == second[0]]
    assert [(r['execution'], r['kind']) for r in stopped] == [(execution, second[1])]
    assert [r['gate'] for r in audit.data['records']][:2] == [first[0], second[0]]
    assert error_types(audit) == (['KeyError'] if stop == 'SUPERVISOR_FAILED' else [])


def test_a_run_stopped_in_a_gate_that_already_reported_gets_no_second_record(tmp_path):
    audit = AuditRun(tmp_path, 'security')
    gate, kind = required_gate_kinds(tmp_path)[0]
    audit.add(gate, 'COMPLETED', kind, 1, 0, 'ok')
    audit.stage(gate)
    role = SecurityRun(tmp_path, audit, no_containers)
    assert close(role, audit, None, stop='TIMEOUT') == 1
    assert [r['execution'] for r in audit.data['records'] if r['gate'] == gate] == ['COMPLETED']
    assert (audit.data['decision'], audit.data['execution']) == ('BLOCK', 'TIMEOUT')


def test_a_run_stopped_outside_any_gate_adds_no_record_for_that_stage(tmp_path):
    audit = AuditRun(tmp_path, 'security')
    audit.stage('initialization')
    role = SecurityRun(tmp_path, audit, no_containers)
    assert close(role, audit, None, stop='CANCELLED') == 1
    assert all(r['gate'] != 'initialization' for r in audit.data['records'])
    assert {r['execution'] for r in audit.data['records']} == {'NOT_RUN'}
    assert (audit.data['decision'], audit.data['execution']) == ('BLOCK', 'CANCELLED')


def test_a_stop_wins_over_a_finished_handoff(tmp_path):
    # 即使 worker 已在清理交接中留下 ALLOW，被 supervisor 停止的執行仍是 BLOCK。 / Even with an ALLOW handed off, a run the
    # supervisor stopped is still BLOCK.
    audit, role = handed_off(tmp_path)
    assert close(role, audit, 0, stop='TIMEOUT') == 1
    assert (audit.data['decision'], audit.data['execution'], audit.data['reasons']) == (
        'BLOCK', 'TIMEOUT', ['supervisor timeout'])


def test_resume_worker_refuses_a_report_whose_plan_differs_from_the_command_line(tmp_path, monkeypatch):
    from security_harness import limits
    monkeypatch.setattr(limits, 'apply_rlimits', lambda limit: None)
    audit = AuditRun(tmp_path, 'security')
    run_id = audit.data['run_id']
    monkeypatch.setattr(supervision, 'run_directory', lambda root, run: tmp_path)
    digest = supervision.plan_digest(audit.data, lifecycle.SECURITY_IMMUTABLE)
    assert lifecycle.resume_worker(tmp_path, run_id, digest).data['run_id'] == run_id
    with pytest.raises(SystemExit) as stopped:
        lifecycle.resume_worker(tmp_path, run_id, '0' * 64)
    assert stopped.value.code == 2


def test_a_deferred_finish_with_a_missing_gate_hands_off_block_not_the_earlier_allow(tmp_path):
    # 延後收尾時，缺少必要 gate 必須連待定判定一起改成 BLOCK；否則 supervisor 之後會採用 worker 的 ALLOW。 / With a
    # deferred finish, a missing required gate must turn the pending decision into BLOCK too, or the supervisor
    # would later adopt the worker's ALLOW.
    audit = AuditRun(tmp_path, 'security')
    audit.data.update(decision='ALLOW', reasons=['all gates passed'])
    assert audit.finish((('G1', 'scan'), ('AUTH', 'test')), defer_final=True) == 1
    assert (audit.data['pending_decision'], audit.data['pending_execution']) == ('BLOCK', 'RUNNING')
    assert (audit.data['decision'], audit.data['execution']) == ('BLOCK', 'AWAITING_CLEANUP')
    assert audit.data['reasons'] == ['all gates passed', 'G1: not run', 'AUTH: not run']
    assert [(r['gate'], r['execution'], r['kind']) for r in audit.data['records']] == [
        ('G1', 'NOT_RUN', 'scan'), ('AUTH', 'NOT_RUN', 'test')]


def test_a_deferred_finish_with_every_gate_present_hands_off_the_allow(tmp_path):
    audit = AuditRun(tmp_path, 'security')
    audit.add('G1', 'COMPLETED', 'scan', 1, 0, 'ok')
    audit.data.update(decision='ALLOW', reasons=[])
    assert audit.finish((('G1', 'scan'),), defer_final=True) == 0
    assert (audit.data['pending_decision'], audit.data['decision'], audit.data['execution']) == (
        'ALLOW', 'BLOCK', 'AWAITING_CLEANUP')
    assert len(audit.data['records']) == 1 and audit.data['reasons'] == []
    assert (tmp_path / 'artifacts/latest.txt').read_text() == audit.data['run_id'] + '\n'


@pytest.mark.parametrize('decision,code', [('ALLOW', 0), ('BLOCK', 1)])
def test_an_immediate_finish_completes_a_running_report_and_returns_its_decision(tmp_path, decision, code):
    audit = AuditRun(tmp_path, 'security')
    audit.data.update(decision=decision, reasons=[])
    assert audit.finish() == code
    assert (audit.data['decision'], audit.data['execution']) == (decision, 'COMPLETED')
    assert 'pending_decision' not in audit.data


def test_finish_keeps_a_failed_execution_and_names_the_pointer_after_the_operation(tmp_path):
    audit = AuditRun(tmp_path, 'model-review')
    audit.fail(RuntimeError('redacted'))
    assert audit.finish() == 1 and audit.data['execution'] == 'ERROR'
    assert (tmp_path / 'artifacts/model-review-latest.txt').read_text() == audit.data['run_id'] + '\n'
    assert not (tmp_path / 'artifacts/latest.txt').exists()
    quiet = AuditRun(tmp_path, 'security')
    quiet.finish(update_pointer=False)
    assert not (tmp_path / 'artifacts/latest.txt').exists()
