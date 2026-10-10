"""可信工作流程的文字契約檢查；核准 lock 沒有 YAML parser。

Text-level contract for the trusted workflow; no YAML parser is in the approved lock."""
import re
import itertools
import subprocess
import pytest
from pathlib import Path

WORKFLOW = (Path(__file__).resolve().parents[1] / ".github/workflows/security.yml").read_text()


def job_name_expression():
    match = re.search(r"^  trusted-security-pilot:\n(?:    #.*\n)*    name: (.+)$", WORKFLOW, re.MULTILINE)
    assert match, "job must declare an explicit, event-dependent name"
    return match.group(1)


def test_manual_runs_never_report_under_the_required_check_name():
    # GitHub 用 job 計算後名稱發布 check；維護者手動 / GitHub reports a job's check run under its evaluated name. A maintainer-
    # 選擇的 ref 不可滿足必要 trusted-security-pilot。 / selected manual ref must not satisfy the required trusted-security-pilot check.
    assert job_name_expression() == ("${{ github.event_name == 'workflow_dispatch' && "
                                     "'manual-security-evaluation' || 'trusted-security-evaluation' }}")
    assert "${{ github.event_name == 'workflow_dispatch' && 'manual-security' || 'trusted-security' }}" in WORKFLOW


def test_candidate_workflow_triggers_are_not_reintroduced():
    triggers = WORKFLOW.split("\npermissions:")[0]
    # pull_request 使用候選控制的 YAML；只有 base workflow 可評估 PR。 / pull_request runs candidate-controlled YAML; only the base-branch workflow may evaluate PRs.
    assert re.search(r"^  pull_request:", triggers, re.MULTILINE) is None
    assert re.search(r"^  pull_request_target:\n    branches: \[main\]", triggers, re.MULTILINE)
    assert "ref: ${{ github.event.pull_request.base.sha || github.sha }}" in WORKFLOW


def test_only_the_guard_step_receives_a_token():
    assert WORKFLOW.count("GH_TOKEN") == 1
    assert WORKFLOW.count("persist-credentials: false") == WORKFLOW.count("uses: actions/checkout@") == 3
    assert "secrets." not in WORKFLOW


def test_manual_and_push_runs_never_share_a_cancellation_group():
    group = re.search(r"^concurrency:\n(?:  #.*\n)*  group: (.+)$", WORKFLOW, re.MULTILINE).group(1)
    assert "${{ github.event_name }}" in group
    assert "cancel-in-progress: true" in WORKFLOW


def completion_job():
    return WORKFLOW.split('\n  security-completion:\n', 1)[1]


def test_required_check_is_downstream_of_both_evaluation_and_signing():
    job = completion_job()
    assert "'manual-security-completion' || 'trusted-security-pilot'" in job
    assert 'needs: [trusted-security-pilot, attest-evidence, mutation-tests]' in job
    assert 'if: always()' in job and 'permissions: {}' in job
    assert 'uses:' not in job and 'checkout' not in job and 'secrets.' not in job
    assert '${{ needs.trusted-security-pilot.result }}' in job
    assert '${{ needs.attest-evidence.result }}' in job
    assert '${{ needs.mutation-tests.result }}' in job


@pytest.mark.parametrize('evaluator,attestation,mutation', list(itertools.product(
    ['success', 'failure', 'cancelled', 'skipped'], repeat=3)))
def test_actual_final_gate_shell_only_passes_three_successes(evaluator, attestation, mutation):
    body = completion_job().split('        run: |\n', 1)[1]
    command = '\n'.join(line[10:] for line in body.splitlines() if line.strip())
    process = subprocess.run(['/bin/bash', '-e', '-c', command],
        env={'EVALUATOR_RESULT': evaluator, 'ATTESTATION_RESULT': attestation, 'MUTATION_RESULT': mutation},
        capture_output=True, timeout=5)
    assert (process.returncode == 0) is (evaluator == attestation == mutation == 'success')


def job(name):
    return WORKFLOW.split(f'\n  {name}:\n', 1)[1].split('\n\n  ', 1)[0]


def test_every_action_is_pinned_to_a_full_sha_with_a_version_comment():
    uses = re.findall(r'uses: (\S+)(.*)$', WORKFLOW, re.MULTILINE)
    assert uses
    for target, comment in uses:
        assert re.fullmatch(r'[\w.-]+/[\w.-]+@[0-9a-f]{40}', target), target
        assert re.fullmatch(r' # v\d+\.\d+\.\d+', comment), target


def test_job_time_budgets_fit_the_mutation_deadline():
    # 突變活動期限 1200 秒，必須在獨立且更長的 job 內。 / The 1200 s campaign needs its own, longer job.
    assert 'mutation_check.py' not in job('trusted-security-pilot')
    mutation = job('mutation-tests')
    assert 'mutation_check.py' in mutation
    assert int(re.search(r'timeout-minutes: (\d+)', mutation).group(1)) * 60 > 1200 + 5 * 60
    assert 'candidate' not in mutation.replace('No candidate', '').replace('no candidate', '')
    assert 'contents: read' in mutation and 'id-token' not in mutation


def test_candidate_documents_are_checked_without_execution():
    evaluator = job('trusted-security-pilot')
    assert 'run: python -I scripts/check_docs.py --root ../candidate' in evaluator
    assert evaluator.index('check_docs.py --root ../candidate') < evaluator.index('Evaluate candidate through external oracle')


def test_edited_events_are_never_skipped_at_job_level():
    # 略過的同名檢查會被規則集視為通過。 / A skipped same-name check would satisfy the ruleset.
    assert 'edited' in WORKFLOW.split('\npermissions:')[0]
    assert not re.search(r"^    if: .*(event\.action|edited)", WORKFLOW, re.MULTILINE)


def test_publisher_step_names_match_the_workflow():
    from security_harness import trusted_publisher as publisher
    workflow = WORKFLOW
    for name in (*publisher.REQUIRED_STEPS, *publisher.MUTATION_STEPS, publisher.COMPLETION_STEP):
        assert f'- name: {name}\n' in workflow, name
