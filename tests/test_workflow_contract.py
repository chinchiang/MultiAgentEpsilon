"""Text-level contract for the trusted workflow; no YAML parser is in the approved lock."""
import re
from pathlib import Path

WORKFLOW = (Path(__file__).resolve().parents[1] / ".github/workflows/security.yml").read_text()


def job_name_expression():
    match = re.search(r"^  trusted-security-pilot:\n(?:    #.*\n)*    name: (.+)$", WORKFLOW, re.MULTILINE)
    assert match, "job must declare an explicit, event-dependent name"
    return match.group(1)


def test_manual_runs_never_report_under_the_required_check_name():
    # GitHub reports a job's check run under its evaluated name. A maintainer-
    # selected manual ref must not satisfy the required trusted-security-pilot check.
    assert job_name_expression() == ("${{ github.event_name == 'workflow_dispatch' && "
                                     "'manual-security-evaluation' || 'trusted-security-pilot' }}")
    assert "${{ github.event_name == 'workflow_dispatch' && 'manual-security' || 'trusted-security' }}" in WORKFLOW


def test_candidate_workflow_triggers_are_not_reintroduced():
    triggers = WORKFLOW.split("\npermissions:")[0]
    # pull_request runs candidate-controlled YAML; only the base-branch workflow may evaluate PRs.
    assert re.search(r"^  pull_request:", triggers, re.MULTILINE) is None
    assert re.search(r"^  pull_request_target:\n    branches: \[main\]", triggers, re.MULTILINE)
    assert "ref: ${{ github.event.pull_request.base.sha || github.sha }}" in WORKFLOW


def test_only_the_guard_step_receives_a_token():
    assert WORKFLOW.count("GH_TOKEN") == 1
    assert WORKFLOW.count("persist-credentials: false") == 2
    assert "secrets." not in WORKFLOW


def test_manual_and_push_runs_never_share_a_cancellation_group():
    group = re.search(r"^concurrency:\n(?:  #.*\n)*  group: (.+)$", WORKFLOW, re.MULTILINE).group(1)
    assert "${{ github.event_name }}" in group
    assert "cancel-in-progress: true" in WORKFLOW
