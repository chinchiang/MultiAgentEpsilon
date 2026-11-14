"""規則集監看的 workflow 與範本綁定；需要 .github/ 與 docs/，不在突變快照內執行。

The ruleset monitor's workflow and template bindings; they need .github/ and docs/, so they stay out of the
mutation snapshot."""
import json
import re
from pathlib import Path

from security_harness.workflow_contract import JOBS, REQUIRED_CHECK
from tests.test_ruleset_monitor import template

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / '.github/workflows/ruleset-monitor.yml').read_text()


def test_the_monitor_tests_use_the_checked_in_ruleset_template():
    expected = template()
    del expected['id'], expected['updated_at']
    assert json.loads((ROOT / 'docs/github-main-ruleset.json').read_text()) == expected


def test_the_monitor_workflow_only_runs_on_a_schedule_or_by_hand_with_read_only_access():
    triggers = re.search(r'^on:\n((?:  .*\n|\n)+)', WORKFLOW, re.M).group(1)
    assert re.findall(r'^  (\w+):', triggers, re.M) == ['schedule', 'workflow_dispatch']
    assert 'pull_request' not in WORKFLOW and 'secrets.' not in WORKFLOW
    assert re.search(r'^permissions:\n  contents: read\n\n', WORKFLOW, re.M)
    assert WORKFLOW.count('permissions:') == 1 and 'write' not in WORKFLOW


def test_the_monitor_workflow_pins_actions_and_never_reports_under_a_trusted_job_name():
    uses = re.findall(r'uses: (\S+)', WORKFLOW)
    assert uses and all(re.fullmatch(r'actions/[\w-]+@[0-9a-f]{40}', item) for item in uses)
    names = re.findall(r'^    name: (.+)$', WORKFLOW, re.M)
    assert names == ['ruleset-monitor']
    assert not set(names) & ({REQUIRED_CHECK} | {job.name for job in JOBS} | {job.id for job in JOBS})
    assert 'python -I scripts/monitor_ruleset.py' in WORKFLOW
