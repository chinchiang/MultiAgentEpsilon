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



def job(name):
    """取出 workflow 中某個 job 的區塊（到下一個同層 job 為止）。 / The block of one job in the workflow, up to the
    next job at the same level."""
    match = re.search(rf'^  {name}:\n((?:    .*\n|\n)+)', WORKFLOW, re.M)
    assert match, name
    return match.group(1)

def test_the_monitor_tests_use_the_checked_in_ruleset_template():
    expected = template()
    del expected['id'], expected['updated_at']
    assert json.loads((ROOT / 'docs/github-main-ruleset.json').read_text()) == expected


def test_the_monitor_workflow_only_runs_on_a_schedule_or_by_hand_with_read_only_access():
    triggers = re.search(r'^on:\n((?:  .*\n|\n)+)', WORKFLOW, re.M).group(1)
    assert re.findall(r'^  (\w+):', triggers, re.M) == ['schedule', 'workflow_dispatch']
    assert 'pull_request' not in WORKFLOW and 'secrets.' not in WORKFLOW
    assert re.search(r'^permissions:\n  contents: read\n\n', WORKFLOW, re.M)
    # 只有示警 job 能寫 issue；比對規則集的 job 維持唯讀。 / Only the alert job may write issues; the job that
    # compares the ruleset stays read-only.
    monitor, notify = job('monitor'), job('notify')
    assert 'write' not in monitor and 'permissions:' not in monitor
    assert re.findall(r'^\s+(\w+): write$', WORKFLOW, re.M) == ['issues']
    assert re.search(r'^    permissions:\n      issues: write\n', notify, re.M)


def test_the_monitor_workflow_pins_actions_and_never_reports_under_a_trusted_job_name():
    uses = re.findall(r'uses: (\S+)', WORKFLOW)
    assert uses and all(re.fullmatch(r'actions/[\w-]+@[0-9a-f]{40}', item) for item in uses)
    names = re.findall(r'^    name: (.+)$', WORKFLOW, re.M)
    assert names == ['ruleset-monitor', 'ruleset-monitor-alert']
    assert not set(names) & ({REQUIRED_CHECK} | {job.name for job in JOBS} | {job.id for job in JOBS})
    assert 'python -I scripts/monitor_ruleset.py' in WORKFLOW


def test_a_failed_monitor_opens_one_issue_without_running_third_party_code():
    # GitHub 的排程失敗通知只寄給最後修改排程的人；監看是唯一的漂移警報，所以失敗時改以 issue 示警。 / GitHub mails a
    # failed schedule only to whoever last edited it; the monitor is the only drift alarm, so a failure opens an issue.
    notify = job('notify')
    assert re.search(r'^    needs: monitor$', notify, re.M)
    assert re.search(r"^    if: \$\{\{ always\(\) && needs\.monitor\.result != 'success' \}\}$", notify, re.M)
    assert re.search(r'^    timeout-minutes: \d+$', notify, re.M)
    # 不 checkout、不跑任何 action：持有寫入權限的 job 只執行 runner 內建的 gh。 / No checkout and no action: the job
    # holding a write permission runs only the runner's own gh.
    assert not re.search(r'^\s+(- )?uses:', notify, re.M) and 'actions/checkout' not in notify
    assert 'gh issue create' in notify
    # 只把 Actions 自己開的 issue 當成既有警報，外人先開同標題 issue 壓不掉示警；已有警報時不重複開。 / Only an issue
    # Actions opened counts as an existing alarm, so someone else's same-titled issue cannot suppress it.
    assert 'author:app/github-actions' in notify and 'gh issue list --state open' in notify
    assert notify.index('gh issue list') < notify.index('gh issue create')


def test_the_monitor_workflow_comments_do_not_promise_an_owner_notification():
    assert 'notifies the owner' not in WORKFLOW and '通知擁有者' not in WORKFLOW
