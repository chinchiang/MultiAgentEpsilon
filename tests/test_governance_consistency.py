"""治理設定須彼此一致：CODEOWNERS、信任政策與發布器範本列出相同審查者。

Governance settings agree: CODEOWNERS, the trust policy and the publisher template
list the same reviewers."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def codeowners():
    rules = [line.split() for line in (ROOT / ".github/CODEOWNERS").read_text().splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    assert len(rules) == 1 and rules[0][0] == "*", "a single catch-all rule keeps every path reviewed"
    return [owner.removeprefix("@") for owner in rules[0][1:]]


def test_reviewers_are_identical_across_governance_files():
    trust = json.loads((ROOT / "security/trust-policy.json").read_text())
    template = json.loads((ROOT / "security/trusted-publisher.example.json").read_text())
    assert codeowners() == trust["baseline_reviewers"] == template["reviewers"]
    assert len(set(trust["baseline_reviewers"])) == len(trust["baseline_reviewers"]) >= 2


def test_publisher_template_targets_the_trusted_repository_and_workflow():
    trust = json.loads((ROOT / "security/trust-policy.json").read_text())
    template = json.loads((ROOT / "security/trusted-publisher.example.json").read_text())
    assert template["repository"] == trust["repository"]
    assert (ROOT / template["workflow_path"]).is_file()


def test_current_baseline_paragraph_lives_only_in_milestone_status():
    """README 與架構概覽只連到里程碑狀態，不重抄基準段落。

    README and the architecture overview link to milestone status instead of copying the baseline."""
    for name in ("README.md", "docs/architecture-overview.zh-TW.md"):
        text = (ROOT / name).read_text()
        assert "正式 main `" not in text and "Reviewed main `" not in text, name
        assert "milestone-status.zh-TW.md)" in text and "milestone-status.zh-TW.md#en)" in text, name


def test_milestone_status_test_count_matches_the_publisher_template_floor():
    """里程碑狀態的現況測試數（中英）等於發布程式範本的下限。

    The current test count in milestone status equals the publisher template floor in both languages."""
    floor = json.loads((ROOT / "security/trusted-publisher.example.json").read_text())["minimum_regression_tests"]
    text = (ROOT / "docs/milestone-status.zh-TW.md").read_text()
    zh = re.search(r"正式 main `[0-9a-f]{7}`.*?成功：(\d+) 項測試", text)
    en = re.search(r"Reviewed main `[0-9a-f]{7}`.*?succeeded with (\d+) tests", text)
    assert zh and en
    assert int(zh.group(1)) == int(en.group(1)) == floor
    assert floor >= 1893


def test_migration_steps_do_not_exclude_the_run_actor_from_approving():
    """受控遷移步驟不得再寫「核准者不可是 CI 的觸發者」：程式已不排除 run 的觸發者。

    The migration steps must not exclude the run actor from approving; the code no longer does."""
    text = (ROOT / "docs/trusted-execution.zh-TW.md").read_text()
    assert "核准者不可是 CI 的觸發者" not in text
    assert "approver must not be the run's actor" not in text
