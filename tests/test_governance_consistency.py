"""治理設定須彼此一致：CODEOWNERS、信任政策與發布器範本列出相同審查者。

Governance settings agree: CODEOWNERS, the trust policy and the publisher template
list the same reviewers."""
import json
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
