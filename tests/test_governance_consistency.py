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


def test_readme_states_the_auth_case_count_of_the_policy_contract():
    """README 的 AUTH 案例數（中英）等於政策契約的案例數。

    The AUTH case count in the README equals the policy contract in both languages."""
    count = len(json.loads((ROOT / "security/policy.json").read_text())["gate_contracts"]["AUTH"]["case_ids"])
    readme = (ROOT / "README.md").read_text()
    assert f"AUTH 有 {count} 個必要案例" in readme
    assert f"| AUTH | {count} synthetic authentication/authorization" in readme
    assert set(re.findall(r"exact unique set of (\d+) cases", readme)) == {str(count)}


def test_ruleset_monitor_docs_name_the_issue_alert_instead_of_an_owner_notification():
    """監看文件（中英）寫出實際的示警方式：失敗時開 issue，而不是宣稱 GitHub 會通知擁有者。

    The monitor docs state the real alert in both languages: a failure opens an issue, not an owner notification."""
    text = (ROOT / "docs/trusted-execution.zh-TW.md").read_text()
    assert "GitHub 會通知擁有者" not in text and "GitHub notifies the owner" not in text
    assert "自動開一個 issue" in text and "opens an issue" in text
    assert "60 天" in text and "60 days" in text


def declared_requirements():
    """requirements.in 的直接依賴：套件名（正規化、去掉 extras）對應釘住的版本。 / Direct dependencies in requirements.in:
    normalized name without extras mapped to its pinned version."""
    declared = {}
    for line in (ROOT / "requirements.in").read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_.,-]+\])?==([0-9][A-Za-z0-9_.+-]*)", line)
        assert match, f"requirements.in must hold only exact pins: {line}"
        name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
        assert name not in declared, f"duplicate requirement: {name}"
        declared[name] = match.group(2)
    return declared


def locked_requirements():
    """requirements.lock 的每個套件：版本，以及 uv 在 `# via` 註解記下的來源。 / Every package in requirements.lock: its
    version and the origins uv recorded in the `# via` comment."""
    locked, current, in_via = {}, None, False
    for line in (ROOT / "requirements.lock").read_text().splitlines():
        pin = re.match(r"([A-Za-z0-9_.-]+)==([0-9][A-Za-z0-9_.+-]*)", line)
        stripped = line.strip()
        if pin:
            current, in_via = re.sub(r"[-_.]+", "-", pin.group(1)).lower(), False
            assert current not in locked, f"duplicate lock entry: {current}"
            locked[current] = {"version": pin.group(2), "via": set()}
        elif current and stripped.startswith("# via"):
            in_via = True
            origin = stripped.removeprefix("# via").strip()
            if origin:
                locked[current]["via"].add(origin)
        elif current and in_via and stripped.startswith("#"):
            locked[current]["via"].add(stripped.removeprefix("#").strip())
        elif stripped and not stripped.startswith(("--hash=", "#")):
            raise AssertionError(f"unexpected lock line: {line}")
    return locked


def test_lock_is_compiled_from_requirements_in():
    """lock 檔開頭記錄的產生指令必須以 requirements.in 為輸入、輸出到 requirements.lock。

    The command recorded at the top of the lock takes requirements.in as input and writes requirements.lock."""
    header = (ROOT / "requirements.lock").read_text().splitlines()[:2]
    assert header[0].startswith("# This file was autogenerated by uv")
    assert re.fullmatch(r"#\s+uv pip compile requirements\.in .*--generate-hashes .*--output-file requirements\.lock.*",
                        header[1])


def test_every_declared_requirement_is_locked_at_the_declared_version():
    """requirements.in 的每個直接依賴都在 lock 裡、版本相同，且 lock 標示它來自 requirements.in；只改其中一個檔案會在這裡失敗。

    Every direct dependency in requirements.in is in the lock at the same version and marked as coming from
    requirements.in; editing only one of the two files fails here."""
    declared, locked = declared_requirements(), locked_requirements()
    assert declared, "requirements.in declares at least one dependency"
    assert {name: locked.get(name, {}).get("version") for name in declared} == declared
    direct = {name for name, entry in locked.items() if "-r requirements.in" in entry["via"]}
    assert direct == set(declared)


def test_every_locked_package_is_reachable_from_a_declared_requirement():
    """lock 裡沒有多出來的套件：每個套件都是直接依賴，或沿著 `# via` 能追到某個直接依賴；來源也必須是 lock 內的套件。

    The lock holds nothing extra: every package is a direct dependency or traces through `# via` to one, and every
    origin is itself a locked package."""
    declared, locked = declared_requirements(), locked_requirements()
    for name, entry in locked.items():
        assert entry["via"], f"lock entry without an origin: {name}"
        assert entry["via"] <= set(locked) | {"-r requirements.in"}, f"unknown origin for {name}: {entry['via']}"
    reachable, pending = set(), list(declared)
    while pending:
        name = pending.pop()
        if name not in reachable:
            reachable.add(name)
            pending.extend(child for child, entry in locked.items() if name in entry["via"])
    assert reachable == set(locked)

