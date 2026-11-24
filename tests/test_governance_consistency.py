"""治理設定須彼此一致：CODEOWNERS、信任政策與發布器範本列出相同審查者。

Governance settings agree: CODEOWNERS, the trust policy and the publisher template
list the same reviewers."""
import json
import re
from pathlib import Path

import pytest

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


REQUIREMENT = re.compile(r"([A-Za-z0-9_.-]+)(?:\[([A-Za-z0-9_.,-]+)\])?==([0-9][A-Za-z0-9_.+-]*)")


def normalized(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def declared_lines(text=None):
    """requirements.in 的每一行：（正規化套件名、extras、釘住的版本）。 / Every line of requirements.in: (normalized
    name, extras, pinned version)."""
    text = (ROOT / "requirements.in").read_text() if text is None else text
    rows = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        match = REQUIREMENT.fullmatch(line)
        assert match, f"requirements.in must hold only exact pins: {line}"
        rows.append((normalized(match.group(1)), set(filter(None, (match.group(2) or "").split(","))), match.group(3)))
    assert len({name for name, _, _ in rows}) == len(rows), "duplicate requirement"
    return rows


def declared_requirements(text=None):
    """requirements.in 的直接依賴：套件名（正規化、去掉 extras）對應釘住的版本。 / Direct dependencies in requirements.in:
    normalized name without extras mapped to its pinned version."""
    return {name: version for name, _, version in declared_lines(text)}


def locked_requirements(text=None):
    """requirements.lock 的每個套件：版本，以及 uv 在 `# via` 註解記下的來源。每個項目只能是「名稱==版本」（不帶 marker、
    extras），且至少附一個 sha256 雜湊。 / Every package in requirements.lock: its version and the origins uv recorded
    in the `# via` comment. Each entry is exactly name==version (no marker, no extras) with at least one sha256 hash."""
    text = (ROOT / "requirements.lock").read_text() if text is None else text
    locked, hashes, current, in_via = {}, {}, None, False
    for line in text.splitlines():
        stripped = line.strip()
        if line[:1].isalnum():
            pin = re.fullmatch(r"([A-Za-z0-9_.-]+)==([0-9][A-Za-z0-9_.+-]*) \\", line)
            assert pin, f"lock entry must be exactly name==version with hashes: {line}"
            current, in_via = normalized(pin.group(1)), False
            assert current not in locked, f"duplicate lock entry: {current}"
            locked[current], hashes[current] = {"version": pin.group(2), "via": set()}, 0
        elif current and stripped.startswith("# via"):
            in_via = True
            origin = stripped.removeprefix("# via").strip()
            if origin:
                locked[current]["via"].add(origin)
        elif current and in_via and stripped.startswith("#"):
            locked[current]["via"].add(stripped.removeprefix("#").strip())
        elif current and not in_via and re.fullmatch(r"--hash=sha256:[0-9a-f]{64}(?: \\)?", stripped):
            hashes[current] += 1
        elif stripped and not stripped.startswith("#"):
            raise AssertionError(f"unexpected lock line: {line}")
    assert all(hashes.values()), f"lock entry without a hash: {sorted(n for n, count in hashes.items() if not count)}"
    return locked


def extra_mismatches(declared, locked, requires):
    """直接依賴的 extras 與 lock 是否一致。requires(name) 回傳該套件 metadata 的依賴宣告。宣告的 extra 所需的套件必須在
    lock 裡並標示來自該依賴；lock 裡標示來自某直接依賴、卻只有未宣告的 extra 才需要的套件，代表 lock 沒有跟著重新產生。

    Whether direct dependencies' extras agree with the lock. requires(name) returns that package's metadata
    requirements. A package a declared extra needs must be locked and marked as coming from that dependency; a locked
    package marked as coming from a direct dependency that only an undeclared extra needs means the lock was not
    recompiled."""
    from packaging.requirements import Requirement
    problems = []
    for name, extras, _ in declared:
        needed = {}
        for raw in requires(name) or ():
            requirement = Requirement(raw)
            child = normalized(requirement.name)
            needed.setdefault(child, set())
            for extra in ("", *sorted(extras)):
                if requirement.marker is None or requirement.marker.evaluate({"extra": extra}):
                    needed[child].add(extra)
        for child, wanted in needed.items():
            via = name in locked.get(child, {}).get("via", ())
            if wanted - {""} and not via:
                problems.append(f"{name}[{','.join(sorted(wanted - {''}))}] needs {child}, absent from the lock")
            if via and not wanted:
                problems.append(f"{child} is locked via {name} but no declared extra needs it")
    return problems


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



def test_declared_extras_match_the_lock():
    """requirements.in 宣告的 extras 與 lock 一致：拿掉或加上 extra 而沒有重新產生 lock，會在這裡失敗。以已安裝套件的
    metadata 判斷每個 extra 需要哪些套件。

    The extras declared in requirements.in agree with the lock: dropping or adding an extra without recompiling the
    lock fails here. Installed package metadata tells which packages each extra needs."""
    from importlib import metadata
    declared, locked = declared_lines(), locked_requirements()
    assert any(extras for _, extras, _ in declared), "requirements.in declares at least one extra"
    assert extra_mismatches(declared, locked, metadata.requires) == []
    # 拿掉 extra 而不重新產生 lock：psycopg-binary 仍在 lock 裡，卻沒有任何宣告的 extra 需要它。 / Dropping the extra
    # without recompiling: psycopg-binary stays locked though no declared extra needs it.
    stale = declared_lines((ROOT / "requirements.in").read_text().replace("psycopg[binary]", "psycopg"))
    assert extra_mismatches(stale, locked, metadata.requires) == [
        "psycopg-binary is locked via psycopg but no declared extra needs it"]
    # 加上 extra 而不重新產生 lock：該 extra 需要的套件不在 lock 裡。 / Adding an extra without recompiling: what it
    # needs is missing from the lock.
    widened = declared_lines((ROOT / "requirements.in").read_text().replace("psycopg[binary]", "psycopg[binary,pool]"))
    assert extra_mismatches(widened, locked, metadata.requires) == [
        "psycopg[pool] needs psycopg-pool, absent from the lock"]


@pytest.mark.parametrize("old,new,message", [
    ("psycopg==3.3.6 \\", 'psycopg==3.3.6 ; sys_platform == "linux" \\', "exactly name==version"),
    ("psycopg==3.3.6 \\", "psycopg[binary]==3.3.6 \\", "exactly name==version"),
    ("psycopg==3.3.6 \\", "psycopg>=3.3.6 \\", "exactly name==version"),
])
def test_a_lock_entry_with_a_marker_extra_or_range_is_refused(old, new, message):
    """lock 的每個項目只能是「名稱==版本」：帶環境 marker、extras 或版本範圍的手改項目都拒絕。

    Every lock entry is exactly name==version: a hand-edited entry with an environment marker, extras or a version
    range is refused."""
    text = (ROOT / "requirements.lock").read_text()
    assert text.count(old) == 1 and locked_requirements(text)["psycopg"]["version"] == "3.3.6"
    with pytest.raises(AssertionError, match=message):
        locked_requirements(text.replace(old, new))


def test_a_lock_entry_without_a_hash_is_refused():
    """lock 的每個項目至少附一個 sha256 雜湊：手動加入、沒有雜湊的項目拒絕；雜湊格式不符也拒絕。

    Every lock entry carries at least one sha256 hash: a hand-added entry without one is refused, and so is a
    malformed hash."""
    text = (ROOT / "requirements.lock").read_text()
    with pytest.raises(AssertionError, match=r"lock entry without a hash: \['extra-package'\]"):
        locked_requirements(text + "extra-package==1.0 \\\n    # via psycopg\n")
    with pytest.raises(AssertionError, match="unexpected lock line"):
        locked_requirements(text + "extra-package==1.0 \\\n    --hash=sha256:abc\n    # via psycopg\n")
