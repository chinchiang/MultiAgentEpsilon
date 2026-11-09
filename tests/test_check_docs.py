"""文件檢查器的回歸：缺錨點、壞連結、目錄樹過期、單語 docstring 與候選模式。

Documentation checker regressions: anchors, links, stale tree, monolingual docstrings
and candidate mode."""
import re
import subprocess
from pathlib import Path

import pytest

from scripts import check_docs

BILINGUAL = '中文說明\n<a id="zh-tw"></a>\n內容\n<a id="en"></a>\nEnglish text\n'


def repo(tmp_path, files):
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    architecture = tmp_path / "docs/architecture-overview.zh-TW.md"
    paths = check_docs.inventory(tmp_path, untracked=False)
    architecture.write_text(BILINGUAL + check_docs.START + "\n" + check_docs.repository_tree(paths) + "\n" + check_docs.END + "\n")
    return tmp_path


@pytest.fixture(autouse=True)
def trusted_root_without_glossary(tmp_path_factory, monkeypatch):
    # 合成 repo 的測試只看自己的名詞表；可信名詞表另有測試。 / Synthetic repositories see only their own glossary; the
    # trusted glossary has its own tests.
    trusted = tmp_path_factory.mktemp("trusted")
    subprocess.run(["git", "init", "-q", str(trusted)], check=True)
    monkeypatch.setattr(check_docs, "ROOT", trusted)


def errors(root):
    return check_docs.validate(check_docs.inventory(root, untracked=False), root)


def base_files(**extra):
    return {"docs/architecture-overview.zh-TW.md": "", "README.md": BILINGUAL, **extra}


def test_clean_repository_passes(tmp_path):
    assert errors(repo(tmp_path, base_files())) == []


@pytest.mark.parametrize("text,expected", [
    ("only english\n", "language anchor"),
    (BILINGUAL + "[x](missing.md)\n", "missing local link"),
    (BILINGUAL + "[x](README.md#en)\n", None),
    (BILINGUAL + "[x](docs#en)\n", "missing linked anchor"),
])
def test_markdown_rules(tmp_path, text, expected):
    root = repo(tmp_path, base_files(**{"guide.md": text}))
    found = errors(root)
    assert (any(expected in e for e in found) if expected else found == [])


def test_stale_tree_and_missing_markers_are_reported_without_crashing(tmp_path):
    root = repo(tmp_path, base_files())
    (root / "new.txt").write_text("x")
    subprocess.run(["git", "-C", str(root), "add", "new.txt"], check=True)
    assert any("repository tree is stale" in e for e in errors(root))
    (root / "docs/architecture-overview.zh-TW.md").write_text(BILINGUAL)
    assert any("markers missing" in e for e in errors(root))


def test_monolingual_python_docstring_is_reported(tmp_path):
    root = repo(tmp_path, base_files(**{"module.py": '"""English only docstring."""\n'}))
    assert any("docstring requires both languages" in e for e in errors(root))


def test_candidate_mode_ignores_untracked_files_and_cannot_update_tree(tmp_path, capsys):
    root = repo(tmp_path, base_files())
    (root / "untracked.md").write_text("no anchors\n")
    assert check_docs.main(["--root", str(root)]) == 0
    with pytest.raises(SystemExit):
        check_docs.main(["--root", str(root), "--update-tree"])


def test_mainland_terms_in_chinese_prose_are_reported(tmp_path):
    root = repo(tmp_path, base_files(**{"guide.md": BILINGUAL.replace("內容", "服務端的默認設定")}))
    found = errors(root)
    assert any("服務端" in e for e in found) and any("默認" in e for e in found)


def test_english_half_may_quote_terms_without_failing(tmp_path):
    root = repo(tmp_path, base_files(**{"guide.md": BILINGUAL + "Glossary: avoid 服務端.\n"}))
    assert errors(root) == []


def test_cli_reads_every_document_as_utf8_regardless_of_the_locale(tmp_path):
    # 未指定編碼時依 locale 解碼（如 Windows cp950），中文文件會讀錯。 / Without an explicit encoding the locale
    # decides (e.g. cp950 on Windows) and Chinese documents are misread.
    import sys
    from pathlib import Path
    svg = '<svg xmlns="http://www.w3.org/2000/svg"><text>新標籤</text><text>New label</text></svg>'
    root = repo(tmp_path, base_files(**{
        "README.md": BILINGUAL + "[指南](docs/guide.md#en)\n", "docs/guide.md": BILINGUAL,
        "docs/d.mmd": 'flowchart TB\n    A["新標籤<br/>New label"]\n', "docs/d.svg": svg,
        "module.py": '"""中文說明。\n\nEnglish description."""\n'}))
    # 可信根目錄換成沒有測試的空 repo，候選測試數下限才不會拿本專案的測試比對。 / The trusted root is an empty
    # repository without tests, so the candidate test floor does not compare against this project's tests.
    source = Path(__file__).resolve().parents[1]
    run = ("import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); from scripts import check_docs; "
           "check_docs.ROOT = Path(sys.argv[2]); sys.argv = ['check_docs.py', '--root', sys.argv[3]]; "
           "raise SystemExit(check_docs.main())")
    process = subprocess.run([sys.executable, "-I", "-X", "utf8=0", "-X", "warn_default_encoding",
                              "-W", "error::EncodingWarning", "-c", run, str(source), str(check_docs.ROOT), str(root)],
                             capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert process.returncode == 0, process.stderr[-500:]
    assert "Documentation checks passed" in process.stdout


def test_stale_svg_labels_are_reported(tmp_path):
    svg = '<svg xmlns="http://www.w3.org/2000/svg"><text>舊標籤</text><text>Old label</text></svg>'
    root = repo(tmp_path, base_files(**{"docs/d.mmd": 'flowchart TB\n    A["新標籤<br/>New label"]\n',
                                         "docs/d.svg": svg}))
    assert any("SVG not regenerated" in e for e in errors(root))



GLOSSARY = ("中文說明\n<a id=\"zh-tw\"></a>\n**讀取**：\n說明。\n"
            "_避免_：唯讀 client、復原清冊、子程序執行、交接（單獨使用時）、判定、`gh api`\n"
            "<a id=\"en\"></a>\n**Reader**:\nText.\n"
            "_Avoid_: read-only client, recovery inventory, handoff (on its own), verdict, `gh api`\n")
MODULE = ("\"\"\"模組說明。\n\nA Read-Only\nclient for one repository.\"\"\"\n"
          "value = \"read-only client\"  # 字串值不算 / a string value is not prose\n"
          "read_only_client = 1\n"
          "# 改用唯讀 client 讀取，先寫復原清冊。 / Read through it\n"
          "# into the recovery\n"
          "# inventory first.\n"
          "def reader():\n    \"\"\"讀取判定與交接。 / Not a read-only clientele, nor gh api or a verdict.\"\"\"\n")


def test_avoided_glossary_terms_in_comments_and_docstrings_are_reported_at_the_matching_line(tmp_path):
    # 只檢查能機械判斷的詞：多字詞與四字以上的中文詞；單字詞、標了情境或以反引號標示的條目留給審查者。 / Only
    # terms a check can judge: multi-word terms and Chinese terms of four or more characters. Single words, qualified
    # entries and entries marked with backticks are left to the reviewer.
    root = repo(tmp_path, base_files(**{"GLOSSARY.md": GLOSSARY, "tool.py": MODULE}))
    assert sorted(e for e in errors(root) if "avoided glossary term" in e) == sorted([
        "tool.py:3: avoided glossary term / 名詞表避用詞 read-only client",
        "tool.py:7: avoided glossary term / 名詞表避用詞 唯讀 client",
        "tool.py:7: avoided glossary term / 名詞表避用詞 復原清冊",
        "tool.py:8: avoided glossary term / 名詞表避用詞 recovery inventory"])


def test_without_avoid_lists_nothing_is_reported(tmp_path):
    root = repo(tmp_path, base_files(**{"tool.py": MODULE}))
    assert not [e for e in errors(root) if "avoided glossary term" in e]


def test_every_term_in_the_real_glossary_keeps_a_parsable_avoid_list():
    # 名詞表格式改變時避用詞會靜默變空、檢查照樣通過，所以每個條目都要有讀得到的「避免」行。 / A changed glossary
    # format would silently empty the avoided terms and let the check pass, so every entry keeps a readable avoid line.
    real = Path(check_docs.__file__).resolve().parents[1]
    lines = (real / "GLOSSARY.md").read_text(encoding="utf-8").splitlines()
    entries = [line for line in lines if re.fullmatch(r"\*\*[^*]+\*\*[：:]", line)]
    assert entries and len(entries) == sum(bool(check_docs.AVOID_LINE.match(line)) for line in lines)
    assert check_docs.avoided_terms(real)


def test_candidate_cannot_drop_an_avoided_term_and_use_it(tmp_path, monkeypatch):
    # 候選刪掉名詞表的避用詞並同時使用它；可信名詞表仍適用。 / The candidate removes an avoided term from its glossary
    # and uses it; the trusted glossary still applies.
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    (trusted / "GLOSSARY.md").write_text(GLOSSARY, encoding="utf-8")
    monkeypatch.setattr(check_docs, "ROOT", trusted)
    root = repo(tmp_path / "candidate", base_files(**{"GLOSSARY.md": BILINGUAL, "tool.py": MODULE}))
    assert "tool.py:8: avoided glossary term / 名詞表避用詞 recovery inventory" in errors(root)


@pytest.mark.parametrize("content", [b"def broken(:\n", b"\xff\xfe not utf-8\n"], ids=["syntax", "encoding"])
def test_unparsable_candidate_python_is_an_error_not_a_traceback(tmp_path, content):
    root = repo(tmp_path, base_files())
    (root / "bad.py").write_bytes(content)
    subprocess.run(["git", "-C", str(root), "add", "bad.py"], check=True)
    assert any(e.startswith("bad.py: unparsable Python") for e in errors(root))


TRUSTED_TESTS = ('"""說明。 / Text."""\nimport pytest\n\n\n'
                 'def test_kept():\n    pass\n\n\n'
                 '@pytest.mark.parametrize("x", [1, 2, 3])\ndef test_cases(x):\n    pass\n\n\n'
                 'def test_doomed():\n    pass\n')


def candidate_floor(tmp_path, monkeypatch, candidate_tests, removed=None):
    trusted = repo(tmp_path / "trusted", base_files(**{"tests/test_x.py": TRUSTED_TESTS}))
    monkeypatch.setattr(check_docs, "ROOT", trusted)
    files = {"tests/test_x.py": candidate_tests}
    if removed is not None:
        files["security/removed-tests.json"] = removed
    candidate = repo(tmp_path / "candidate", base_files(**files))
    return candidate


def floor_errors(candidate, capsys):
    code = check_docs.main(["--root", str(candidate)])
    return code, [line for line in capsys.readouterr().out.splitlines() if "regression test" in line or "removed-tests" in line]


def test_candidate_that_deletes_a_regression_test_is_refused(tmp_path, monkeypatch, capsys):
    candidate = candidate_floor(tmp_path, monkeypatch, TRUSTED_TESTS.replace('\n\n\ndef test_doomed():\n    pass\n', '\n'))
    code, errors = floor_errors(candidate, capsys)
    assert code == 1 and len(errors) == 1 and errors[0].startswith("tests/test_x.py::test_doomed: regression test removed")


def test_candidate_that_shrinks_a_parametrized_test_is_refused(tmp_path, monkeypatch, capsys):
    candidate = candidate_floor(tmp_path, monkeypatch, TRUSTED_TESTS.replace("[1, 2, 3]", "[1, 2]"))
    code, errors = floor_errors(candidate, capsys)
    assert code == 1 and errors and "test_cases" in errors[0] and "(3 → 2)" in errors[0]


def test_renaming_a_test_counts_as_removing_the_old_name(tmp_path, monkeypatch, capsys):
    candidate = candidate_floor(tmp_path, monkeypatch, TRUSTED_TESTS.replace("def test_doomed", "def test_renamed"))
    code, errors = floor_errors(candidate, capsys)
    assert code == 1 and "test_doomed" in errors[0]


def test_declared_removal_with_a_reason_is_accepted(tmp_path, monkeypatch, capsys):
    removed = '[{"test": "tests/test_x.py::test_doomed", "reason": "covered by test_kept"}]'
    candidate = candidate_floor(tmp_path, monkeypatch,
                                TRUSTED_TESTS.replace('\n\n\ndef test_doomed():\n    pass\n', '\n'), removed)
    code, errors = floor_errors(candidate, capsys)
    assert (code, errors) == (0, [])


@pytest.mark.parametrize("removed", ['[{"test": "tests/test_x.py::test_doomed", "reason": " "}]',
                                     '[{"test": "tests/test_x.py::test_doomed"}]', 'not json'])
def test_removal_without_a_reason_is_refused(tmp_path, monkeypatch, capsys, removed):
    candidate = candidate_floor(tmp_path, monkeypatch,
                                TRUSTED_TESTS.replace('\n\n\ndef test_doomed():\n    pass\n', '\n'), removed)
    code, errors = floor_errors(candidate, capsys)
    assert code == 1 and any("removed-tests" in e for e in errors)


def test_adding_tests_and_cases_is_never_refused(tmp_path, monkeypatch, capsys):
    grown = TRUSTED_TESTS.replace("[1, 2, 3]", "[1, 2, 3, 4]") + '\n\ndef test_new():\n    pass\n'
    candidate = candidate_floor(tmp_path, monkeypatch, grown)
    code, errors = floor_errors(candidate, capsys)
    assert (code, errors) == (0, [])


def test_static_count_never_runs_candidate_code(tmp_path, monkeypatch, capsys):
    # 非 literal 參數只計 1，候選無法以程式碼灌大數量，也不會被執行。 / A non-literal parameter counts one: candidate code
    # can neither inflate the count nor run.
    hostile = TRUSTED_TESTS + '\n\n@pytest.mark.parametrize("x", __import__("os").system("touch PWNED") or range(999))\ndef test_hostile(x):\n    pass\n'
    candidate = candidate_floor(tmp_path, monkeypatch, hostile)
    from security_harness import regression_inventory
    counts = regression_inventory.inventory(candidate, ["tests/test_x.py"])
    assert counts["tests/test_x.py::test_hostile"] == 1 and not (candidate / "PWNED").exists()


@pytest.mark.parametrize("name,text,blocked", [
    ("CLAUDE.md", "@AGENTS.md\n", False),
    ("CLAUDE.md", "@AGENTS.md", False),
    ("CLAUDE.md", "@AGENTS.md\nextra rules\n", True),
    ("docs/CLAUDE.md", "@AGENTS.md\n", True),
    ("docs/x.md", "@AGENTS.md\n", True),
])
def test_only_the_root_claude_pointer_may_skip_language_anchors(tmp_path, name, text, blocked):
    # CLAUDE.md 只是指向 AGENTS.md 的指標；其他內容或其他位置仍須雙語錨點。 / CLAUDE.md is just a pointer to
    # AGENTS.md; any other content or location still needs both language anchors.
    root = repo(tmp_path, base_files(**{"AGENTS.md": BILINGUAL, name: text}))
    found = [e for e in errors(root) if "language anchor" in e]
    assert bool(found) is blocked


CHECKED_TESTS = ('"""說明。 / Text."""\nimport pytest\n\n\n'
                 'def test_strict():\n    assert 1 == 1\n    assert 2 == 2\n    with pytest.raises(ValueError):\n'
                 '        int("x")\n\n\n'
                 'def test_other():\n    assert True\n')


def checked_floor(tmp_path, monkeypatch, candidate_tests, removed=None):
    trusted = repo(tmp_path / "trusted", base_files(**{"tests/test_x.py": CHECKED_TESTS}))
    monkeypatch.setattr(check_docs, "ROOT", trusted)
    files = {"tests/test_x.py": candidate_tests}
    if removed is not None:
        files["security/removed-tests.json"] = removed
    return repo(tmp_path / "candidate", base_files(**files))


@pytest.mark.parametrize("weakened", [
    CHECKED_TESTS.replace("    assert 2 == 2\n", ""),
    CHECKED_TESTS.replace('    with pytest.raises(ValueError):\n        int("x")\n', '    int("1")\n'),
], ids=["assert-dropped", "raises-dropped"])
def test_candidate_that_drops_checks_from_a_test_is_refused(tmp_path, monkeypatch, capsys, weakened):
    # 先前只比對測試名稱與案例數，保留名稱但刪掉斷言的弱化不會被發現。 / Only names and case counts used to be compared, so
    # a test kept by name with its assertions removed went unnoticed.
    code = check_docs.main(["--root", str(checked_floor(tmp_path, monkeypatch, weakened))])
    found = [line for line in capsys.readouterr().out.splitlines() if "checks" in line]
    assert code == 1 and len(found) == 1 and found[0].startswith("tests/test_x.py::test_strict:")


def test_declared_weakening_with_a_reason_is_accepted(tmp_path, monkeypatch, capsys):
    removed = '[{"test": "tests/test_x.py::test_strict", "reason": "duplicate assertion"}]'
    candidate = checked_floor(tmp_path, monkeypatch, CHECKED_TESTS.replace("    assert 2 == 2\n", ""), removed)
    assert check_docs.main(["--root", str(candidate)]) == 0


def test_stale_declaration_for_an_intact_test_is_refused(tmp_path, monkeypatch, capsys):
    # 列給未被削減的測試，等於預先放行它日後被弱化。 / Listing an intact test would pre-authorize weakening it later.
    removed = '[{"test": "tests/test_x.py::test_other", "reason": "not needed"}]'
    candidate = checked_floor(tmp_path, monkeypatch, CHECKED_TESTS, removed)
    code = check_docs.main(["--root", str(candidate)])
    found = [line for line in capsys.readouterr().out.splitlines() if "stale" in line]
    assert code == 1 and len(found) == 1 and "test_other" in found[0]


def test_declaration_for_a_test_the_base_no_longer_has_is_tolerated(tmp_path, monkeypatch, capsys):
    # 已合併的移除留在檔案中無害：base 已沒有該測試，無從放行。 / A merged removal left in the file is harmless: the base
    # no longer has the test, so it authorizes nothing.
    removed = '[{"test": "tests/test_x.py::test_gone_long_ago", "reason": "merged earlier"}]'
    candidate = checked_floor(tmp_path, monkeypatch, CHECKED_TESTS, removed)
    assert check_docs.main(["--root", str(candidate)]) == 0


def test_moving_checks_into_more_assertions_is_never_refused(tmp_path, monkeypatch, capsys):
    stronger = CHECKED_TESTS.replace("    assert True\n", "    assert True\n    assert 3 == 3\n")
    assert check_docs.main(["--root", str(checked_floor(tmp_path, monkeypatch, stronger))]) == 0


def test_claude_pointer_requires_agents_md(tmp_path):
    # 指標指向不存在的 AGENTS.md 時，協作規則實際上不存在。 / A pointer to a missing AGENTS.md leaves no collaboration rules.
    root = repo(tmp_path, base_files(**{"CLAUDE.md": "@AGENTS.md\n"}))
    assert any("AGENTS.md" in e for e in errors(root))
