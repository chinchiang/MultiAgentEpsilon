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
    monkeypatch.setattr(check_docs, "ROOT", tmp_path_factory.mktemp("trusted"))


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
    script = Path(__file__).resolve().parents[1] / "scripts/check_docs.py"
    process = subprocess.run([sys.executable, "-I", "-X", "utf8=0", "-X", "warn_default_encoding",
                              "-W", "error::EncodingWarning", str(script), "--root", str(root)],
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
