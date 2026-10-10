"""文件檢查器的回歸：缺錨點、壞連結、目錄樹過期、單語 docstring 與候選模式。

Documentation checker regressions: anchors, links, stale tree, monolingual docstrings
and candidate mode."""
import subprocess

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


def test_stale_svg_labels_are_reported(tmp_path):
    svg = '<svg xmlns="http://www.w3.org/2000/svg"><text>舊標籤</text><text>Old label</text></svg>'
    root = repo(tmp_path, base_files(**{"docs/d.mmd": 'flowchart TB\n    A["新標籤<br/>New label"]\n',
                                         "docs/d.svg": svg}))
    assert any("SVG not regenerated" in e for e in errors(root))
