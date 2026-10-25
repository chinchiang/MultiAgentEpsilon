#!/usr/bin/env python3
"""檢查雙語入口、連結、圖表、目錄樹與名詞表避用詞；Validate bilingual entries, links, diagrams, repository tree and
avoided glossary terms."""
import argparse
import ast
import io
import re
import sys
import tokenize
from pathlib import Path
from urllib.parse import unquote, urlsplit
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
if __name__ == '__main__':
    sys.path.insert(0, str(ROOT))
from security_harness import candidate_git
# 臺灣慣用語規則：中文段落與圖表不得使用這些中國大陸用語。 / Taiwan terminology: these mainland-Chinese terms
# are refused in Chinese prose and diagrams.
MAINLAND_TERMS = ('軟件', '信息', '數據庫', '服務器', '默認', '用戶', '文件夾', '服務端', '網絡', '視頻', '原碼')
START = '<!-- repository-tree:start -->'
END = '<!-- repository-tree:end -->'


def inventory(root=ROOT, untracked=True):
    """列出要檢查的檔案；候選目錄只看已追蹤檔案。 / Files to check; a candidate checkout uses tracked files only."""
    flags = ('-co', '--exclude-standard') if untracked else ('-c',)
    raw = candidate_git.run(root, 'ls-files', *flags, '-z',
                            capture_output=True, check=True, timeout=10).stdout.decode()
    return sorted(set(p for p in raw.split('\0') if p and (root / p).is_file() and not (root / p).is_symlink()))


def repository_tree(paths):
    tree = {}
    for name in paths:
        node = tree
        for part in Path(name).parts:
            node = node.setdefault(part, {})
    lines = ['MultiAgentEpsilon/']
    def visit(node, prefix=''):
        entries = sorted(node, key=lambda k: (not bool(node[k]), k))
        for i, name in enumerate(entries):
            last = i == len(entries) - 1
            lines.append(prefix + ('└── ' if last else '├── ') + name + ('/' if node[name] else ''))
            visit(node[name], prefix + ('    ' if last else '│   '))
    visit(tree)
    return '```text\n' + '\n'.join(lines) + '\n```'


def mermaid_labels(text):
    """Mermaid 節點與連線標籤的各行文字。 / Each line of Mermaid node and edge labels."""
    labels = re.findall(r'(?:\[|\{|\|)"([^"]*)"(?:\]|\}|\|)', text)
    return [part for label in labels for part in label.split('<br/>') if part.strip()]


def terminology_errors(name, text):
    return [f'{name}: mainland term / 非臺灣慣用語 {term}' for term in MAINLAND_TERMS if term in text]


# 名詞表的「避免」行，中英段落的冒號寬度不同。 / The glossary's avoid lines; the colon differs between the two halves.
AVOID_LINE = re.compile(r'_(?:避免|Avoid)_[：:]\s*(.+)')
# 沒有空白的中文避用詞至少這麼長才檢查；較短的詞（例如「判定」）在別處另有正當用法。 / A Chinese avoided term without
# spaces is checked from this length; shorter words such as 判定 have legitimate uses elsewhere.
MIN_CJK_TERM = 4


def avoided_terms(root):
    """名詞表「避免」清單中能機械判斷的詞：含空白的多字詞，或至少四個字的中文詞；條目本身帶使用情境括號或反引號的
不檢查，單字詞也不檢查，這些由審查者判斷。

The glossary's avoided terms that a check can judge: multi-word terms, or Chinese terms of at least four characters.
Entries that carry a usage qualifier in parentheses or are marked with backticks, and single words, are left to the
reviewer.
    """
    glossary = root / 'GLOSSARY.md'
    terms = []
    for line in glossary.read_text(encoding='utf-8').splitlines() if glossary.is_file() else []:
        match = AVOID_LINE.match(line)
        for item in re.split(r'、|,\s*', match.group(1)) if match else []:
            item = item.strip()
            judged = ' ' in item or (len(item) >= MIN_CJK_TERM and re.fullmatch('[\u4e00-\u9fff]+', item))
            if judged and not re.search(r'[()（）`]', item) and item not in terms:
                terms.append(item)
    return terms


def term_pattern(term):
    # 英文字邊界避免比對到較長的字；換行的文字以任意空白相連。 / English word edges keep a term from matching inside a
    # longer word; wrapped text joins on any whitespace.
    body = r'\s+'.join(re.escape(part) for part in term.split())
    start = r'(?<![A-Za-z0-9_])' if re.match(r'[A-Za-z0-9]', term) else ''
    end = r'(?![A-Za-z0-9_])' if re.search(r'[A-Za-z0-9]$', term) else ''
    return re.compile(start + body + end, re.IGNORECASE)


def docstrings(tree):
    """模組、類別與函式的 docstring：節點、清理後的文字與原始字串節點。

The docstrings of modules, classes and functions: the node, the cleaned text and the raw string node.
    """
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and ast.get_docstring(node):
            yield node, ast.get_docstring(node), node.body[0].value


def python_prose(source, tree):
    """Python 原始碼中寫給人看的文字區塊與各自的第一行：連續的註解行接成一塊，每個 docstring 一塊；字串值與程式本身
不算。

The prose blocks in Python source with each block's first line: consecutive comment lines join into one block and
each docstring is one block. String values and code are not prose.
    """
    blocks, last = [], None
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type != tokenize.COMMENT:
            continue
        line, text = token.start[0], token.string.lstrip('#').strip()
        if last is not None and line == last + 1:
            blocks[-1] = (blocks[-1][0], blocks[-1][1] + '\n' + text)
        else:
            blocks.append((line, text))
        last = line
    blocks.extend((raw.lineno, raw.value) for _, _, raw in docstrings(tree))
    return blocks


def avoided_term_errors(name, source, tree, avoided):
    """註解與 docstring 中的避用詞，回報命中的那一行。 / Avoided terms in comments and docstrings, reported at the line
    that matched."""
    errors = []
    for first, text in python_prose(source, tree):
        for term, pattern in avoided:
            for found in pattern.finditer(text):
                errors.append(f'{name}:{first + text.count(chr(10), 0, found.start())}: '
                              f'avoided glossary term / 名詞表避用詞 {term}')
    return errors


def validate(paths, root=ROOT):
    errors = []
    avoided = [(term, term_pattern(term)) for term in avoided_terms(root)]
    markdown = [root / p for p in paths if p.endswith('.md')]
    for path in markdown:
        text = path.read_text(encoding='utf-8')
        for anchor in ('zh-tw', 'en'):
            if text.count(f'<a id="{anchor}"></a>') != 1:
                errors.append(f'{path.relative_to(root)}: language anchor / 語言入口 {anchor}')
        errors.extend(terminology_errors(path.name, text.split('<a id="en"></a>', 1)[0]))
        if '<a id="en"></a>' in text:
            zh, en = text.split('<a id="en"></a>', 1)
            if not re.search('[\u4e00-\u9fff]', zh) or not re.search('[A-Za-z]{3,}', en):
                errors.append(f'{path.name}: missing language content / 缺少語言內容')
        prose = re.sub(r'```.*?```', '', text, flags=re.S)
        for target in re.findall(r'!?\[[^\]]*\]\(([^\s)]+)\)', prose):
            parts = urlsplit(target.strip('<>'))
            if parts.scheme or parts.netloc:
                continue
            destination = (path.parent / unquote(parts.path)).resolve() if parts.path else path
            if not destination.is_relative_to(root.resolve()) or not destination.exists():
                errors.append(f'{path.name}: missing local link / 本機連結不存在 {target}')
            elif (parts.fragment in ('en', 'zh-tw') and
                  (not destination.is_file() or f'<a id="{parts.fragment}"></a>' not in destination.read_text(encoding='utf-8'))):
                errors.append(f'{path.name}: missing linked anchor / 連結錨點不存在 {target}')
    architecture = root / 'docs/architecture-overview.zh-TW.md'
    text = architecture.read_text(encoding='utf-8') if architecture.is_file() else ''
    if text.count(START) != 1 or text.count(END) != 1:
        errors.append('repository tree markers missing / 缺少目錄樹標記')
    elif text.split(START, 1)[1].split(END, 1)[0].strip() != repository_tree(paths):
        errors.append('repository tree is stale / 目錄樹尚未同步')
    for name in paths:
        path = root / name
        if path.suffix == '.mmd':
            svg = path.with_suffix('.svg')
            if not svg.is_file():
                errors.append(f'{name}: missing SVG / 缺少 SVG')
                continue
            source = path.read_text(encoding='utf-8')
            errors.extend(terminology_errors(name, source))
            try:
                element = ET.fromstring(svg.read_text(encoding='utf-8'))
                if any(e.tag.rsplit('}', 1)[-1] in ('script', 'foreignObject') for e in element.iter()):
                    errors.append(f'{name}: active SVG content / SVG 含主動內容')
                # 換行可能拆開文字，因此忽略空白後比對。 / Wrapping can split text, so compare without whitespace.
                rendered = re.sub(r'\s+', '', ''.join(element.itertext()))
                stale = [label for label in mermaid_labels(source) if re.sub(r'\s+', '', label) not in rendered]
                if stale:
                    errors.append(f'{name}: SVG not regenerated / SVG 未重新產生 ({len(stale)} labels)')
            except ET.ParseError:
                errors.append(f'{name}: invalid SVG / SVG 格式錯誤')
        if path.suffix == '.py':
            source = path.read_text(encoding='utf-8')
            tree = ast.parse(source)
            errors.extend(avoided_term_errors(name, source, tree, avoided))
            for node, doc, _ in docstrings(tree):
                if not re.search('[\u4e00-\u9fff]', doc) or not re.search('[A-Za-z]{3,}', doc):
                    errors.append(f'{name}:{getattr(node, "lineno", 1)}: docstring requires both languages / 文件字串需雙語')
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--update-tree', action='store_true', help='同步目錄樹 / regenerate repository tree')
    parser.add_argument('--root', type=Path, default=ROOT,
                        help='要檢查的 checkout，候選僅讀取不執行 / checkout to check; a candidate is read, never executed')
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if args.update_tree and root != ROOT:
        parser.error('只能更新本儲存庫的目錄樹 / --update-tree only applies to this repository')
    paths = inventory(root, untracked=root == ROOT)
    if args.update_tree:
        path = ROOT / 'docs/architecture-overview.zh-TW.md'
        before, tail = path.read_text(encoding='utf-8').split(START, 1)
        _, after = tail.split(END, 1)
        path.write_text(before + START + '\n' + repository_tree(paths) + '\n' + END + after, encoding='utf-8')
    errors = validate(paths, root)
    for error in errors:
        print(error)
    if not errors:
        print(f'雙語結構與連結檢查通過 / Documentation checks passed ({len(paths)} files)')
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
