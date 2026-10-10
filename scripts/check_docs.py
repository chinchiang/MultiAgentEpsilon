#!/usr/bin/env python3
"""檢查雙語入口、連結、圖表與目錄樹；Validate bilingual entries, links, diagrams and repository tree."""
import argparse
import ast
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
if __name__ == '__main__':
    sys.path.insert(0, str(ROOT))
from security_harness import candidate_git
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


def validate(paths, root=ROOT):
    errors = []
    markdown = [root / p for p in paths if p.endswith('.md')]
    for path in markdown:
        text = path.read_text()
        for anchor in ('zh-tw', 'en'):
            if text.count(f'<a id="{anchor}"></a>') != 1:
                errors.append(f'{path.relative_to(root)}: language anchor / 語言入口 {anchor}')
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
                  (not destination.is_file() or f'<a id="{parts.fragment}"></a>' not in destination.read_text())):
                errors.append(f'{path.name}: missing linked anchor / 連結錨點不存在 {target}')
    architecture = root / 'docs/architecture-overview.zh-TW.md'
    text = architecture.read_text() if architecture.is_file() else ''
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
            try:
                element = ET.fromstring(svg.read_text())
                if any(e.tag.rsplit('}', 1)[-1] in ('script', 'foreignObject') for e in element.iter()):
                    errors.append(f'{name}: active SVG content / SVG 含主動內容')
            except ET.ParseError:
                errors.append(f'{name}: invalid SVG / SVG 格式錯誤')
        if path.suffix == '.py':
            for node in ast.walk(ast.parse(path.read_text())):
                if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                doc = ast.get_docstring(node)
                if doc and (not re.search('[\u4e00-\u9fff]', doc) or not re.search('[A-Za-z]{3,}', doc)):
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
        before, tail = path.read_text().split(START, 1)
        _, after = tail.split(END, 1)
        path.write_text(before + START + '\n' + repository_tree(paths) + '\n' + END + after)
    errors = validate(paths, root)
    for error in errors:
        print(error)
    if not errors:
        print(f'雙語結構與連結檢查通過 / Documentation checks passed ({len(paths)} files)')
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
