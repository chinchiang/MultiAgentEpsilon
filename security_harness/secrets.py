"""Verified Gitleaks over an explicit, bounded worktree and HEAD-blob inventory."""
from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path

from . import candidate_git
from .results import digest_file, read_regular
from .inputs import input_files
from .limits import LIMITS, ResourceLimit
from .processes import bounded_output
from .scan_content import ContentInventory, load_binary_allowlist


def history_blobs(root, required=False):
    """HEAD-reachable blobs of the input root's own repository; `required` refuses to
    report complete coverage for an input without history."""
    if candidate_git.git_dir(root) is None:
        if required:
            raise ValueError('history coverage required but input root is not a repository')
        return None, []
    head = candidate_git.run(root, 'rev-parse', '--verify', 'HEAD', capture_output=True, text=True, timeout=10)
    if head.returncode:
        ref = candidate_git.run(root, 'symbolic-ref', '-q', 'HEAD', capture_output=True, text=True, timeout=10)
        if ref.returncode or candidate_git.run(root, 'show-ref', '--verify', '--quiet', ref.stdout.strip(),
                                               timeout=10).returncode != 1:
            raise ValueError('Git history unavailable for an existing repository')
        if required:
            raise ValueError('history coverage required but repository has no commits')
        return None, []
    tip = head.stdout.strip()
    if not re.fullmatch('[a-f0-9]{40}|[a-f0-9]{64}', tip):
        raise ValueError('invalid history identity')
    shallow = bounded_output(candidate_git.command(root, 'rev-parse', '--is-shallow-repository'), b'',
                             env=candidate_git.environment())
    if shallow.strip() != b'false':
        raise ValueError('shallow repository cannot establish history coverage')
    objects = bounded_output(candidate_git.command(root, 'rev-list', '--objects', tip), b'', timeout=30,
                             limit=4*1024*1024, env=candidate_git.environment()).decode().splitlines()
    names = {}
    for row in objects:
        oid, _, name = row.partition(' ')
        if not re.fullmatch('[a-f0-9]{40}|[a-f0-9]{64}', oid):
            raise ValueError('invalid history object')
        names[oid] = name
    if len(names) > LIMITS.max_history_blobs * 4:
        raise ResourceLimit('history object inventory too large')
    blobs = []
    total = 0
    ids = list(names)
    for offset in range(0, len(ids), 128):
        chunk = ids[offset:offset+128]
        output = bounded_output(candidate_git.command(root, 'cat-file',
                                                       '--batch-check=%(objectname) %(objecttype) %(objectsize)'),
                                ('\n'.join(chunk)+'\n').encode(), timeout=20, env=candidate_git.environment()).decode().splitlines()
        if len(output) != len(chunk):
            raise ValueError('incomplete history metadata')
        for expected, row in zip(chunk, output):
            oid, kind, size_text = row.split()
            if oid != expected:
                raise ValueError('history metadata mismatch')
            if kind != 'blob':
                continue
            size = int(size_text)
            total += size
            if size > LIMITS.max_file_bytes or total > LIMITS.max_history_bytes or len(blobs) >= LIMITS.max_history_blobs:
                raise ResourceLimit('history byte or blob limit exceeded')
            blobs.append((oid, names[oid], size))
    return tip, blobs


def history_metadata(root, tip):
    """HEAD commit messages/identities and all tag names/annotated-tag metadata.

    Tag target histories outside HEAD remain excluded. Bound raw bytes before
    scanning; never copy metadata or tag names into evidence diagnostics.
    """
    env = candidate_git.environment()
    commits = bounded_output(candidate_git.command(root, 'log', '--format=raw', '--no-decorate',
                             '--no-color', '--no-show-signature', tip), b'', timeout=30,
                             limit=LIMITS.max_file_bytes, env=env)
    yield commits, 'git:commit-metadata', tip
    tags = bounded_output(candidate_git.command(root, 'for-each-ref',
                          '--format=%(objecttype) %(objectname) %(refname)', 'refs/tags'), b'',
                          timeout=20, limit=1024*1024, env=env)
    rows = tags.splitlines()
    if len(rows) > 1000:
        raise ResourceLimit('tag metadata inventory exceeds limit')
    if tags:
        yield tags, 'git:tag-refs', tip
    for row in rows:
        kind, oid, name = row.split(b' ', 2)
        if not re.fullmatch(rb'[a-f0-9]{40}|[a-f0-9]{64}', oid) or not name.startswith(b'refs/tags/'):
            raise ValueError('invalid tag metadata')
        if kind == b'tag':
            data = bounded_output(candidate_git.command(root, 'cat-file', 'tag', oid.decode('ascii')), b'',
                                  timeout=20, limit=LIMITS.max_file_bytes, env=env)
            yield data, 'git:annotated-tag', oid.decode('ascii')


def scan(root: Path, binary: Path, config: Path, expected_hash: str, *, history=True,
         require_history=False, binary_allowlist: Path | None = None) -> dict:
    if digest_file(binary) != expected_hash:
        raise ValueError('scanner integrity mismatch')
    # The allowlist sits next to the trusted scanner config, never in the scanned tree.
    reviewed = load_binary_allowlist(binary_allowlist or config.with_name('binary-allowlist.json'))
    paths = input_files(root)
    if not paths:
        raise ValueError('empty scan scope')
    findings = []
    tip, blobs = history_blobs(root, require_history) if history else (None, [])
    metadata_count = 0
    with tempfile.TemporaryDirectory(prefix='epsilon-gitleaks-') as temp:
        temp = Path(temp)
        snapshot = temp / 'snapshot'
        snapshot.mkdir()
        inventory = ContentInventory(snapshot, LIMITS, reviewed)
        selected_bytes = 0
        for path in paths:
            data = read_regular(path, LIMITS.max_file_bytes)
            inventory.expanded_bytes += len(data)
            if inventory.expanded_bytes > LIMITS.max_expanded_bytes:
                raise ResourceLimit('combined scan content limit exceeded')
            selected_bytes += len(data)
            inventory.add(data, path.relative_to(root).as_posix(), scope='worktree')
        for oid, name, size in blobs:
            data = bounded_output(candidate_git.command(root, 'cat-file', 'blob', oid), b'', timeout=20,
                                  limit=LIMITS.max_file_bytes, env=candidate_git.environment())
            if len(data) != size:
                raise ValueError('history content size mismatch')
            inventory.expanded_bytes += len(data)
            if inventory.expanded_bytes > LIMITS.max_expanded_bytes:
                raise ResourceLimit('combined scan content limit exceeded')
            inventory.add(data, name or ('git:' + oid), scope='history', object_id=oid)
        if tip:
            for data, name, oid in history_metadata(root, tip):
                inventory.expanded_bytes += len(data)
                if inventory.expanded_bytes > LIMITS.max_expanded_bytes:
                    raise ResourceLimit('combined scan content limit exceeded')
                inventory.add(data, name, scope='history-metadata', object_id=oid)
                metadata_count += 1
        report = temp / 'scan.json'
        # Output goes to a bounded report file, never to a captured diagnostic stream.
        process = subprocess.run([str(binary), 'dir', str(snapshot), '--config', str(config),
                                  '--redact=100', '--ignore-gitleaks-allow', '--gitleaks-ignore-path', str(temp),
                                  '--no-banner', '--report-format=json', '--report-path', str(report)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=90)
        if process.returncode not in (0, 1) or not report.exists():
            raise RuntimeError('scanner did not produce a valid report')
        if report.stat().st_size > 16*1024*1024:
            raise ResourceLimit('scanner evidence too large')
        records = json.loads(report.read_text())
        if not isinstance(records, list) or bool(records) != (process.returncode == 1):
            raise ValueError('scanner exit code/report mismatch')
        for item in records:
            if not isinstance(item, dict) or not item.get('RuleID') or not item.get('File'):
                raise ValueError('malformed scanner finding')
            entry = inventory.entries[Path(item['File']).name]
            findings.append({'rule': item['RuleID'], 'file': entry['file'], 'scope': entry['scope'],
                             'object_id': entry['object_id'], 'line': item.get('StartLine')})
        coverage = {'status': 'COMPLETE', 'selected_files': len(paths), 'selected_bytes': selected_bytes,
                    'scanned_leaves': len(inventory.entries), 'scanned_bytes': sum(e['bytes'] for e in inventory.entries.values()),
                    'expanded_bytes': inventory.expanded_bytes, 'archives': inventory.archives,
                    'history_head': tip, 'history_blobs': len(blobs), 'unsupported_files': 0,
                    'history_metadata': metadata_count,
                    'reviewed_binaries': inventory.reviewed,
                    'formats': ['UTF-8', 'gzip', 'zip', 'ustar', 'reviewed-binary-strings'],
                    'scope': 'worktree and HEAD-reachable blobs/commit metadata plus tag names/annotations; other ref target contents excluded',
                    'limits': vars(LIMITS)}
    return {'targets': len(paths), 'findings': findings, 'coverage': coverage,
            'scopes': ['explicit worktree inventory', 'HEAD history' if tip else 'history NOT_AVAILABLE/NOT_REQUESTED'],
            'scanner': 'gitleaks', 'redacted': True}
