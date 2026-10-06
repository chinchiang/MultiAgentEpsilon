import gzip
import hashlib
import io
import json
import secrets
import subprocess
import tarfile
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest
from security_harness import secrets as scanner, inputs
from security_harness.limits import LIMITS, ResourceLimit
from security_harness.scan_content import UnsupportedContent
from tests.test_gitleaks import run


def archive(kind, content):
    if kind == 'gzip':
        return gzip.compress(content)
    stream = io.BytesIO()
    if kind == 'zip':
        with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED) as output:
            output.writestr('nested/credential.txt', content)
    else:
        with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as output:
            item = tarfile.TarInfo('nested/credential.txt')
            item.size = len(content)
            output.addfile(item, io.BytesIO(content))
    return stream.getvalue()


@pytest.mark.parametrize('kind', ['gzip', 'zip', 'tar'])
def test_archived_secret_is_scanned_even_with_wrong_extension(tmp_path, kind):
    canary = ('VIBE_TEST_' + 'SECRET_' + secrets.token_hex(16)).encode()
    (tmp_path / 'ordinary.py').write_bytes(archive(kind, canary))
    result = run(tmp_path)
    assert len(result['findings']) == 1
    assert result['findings'][0]['file'].startswith('ordinary.py!')
    assert canary.decode() not in json.dumps(result)
    assert result['coverage']['archives'] == 1
    assert result['coverage']['scanned_leaves'] == 1
    assert result['coverage']['status'] == 'COMPLETE'


def test_secret_removed_from_compressed_history_is_detected(tmp_path):
    def git(*args):
        subprocess.run(['git', '-C', str(tmp_path), *args], check=True, capture_output=True)
    git('init', '-q'); git('config', 'user.name', 'Synthetic')
    git('config', 'user.email', 'fixture@example.invalid')
    path = tmp_path / 'old.bin'
    path.write_bytes(gzip.compress(('VIBE_TEST_' + 'SECRET_' + secrets.token_hex(16)).encode()))
    git('add', '.'); git('commit', '-qm', 'compressed synthetic canary')
    path.write_text('clean replacement')
    git('add', '.'); git('commit', '-qm', 'clean')
    result = run(tmp_path, history=True)
    assert any(f['scope'] == 'history' and f['object_id'] for f in result['findings'])
    assert result['coverage']['history_blobs'] == 2


@pytest.mark.parametrize('data', [b'\xff\x00\xfe', b'\x00synthetic', b'\x1f\x8bbroken'])
def test_unknown_or_corrupt_content_never_claims_complete(tmp_path, data):
    (tmp_path / 'data').write_bytes(data)
    with pytest.raises((UnsupportedContent, OSError, EOFError)):
        run(tmp_path)


def test_expansion_bomb_is_stopped_at_small_budget(tmp_path, monkeypatch):
    (tmp_path / 'data').write_bytes(gzip.compress(b'x' * 100000))
    monkeypatch.setattr(scanner, 'LIMITS', replace(LIMITS, max_expanded_bytes=2048))
    with pytest.raises(ResourceLimit):
        run(tmp_path)


def test_archive_depth_is_bounded(tmp_path):
    data = b'synthetic'
    for _ in range(4):
        data = gzip.compress(data)
    (tmp_path / 'nested').write_bytes(data)
    with pytest.raises(ResourceLimit):
        run(tmp_path)


def test_zip_path_traversal_is_refused_without_extraction(tmp_path):
    path = tmp_path / 'payload'
    with zipfile.ZipFile(path, 'w') as output:
        output.writestr('../escape.txt', 'synthetic')
    with pytest.raises(UnsupportedContent):
        run(tmp_path)
    assert not (tmp_path.parent / 'escape.txt').exists()


def test_aggregate_source_limit_applies_before_digest(tmp_path, monkeypatch):
    from security_harness.results import subject_digest
    for name in ('a', 'b'):
        (tmp_path / name).write_text('x' * 60)
    monkeypatch.setattr(inputs, 'LIMITS', replace(LIMITS, max_input_bytes=100))
    with pytest.raises(ResourceLimit):
        subject_digest(tmp_path)


def png_like(payload=b''):
    return b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR' + bytes(range(0, 32)) + payload + b'\x00\xff\x00'


def allowlist(tmp_path, *blobs, reason='reviewed synthetic asset'):
    path = tmp_path.parent / (tmp_path.name + '-binary-allowlist.json')
    path.write_text(json.dumps({'schema_version': 1, 'entries': [
        {'sha256': hashlib.sha256(b).hexdigest(), 'reason': reason} for b in blobs]}))
    return path


def scan_with(tmp_path, allowed, history=False):
    from tests.test_gitleaks import LOCK, ROOT
    return scanner.scan(tmp_path, ROOT / '.tools/gitleaks', ROOT / 'security/gitleaks.toml', LOCK['binary_sha256'],
                        history=history, binary_allowlist=allowed)


def test_unreviewed_binary_still_blocks_but_reviewed_digest_is_strings_scanned(tmp_path):
    data = png_like()
    (tmp_path / 'diagram.png').write_bytes(data)
    with pytest.raises(UnsupportedContent, match='reviewed digest'):
        scan_with(tmp_path, allowlist(tmp_path))
    result = scan_with(tmp_path, allowlist(tmp_path, data))
    assert result['findings'] == [] and result['coverage']['reviewed_binaries'] == 1
    assert result['coverage']['status'] == 'COMPLETE' and result['coverage']['unsupported_files'] == 0


@pytest.mark.parametrize('encoding', ['ascii', 'utf-16-le'])
def test_secret_embedded_in_reviewed_binary_is_still_found(tmp_path, encoding):
    canary = 'VIBE_TEST_' + 'SECRET_' + secrets.token_hex(16)
    data = png_like(b' key=' + canary.encode(encoding) + b' ')
    (tmp_path / 'asset.bin').write_bytes(data)
    result = scan_with(tmp_path, allowlist(tmp_path, data))
    assert [f['file'] for f in result['findings']] == ['asset.bin!strings']
    assert canary not in json.dumps(result)


def test_changed_binary_needs_a_new_review(tmp_path):
    reviewed = png_like(b'version-one')
    (tmp_path / 'asset.bin').write_bytes(png_like(b'version-two'))
    with pytest.raises(UnsupportedContent):
        scan_with(tmp_path, allowlist(tmp_path, reviewed))


@pytest.mark.parametrize('entries', [[{'sha256': 'x'}], [{'sha256': 'a' * 64, 'reason': ' '}],
                                     [{'sha256': 'a' * 64, 'reason': 'r'}] * 2,
                                     [{'sha256': 'a' * 64, 'reason': 'r', 'path': 'any'}]])
def test_malformed_binary_allowlist_fails_closed(tmp_path, entries):
    (tmp_path / 'README.md').write_text('synthetic\n')
    path = tmp_path.parent / (tmp_path.name + '-bad.json')
    path.write_text(json.dumps({'schema_version': 1, 'entries': entries}))
    with pytest.raises(ValueError, match='invalid binary allowlist'):
        scan_with(tmp_path, path)


def test_repository_binary_allowlist_is_valid_and_reviewed():
    from security_harness.scan_content import load_binary_allowlist
    from tests.test_gitleaks import ROOT
    assert isinstance(load_binary_allowlist(ROOT / 'security/binary-allowlist.json'), frozenset)
