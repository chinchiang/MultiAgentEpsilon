import gzip
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
