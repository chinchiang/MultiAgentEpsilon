"""掃描器下載：有界重試、多來源、完整性與原子安裝。 / Scanner download: bounded retries, several sources, integrity and
atomic installation."""
import hashlib
import http.client
import io
import os
import tarfile
import urllib.error

import pytest

from scripts import bootstrap

EXECUTABLE = b"#!/bin/sh\necho gitleaks\n"


def archive(member=EXECUTABLE, kind=tarfile.REGTYPE):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo("gitleaks")
        info.type = kind
        if kind == tarfile.SYMTYPE:
            info.linkname = "/etc/passwd"
            tar.addfile(info)
        else:
            info.size = len(member)
            tar.addfile(info, io.BytesIO(member))
    return buffer.getvalue()


GOOD = archive()


def lock(body=GOOD, **extra):
    return {"url": "https://a.example/gitleaks.tar.gz", "archive_sha256": hashlib.sha256(body).hexdigest(),
            "binary_sha256": hashlib.sha256(EXECUTABLE).hexdigest(), **extra}


class Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class Sources:
    """依 URL 依序回傳結果的 urlopen 假實作。 / A fake urlopen that answers each URL from its own queue."""

    def __init__(self, answers):
        self.answers = {url: list(queue) for url, queue in answers.items()}
        self.calls = []

    def __call__(self, url, timeout):
        self.calls.append(url)
        answer = self.answers[url].pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return Response(answer)


def http_error(code):
    return urllib.error.HTTPError("https://a.example/", code, "error", {}, None)


@pytest.fixture
def slept(monkeypatch):
    calls = []
    monkeypatch.setattr(bootstrap.time, "sleep", calls.append)
    return calls


@pytest.mark.parametrize("failure", [urllib.error.URLError("down"), TimeoutError(), http_error(503), http_error(429),
                                     http.client.IncompleteRead(b"x"), ConnectionResetError()],
                         ids=["url-error", "timeout", "5xx", "429", "incomplete-read", "reset"])
def test_transient_failures_are_retried_with_backoff(monkeypatch, slept, failure):
    # 先前只試一次；GitHub 暫時逾時就讓 CI 失敗。 / There used to be a single attempt, so a transient GitHub timeout
    # failed CI.
    fake = Sources({"https://a.example/gitleaks.tar.gz": [failure, failure, GOOD]})
    monkeypatch.setattr(bootstrap.urllib.request, "urlopen", fake)
    assert bootstrap.fetch_scanner(lock()) == EXECUTABLE
    assert len(fake.calls) == 3 and slept == [2.0, 4.0]


def test_all_sources_unavailable_is_reported_as_unavailable(monkeypatch, slept):
    down = urllib.error.URLError("down")
    fake = Sources({"https://a.example/1": [down] * 3, "https://b.example/2": [http_error(404)]})
    monkeypatch.setattr(bootstrap.urllib.request, "urlopen", fake)
    with pytest.raises(bootstrap.ScannerUnavailable, match=r"^https://a\.example/1: URLError; https://b\.example/2: HTTPError$"):
        bootstrap.fetch_scanner(lock(urls=["https://a.example/1", "https://b.example/2"]))
    # 4xx 不是暫時性錯誤，不重試。 / A 4xx is not transient and is not retried.
    assert fake.calls == ["https://a.example/1"] * 3 + ["https://b.example/2"]


def test_digest_mismatch_moves_to_the_next_source_without_retrying(monkeypatch, slept):
    fake = Sources({"https://a.example/1": [GOOD + b"tampered"], "https://b.example/2": [GOOD]})
    monkeypatch.setattr(bootstrap.urllib.request, "urlopen", fake)
    assert bootstrap.fetch_scanner(lock(urls=["https://a.example/1", "https://b.example/2"])) == EXECUTABLE
    assert fake.calls == ["https://a.example/1", "https://b.example/2"] and slept == []


def test_integrity_failure_everywhere_is_an_integrity_error(monkeypatch, slept):
    fake = Sources({"https://a.example/gitleaks.tar.gz": [GOOD + b"tampered"]})
    monkeypatch.setattr(bootstrap.urllib.request, "urlopen", fake)
    with pytest.raises(bootstrap.ScannerIntegrity, match="^Gitleaks release checksum mismatch: https://a"):
        bootstrap.fetch_scanner(lock())
    assert len(fake.calls) == 1


@pytest.mark.parametrize("body", [archive(kind=tarfile.SYMTYPE), archive(kind=tarfile.DIRTYPE), b"not a tarball"],
                         ids=["symlink", "directory", "not-gzip"])
def test_archive_member_must_be_a_regular_file(monkeypatch, slept, body):
    fake = Sources({"https://a.example/gitleaks.tar.gz": [body]})
    monkeypatch.setattr(bootstrap.urllib.request, "urlopen", fake)
    with pytest.raises(bootstrap.ScannerIntegrity, match="Gitleaks archive"):
        bootstrap.fetch_scanner(lock(body))


def test_executable_digest_is_checked_after_extraction(monkeypatch, slept):
    other = archive(b"something else")
    fake = Sources({"https://a.example/gitleaks.tar.gz": [other]})
    monkeypatch.setattr(bootstrap.urllib.request, "urlopen", fake)
    with pytest.raises(bootstrap.ScannerIntegrity, match="^Gitleaks executable checksum mismatch"):
        bootstrap.fetch_scanner(lock(other))


def test_oversized_download_is_refused(monkeypatch, slept):
    monkeypatch.setattr(bootstrap, "SCANNER_LIMIT", 10)
    fake = Sources({"https://a.example/gitleaks.tar.gz": [b"x" * 11]})
    monkeypatch.setattr(bootstrap.urllib.request, "urlopen", fake)
    with pytest.raises(bootstrap.ScannerIntegrity, match="^scanner archive exceeds size limit"):
        bootstrap.fetch_scanner(lock())
    assert len(fake.calls) == 1


@pytest.mark.parametrize("urls", [[], "https://a.example/", ["http://a.example/"], [1], ["https://a/"] * 6])
def test_invalid_source_lists_are_refused(urls):
    with pytest.raises(bootstrap.ScannerIntegrity, match="^invalid scanner sources$"):
        bootstrap.scanner_sources(lock(urls=urls))


def test_single_url_lock_remains_supported():
    assert bootstrap.scanner_sources(lock()) == ["https://a.example/gitleaks.tar.gz"]


def test_installation_is_atomic_and_executable(tmp_path):
    binary = tmp_path / "gitleaks"
    binary.write_bytes(b"old")
    bootstrap.install_scanner(binary, EXECUTABLE)
    assert binary.read_bytes() == EXECUTABLE and os.access(binary, os.X_OK)
    assert [p.name for p in tmp_path.iterdir()] == ["gitleaks"]
