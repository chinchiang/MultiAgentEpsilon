#!/usr/bin/env python3
"""安裝前先執行 G1；驗證掃描器並鎖定二進位 wheels，不使用模型憑證。

G1 before install; verified scanner; pinned binary wheels; no model credentials."""
import argparse
import hashlib
import http.client
import io
import json
import os
import platform
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
from security_harness.preflight import verify
from security_harness.dependencies import DependencyError, scan as dependency_scan
from security_harness.audit import AuditRun
from security_harness.results import digest_file, subject_digest, validate_policy, write_json


# 掃描器壓縮檔與執行檔的大小上限。 / Size limit for the scanner archive and its executable.
SCANNER_LIMIT = 32 * 1024 * 1024
# 每個來源的嘗試次數與指數退避基準秒數。 / Attempts per source and the exponential backoff base in seconds.
DOWNLOAD_ATTEMPTS = 3
DOWNLOAD_BACKOFF = 2.0


class ScannerUnavailable(RuntimeError):
    """所有來源都因網路錯誤無法取得掃描器。 / No source could deliver the scanner because of network errors."""


class ScannerIntegrity(RuntimeError):
    """掃描器來源、壓縮檔或執行檔未通過驗證。 / A scanner source, archive or executable failed verification."""


def scanner_sources(scanner):
    """依序回傳掃描器來源；`urls` 可列出多個來源，沒有時沿用 `url`。

Return the scanner sources in order: `urls` may list several, and `url` is used without it."""
    urls = scanner["urls"] if "urls" in scanner else [scanner["url"]]
    if (type(urls) is not list or not urls or len(urls) > 5
            or any(type(u) is not str or not u.startswith("https://") for u in urls)):
        raise ScannerIntegrity("invalid scanner sources")
    return urls


def transient(exc):
    """可在同一來源重試的網路錯誤：連線、逾時、讀取中斷、5xx 與 429。

A network error worth retrying at the same source: connection, timeout, truncated read, 5xx and 429."""
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code == 429 or exc.code >= 500
    return isinstance(exc, (urllib.error.URLError, TimeoutError, ConnectionError, http.client.IncompleteRead))


def download(url):
    """分段讀取來源內容並限制大小。 / Read a source in chunks within the size limit."""
    body = bytearray()
    with urllib.request.urlopen(url, timeout=45) as response:
        while chunk := response.read(1024 * 1024):
            body += chunk
            if len(body) > SCANNER_LIMIT:
                raise ScannerIntegrity(f"scanner archive exceeds size limit: {url}")
    return bytes(body)


def extract(body, url):
    """取出壓縮檔內的 gitleaks；只接受一般檔案。 / Take gitleaks out of the archive, accepting only a regular file."""
    try:
        with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as archive:
            member = archive.getmember("gitleaks")
            if not member.isfile() or member.size > SCANNER_LIMIT:
                raise ScannerIntegrity(f"Gitleaks archive member is not a regular file: {url}")
            return archive.extractfile(member).read()
    except (tarfile.TarError, KeyError, EOFError, OSError) as exc:
        raise ScannerIntegrity(f"unreadable Gitleaks archive: {url}") from exc


def fetch_scanner(scanner):
    """依序從來源取得並驗證掃描器。網路錯誤在同一來源有界重試；雜湊或格式錯誤改試下一個來源，不重試。

Fetch and verify the scanner from its sources in order. Network errors are retried at the
    same source within a bound; a digest or format failure moves on to the next source without retrying."""
    unavailable, integrity = [], []
    for url in scanner_sources(scanner):
        for attempt in range(DOWNLOAD_ATTEMPTS):
            try:
                body = download(url)
            except ScannerIntegrity as exc:
                integrity.append(str(exc))
                break
            except Exception as exc:
                if transient(exc) and attempt + 1 < DOWNLOAD_ATTEMPTS:
                    time.sleep(DOWNLOAD_BACKOFF * 2 ** attempt)
                    continue
                unavailable.append(f"{url}: {type(exc).__name__}")
                break
            if hashlib.sha256(body).hexdigest() != scanner["archive_sha256"]:
                integrity.append(f"Gitleaks release checksum mismatch: {url}")
                break
            try:
                data = extract(body, url)
            except ScannerIntegrity as exc:
                integrity.append(str(exc))
                break
            if hashlib.sha256(data).hexdigest() != scanner["binary_sha256"]:
                integrity.append(f"Gitleaks executable checksum mismatch: {url}")
                break
            return data
    if integrity:
        raise ScannerIntegrity("; ".join(integrity + unavailable))
    raise ScannerUnavailable("; ".join(unavailable))


def install_scanner(binary, data):
    """以暫存檔加 os.replace 原子安裝掃描器。 / Install the scanner atomically through a temporary file and os.replace."""
    fd, temporary = tempfile.mkstemp(dir=binary.parent, prefix=".gitleaks-")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(temporary, 0o755)
        os.replace(temporary, binary)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def install(audit):
    audit.stage("configuration")
    if sys.version_info[:2] != (3, 12):
        raise RuntimeError("use Python 3.12 for the pinned lock")
    policy = json.loads((ROOT / "security/policy.json").read_text())
    validate_policy(policy)
    audit.data["policy_digest"] = digest_file(ROOT / "security/policy.json")
    audit.data["subject_digest"] = subject_digest(ROOT)
    audit.stage("G1")
    packages = verify(ROOT / "requirements.lock", policy)
    try:
        sca = dependency_scan(ROOT / "requirements.lock")
    except DependencyError as exc:
        if exc.evidence:
            write_json(audit.output / "sbom.cdx.json", exc.evidence['sbom'])
            audit.add("G1", "ERROR", "scan", len(packages), len(exc.evidence['findings']),
                      "incomplete dependency query", packages=packages, sca=exc.evidence)
        raise
    write_json(audit.output / "sbom.cdx.json", sca["sbom"])
    audit.add("G1", "COMPLETED", "scan", len(packages), len(sca["findings"]),
              "installation provenance and OSV preflight", packages=packages, sca=sca)
    if sca["findings"]:
        raise RuntimeError("known dependency vulnerabilities; installation blocked")
    print(f"G1 preflight verified {len(packages)} pinned packages before installation", flush=True)
    audit.stage("scanner")
    scanner = json.loads((ROOT / "security/tools.lock.json").read_text())["gitleaks"]
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "AMD64"):
        raise RuntimeError("scanner pin currently supports Linux x86_64 only")
    binary = ROOT / ".tools/gitleaks"
    binary.parent.mkdir(exist_ok=True)
    # 已存在（含 CI 快取取回）的執行檔一律重新驗證雜湊。 / An existing executable, including one restored from the CI
    # cache, is always re-verified by digest.
    if (binary.is_symlink() or not binary.is_file()
            or hashlib.sha256(binary.read_bytes()).hexdigest() != scanner["binary_sha256"]):
        binary.unlink(missing_ok=True)
        install_scanner(binary, fetch_scanner(scanner))
    from security_harness.secrets import scan
    audit.stage("G2")
    secret_scan = scan(ROOT, binary, ROOT / "security/gitleaks.toml", scanner["binary_sha256"])
    audit.add("G2", "COMPLETED", "scan", secret_scan["targets"], len(secret_scan["findings"]), "installation secret scan")
    if secret_scan["findings"]:
        raise RuntimeError("G2 found secrets; target dependency installation blocked")
    print(f"G2 scanned {secret_scan['targets']} files before installation", flush=True)
    audit.stage("installation")
    # 此目錄由 bootstrap 產生並管理，更新時清除舊內容， / This directory is owned/generated by bootstrap. Clear it so stale packages
    # 避免舊套件或 .pth 殘留於新核准 lock。 / or .pth files cannot survive a refresh of the approved lock.
    subprocess.run([sys.executable, "-m", "venv", "--clear", str(ROOT / ".venv")], check=True)
    python = str(ROOT / ".venv/bin/python")
    # 忽略套件管理器設定與繼承的索引覆寫變數。 / Ignore package manager configuration and inherited index override variables.
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PIP_", "UV_"))}
    env["PIP_CONFIG_FILE"] = os.devnull
    wheels = ROOT / ".state/wheels"
    wheels.mkdir(parents=True, exist_ok=True)
    base = [python, "-m", "pip", "--isolated", "--disable-pip-version-check", "--no-cache-dir"]
    subprocess.run(base + ["download", "--only-binary=:all:", "--no-deps", "--require-hashes",
                          "--index-url", "https://pypi.org/simple", "-r", str(ROOT / "requirements.lock"),
                          "--dest", str(wheels)], check=True, env=env)
    subprocess.run(base + ["install", "--no-index", "--find-links", str(wheels), "--only-binary=:all:",
                          "--no-deps", "--require-hashes", "-r", str(ROOT / "requirements.lock")], check=True, env=env)
    subprocess.run([python, "-m", "pip", "check"], check=True, env=env)
    print("Bootstrap complete; wheel-only environment and scanner verified")


def main(argv=None):
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    audit = AuditRun(ROOT, "bootstrap")
    try:
        install(audit)
        audit.data.update(decision="ALLOW", reasons=[])
    except (Exception, KeyboardInterrupt, SystemExit) as exc:
        audit.fail(exc)
    code = audit.finish((("G1", "scan"), ("G2", "scan")))
    print(f"Bootstrap {audit.data['decision']}: {audit.output / 'report.json'}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
