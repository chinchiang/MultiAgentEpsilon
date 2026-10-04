"""G1: stdlib-only, fail-closed PyPI lock verification before wheel-only install.

This MVP checks provenance metadata, not malicious package behavior or CVEs.
No dependency or build backend is imported/executed by this module.
"""
from __future__ import annotations

import json
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


class PreflightError(ValueError):
    pass


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_lock(path: Path) -> list[dict]:
    records = []
    content = path.read_text().replace("\\\n", " ")
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(
            r"([a-zA-Z0-9_.-]+)(?:\[[a-zA-Z0-9_.,-]+\])?==([0-9][a-zA-Z0-9_.+-]*)"
            r"((?:\s+--hash=sha256:[a-f0-9]{64})+)", line)
        if not match:
            raise PreflightError("lock must contain only exact pins and SHA-256 hashes")
        name, version, hashes = match.groups()
        records.append({"name": canonical(name), "version": version,
                        "hashes": set(re.findall(r"sha256:([a-f0-9]{64})", hashes))})
    if not records or len({r["name"] for r in records}) != len(records):
        raise PreflightError("empty or duplicate lock entries")
    return records


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise PreflightError("registry redirect refused")


def fetch_metadata(name: str, version: str) -> dict:
    # Name/version are restricted by parse_lock; host cannot be supplied by the target.
    request = urllib.request.Request(f"https://pypi.org/pypi/{name}/{version}/json",
                                     headers={"Accept": "application/json"})
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=20) as response:
        raw = response.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        raise PreflightError("registry response too large")
    return json.loads(raw)


def check_metadata(record: dict, metadata: dict, policy: dict, now: datetime) -> dict:
    name, version = record["name"], record["version"]
    if name not in policy["allowed_packages"]:
        raise PreflightError(f"{name}: package not approved")
    if canonical(metadata["info"]["name"]) != name or metadata["info"]["version"] != version:
        raise PreflightError(f"{name}: registry identity mismatch")
    if not re.fullmatch(r"\d+(?:\.\d+)*", version):
        raise PreflightError(f"{name}: prerelease/local versions need separate policy")
    files = metadata["urls"]
    if not files:
        raise PreflightError(f"{name}: no release artifacts")
    available = {f["digests"]["sha256"]: f for f in files}
    if not record["hashes"] <= available.keys():
        raise PreflightError(f"{name}: lock hash not published by registry")
    matched = [available[h] for h in record["hashes"]]
    for item in matched:
        url = urlsplit(item["url"])
        if (url.scheme != "https" or url.hostname != policy["allowed_artifact_host"]
                or url.username or url.password or url.port not in (None, 443)):
            raise PreflightError(f"{name}: unexpected artifact origin")
        if item.get("yanked"):
            raise PreflightError(f"{name}: yanked artifact")
        published = datetime.fromisoformat(item["upload_time_iso_8601"].replace("Z", "+00:00"))
        if (now - published).total_seconds() < policy["minimum_package_age_days"] * 86400:
            raise PreflightError(f"{name}: artifact inside cooling period")
    if not any(f["packagetype"] == "bdist_wheel" for f in matched):
        raise PreflightError(f"{name}: no approved wheel; source builds forbidden")
    return {"name": name, "version": version, "approved_hash_count": len(matched),
            "registry": "https://pypi.org", "wheel_only_required": True}


def verify(lock: Path, policy: dict, fetch=fetch_metadata, now=None) -> list[dict]:
    if policy["allowed_registry"] != "https://pypi.org":
        raise PreflightError("this adapter only supports the approved PyPI registry")
    now = now or datetime.now(timezone.utc)
    records = parse_lock(lock)
    checked = []
    for record in records:
        if record["name"] not in policy["allowed_packages"]:
            raise PreflightError(f"{record['name']}: package not approved")
        checked.append(check_metadata(record, fetch(record["name"], record["version"]), policy, now))
    return checked
