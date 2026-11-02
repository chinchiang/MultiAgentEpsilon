"""驗證可信離線測試設定並準備確定性建置內容。

Verify the trusted offline test profile and prepare its deterministic build context.

候選 checkout 僅供資料使用；本模組及信任輸入均取自可信儲存庫。
Candidate checkouts are data only. This module and every trust input are read from
the trusted repository checkout; the caller receives a context only after all
source, registry, wheel, and runtime-contract checks pass.
"""
from __future__ import annotations

from dataclasses import dataclass
from email.parser import BytesParser
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import urllib.request
import zipfile
from urllib.parse import urlsplit
from datetime import datetime, timezone

from security_harness import preflight


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "security/offline-test-profile"
TRUST_MANIFEST = ROOT / "security/offline-test-profile-trust.json"
WHEEL_CACHE = ROOT / ".state/verified-wheels/offline-test-profile"
PROFILE_ID = "offline-supplemental-tests"
PROFILE_PATH = "security/offline-test-profile"
TEST_PATH = "tests/test_offline_test_profile.py"
MAX_SOURCE_BYTES = 128 * 1024 * 1024
MAX_WHEEL_METADATA_BYTES = 128 * 1024


@dataclass(frozen=True)
class VerifiedProfile:
    """保存唯一設定準備介面回傳的驗證結果。 / Evidence returned by the profile-preparation interface."""

    profile: str
    context_path: Path
    context_manifest_sha256: str
    profile_lock_sha256: str
    wheel_count: int
    runtime_package_count: int


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_regular(path: Path, *, limit: int = MAX_SOURCE_BYTES) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("regular bounded source file required")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("source size limit")
    return data


def _read_json(path: Path, *, limit: int = MAX_SOURCE_BYTES) -> tuple[bytes, dict]:
    raw = _read_regular(path, limit=limit)
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("JSON object required")
    return raw, value


def _check_cache_path(root: Path, directory: Path) -> None:
    root = root.resolve()
    absolute = Path(os.path.abspath(directory))
    if not absolute.is_relative_to(root):
        raise ValueError("WHEEL_CACHE_PATH")
    current = root
    for part in absolute.relative_to(root).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("WHEEL_CACHE_SYMLINK")
        if current.exists() and not current.is_dir():
            raise ValueError("WHEEL_CACHE_DIRECTORY")


def _profile_inputs(root: Path, profile: Path, lock: dict) -> dict[str, bytes]:
    if profile.is_symlink() or not profile.is_dir():
        raise ValueError("PROFILE_DIRECTORY")
    entries = list(profile.rglob("*"))
    for entry in entries:
        if entry.is_symlink():
            raise ValueError("PROFILE_SYMLINK")
        if not entry.is_file() and not entry.is_dir():
            raise ValueError("PROFILE_SPECIAL_FILE")
    records = preflight.parse_lock(profile / "requirements-runtime.lock")
    build_records = preflight.parse_lock(profile / "requirements-build.lock")
    all_records = records + build_records
    if len({record["name"] for record in all_records}) != len(all_records):
        raise ValueError("PROFILE_PACKAGE_NAMES")
    expected_proofs = {
        f"{PROFILE_PATH}/source-proofs/{record['name']}.json" for record in all_records
    }
    expected_inputs = {
        f"{PROFILE_PATH}/{name}"
        for name in (
            "Dockerfile",
            "requirements-runtime.lock",
            "requirements-build.lock",
            "entrypoint.py",
            "supplemental_manifest.py",
            "runtime_guard.py",
            "runtime-contract.json",
            "gh-deny",
        )
    } | expected_proofs | {TEST_PATH}
    if set(lock.get("input_sha256", {})) != expected_inputs:
        raise ValueError("PROFILE_SOURCE_INVENTORY")

    # 讀取前拒絕未審閱檔案、連結及特殊檔案。 / Reject unreviewed files, links, and special entries.
    expected_profile_files = {
        PurePosixPath(name).relative_to(PROFILE_PATH).as_posix()
        for name in expected_inputs
        if name.startswith(PROFILE_PATH + "/")
    } | {"profile.lock.json"}
    seen_files: set[str] = set()
    for entry in entries:
        relative = entry.relative_to(profile).as_posix()
        if entry.is_file():
            seen_files.add(relative)
    if seen_files != expected_profile_files:
        raise ValueError("PROFILE_DIRECTORY_INVENTORY")

    contents: dict[str, bytes] = {}
    for relative in sorted(expected_inputs):
        path = root / relative
        contents[relative] = _read_regular(path)
    actual = {name: _digest(body) for name, body in contents.items()}
    if actual != lock["input_sha256"]:
        raise ValueError("PROFILE_SOURCE_DIGEST")
    return contents


def _wheel_identity(data: bytes) -> tuple[str, str]:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        metadata = [item for item in archive.infolist() if item.filename.endswith(".dist-info/METADATA")]
        if len(metadata) != 1 or metadata[0].file_size > MAX_WHEEL_METADATA_BYTES:
            raise ValueError("WHEEL_METADATA_INVENTORY")
        with archive.open(metadata[0]) as stream:
            raw = stream.read(MAX_WHEEL_METADATA_BYTES + 1)
    if len(raw) > MAX_WHEEL_METADATA_BYTES:
        raise ValueError("WHEEL_METADATA_SIZE")
    message = BytesParser().parsebytes(raw)
    return preflight.canonical(message["Name"]), message["Version"]


def _wheel_pins(lock: dict, records: list[dict]) -> dict[str, tuple[dict, str]]:
    pins = lock.get("wheel_sha256")
    if not isinstance(pins, dict) or not pins:
        raise ValueError("WHEEL_PIN_INVENTORY")
    by_name = {record["name"]: record for record in records}
    selected: dict[str, tuple[dict, str]] = {}
    for filename, digest in pins.items():
        if (not isinstance(filename, str) or not filename.endswith(".whl")
                or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise ValueError("WHEEL_PIN_FORMAT")
        matches = [record for record in records if digest in record["hashes"]]
        if len(matches) != 1 or matches[0]["name"] in selected:
            raise ValueError("WHEEL_PIN_NOT_UNIQUE")
        selected[matches[0]["name"]] = (matches[0], filename)
    if set(selected) != set(by_name):
        raise ValueError("WHEEL_PIN_PACKAGE_INVENTORY")
    return {filename: (record, pins[filename]) for record, filename in selected.values()}


def _proof_size(contents: dict[str, bytes], record: dict, digest: str) -> int:
    proof = json.loads(contents[f"{PROFILE_PATH}/source-proofs/{record['name']}.json"])
    matches = [item for item in proof["urls"] if item.get("digests", {}).get("sha256") == digest
               and item.get("packagetype") == "bdist_wheel"]
    if len(matches) != 1 or type(matches[0].get("size")) is not int or matches[0]["size"] < 0:
        raise ValueError("WHEEL_SOURCE_SIZE")
    return matches[0]["size"]


def _verified_wheels(directory: Path, records: list[dict], lock: dict, contents: dict[str, bytes]) -> dict[str, tuple[str, bytes]]:
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("WHEEL_CACHE_DIRECTORY")
    by_name = {record["name"]: record for record in records}
    if len(by_name) != len(records):
        raise ValueError("DUPLICATE_LOCK_PACKAGE")
    pins = _wheel_pins(lock, records)
    entries = sorted(directory.iterdir())
    if ({entry.name for entry in entries} != set(pins)
            or any(not entry.name.endswith(".whl") for entry in entries)):
        raise ValueError("WHEEL_CACHE_INVENTORY")
    found: dict[str, tuple[str, bytes]] = {}
    for path in entries:
        data = _read_regular(path)
        hashed = _digest(data)
        # 摘要核准後才解析封存。 / Parse the archive only after its digest is approved.
        record, pinned_hash = pins[path.name]
        if hashed != pinned_hash:
            raise ValueError("WHEEL_HASH_NOT_UNIQUELY_APPROVED")
        if len(data) != _proof_size(contents, record, pinned_hash):
            raise ValueError("WHEEL_SOURCE_SIZE")
        name, version = _wheel_identity(data)
        if (name, version) != (record["name"], record["version"]) or name in found:
            raise ValueError("WHEEL_IDENTITY_OR_DUPLICATE")
        found[name] = (path.name, data)
    if set(found) != set(by_name):
        raise ValueError("INCOMPLETE_WHEEL_INVENTORY")
    return found


def _approved_policy(root: Path, records: list[dict]) -> dict:
    policy = json.loads(_read_regular(root / "security/policy.json"))
    policy["allowed_packages"] = [record["name"] for record in records]
    preflight.validate_package_policy(policy)
    return policy


def _load_verified(root: Path) -> tuple[dict, bytes, dict, dict[str, bytes], list[dict], list[dict]]:
    profile = root / PROFILE_PATH
    trust_path = root / "security/offline-test-profile-trust.json"
    trust_raw, trust = _read_json(trust_path, limit=64 * 1024)
    if (set(trust) != {"schema_version", "profile", "profile_lock_path", "profile_lock_sha256", "platforms"}
            or type(trust["schema_version"]) is not int or trust["schema_version"] != 1
            or trust["profile"] != PROFILE_ID
            or trust["profile_lock_path"] != f"{PROFILE_PATH}/profile.lock.json"
            or trust["platforms"] != ["linux/amd64"]
            or not re.fullmatch(r"[0-9a-f]{64}", trust["profile_lock_sha256"])):
        raise ValueError("TRUST_MANIFEST_SCHEMA")

    lock_raw, lock = _read_json(profile / "profile.lock.json", limit=64 * 1024)
    lock_hash = _digest(lock_raw)
    if lock_hash != trust["profile_lock_sha256"]:
        raise ValueError("PROFILE_LOCK_ANCHOR")
    if (lock.get("schema") != 1 or lock.get("profile") != PROFILE_ID
            or lock.get("platform") not in trust["platforms"]
            or type(lock.get("source_date_epoch")) is not int or lock["source_date_epoch"] != 0):
        raise ValueError("PROFILE_SCHEMA")

    contents = _profile_inputs(root, profile, lock)
    runtime_records = preflight.parse_lock(profile / "requirements-runtime.lock")
    build_records = preflight.parse_lock(profile / "requirements-build.lock")
    approved_records = {
        record["name"]: record
        for path in (root / "requirements.lock", root / "requirements-test.lock")
        for record in preflight.parse_lock(path)
    }
    if any(record != approved_records.get(record["name"]) for record in runtime_records):
        raise ValueError("APPROVED_RUNTIME_SUBSET")
    _wheel_pins(lock, runtime_records + build_records)
    policy = _approved_policy(root, runtime_records + build_records)
    for record in runtime_records + build_records:
        proof_path = f"{PROFILE_PATH}/source-proofs/{record['name']}.json"
        preflight.check_metadata(record, json.loads(contents[proof_path]), policy, datetime.now(timezone.utc))

    contract = json.loads(contents[f"{PROFILE_PATH}/runtime-contract.json"])
    expected_packages = {record["name"]: record["version"] for record in runtime_records}
    deny = contents[f"{PROFILE_PATH}/gh-deny"]
    if (contract.get("packages") != expected_packages
            or contract.get("gh_deny_sha256") != _digest(deny)
            or contract.get("collection_sha256") != lock.get("collection_sha256")):
        raise ValueError("RUNTIME_CONTRACT")
    dockerfile = contents[f"{PROFILE_PATH}/Dockerfile"].decode("utf-8")
    if (("FROM " + lock["git_source_image"] + " AS git-source\n") not in dockerfile
            or ("FROM " + lock["base_image"] + "\n") not in dockerfile):
        raise ValueError("IMAGE_PINS")
    if (not re.fullmatch(r"sha256:[0-9a-f]{64}", lock.get("git_amd64_manifest", ""))
            or not lock.get("git_version")
            or not isinstance(lock.get("native_sha256"), dict)
            or not lock["native_sha256"]):
        raise ValueError("NATIVE_SOURCE_PINS")
    return lock, lock_raw, trust, contents, runtime_records, build_records


def _cache_wheels(root: Path, directory: Path, *, opener=None) -> int:
    """只下載可信鎖與來源證明固定的 wheel。 / Fetch only wheels pinned by trusted locks and proofs."""
    _check_cache_path(root, directory)
    lock, _lock_raw, _trust, contents, runtime_records, build_records = _load_verified(root)
    records = runtime_records + build_records
    pins = _wheel_pins(lock, records)
    if directory.is_symlink():
        raise ValueError("WHEEL_CACHE_DIRECTORY")
    present: dict[str, bytes] = {}
    if directory.exists():
        if not directory.is_dir():
            raise ValueError("WHEEL_CACHE_DIRECTORY")
        for path in directory.iterdir():
            if path.name not in pins:
                raise ValueError("WHEEL_CACHE_INVENTORY")
            data = _read_regular(path)
            if _digest(data) != pins[path.name][1]:
                raise ValueError("WHEEL_HASH_NOT_UNIQUELY_APPROVED")
            record, _ = pins[path.name]
            if len(data) != _proof_size(contents, record, pins[path.name][1]):
                raise ValueError("WHEEL_SOURCE_SIZE")
            if _wheel_identity(data) != (record["name"], record["version"]):
                raise ValueError("WHEEL_IDENTITY_OR_DUPLICATE")
            present[path.name] = data
    if len(present) == len(pins):
        _verified_wheels(directory, records, lock, contents)
        return len(present)

    if opener is None:
        opener = urllib.request.build_opener(preflight.NoRedirect())
    missing: dict[str, bytes] = {}
    for filename, (record, digest) in pins.items():
        if filename in present:
            continue
        proof_path = f"{PROFILE_PATH}/source-proofs/{record['name']}.json"
        metadata = json.loads(contents[proof_path])
        artifacts = [item for item in metadata["urls"]
                     if item.get("digests", {}).get("sha256") == digest
                     and item.get("packagetype") == "bdist_wheel"]
        if len(artifacts) != 1 or artifacts[0].get("yanked"):
            raise ValueError("WHEEL_SOURCE_PROOF")
        url = urlsplit(artifacts[0]["url"])
        if (url.scheme != "https" or url.hostname != "files.pythonhosted.org"
                or url.username or url.password or url.port not in (None, 443)):
            raise ValueError("WHEEL_SOURCE_ORIGIN")
        request = urllib.request.Request(artifacts[0]["url"], headers={"Accept": "application/octet-stream"})
        with opener.open(request, timeout=45) as response:
            data = response.read(MAX_SOURCE_BYTES + 1)
        if len(data) > MAX_SOURCE_BYTES or _digest(data) != digest:
            raise ValueError("WHEEL_DOWNLOAD_DIGEST")
        if len(data) != _proof_size(contents, record, digest):
            raise ValueError("WHEEL_SOURCE_SIZE")
        if _wheel_identity(data) != (record["name"], record["version"]):
            raise ValueError("WHEEL_DOWNLOAD_IDENTITY")
        missing[filename] = data

    # 寫入下載檔前驗證完整快取。 / Validate the complete cache before writing downloaded files.
    prospective = dict(present)
    prospective.update(missing)
    if set(prospective) != set(pins):
        raise ValueError("INCOMPLETE_WHEEL_INVENTORY")
    for filename, data in missing.items():
        record, digest = pins[filename]
        if _digest(data) != digest or _wheel_identity(data) != (record["name"], record["version"]):
            raise ValueError("WHEEL_DOWNLOAD_IDENTITY")

    directory.mkdir(parents=True, exist_ok=True)
    for filename, data in missing.items():
        target = directory / filename
        try:
            with target.open("xb") as stream:
                stream.write(data)
            target.chmod(0o644)
        except FileExistsError:
            if _digest(_read_regular(target)) != pins[filename][1]:
                raise ValueError("WHEEL_CACHE_RACE") from None
    _verified_wheels(directory, records, lock, contents)
    return len(pins)


def _prepare(output: Path, *, root: Path, wheel_cache: Path) -> VerifiedProfile:
    lock, lock_raw, trust, contents, runtime_records, build_records = _load_verified(root)
    wheels = _verified_wheels(wheel_cache, runtime_records + build_records, lock, contents)

    files = {
        PurePosixPath(name).name: data
        for name, data in contents.items()
        if name.startswith(PROFILE_PATH + "/")
        and "/source-proofs/" not in name
        and not name.endswith("/profile.lock.json")
    }
    files["native.sha256"] = "".join(
        f"{digest}  {path}\n" for path, digest in sorted(lock["native_sha256"].items())
    ).encode()
    files[".dockerignore"] = (
        b"*\n!Dockerfile\n!entrypoint.py\n!supplemental_manifest.py\n"
        b"!runtime_guard.py\n!runtime-contract.json\n!gh-deny\n!native.sha256\n"
        b"!requirements*.lock\n!wheels/\n!wheels/*.whl\n"
    )
    files.update({f"wheels/{filename}": data for filename, data in wheels.values()})
    manifest = {
        "schema": 1,
        "profile": PROFILE_ID,
        "platform": lock["platform"],
        "source_date_epoch": lock["source_date_epoch"],
        "profile_lock_sha256": _digest(lock_raw),
        "trust_manifest_sha256": _digest(_read_regular(root / "security/offline-test-profile-trust.json")),
        "classification": "UNTRUSTED_SUPPLEMENTAL_TEST_EVIDENCE",
        "files": {
            name: {"sha256": _digest(body), "size": len(body), "mode": "0755" if name == "gh-deny" else "0644"}
            for name, body in sorted(files.items())
        },
    }
    files["context-manifest.json"] = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()

    output.mkdir(parents=True, exist_ok=False)
    for name, body in sorted(files.items()):
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
        target.chmod(0o755 if name == "gh-deny" else 0o644)
        os.utime(target, (0, 0))
    for directory in sorted((entry for entry in output.rglob("*") if entry.is_dir()), reverse=True):
        directory.chmod(0o755)
        os.utime(directory, (0, 0))
    output.chmod(0o755)
    os.utime(output, (0, 0))
    manifest_bytes = files["context-manifest.json"]
    return VerifiedProfile(
        profile=PROFILE_ID,
        context_path=output,
        context_manifest_sha256=_digest(manifest_bytes),
        profile_lock_sha256=_digest(lock_raw),
        wheel_count=len(wheels),
        runtime_package_count=len(runtime_records),
    )


def prepare(output: Path) -> VerifiedProfile:
    """驗證可信設定來源並建立確定性的 Docker context。 / Verify trusted inputs and create a deterministic context."""
    _check_cache_path(ROOT, WHEEL_CACHE)
    return _prepare(output, root=ROOT, wheel_cache=WHEEL_CACHE)


def cache_wheels() -> int:
    """下載信任清冊固定的 wheel 至 `.state/` 快取。 / Cache only trust-pinned wheels under `.state/`."""
    return _cache_wheels(ROOT, WHEEL_CACHE)
