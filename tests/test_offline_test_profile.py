"""可信離線測試設定與執行期拒絕行為回歸。 / Trusted profile preparation and runtime refusal regressions."""
from contextlib import ExitStack
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import types
import unittest
import zipfile
from types import SimpleNamespace
from unittest.mock import patch

from security_harness import offline_test_profile as profile


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "security/offline-test-profile"


def load_profile_file(name):
    path = PROFILE / name
    module = types.ModuleType(name.replace("-", "_"))
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


guard = load_profile_file("runtime_guard.py")
manifest_plugin = load_profile_file("supplemental_manifest.py")


def clone_trusted_inputs(directory: Path) -> Path:
    root = directory / "repo"
    (root / "security").mkdir(parents=True)
    shutil.copytree(PROFILE, root / "security/offline-test-profile")
    shutil.copyfile(ROOT / "security/offline-test-profile-trust.json",
                    root / "security/offline-test-profile-trust.json")
    shutil.copyfile(ROOT / "security/policy.json", root / "security/policy.json")
    shutil.copyfile(ROOT / "requirements.lock", root / "requirements.lock")
    shutil.copyfile(ROOT / "requirements-test.lock", root / "requirements-test.lock")
    (root / "tests").mkdir()
    shutil.copyfile(Path(__file__), root / "tests/test_offline_test_profile.py")
    # 合成 wheel 只供測試，無須依賴本機快取。 / Synthetic wheels keep tests independent of local caches.
    profile_dir = root / "security/offline-test-profile"
    lock_path = profile_dir / "profile.lock.json"
    lock = json.loads(lock_path.read_text())
    wheel_dir = root / ".state/verified-wheels/offline-test-profile"
    wheel_dir.mkdir(parents=True)
    records = profile.preflight.parse_lock(profile_dir / "requirements-runtime.lock")
    records += profile.preflight.parse_lock(profile_dir / "requirements-build.lock")
    pins = {}
    for record in records:
        filename = record["name"] + "-" + record["version"] + "-py3-none-any.whl"
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr(record["name"] + "-" + record["version"] + ".dist-info/METADATA",
                             "Name: " + record["name"] + "\nVersion: " + record["version"] + "\n")
        data = stream.getvalue()
        digest = hashlib.sha256(data).hexdigest()
        (wheel_dir / filename).write_bytes(data)
        pins[filename] = digest
        for path in (profile_dir / "requirements-runtime.lock", profile_dir / "requirements-build.lock",
                     root / "requirements.lock", root / "requirements-test.lock"):
            text = path.read_text()
            for old in record["hashes"]:
                text = text.replace(old, digest)
            path.write_text(text)
        proof_path = profile_dir / "source-proofs" / (record["name"] + ".json")
        proof = json.loads(proof_path.read_text())
        artifact = next(item for item in proof["urls"] if item["digests"]["sha256"] in record["hashes"])
        artifact["digests"]["sha256"] = digest
        artifact["size"] = len(data)
        artifact["packagetype"] = "bdist_wheel"
        proof["urls"] = [artifact]
        proof_path.write_text(json.dumps(proof))
    lock["wheel_sha256"] = pins
    for name in lock["input_sha256"]:
        lock["input_sha256"][name] = hashlib.sha256((root / name).read_bytes()).hexdigest()
    raw = (json.dumps(lock, sort_keys=True, indent=2) + "\n").encode()
    lock_path.write_bytes(raw)
    trust_path = root / "security/offline-test-profile-trust.json"
    trust = json.loads(trust_path.read_text())
    trust["profile_lock_sha256"] = hashlib.sha256(raw).hexdigest()
    trust_path.write_text(json.dumps(trust))
    return root


def repin_lock(root: Path, changed_path: str) -> None:
    profile_dir = root / "security/offline-test-profile"
    lock_path = profile_dir / "profile.lock.json"
    lock = json.loads(lock_path.read_text())
    lock["input_sha256"][changed_path] = hashlib.sha256((root / changed_path).read_bytes()).hexdigest()
    lock_raw = (json.dumps(lock, sort_keys=True, indent=2) + "\n").encode()
    lock_path.write_bytes(lock_raw)
    trust_path = root / "security/offline-test-profile-trust.json"
    trust = json.loads(trust_path.read_text())
    trust["profile_lock_sha256"] = hashlib.sha256(lock_raw).hexdigest()
    trust_path.write_text(json.dumps(trust, sort_keys=True, indent=2) + "\n")


class ProfilePreparationTests(unittest.TestCase):
    def test_independent_lock_anchor_rejects_changed_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = clone_trusted_inputs(Path(directory))
            lock_path = root / "security/offline-test-profile/profile.lock.json"
            lock = json.loads(lock_path.read_text())
            lock["platform"] = "linux/arm64"
            lock_path.write_text(json.dumps(lock))
            with self.assertRaisesRegex(ValueError, "PROFILE_LOCK_ANCHOR"):
                profile._prepare(Path(directory) / "context", root=root, wheel_cache=root / ".state/verified-wheels/offline-test-profile")

    def test_wrong_independent_anchor_rejects_before_context_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = clone_trusted_inputs(Path(directory))
            trust_path = root / "security/offline-test-profile-trust.json"
            trust = json.loads(trust_path.read_text())
            trust["profile_lock_sha256"] = "0" * 64
            trust_path.write_text(json.dumps(trust))
            output = Path(directory) / "context"
            with self.assertRaisesRegex(ValueError, "PROFILE_LOCK_ANCHOR"):
                profile._prepare(output, root=root, wheel_cache=root / ".state/verified-wheels/offline-test-profile")
            self.assertFalse(output.exists())

    def test_verified_contexts_are_byte_and_metadata_identical(self):
        with tempfile.TemporaryDirectory() as directory:
            root = clone_trusted_inputs(Path(directory))
            outputs = [Path(directory) / name for name in ("a", "b")]
            results = [profile._prepare(output, root=root, wheel_cache=root / ".state/verified-wheels/offline-test-profile") for output in outputs]
            self.assertEqual(results[0].context_manifest_sha256, results[1].context_manifest_sha256)
            self.assertEqual(results[0].wheel_count, 8)
            self.assertEqual(results[0].runtime_package_count, 7)

            def inventory(path):
                return {
                    str(entry.relative_to(path)): (
                        entry.read_bytes(), entry.stat().st_mode & 0o777, entry.stat().st_mtime_ns
                    )
                    for entry in path.rglob("*") if entry.is_file()
                }

            self.assertEqual(inventory(outputs[0]), inventory(outputs[1]))
            names = set(inventory(outputs[0]))
            self.assertNotIn("profile.lock.json", names)
            self.assertIn("entrypoint.py", names)
            self.assertNotIn("test_offline_test_profile.py", names)
            self.assertNotIn("source-proofs/pip.json", names)

    def test_tampered_inputs_fail_before_context_creation(self):
        for relative in (
            "security/offline-test-profile/Dockerfile",
            "security/offline-test-profile/gh-deny",
            "security/offline-test-profile/runtime_guard.py",
            "security/offline-test-profile/supplemental_manifest.py",
            "security/offline-test-profile/requirements-runtime.lock",
            "security/offline-test-profile/requirements-build.lock",
            "security/offline-test-profile/source-proofs/pip.json",
            "tests/test_offline_test_profile.py",
        ):
            with self.subTest(file=relative), tempfile.TemporaryDirectory() as directory:
                root = clone_trusted_inputs(Path(directory))
                with (root / relative).open("ab") as stream:
                    stream.write(b"\nchanged")
                output = Path(directory) / "context"
                with self.assertRaises(ValueError):
                    profile._prepare(output, root=root, wheel_cache=root / ".state/verified-wheels/offline-test-profile")
                self.assertFalse(output.exists())

    def test_symlink_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = clone_trusted_inputs(Path(directory))
            deny = root / "security/offline-test-profile/gh-deny"
            deny.unlink()
            deny.symlink_to(PROFILE / "gh-deny")
            with self.assertRaisesRegex(ValueError, "PROFILE_SYMLINK"):
                profile._prepare(Path(directory) / "context", root=root, wheel_cache=root / ".state/verified-wheels/offline-test-profile")

    def test_extra_profile_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = clone_trusted_inputs(Path(directory))
            (root / "security/offline-test-profile/unreviewed.txt").write_text("extra")
            with self.assertRaisesRegex(ValueError, "PROFILE_DIRECTORY_INVENTORY"):
                profile._prepare(Path(directory) / "context", root=root, wheel_cache=root / ".state/verified-wheels/offline-test-profile")

    def test_missing_or_unapproved_wheel_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = clone_trusted_inputs(Path(directory))
            wheels = Path(directory) / "wheels"
            wheels.mkdir()
            for source in (root / ".state/verified-wheels/offline-test-profile").glob("*.whl"):
                if not source.name.startswith("pip-"):
                    shutil.copyfile(source, wheels / source.name)
            with self.assertRaisesRegex(ValueError, "WHEEL_CACHE_INVENTORY"):
                profile._prepare(Path(directory) / "missing", root=root, wheel_cache=wheels)
            shutil.copyfile(next((root / ".state/verified-wheels/offline-test-profile").glob("pip-*.whl")), wheels / next((root / ".state/verified-wheels/offline-test-profile").glob("pip-*.whl")).name)
            (wheels / "bad.whl").write_bytes(b"unapproved")
            with self.assertRaisesRegex(ValueError, "WHEEL_CACHE_INVENTORY"):
                profile._prepare(Path(directory) / "extra", root=root, wheel_cache=wheels)

    def test_cache_fetches_only_locked_proof_urls_and_verifies_all_wheels(self):
        with tempfile.TemporaryDirectory() as directory:
            root = clone_trusted_inputs(Path(directory))
            lock = json.loads((root / "security/offline-test-profile/profile.lock.json").read_text())
            records = profile.preflight.parse_lock(root / "security/offline-test-profile/requirements-runtime.lock")
            records += profile.preflight.parse_lock(root / "security/offline-test-profile/requirements-build.lock")
            pins = profile._wheel_pins(lock, records)
            responses = {}
            for filename, (record, digest) in pins.items():
                proof = json.loads((root / f"security/offline-test-profile/source-proofs/{record['name']}.json").read_text())
                artifact = next(item for item in proof["urls"] if item["digests"]["sha256"] == digest)
                responses[artifact["url"]] = (root / ".state/verified-wheels/offline-test-profile" / filename).read_bytes()

            class FakeOpener:
                def open(self, request, timeout):
                    self_url = request.full_url
                    if timeout != 45 or self_url not in responses:
                        raise AssertionError("unreviewed URL or timeout")
                    return io.BytesIO(responses[self_url])

            cache = root / ".state/test-cache"
            self.assertEqual(profile._cache_wheels(root, cache, opener=FakeOpener()), 8)
            self.assertEqual({path.name for path in cache.iterdir()}, set(pins))

    def test_bad_download_writes_no_wheel_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = clone_trusted_inputs(Path(directory))

            class BadOpener:
                def open(self, request, timeout):
                    return io.BytesIO(b"not a wheel")

            cache = root / ".state/test-cache"
            with self.assertRaisesRegex(ValueError, "WHEEL_DOWNLOAD_DIGEST"):
                profile._cache_wheels(root, cache, opener=BadOpener())
            self.assertFalse(cache.exists())

    def test_symlinked_wheel_cache_parent_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = clone_trusted_inputs(Path(directory))
            outside = Path(directory) / "outside"
            outside.mkdir()
            state = root / ".state"
            (state / "linked-cache").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "WHEEL_CACHE_SYMLINK"):
                profile._cache_wheels(root, state / "linked-cache/offline-test-profile")

    def test_wheel_size_must_match_source_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root = clone_trusted_inputs(Path(directory))
            relative = "security/offline-test-profile/source-proofs/pip.json"
            path = root / relative
            proof = json.loads(path.read_text())
            proof["urls"][0]["size"] += 1
            path.write_text(json.dumps(proof))
            repin_lock(root, relative)
            with self.assertRaisesRegex(ValueError, "WHEEL_SOURCE_SIZE"):
                profile._prepare(Path(directory) / "context", root=root,
                                 wheel_cache=root / ".state/verified-wheels/offline-test-profile")

    def test_runtime_contract_must_agree_after_reviewed_repin(self):
        with tempfile.TemporaryDirectory() as directory:
            root = clone_trusted_inputs(Path(directory))
            contract_path = root / "security/offline-test-profile/runtime-contract.json"
            contract = json.loads(contract_path.read_text())
            contract["packages"]["pytest"] = "0.0.0"
            contract_path.write_text(json.dumps(contract))
            repin_lock(root, "security/offline-test-profile/runtime-contract.json")
            with self.assertRaisesRegex(ValueError, "RUNTIME_CONTRACT"):
                profile._prepare(Path(directory) / "context", root=root, wheel_cache=root / ".state/verified-wheels/offline-test-profile")


class RuntimeGuardTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.contract = self.root / "contract.json"
        self.gh = self.root / "gh"
        self.gh.write_bytes((PROFILE / "gh-deny").read_bytes())
        self.gh.chmod(0o755)
        self.data = json.loads((PROFILE / "runtime-contract.json").read_text())
        self.contract.write_text(json.dumps(self.data))
        self.installed = [SimpleNamespace(metadata={"Name": name}, version=version)
                          for name, version in self.data["packages"].items()]
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(guard.importlib.metadata, "distributions",
                                              side_effect=lambda: self.installed))
        self.stack.enter_context(patch.object(guard.importlib.util, "find_spec", return_value=None))
        self.stack.enter_context(patch.object(guard.shutil, "which", return_value=None))
        self.stack.enter_context(patch.object(guard.sysconfig, "get_path", return_value=str(self.root / "stdlib")))

    def verify(self):
        return guard.verify(contract_path=self.contract, gh_path=self.gh)

    def test_exact_runtime_and_actual_deny_script_are_accepted(self):
        self.assertEqual(self.verify()["runtime_package_count"], 7)

    def test_actual_deny_script_rejects_github_operations(self):
        expected = self.data["gh_deny_stderr"].encode()
        for arguments in (("--version",), ("api", "user"), ("pr", "view", "65")):
            with self.subTest(arguments=arguments):
                result = subprocess.run([str(self.gh), *arguments], capture_output=True)
                self.assertEqual(result.returncode, 126)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(result.stderr, expected)

    def test_extra_package_is_rejected(self):
        self.installed.append(SimpleNamespace(metadata={"Name": "pip"}, version="26.2.2"))
        with self.assertRaisesRegex(ValueError, "PACKAGE_INVENTORY"):
            self.verify()

    def test_duplicate_distribution_is_rejected(self):
        self.installed.append(SimpleNamespace(metadata={"Name": "pytest"}, version="9.1.1"))
        with self.assertRaisesRegex(ValueError, "DUPLICATE_PACKAGE"):
            self.verify()

    def test_wrong_version_is_rejected(self):
        self.installed[0].version = "0.0.0"
        with self.assertRaisesRegex(ValueError, "PACKAGE_INVENTORY"):
            self.verify()

    def test_importable_build_tool_is_rejected(self):
        with patch.object(guard.importlib.util, "find_spec", return_value=object()), \
                self.assertRaisesRegex(ValueError, "BUILD_TOOL_PRESENT"):
            self.verify()

    def test_leftover_pip_entrypoint_is_rejected(self):
        with patch.object(guard.shutil, "which", return_value="/usr/local/bin/pip"), \
                self.assertRaisesRegex(ValueError, "PIP_ENTRYPOINT"):
            self.verify()

    def test_ensurepip_directory_is_rejected(self):
        (self.root / "stdlib/ensurepip").mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, "ENSUREPIP_PRESENT"):
            self.verify()

    def test_changed_or_symlink_sentinel_is_rejected(self):
        self.gh.write_text("#!/bin/sh\nexit 0\n")
        with self.assertRaisesRegex(ValueError, "SENTINEL_DIGEST"):
            self.verify()
        self.gh.unlink()
        self.gh.symlink_to(PROFILE / "gh-deny")
        with self.assertRaisesRegex(ValueError, "SENTINEL_DIGEST"):
            self.verify()

    def test_successful_sentinel_is_rejected_even_with_matching_digest(self):
        self.gh.write_text("#!/bin/sh\nexit 0\n")
        self.data["gh_deny_sha256"] = hashlib.sha256(self.gh.read_bytes()).hexdigest()
        self.contract.write_text(json.dumps(self.data))
        with self.assertRaisesRegex(ValueError, "SENTINEL_BEHAVIOR"):
            self.verify()

    def test_missing_sentinel_is_rejected(self):
        self.gh.unlink()
        with self.assertRaises(OSError):
            self.verify()


class CollectionManifestTests(unittest.TestCase):
    def test_changed_collection_does_not_write_success_evidence(self):
        with patch.object(manifest_plugin.Path, "read_text",
                          return_value=json.dumps({"collection_sha256": "0" * 64})), \
                patch.object(manifest_plugin.Path, "write_text") as write:
            with self.assertRaisesRegex(ValueError, "COLLECTION_CHANGED"):
                manifest_plugin.pytest_collection_modifyitems([SimpleNamespace(nodeid="different")])
            write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
