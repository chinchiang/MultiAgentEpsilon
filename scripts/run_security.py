#!/usr/bin/env python3
"""Fresh run-bound evidence, mandatory case IDs and fail-closed early errors."""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from security_harness.audit import AuditRun
from security_harness.results import decide, digest_file, subject_digest, validate_cases, validate_policy
from security_harness.preflight import verify
from security_harness.secrets import scan
from security_harness.scope import validate_roe


def main():
    audit = AuditRun(ROOT, "security")
    try:
        audit.data["stage"] = "arguments"
        parser = argparse.ArgumentParser()
        parser.add_argument("--variant", choices=["fixed", "vulnerable"], default="fixed")
        parser.add_argument("--candidate", type=Path, default=ROOT)
        args = parser.parse_args()
        audit.data["variant"] = args.variant
        candidate = args.candidate.resolve()
        audit.data["stage"] = "configuration"
        roe = validate_roe(json.loads((ROOT / "security/roe.json").read_text()))
        policy_file = ROOT / "security/policy.json"
        policy = json.loads(policy_file.read_text())
        validate_policy(policy)
        if len(policy["gate_contracts"]["AUTH"]["case_ids"]) > roe["max_cases"]:
            raise ValueError("case manifest exceeds RoE")
        audit.data["policy_digest"] = digest_file(policy_file)
        audit.data["stage"] = "subject"
        audit.data["subject_digest"] = subject_digest(candidate)
        audit.data["evaluator_digest"] = subject_digest(ROOT)
        audit.data["stage"] = "G1"
        try:
            packages = verify(candidate / "requirements.lock", policy)
            audit.add("G1", "COMPLETED", "scan", len(packages), 0, "registry/hash/age/wheel checks", packages=packages)
        except Exception as exc:
            audit.add("G1", "ERROR", "scan", 0, 0, type(exc).__name__)
        audit.data["stage"] = "G2"
        try:
            scanner = json.loads((ROOT / "security/tools.lock.json").read_text())["gitleaks"]
            data = scan(candidate, ROOT / ".tools/gitleaks", ROOT / "security/gitleaks.toml", scanner["binary_sha256"])
            audit.add("G2", "COMPLETED", "scan", data["targets"], len(data["findings"]),
                      "real redacted Gitleaks scan", evidence=data, scanner_version=scanner["version"])
        except Exception as exc:
            audit.add("G2", "ERROR", "scan", 0, 0, type(exc).__name__)
        audit.data["stage"] = "AUTH"
        if any(r["execution"] != "COMPLETED" or r["findings"] for r in audit.data["records"]):
            audit.add("AUTH", "NOT_RUN", "test", 0, 0, "prerequisite gate failed")
        else:
            try:
                from security_harness.isolation import cleanup_run
                try:
                    process = subprocess.run([sys.executable, "-I", str(ROOT / "scripts/isolation_worker.py"),
                                              str(candidate), args.variant, audit.data["run_id"]],
                                             capture_output=True, text=True, timeout=roe["max_seconds"], cwd=ROOT)
                finally:
                    cleanup_run(audit.data["run_id"])
                if process.returncode != 0:
                    raise RuntimeError("authorization worker failed")
                worker = json.loads(process.stdout)
                cases = worker["cases"]
                validate_cases(cases, policy["gate_contracts"]["AUTH"])
                if len(cases) > roe["max_cases"]:
                    raise ValueError("case manifest exceeds RoE")
                audit.add("AUTH", "COMPLETED", "test", len(cases), sum(not x["passed"] for x in cases),
                          "PostgreSQL authorization + side effects", cases=cases, variant=args.variant,
                          mode="external HTTP over Unix socket; independent PostgreSQL oracle",
                          isolation=worker["isolation"])
            except Exception as exc:
                audit.add("AUTH", "TIMEOUT" if isinstance(exc, subprocess.TimeoutExpired) else "ERROR",
                          "test", 0, 0, type(exc).__name__)
        audit.data["stage"] = "decision"
        audit.data.update(decide(audit.data["records"], policy, audit.data["subject_digest"],
                                audit.data["policy_digest"], run_id=audit.data["run_id"]))
        if subject_digest(candidate) != audit.data["subject_digest"] or subject_digest(ROOT) != audit.data["evaluator_digest"]:
            raise ValueError("source changed during execution")
        audit.data["limitations"] = ["unsigned local evidence", "G1 metadata only, no SCA",
                                     "no full ASVS verification", "no real LLM calls"]
    except (Exception, KeyboardInterrupt, SystemExit) as exc:
        audit.fail(exc)
    code = audit.finish((("G1", "scan"), ("G2", "scan"), ("AUTH", "test")))
    print(f"{audit.data['decision']}: {audit.output / 'report.json'}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
