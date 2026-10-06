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


def main(audit=None, defer_final=False):
    audit = audit or AuditRun(ROOT, "security")
    try:
        audit.stage("arguments")
        parser = argparse.ArgumentParser()
        parser.add_argument("--variant", choices=["fixed", "vulnerable"], default="fixed")
        parser.add_argument("--candidate", type=Path, default=ROOT)
        args = parser.parse_args()
        audit.data["variant"] = args.variant
        candidate = args.candidate.resolve()
        audit.stage("configuration")
        roe = validate_roe(json.loads((ROOT / "security/roe.json").read_text()))
        policy_file = ROOT / "security/policy.json"
        policy = json.loads(policy_file.read_text())
        validate_policy(policy)
        if len(policy["gate_contracts"]["AUTH"]["case_ids"]) > roe["max_cases"]:
            raise ValueError("case manifest exceeds RoE")
        audit.data["policy_digest"] = digest_file(policy_file)
        audit.stage("subject")
        audit.data["subject_digest"] = subject_digest(candidate)
        audit.data["evaluator_digest"] = subject_digest(ROOT)
        audit.stage("G1")
        try:
            packages = verify(candidate / "requirements.lock", policy)
            audit.add("G1", "COMPLETED", "scan", len(packages), 0, "registry/hash/age/wheel checks", packages=packages)
        except Exception as exc:
            audit.add("G1", "ERROR", "scan", 0, 0, type(exc).__name__)
        audit.stage("G2")
        try:
            scanner = json.loads((ROOT / "security/tools.lock.json").read_text())["gitleaks"]
            data = scan(candidate, ROOT / ".tools/gitleaks", ROOT / "security/gitleaks.toml", scanner["binary_sha256"])
            audit.add("G2", "COMPLETED", "scan", data["targets"], len(data["findings"]),
                      "real redacted Gitleaks scan", evidence=data, scanner_version=scanner["version"])
        except Exception as exc:
            audit.add("G2", "ERROR", "scan", 0, 0, type(exc).__name__,
                      coverage={"status": "INCOMPLETE", "error_type": type(exc).__name__})
        audit.stage("AUTH")
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
                          mode="bounded container HTTP bridge; independent PostgreSQL oracle",
                          isolation=worker["isolation"])
            except Exception as exc:
                audit.add("AUTH", "TIMEOUT" if isinstance(exc, subprocess.TimeoutExpired) else "ERROR",
                          "test", 0, 0, type(exc).__name__)
        audit.stage("decision")
        audit.data.update(decide(audit.data["records"], policy, audit.data["subject_digest"],
                                audit.data["policy_digest"], run_id=audit.data["run_id"]))
        if subject_digest(candidate) != audit.data["subject_digest"] or subject_digest(ROOT) != audit.data["evaluator_digest"]:
            raise ValueError("source changed during execution")
        for record in audit.data['records']:
            head = record.get('evidence', {}).get('coverage', {}).get('history_head')
            if head and subprocess.check_output(['git', '-C', str(candidate), 'rev-parse', 'HEAD'],
                                                text=True, timeout=10).strip() != head:
                raise ValueError('history changed during execution')
        audit.data["limitations"] = ["unsigned local evidence", "G1 metadata only, no SCA",
                                     "no full ASVS verification", "no real LLM calls"]
    except (Exception, KeyboardInterrupt, SystemExit) as exc:
        audit.fail(exc)
    pending_code = 0 if audit.data['decision'] == 'ALLOW' else 1
    if defer_final:
        audit.data['pending_decision'] = audit.data['decision']
        audit.data['pending_execution'] = audit.data['execution']
        audit.data.update(decision='BLOCK', execution='AWAITING_CLEANUP')
    code = audit.finish((("G1", "scan"), ("G2", "scan"), ("AUTH", "test")))
    print(f"{audit.data['decision']}: {audit.output / 'report.json'}")
    return pending_code if defer_final else code


def supervised_main():
    from security_harness.lifecycle import supervise
    audit = AuditRun(ROOT, "security")
    try:
        audit.stage("arguments")
        parser = argparse.ArgumentParser()
        parser.add_argument("--variant", choices=["fixed", "vulnerable"], default="fixed")
        parser.add_argument("--candidate", type=Path, default=ROOT)
        args = parser.parse_args()
        roe = validate_roe(json.loads((ROOT / "security/roe.json").read_text()))
        audit.data["resource_limits"] = {"total_seconds": roe["max_total_seconds"],
            "address_space_bytes": 8*1024**3, "per_process_data_bytes": 512*1024**2, "per_process_cpu_seconds": 120,
            "per_file_output_bytes": 64*1024**2, "file_descriptors": 256}
        audit.save()
        code = supervise(ROOT, audit,
            [sys.executable, "-I", str(ROOT / "scripts/security_worker.py"), audit.data["run_id"],
             str(args.candidate.resolve()), args.variant], roe["max_total_seconds"])
    except (Exception, KeyboardInterrupt, SystemExit) as exc:
        audit.fail(exc)
        code = audit.finish((("G1", "scan"), ("G2", "scan"), ("AUTH", "test")))
    print(f"{audit.data['decision']}: {audit.output / 'report.json'}")
    return code


if __name__ == "__main__":
    raise SystemExit(supervised_main())
