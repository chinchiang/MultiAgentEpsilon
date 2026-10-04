#!/usr/bin/env python3
"""One fresh run, real adapters, deterministic decision, nonzero on any missing gate."""
import argparse
import json
import subprocess
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from security_harness.results import decide, digest_file, result, subject_digest, write_json
from security_harness.preflight import verify
from security_harness.secrets import scan
from security_harness.scope import validate_roe


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--variant", choices=["fixed", "vulnerable"], default="fixed")
    args = parser.parse_args()
    roe = validate_roe(json.loads((ROOT / "security/roe.json").read_text()))
    policy_file = ROOT / "security/policy.json"
    policy = json.loads(policy_file.read_text())
    policy_digest = digest_file(policy_file)
    subject = subject_digest(ROOT)
    records = []
    run_id = str(uuid.uuid4())
    output = ROOT / "artifacts" / run_id
    output.mkdir(parents=True)
    try:
        packages = verify(ROOT / "requirements.lock", policy)
        records.append(result("G1", "COMPLETED", "scan", len(packages), 0, subject, policy_digest,
                              "registry/hash/age/wheel checks", packages=packages))
    except Exception as exc:
        records.append(result("G1", "ERROR", "scan", 0, 0, subject, policy_digest, type(exc).__name__))
    try:
        scanner = json.loads((ROOT / "security/tools.lock.json").read_text())["gitleaks"]
        data = scan(ROOT, ROOT / ".tools/gitleaks", ROOT / "security/gitleaks.toml", scanner["binary_sha256"])
        records.append(result("G2", "COMPLETED", "scan", data["targets"], len(data["findings"]), subject,
                              policy_digest, "real redacted Gitleaks scan", evidence=data, scanner_version=scanner["version"]))
    except Exception as exc:
        records.append(result("G2", "ERROR", "scan", 0, 0, subject, policy_digest, type(exc).__name__))
    if any(r["execution"] != "COMPLETED" or r["findings"] for r in records):
        records.append(result("AUTH", "NOT_RUN", "test", 0, 0, subject, policy_digest, "prerequisite gate failed"))
    else:
        # Separate process provides a wall-clock deadline for all fixture work.
        try:
            process = subprocess.run([sys.executable, str(ROOT / "scripts/auth_worker.py"), args.variant],
                                     capture_output=True, text=True, timeout=roe["max_seconds"], cwd=ROOT)
            if process.returncode != 0:
                raise RuntimeError("authorization worker failed")
            cases = json.loads(process.stdout)
            if not isinstance(cases, list) or not cases or len(cases) > roe["max_cases"]:
                raise ValueError("invalid case coverage")
            if any(not isinstance(c, dict) or type(c.get("passed")) is not bool or not c.get("case") for c in cases):
                raise ValueError("invalid case result")
            records.append(result("AUTH", "COMPLETED", "test", len(cases), sum(not x["passed"] for x in cases),
                                  subject, policy_digest, "PostgreSQL authorization + side effects", cases=cases,
                                  variant=args.variant, mode="in-process HTTP/ASGI gray-box; real PostgreSQL"))
        except Exception as exc:
            status = "TIMEOUT" if isinstance(exc, subprocess.TimeoutExpired) else "ERROR"
            records.append(result("AUTH", status, "test", 0, 0, subject, policy_digest, type(exc).__name__))
    decision = decide(records, policy, subject, policy_digest)
    if subject_digest(ROOT) != subject:
        decision = {"decision": "BLOCK", "reasons": ["source changed during execution"]}
    bundle = {"run_id": run_id, "subject_digest": subject, "policy_digest": policy_digest,
              "variant": args.variant, "records": records, **decision,
              "limitations": ["unsigned local evidence", "G1 metadata only, no SCA", "no full ASVS verification",
                              "no remote GitHub protection validation", "no real LLM calls"]}
    write_json(output / "report.json", bundle)
    (ROOT / "artifacts/latest.txt").write_text(run_id + "\n")
    print(f"{decision['decision']}: {output / 'report.json'}")
    for r in records:
        print(f"  {r['gate']}: {r['execution']}, coverage={r['coverage_count']}, findings={r['findings']}")
    return 0 if decision["decision"] == "ALLOW" else 1


if __name__ == "__main__":
    raise SystemExit(main())
