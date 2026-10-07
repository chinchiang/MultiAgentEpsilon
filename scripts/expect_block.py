#!/usr/bin/env python3
"""An arbitrary error is not proof that the seeded defect was detected."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from security_harness.results import seeded_defects


def seeded_block_verified(report: dict, contract: dict, returncode: int) -> bool:
    """Exactly the seeded AUTH failures from a run that itself completed cleanly."""
    expected = seeded_defects(contract)
    auth = [r for r in report.get("records", []) if r.get("gate") == "AUTH"]
    if len(auth) != 1:
        return False
    auth = auth[0]
    failed = {c["case"] for c in auth.get("cases", []) if c.get("passed") is False}
    return (returncode == 1 and report.get("decision") == "BLOCK"
            and report.get("execution") == "COMPLETED" and report.get("variant") == "vulnerable"
            and not report.get("errors") and report.get("cleanup", {}).get("completed") is True
            and all(r["execution"] == "COMPLETED" for r in report["records"])
            and not any(r["findings"] for r in report["records"] if r["gate"] != "AUTH")
            and auth["coverage_count"] == len(contract["case_ids"]) and auth["findings"] == len(expected)
            and failed == expected)


def main():
    contract = json.loads((ROOT / "security/policy.json").read_text())["gate_contracts"]["AUTH"]
    expected = seeded_defects(contract)
    latest = ROOT / "artifacts/latest.txt"
    previous = latest.read_text().strip() if latest.exists() else None
    run = subprocess.run([sys.executable, str(ROOT / "scripts/run_security.py"), "--variant", "vulnerable"], cwd=ROOT)
    current = latest.read_text().strip()
    report = json.loads((ROOT / "artifacts" / current / "report.json").read_text())
    if current == previous or not seeded_block_verified(report, contract, run.returncode):
        raise SystemExit(f"Seeded defect acceptance FAILED: need exactly the {len(expected)} seeded authorization "
                         "failures from a cleanly completed run")
    print(f"Expected BLOCK verified: exactly the {len(expected)} seeded authorization failures, no adapter errors")


if __name__ == "__main__":
    main()
