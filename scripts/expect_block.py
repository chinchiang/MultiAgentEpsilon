#!/usr/bin/env python3
"""An arbitrary error is not proof that the seeded defect was detected."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from security_harness.results import seeded_defects

if __name__ == "__main__":
    contract = json.loads((ROOT / "security/policy.json").read_text())["gate_contracts"]["AUTH"]
    expected = seeded_defects(contract)
    previous = (ROOT / "artifacts/latest.txt").read_text().strip() if (ROOT / "artifacts/latest.txt").exists() else None
    run = subprocess.run([sys.executable, str(ROOT / "scripts/run_security.py"), "--variant", "vulnerable"], cwd=ROOT)
    current = (ROOT / "artifacts/latest.txt").read_text().strip()
    report = json.loads((ROOT / "artifacts" / current / "report.json").read_text())
    auth = next(r for r in report["records"] if r["gate"] == "AUTH")
    failed = {c["case"] for c in auth.get("cases", []) if c.get("passed") is False}
    if (run.returncode != 1 or current == previous or report["decision"] != "BLOCK"
            or any(r["execution"] != "COMPLETED" for r in report["records"])
            or any(r["findings"] for r in report["records"] if r["gate"] != "AUTH")
            or auth["coverage_count"] != len(contract["case_ids"]) or auth["findings"] != len(expected)
            or failed != expected):
        raise SystemExit(f"Seeded defect acceptance FAILED: need exactly the {len(expected)} seeded authorization failures")
    print(f"Expected BLOCK verified: exactly the {len(expected)} seeded authorization failures, no adapter errors")
