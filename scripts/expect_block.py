#!/usr/bin/env python3
"""An arbitrary error is not proof that the seeded defect was detected."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

if __name__ == "__main__":
    previous = (ROOT / "artifacts/latest.txt").read_text().strip() if (ROOT / "artifacts/latest.txt").exists() else None
    run = subprocess.run([sys.executable, str(ROOT / "scripts/run_security.py"), "--variant", "vulnerable"], cwd=ROOT)
    current = (ROOT / "artifacts/latest.txt").read_text().strip()
    report = json.loads((ROOT / "artifacts" / current / "report.json").read_text())
    auth = next(r for r in report["records"] if r["gate"] == "AUTH")
    if (run.returncode != 1 or current == previous or report["decision"] != "BLOCK"
            or any(r["execution"] != "COMPLETED" for r in report["records"])
            or any(r["findings"] for r in report["records"] if r["gate"] != "AUTH")
            or auth["coverage_count"] != 14 or auth["findings"] != 5):
        raise SystemExit("Seeded defect acceptance FAILED: need five observed authorization failures")
    print("Expected BLOCK verified: five real authorization failures, no adapter errors")
