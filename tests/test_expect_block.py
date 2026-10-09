import copy
import json
from pathlib import Path

import pytest
from scripts.expect_block import seeded_block_verified

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = json.loads((ROOT / "security/policy.json").read_text())["gate_contracts"]["AUTH"]


def accepted_report():
    seeded = set(CONTRACT["seeded_defect_case_ids"])
    cases = [{"case": c, "passed": c not in seeded} for c in CONTRACT["case_ids"]]
    return {"decision": "BLOCK", "execution": "COMPLETED", "variant": "vulnerable", "errors": [],
            "cleanup": {"completed": True},
            "records": [{"gate": "G1", "execution": "COMPLETED", "findings": 0},
                        {"gate": "G2", "execution": "COMPLETED", "findings": 0},
                        {"gate": "AUTH", "execution": "COMPLETED", "findings": len(seeded),
                         "coverage_count": len(cases), "cases": cases}]}


def test_exact_seeded_block_from_a_clean_run_is_accepted():
    assert seeded_block_verified(accepted_report(), CONTRACT, 1)


def swap_one_seeded_case(report):
    cases = report["records"][2]["cases"]
    next(c for c in cases if not c["passed"])["passed"] = True
    next(c for c in cases if c["passed"] and c["case"] not in CONTRACT["seeded_defect_case_ids"])["passed"] = False


@pytest.mark.parametrize("mutate", [
    lambda r: r.update(execution="ERROR"),        # 例如所有 gate 後來源變更或清理不完整。 / e.g. source changed or cleanup incomplete after all gates
    lambda r: r.update(execution="TIMEOUT"),
    lambda r: r.update(execution="CANCELLED"),
    lambda r: r["errors"].append({"stage": "decision", "error_type": "ValueError"}),
    lambda r: r.update(cleanup={"completed": False}),
    lambda r: r.pop("cleanup"),
    lambda r: r.update(variant="fixed"),
    lambda r: r.update(decision="ALLOW"),
    lambda r: r["records"][1].update(findings=1),
    lambda r: r["records"][0].update(execution="ERROR"),
    lambda r: r["records"].append(copy.deepcopy(r["records"][2])),
    lambda r: r["records"].pop(2),
    swap_one_seeded_case,
])
def test_anything_but_the_exact_clean_seeded_block_is_rejected(mutate):
    report = accepted_report()
    mutate(report)
    assert not seeded_block_verified(report, CONTRACT, 1)


def test_wrong_exit_code_is_rejected():
    assert not seeded_block_verified(accepted_report(), CONTRACT, 0)
    assert not seeded_block_verified(accepted_report(), CONTRACT, 2)
