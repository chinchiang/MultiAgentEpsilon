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


RUN_ID = "0123abcd-0123-4abc-8def-0123456789ab"


@pytest.mark.parametrize("stdout, expected", [
    (f"BLOCK: {ROOT}/artifacts/{RUN_ID}/report.json\n", RUN_ID),
    # worker 與 supervisor 都會印一行；只採最後一行。 / The worker and the supervisor both print; only the last line counts.
    (f"BLOCK: {ROOT}/artifacts/ffffffff-ffff-4fff-8fff-ffffffffffff/report.json\nBLOCK: {ROOT}/artifacts/{RUN_ID}/report.json\n", RUN_ID),
    (f"BLOCK: /elsewhere/artifacts/{RUN_ID}/report.json\n", None),
    (f"BLOCK: {ROOT}/artifacts/../{RUN_ID}/report.json\n", None),
    ("nothing printed\n", None),
])
def test_expect_block_reads_the_run_it_started_not_latest_pointer(stdout, expected):
    from scripts.expect_block import reported_run
    assert reported_run(stdout) == expected


def test_expect_block_ignores_a_moved_latest_pointer(tmp_path, monkeypatch):
    from scripts import expect_block
    monkeypatch.setattr(expect_block, "ROOT", tmp_path)
    (tmp_path / "security").mkdir()
    (tmp_path / "security/policy.json").write_text(json.dumps({"gate_contracts": {"AUTH": CONTRACT}}))
    other = "ffffffff-ffff-4fff-8fff-ffffffffffff"
    for run_id, report in ((RUN_ID, {**accepted_report(), "run_id": RUN_ID, "errors": [{"stage": "AUTH"}]}),
                           (other, {**accepted_report(), "run_id": other})):
        (tmp_path / "artifacts" / run_id).mkdir(parents=True)
        (tmp_path / "artifacts" / run_id / "report.json").write_text(json.dumps(report))
    class Done:
        returncode = 1
        stdout = f"BLOCK: {tmp_path}/artifacts/{RUN_ID}/report.json\n"
        stderr = ""

    def run(*args, **kwargs):
        # 執行期間另一個執行把 latest.txt 移到一份「看起來通過」的報告。 /
        # While it runs, another run moves latest.txt to a report that looks accepted.
        (tmp_path / "artifacts/latest.txt").write_text(other + "\n")
        return Done()
    monkeypatch.setattr(expect_block.subprocess, "run", run)
    with pytest.raises(SystemExit, match="Seeded defect acceptance FAILED"):
        expect_block.main([])
