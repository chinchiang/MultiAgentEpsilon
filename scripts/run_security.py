#!/usr/bin/env python3
"""每次建立綁定執行的新證據、必要案例識別與故障即阻擋的早期錯誤處理。

Fresh run-bound evidence, mandatory case IDs and fail-closed early errors."""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
from security_harness import candidate_git
from security_harness.audit import AuditRun
from security_harness.supervision import PlanMismatch
from security_harness.results import (decide, required_gate_kinds, subject_digest, validate_cases, validate_policy,
                                      write_json)
from security_harness.preflight import verify
from security_harness.dependencies import scan as dependency_scan
from security_harness.secrets import scan
from security_harness.scope import validate_roe



def argument_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", choices=["fixed", "vulnerable"], default="fixed",
                        help="受測版本 / fixture variant")
    parser.add_argument("--candidate", type=Path, default=ROOT,
                        help="候選儲存庫路徑 / candidate repository path")
    return parser


def run_isolation_worker(command, timeout, run_id=None):
    """在獨立 session 執行 isolation worker；有 supervisor 時先登記程序群組再放行，逾時時終止整個群組。

    Run the isolation worker in its own session. Under a supervisor its process group is
    registered before the worker may run, so a supervisor timeout or cancel stops it too. On
    timeout the whole group is terminated, including its docker CLI children, before the
    timeout is re-raised."""
    from security_harness.supervision import run_gated_subprocess
    return run_gated_subprocess(command, timeout, root=ROOT, run_id=run_id)


class AuthorizationWorkerFailed(RuntimeError):
    def __init__(self, failure):
        super().__init__("authorization worker failed")
        self.evidence = {"worker_failure": failure}


def worker_failure(stdout: str) -> dict:
    """把 isolation worker 的失敗摘要限定為識別字與檢查名稱；其他內容一律丟棄。

Keep only an identifier-shaped error type and check names from the isolation worker's
    failure summary; anything else is dropped rather than copied into evidence."""
    unknown = {"error_type": "Unknown", "failed_checks": []}
    if len(stdout) > 4096:
        return unknown
    try:
        data = json.loads(stdout)
    except ValueError:
        return unknown
    if not isinstance(data, dict):
        return unknown
    error_type = data.get("error_type")
    checks = data.get("failed_checks")
    if not isinstance(error_type, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", error_type):
        return unknown
    if (not isinstance(checks, list) or len(checks) > 32
            or not all(isinstance(c, str) and re.fullmatch(r"[a-z_]{1,32}", c) for c in checks)):
        checks = []
    return {"error_type": error_type, "failed_checks": checks}


def plan(audit, candidate, variant):
    """supervisor 在放行 worker 前決定的計畫：候選、版本、RoE、政策、評估者摘要與限額。

The supervisor's plan, decided before the worker is released: the candidate,
    variant, RoE, policy, evaluator digest and limits.
    """
    from security_harness.lifecycle import plan_security
    return plan_security(ROOT, audit, candidate, variant)


def planned_configuration(audit):
    """核對評估者摘要，再讀取一次 RoE 與政策並核對計畫；回傳同一份位元組供解析。

Check the evaluator digest, then read the RoE and policy once and check them
    against the plan. Return those same bytes for parsing.
    """
    if subject_digest(ROOT) != audit.data["evaluator_digest"]:
        raise PlanMismatch("evaluator differs from the plan")
    # 雜湊與解析使用同一份位元組，規劃後被換掉的檔案不會被讀到。 / Hash and parse the same bytes, so a file
    # replaced after planning is never the one parsed.
    roe_bytes = (ROOT / "security/roe.json").read_bytes()
    policy_bytes = (ROOT / "security/policy.json").read_bytes()
    if (hashlib.sha256(roe_bytes).hexdigest() != audit.data["roe_sha256"]
            or hashlib.sha256(policy_bytes).hexdigest() != audit.data["policy_digest"]):
        raise PlanMismatch("configuration differs from the plan")
    return roe_bytes, policy_bytes


def main(audit, defer_final=False):
    try:
        audit.stage("configuration")
        candidate = Path(audit.data["candidate"])
        variant = audit.data["variant"]
        roe_bytes, policy_bytes = planned_configuration(audit)
        roe = validate_roe(json.loads(roe_bytes))
        policy = json.loads(policy_bytes)
        validate_policy(policy)
        if len(policy["gate_contracts"]["AUTH"]["case_ids"]) > roe["max_cases"]:
            raise ValueError("case manifest exceeds RoE")
        audit.stage("subject")
        audit.data["subject_digest"] = subject_digest(candidate)
        audit.stage("G1")
        packages = []
        try:
            packages = verify(candidate / "requirements.lock", policy)
            sca = dependency_scan(candidate / "requirements.lock")
            write_json(audit.output / "sbom.cdx.json", sca["sbom"])
            audit.add("G1", "COMPLETED", "scan", len(packages), len(sca["findings"]),
                      "registry/hash/age/wheel and exact-version OSV checks", packages=packages, sca=sca)
        except Exception as exc:
            partial = getattr(exc, 'evidence', None) or {"status": "INCOMPLETE", "error_type": type(exc).__name__}
            audit.add("G1", "ERROR", "scan", len(packages), len(partial.get('findings', [])),
                      type(exc).__name__, packages=packages, sca=partial)
        audit.stage("G2")
        try:
            scanner = json.loads((ROOT / "security/tools.lock.json").read_text())["gitleaks"]
            data = scan(candidate, ROOT / ".tools/gitleaks", ROOT / "security/gitleaks.toml", scanner["binary_sha256"],
                        require_history=True)
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
                    process = run_isolation_worker([sys.executable, "-I", str(ROOT / "scripts/isolation_worker.py"),
                                                    str(candidate), variant, audit.data["run_id"]], roe["max_seconds"],
                                                    audit.data["run_id"])
                finally:
                    cleanup_run(audit.data["run_id"])
                if process.returncode != 0:
                    raise AuthorizationWorkerFailed(worker_failure(process.stdout))
                worker = json.loads(process.stdout)
                cases = worker["cases"]
                validate_cases(cases, policy["gate_contracts"]["AUTH"])
                if len(cases) > roe["max_cases"]:
                    raise ValueError("case manifest exceeds RoE")
                audit.add("AUTH", "COMPLETED", "test", len(cases), sum(not x["passed"] for x in cases),
                          "PostgreSQL authorization + side effects", cases=cases, variant=variant,
                          mode="bounded container HTTP bridge; independent PostgreSQL oracle",
                          isolation=worker["isolation"])
            except Exception as exc:
                # worker 整體逾時，或橋接請求在整輪重跑後仍超過期限，都記為 TIMEOUT。 / A worker timeout, or a bridge
                # request still past its deadline after the whole-run retry, is recorded as TIMEOUT.
                evidence = getattr(exc, "evidence", {})
                timed_out = (isinstance(exc, subprocess.TimeoutExpired)
                             or evidence.get("worker_failure", {}).get("error_type") == "DeadlineExceeded")
                audit.add("AUTH", "TIMEOUT" if timed_out else "ERROR", "test", 0, 0, type(exc).__name__, **evidence)
        audit.stage("decision")
        audit.data.update(decide(audit.data["records"], policy, audit.data["subject_digest"],
                                audit.data["policy_digest"], run_id=audit.data["run_id"]))
        if subject_digest(candidate) != audit.data["subject_digest"] or subject_digest(ROOT) != audit.data["evaluator_digest"]:
            raise ValueError("source changed during execution")
        for record in audit.data['records']:
            head = record.get('evidence', {}).get('coverage', {}).get('history_head')
            if head and candidate_git.head(candidate) != head:
                raise ValueError('history changed during execution')
        audit.data["limitations"] = ["unsigned local evidence", "lockfile SBOM and OSV only; no installed image inventory or malicious-package analysis",
                                     "no full ASVS verification", "no real LLM calls"]
    except (Exception, KeyboardInterrupt, SystemExit) as exc:
        audit.fail(exc)
    code = audit.finish(required_gate_kinds(ROOT), defer_final=defer_final)
    print(f"{audit.data['decision']}: {audit.output / 'report.json'}")
    return code


def supervised_main():
    if sys.argv[1:] in (["--help"], ["-h"]):
        argument_parser().parse_args()
    from security_harness.lifecycle import supervise, worker_command
    audit = AuditRun(ROOT, "security")
    try:
        audit.stage("arguments")
        args = argument_parser().parse_args()
        roe = plan(audit, args.candidate, args.variant)
        code = supervise(ROOT, audit, worker_command(ROOT, audit), roe["max_total_seconds"])
    except (Exception, KeyboardInterrupt, SystemExit) as exc:
        audit.fail(exc)
        code = audit.finish(required_gate_kinds(ROOT))
    print(f"{audit.data['decision']}: {audit.output / 'report.json'}")
    return code


if __name__ == "__main__":
    raise SystemExit(supervised_main())
