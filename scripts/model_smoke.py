#!/usr/bin/env python3
"""執行固定合成 gateway 測試；真實呼叫必須明確啟用。

Run the fixed synthetic gateway fixture. Live calls are explicit opt-in."""
import argparse
import asyncio
import hashlib
import json
import signal
import sys
import uuid
from datetime import datetime, timezone
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))

from security_harness.llm import config
from security_harness.llm.gateway import Gateway, Limits, ModelError, Request
from security_harness.llm.transport import JsonHTTP
from security_harness.llm.benchmark_runner import deadline_policy
from security_harness.llm.lifecycle import REPORT_VERSION, archive_inputs, read_report, smoke_plan_digest, supervise
from security_harness.supervision import persist, run_directory
from security_harness.scope import call_seconds, load_model_roe, run_seconds

FIXTURE = Request(
    system="You are running a synthetic transport check. Follow the user's exact output instruction.",
    user="Reply with exactly EPSILON_SYNTHETIC_OK and no other text.", max_output_tokens=256)


# 設定與摘要位於函式庫；此處保留名稱供 CLI 與既有匯入使用。 / Configuration and digest live in the library;
# names are re-exported for the CLI and existing imports.
PLACEHOLDER_HOSTS = config.PLACEHOLDER_HOSTS
setting = config.setting
implementation_digest = config.implementation_digest


def configured_adapter(provider, roe_sha256, work=None, http=None):
    return config.configured_adapter(provider, roe_sha256, work, http)


def initial_report(providers, run_id, roe_raw=None):
    """roe_raw 是計畫綁定並封存的模型 RoE 位元組。 / roe_raw is the model RoE bytes the plan binds and archives."""
    roe_raw = (ROOT / 'security/model-roe.json').read_bytes() if roe_raw is None else roe_raw
    policy = deadline_policy(roe_raw)
    limits = Limits(max_calls=len(providers), reserved_output_tokens=256 * len(providers),
                    timeout_seconds=max(call_seconds(policy, p) for p in providers))
    return {"schema_version": REPORT_VERSION, "operation": "model-smoke", "run_id": run_id, "advisory_only": True,
            "data_class": "synthetic", "fixture": "fixed-ack-v1", "providers": providers,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "implementation_sha256": config.implementation_digest(), "status": "INCOMPLETE", "code": None,
            "limits": asdict(limits), "total_timeout_seconds": run_seconds(policy, providers),
            "deadline_policy": policy,
            "max_output_tokens_per_call": FIXTURE.max_output_tokens,
            "checks": [{"provider": p, "live": p != "mock", "status": "NOT_RUN", "code": None} for p in providers],
            "calls": [], "reserved_calls": 0, "reserved_output_tokens": 0,
            "model_roe_sha256": hashlib.sha256(roe_raw).hexdigest(),
            "cleanup": {"completed": False}}


async def run_worker(root, run_id, plan_digest):
    output = root / 'artifacts' / run_id / 'report.json'
    report = read_report(root, run_id)
    # 磁碟上的報告與 supervisor 的計畫不同時，一次呼叫都不發，也不寫報告。 / Make no call and write nothing when the
    # report on disk differs from the supervisor's plan.
    if smoke_plan_digest(report) != plan_digest:
        return 2
    # 計畫後被改的模型程式不可發出任何呼叫。 / Model code changed after planning makes no call.
    try:
        changed = config.implementation_digest() != report['implementation_sha256']
    except OSError:
        changed = True  # 無法讀取實作即視為已變更。 / An unreadable implementation counts as changed.
    # 限額只取自計畫，不另行重算。 / The limits come from the plan only and are never recomputed.
    gateway = Gateway(Limits(**report['limits']))
    report['calls'] = gateway.evidence
    task = asyncio.current_task()
    loop = asyncio.get_running_loop()
    def checkpoint():
        report.update(reserved_calls=gateway.calls, reserved_output_tokens=gateway.reserved_tokens)
        persist(output, report)
    gateway.checkpoint = checkpoint
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, task.cancel)
    try:
        for check in report['checks']:
            provider = check['provider']
            if changed:
                check.update(status='ERROR', code='CONFIGURATION')
                persist(output, report)
                continue
            check['status'] = 'RUNNING'
            persist(output, report)
            try:
                seconds = call_seconds(report['deadline_policy'], provider)
                adapter = config.configured_adapter(provider, report['model_roe_sha256'], run_directory(root, run_id),
                                                    None if provider == 'mock' else JsonHTTP(timeout_seconds=seconds))
            except (KeyError, ModelError):
                check.update(status='ERROR', code='CONFIGURATION')
                persist(output, report)
                continue
            reply = await gateway.generate(adapter, FIXTURE, seconds)
            if reply is not None and reply.text.strip() == "EPSILON_SYNTHETIC_OK":
                check["status"] = "SUCCESS"
            else:
                check['status'] = 'ERROR'
                check["code"] = gateway.evidence[-1]["code"] or "FIXTURE_MISMATCH"
            persist(output, report)
        if all(c["status"] == "SUCCESS" for c in report["checks"]):
            report["pending_status"] = "COMPLETE"
    except asyncio.CancelledError:
        report["code"] = "CANCELLED"
    finally:
        report["reserved_calls"] = gateway.calls
        report["reserved_output_tokens"] = gateway.reserved_tokens
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(sig)
        report['status'] = 'AWAITING_CLEANUP'
        report.setdefault('pending_status', 'INCOMPLETE')
        persist(output, report)
    return 0 if report['pending_status'] == 'COMPLETE' else 1


def require_model_roe(parser, providers, planned_calls):
    try:
        load_model_roe(ROOT, providers, planned_calls)
    except (OSError, ValueError):
        parser.error("live model calls are outside the approved model RoE (security/model-roe.json)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", choices=("mock", "gemini", "bedrock", "glm", "deepseek", "lmstudio"), action="append",
                        help='可重複指定；真實供應商需 --live / repeatable; live providers need --live')
    parser.add_argument("--live", action="store_true", help="允許選定供應商執行固定合成測試 / permit selected live providers for the fixed synthetic fixture")
    parser.add_argument("--output", type=Path,
                        help='另存報告的路徑 / extra copy of the report')
    args = parser.parse_args()
    providers = args.provider or ["mock"]
    if len(providers) != len(set(providers)):
        parser.error("duplicate providers are not allowed")
    if any(p != "mock" for p in providers) and not args.live:
        parser.error("live providers require --live")
    if args.live:
        require_model_roe(parser, providers, sum(p != "mock" for p in providers))
    run_id = str(uuid.uuid4())
    canonical = ROOT / 'artifacts' / run_id / 'report.json'
    output = args.output or canonical
    if output.exists():
        parser.error("output already exists; choose a new evidence path")
    roe_raw = (ROOT / 'security/model-roe.json').read_bytes()
    report = initial_report(providers, run_id, roe_raw)
    report['canonical_report'] = str(canonical)
    persist(canonical, report)
    archive_inputs(canonical.parent, {'model-roe.json': roe_raw})
    if output != canonical:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open('x') as handle:
            json.dump(report, handle)
    data = supervise(ROOT, report, [sys.executable, '-I', str(ROOT / 'scripts/model_worker.py'),
                                  str(ROOT), run_id, 'smoke', smoke_plan_digest(report)],
                     report['total_timeout_seconds'])
    if output != canonical:
        persist(output, data)
    print(json.dumps({'status': data['status'], 'checks': data['checks'], 'evidence': str(canonical)}))
    return 0 if data['status'] == 'COMPLETE' else 1


if __name__ == "__main__":
    raise SystemExit(main())
