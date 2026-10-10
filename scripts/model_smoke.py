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
from security_harness.llm.lifecycle import persist, read_report, supervise
from security_harness.lifecycle import run_directory
from security_harness.scope import load_model_roe

FIXTURE = Request(
    system="You are running a synthetic transport check. Follow the user's exact output instruction.",
    user="Reply with exactly EPSILON_SYNTHETIC_OK and no other text.", max_output_tokens=256)


# 設定與摘要位於函式庫；此處保留名稱供 CLI 與既有匯入使用。 / Configuration and digest live in the library;
# names are re-exported for the CLI and existing imports.
PLACEHOLDER_HOSTS = config.PLACEHOLDER_HOSTS
setting = config.setting
implementation_digest = config.implementation_digest


def configured_adapter(provider, work=None, http=None):
    return config.configured_adapter(provider, work, http)


def initial_report(providers, run_id):
    limits = Limits(max_calls=len(providers), reserved_output_tokens=256 * len(providers))
    return {"schema_version": 2, "operation": "model-smoke", "run_id": run_id, "advisory_only": True,
            "data_class": "synthetic", "fixture": "fixed-ack-v1", "providers": providers,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "implementation_sha256": implementation_digest(), "status": "INCOMPLETE", "code": None,
            "limits": asdict(limits), "total_timeout_seconds": min(130, 30 * len(providers) + 10),
            "max_output_tokens_per_call": FIXTURE.max_output_tokens,
            "checks": [{"provider": p, "live": p != "mock", "status": "NOT_RUN", "code": None} for p in providers],
            "calls": [], "reserved_calls": 0, "reserved_output_tokens": 0,
            "model_roe_sha256": hashlib.sha256((ROOT / 'security/model-roe.json').read_bytes()).hexdigest(),
            "cleanup": {"completed": False}}


async def run_worker(root, run_id):
    output = root / 'artifacts' / run_id / 'report.json'
    report = read_report(root, run_id)
    providers = report['providers']
    gateway = Gateway(Limits(max_calls=len(providers), reserved_output_tokens=256 * len(providers)))
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
            check['status'] = 'RUNNING'
            persist(output, report)
            try:
                adapter = config.configured_adapter(provider, run_directory(root, run_id))
            except (KeyError, ModelError):
                check.update(status='ERROR', code='CONFIGURATION')
                persist(output, report)
                continue
            reply = await gateway.generate(adapter, FIXTURE)
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
    parser.add_argument("--provider", choices=("mock", "gemini", "bedrock", "glm", "lmstudio"), action="append")
    parser.add_argument("--live", action="store_true", help="允許選定供應商執行固定合成測試 / permit selected live providers for the fixed synthetic fixture")
    parser.add_argument("--output", type=Path)
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
    report = initial_report(providers, run_id)
    report['canonical_report'] = str(canonical)
    persist(canonical, report)
    if output != canonical:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open('x') as handle:
            json.dump(report, handle)
    data = supervise(ROOT, report, [sys.executable, '-I', str(ROOT / 'scripts/model_worker.py'),
                                  str(ROOT), run_id], report['total_timeout_seconds'])
    if output != canonical:
        persist(output, data)
    print(json.dumps({'status': data['status'], 'checks': data['checks'], 'evidence': str(canonical)}))
    return 0 if data['status'] == 'COMPLETE' else 1


if __name__ == "__main__":
    raise SystemExit(main())
