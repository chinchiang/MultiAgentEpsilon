"""避免模型 CLI 測試留下參考性報告，混入 evaluator 上傳的 artifacts。

Keep model CLI tests from leaving advisory reports in the evaluator's uploaded artifacts/."""
import contextlib
import json
import re
import shutil
from pathlib import Path

RUN_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")


@contextlib.contextmanager
def remove_new_model_evidence(root: Path):
    artifacts = root / "artifacts"
    before = {p.name for p in artifacts.iterdir()} if artifacts.is_dir() else set()
    try:
        yield
    finally:
        for path in (artifacts.iterdir() if artifacts.is_dir() else ()):
            if path.name in before or not RUN_ID.fullmatch(path.name) or path.is_symlink() or not path.is_dir():
                continue
            try:
                report = json.loads((path / "report.json").read_text())
            except (OSError, ValueError):
                continue
            providers = report.get("providers")
            # 不可刪除閘門證據或同時執行中的真實模型證據。 / Never gate evidence, and never a concurrent live run's advisory evidence.
            if (report.get("operation") == "model-smoke" and isinstance(providers, list) and providers
                    and all(isinstance(p, str) and p.startswith("mock") for p in providers)):
                shutil.rmtree(path)


def provider_answer(report, check):
    """模擬供應商恰好回傳 check 的 review；審查綁定原始文字與該次摘要，替換答案時三者須同步更新。

Make `check` look as if its provider had returned exactly check['review'].

    Reviews are bound to the raw provider text and that call's response digest, so
    a test simulating another model answer must change all three together.
    """
    from security_harness.llm.gateway import digest
    text = json.dumps(check["review"])
    check["response_text"] = text
    check["review_sha256"] = digest(json.dumps(check["review"], sort_keys=True))
    call = next(c for c in report["calls"] if c["call_id"] == check["call_id"])
    call["response_sha256"] = digest(text)
