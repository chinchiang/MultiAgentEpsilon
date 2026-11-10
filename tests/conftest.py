"""性質測試快取留在既有生成目錄，避免污染來源摘要。

Keep property-test caches in the existing generated area, outside source digests."""
import os
import signal
import sys
from pathlib import Path

import pytest
from hypothesis.configuration import set_hypothesis_home_dir

if sys.version_info[:2] != (3, 12):
    # lock 只為 Python 3.12 鎖定；其他版本的結果不能代表可信基準。 / The lock is pinned for Python 3.12 only;
    # results on another interpreter do not represent the trusted baseline.
    pytest.exit("use the repository .venv (Python 3.12) / 請使用儲存庫 .venv（Python 3.12）", returncode=4)

set_hypothesis_home_dir(Path(__file__).resolve().parents[1] / '.state/hypothesis')


# 每項測試的牆鐘上限；終止路徑若退化，失敗會指出卡住的測試，而不是等整個 CI job 逾時。 / Per-test wall-clock
# limit: if a termination path regresses, the failure names the stuck test instead of waiting for the CI job timeout.
TEST_TIMEOUT_SECONDS = 180


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    def expired(signum, frame):
        pytest.fail(f"test exceeded {TEST_TIMEOUT_SECONDS} s / 測試超過 {TEST_TIMEOUT_SECONDS} 秒: {item.nodeid}",
                    pytrace=False)
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, TEST_TIMEOUT_SECONDS)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def pytest_report_header(config):
    """顯示執行身分；root 會走與 CI 不同的權限分支。 / Show the running uid; root takes permission branches CI never takes."""
    uid = os.geteuid()
    lines = [f"uid: {uid}"]
    if uid == 0:
        # CI runner 為非 root；權限相關斷言須另以一般使用者驗證。 / CI runs as a non-root user; verify
        # permission-dependent assertions as an ordinary user too (see README).
        lines.append("WARNING running as root / 以 root 執行：CI 為非 root，推送前請以一般使用者重跑 / "
                     "CI is non-root; rerun as an ordinary user before pushing")
    return lines



@pytest.fixture(autouse=True)
def _offline_docker(request, monkeypatch):
    """非整合測試不得依賴 Docker daemon：孤兒容器清掃看到空清單，其他 docker 呼叫直接失敗。

Non-integration tests must not need a Docker daemon: the orphan-container sweep sees an empty list and any other
docker call fails loudly. Tests that fake docker themselves override this; integration tests use the real daemon."""
    if request.node.get_closest_marker("integration"):
        return
    import subprocess
    from security_harness import isolation

    def docker(*args, check=True, timeout=45):
        if args[:2] == ("ps", "-aq"):
            return subprocess.CompletedProcess(("docker", *args), 0, "", "")
        raise RuntimeError("non-integration test called docker / 非整合測試呼叫了 docker")
    monkeypatch.setattr(isolation, "docker", docker)


# 發布器證據 fixture 由多個測試檔共用。 / The publisher evidence fixture is shared by several test modules.
from tests.test_trusted_publisher import bundle  # noqa: E402,F401
