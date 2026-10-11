"""性質測試快取留在既有生成目錄，避免污染來源摘要。

Keep property-test caches in the existing generated area, outside source digests."""
import os
import sys
from pathlib import Path

import pytest
from hypothesis.configuration import set_hypothesis_home_dir

if sys.version_info[:2] != (3, 12):
    # lock 只為 Python 3.12 鎖定；其他版本的結果不能代表可信基準。 / The lock is pinned for Python 3.12 only;
    # results on another interpreter do not represent the trusted baseline.
    pytest.exit("use the repository .venv (Python 3.12) / 請使用儲存庫 .venv（Python 3.12）", returncode=4)

set_hypothesis_home_dir(Path(__file__).resolve().parents[1] / '.state/hypothesis')


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


# 發布器證據 fixture 由多個測試檔共用。 / The publisher evidence fixture is shared by several test modules.
from tests.test_trusted_publisher import bundle  # noqa: E402,F401
