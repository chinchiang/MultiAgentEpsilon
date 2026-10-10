"""性質測試快取留在既有生成目錄，避免污染來源摘要。

Keep property-test caches in the existing generated area, outside source digests."""
import sys
from pathlib import Path

import pytest
from hypothesis.configuration import set_hypothesis_home_dir

if sys.version_info[:2] != (3, 12):
    # lock 只為 Python 3.12 鎖定；其他版本的結果不能代表可信基準。 / The lock is pinned for Python 3.12 only;
    # results on another interpreter do not represent the trusted baseline.
    pytest.exit("use the repository .venv (Python 3.12) / 請使用儲存庫 .venv（Python 3.12）", returncode=4)

set_hypothesis_home_dir(Path(__file__).resolve().parents[1] / '.state/hypothesis')


# 發布器證據 fixture 由多個測試檔共用。 / The publisher evidence fixture is shared by several test modules.
from tests.test_trusted_publisher import bundle  # noqa: E402,F401
