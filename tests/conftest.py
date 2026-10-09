"""性質測試快取留在既有生成目錄，避免污染來源摘要。

Keep property-test caches in the existing generated area, outside source digests."""
from pathlib import Path
from hypothesis.configuration import set_hypothesis_home_dir

set_hypothesis_home_dir(Path(__file__).resolve().parents[1] / '.state/hypothesis')
