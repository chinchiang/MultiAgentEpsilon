"""記錄本次實際收集的測試；輸出仍是不可信補充資料。

Record actual collection; candidate-produced results remain untrusted supplemental data.
"""
import json
import hashlib
from pathlib import Path


def pytest_collection_modifyitems(items):
    raw = json.dumps([item.nodeid for item in items], ensure_ascii=False)
    contract = json.loads(Path('/opt/supplemental/runtime-contract.json').read_text())
    if hashlib.sha256(raw.encode()).hexdigest() != contract['collection_sha256']:
        raise ValueError('REVIEWED_TEST_COLLECTION_CHANGED')
    Path('/results/collection.json').write_text(raw, encoding='utf-8')
