"""信任範圍：受保護的儲存庫、base 分支、可信 workflow 路徑與必要檢查名稱，guard、verifier 與發布程式共用。

The trust scope (the protected repository, its base branch, the trusted workflow path and the required check),
shared by the guard, the required-check verifier and the publisher instead of three copies."""
import json
import re
from pathlib import Path
from typing import NamedTuple

from .workflow_contract import BASE_BRANCH, REQUIRED_CHECK, WORKFLOW_PATH

REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


class TrustScope(NamedTuple):
    repository: str
    base_branch: str
    workflow_path: str
    required_check: str


def load(root):
    """儲存庫取自可信基準的 trust-policy.json，其餘取自 workflow 契約。 / The repository comes from the trusted
    baseline's trust-policy.json; the rest comes from the workflow contract."""
    repository = json.loads((Path(root) / "security/trust-policy.json").read_text())["repository"]
    if not isinstance(repository, str) or not REPOSITORY.fullmatch(repository):
        raise ValueError("invalid trusted repository")
    return TrustScope(repository, BASE_BRANCH, WORKFLOW_PATH, REQUIRED_CHECK)
