"""變更守門檢查（guard）證據格式：guard 寫入、CI 自我檢查與發布程式讀取都用這一份定義。

The guard evidence format, shared by the guard that writes audit/trusted-guard.json, the CI self-check and the
publisher that reads it, so a renamed field or schema bump fails where it is made rather than after deployment."""
from .github_http import need

SCHEMA_VERSION = 2
POLICY = "trusted base remains authoritative for this run"
FIELDS = frozenset({"schema_version", "base_sha", "candidate_sha", "protected_changes", "decision",
                    "baseline_approval", "approval_error", "approval_refusal", "policy"})
APPROVAL_FIELDS = frozenset({"review_id", "reviewer", "commit_id"})


def build(base_sha, candidate_sha, protected_changes, approval, approval_error, approval_refusal):
    """有錯誤，或有受保護變更卻沒有核准時判定 BLOCK。 / BLOCK on an error, or on protected changes without an
    approval."""
    blocked = approval_error is not None or (bool(protected_changes) and approval is None)
    return {"schema_version": SCHEMA_VERSION, "base_sha": base_sha, "candidate_sha": candidate_sha,
            "protected_changes": list(protected_changes), "decision": "BLOCK" if blocked else "ALLOW",
            "baseline_approval": approval, "approval_error": approval_error,
            # 沒有核准時的固定診斷碼，例如 INDEPENDENT_APPROVAL_MISSING。 / The fixed diagnostic code when no
            # approval counts, such as INDEPENDENT_APPROVAL_MISSING.
            "approval_refusal": approval_refusal, "policy": POLICY}


def validate(guard, base_sha, candidate_sha):
    """只接受綁定此 base／head 的 ALLOW 證據；格式不符一律以 TRUSTED_GUARD 拒絕。 / Accept only ALLOW evidence bound
    to this base and head; any other shape is refused as TRUSTED_GUARD."""
    need(isinstance(guard, dict) and set(guard) == FIELDS, "TRUSTED_GUARD")
    need(type(guard["schema_version"]) is int and guard["schema_version"] == SCHEMA_VERSION
         and guard["policy"] == POLICY and guard["decision"] == "ALLOW"
         and guard["base_sha"] == base_sha and guard["candidate_sha"] == candidate_sha
         and guard["approval_error"] is None
         and (guard["approval_refusal"] is None or isinstance(guard["approval_refusal"], str)), "TRUSTED_GUARD")
    changes = guard["protected_changes"]
    need(isinstance(changes, list) and all(isinstance(c, str) and c for c in changes), "TRUSTED_GUARD")
    approval = guard["baseline_approval"]
    if approval is None:
        # ALLOW 卻沒有核准，只可能是沒有受保護變更。 / ALLOW without an approval means no protected change.
        need(not changes, "TRUSTED_GUARD")
        return guard
    need(isinstance(approval, dict) and set(approval) == APPROVAL_FIELDS
         and type(approval["review_id"]) is int and approval["review_id"] > 0
         and isinstance(approval["reviewer"], str) and approval["reviewer"]
         and approval["commit_id"] == candidate_sha, "TRUSTED_GUARD")
    return guard

