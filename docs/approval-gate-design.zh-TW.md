[正體中文](#zh-tw) | [English](#en)

<a id="zh-tw"></a>

# 核准閘門設計：免除核准後的整輪重跑

**狀態：設計提案，尚未實作。** 本文件回應第五次架構審視 A1，比較三種做法並提出建議；任何會改動可信 workflow、發布程式或信任邊界的方案，都須另經獨立安全審查與使用者核准才會實作。

## 現況與成本

- 受保護變更守門檢查（guard，`scripts/check_trusted_changes.py`）是評估 job 的第 6 步，位於任何候選處理之前；沒有符合規則的核准就以 exit 1 結束，整個 run 失敗。
- `protected_changes()` 回傳全部變更路徑，所以每個 PR 都需要獨立核准。
- 送出審查不會觸發 `pull_request_target`；審查者核准後，必須等第一次 run 結束，再整輪重跑。
- 2026-11-10～13 的 PR #84–#88 每個都經歷同一循環：第一次 run 被 `INDEPENDENT_APPROVAL_MISSING` 擋下 → 核准 → 重跑約 8 分鐘（評估約 5 分鐘、突變 job 約 6–7 分鐘並行）→ verify ALLOW → 合併。
- 不能只重跑失敗的 job：發布程式以 run 的最新 attempt 取 jobs、artifact（`trusted-security-<run_id>-<attempt>`）與 attestation，且要求 guard 證據為 ALLOW（`guard_evidence.validate`）。

## 不可破壞的不變量

1. 核准綁定精確 head、獨立審查者、規則集要求的最後推送核准（`github_trust.review_decision`）。
2. 規則集以同一 head 上同名必要檢查的**最新一筆**判定（2026-11-11 實測，見[可信執行](trusted-execution.zh-TW.md)）。
3. `pull_request_review` 等事件執行候選版本的 YAML，不能用來觸發可信 workflow。
4. 發布程式的證據、jobs 與 attestation 須屬於同一個 run attempt。
5. **現行 guard 在處理候選之前就擋下**：未核准的 PR 不會進入受限 runtime 的候選評估。這是現行設計提供的保護，改動前須明確決定是否放棄。

## 方案比較

| | A. 獨立 approval-gate job | B. 維持現狀、優化流程 | C. 專用發布 App |
|---|---|---|---|
| 核准後成本 | 只重跑 gate 與最終 job（數秒） | 仍整輪重跑（約 8 分鐘） | 不需 CI 重跑，App 收到審查事件即重新發布 |
| 信任邊界 | **改變**：未核准的候選也會先被評估 | 不變 | 不變（App 不執行候選）；guard 改為只記錄差異 |
| 需改動 | workflow、`workflow_contract`（第 5 個 job）、發布程式改以評估 job 的 attempt 取證據與 attestation、guard 證據分成差異紀錄與核准紀錄、verifier 的 attempt 規則 | 無程式變更 | 建立並安裝 App、部署主機、規則集改綁 `epsilon/trusted-merge`、guard 證據格式調整 |
| 風險 | 中：信任邊界變更、attempt 綁定改寫 | 低 | 中：外部資源與部署作業 |

### A. 獨立 approval-gate job

guard 步驟只記錄差異與 SHA；新增 `approval-gate` job（`needs: evaluation`、唯讀權杖、不 checkout 候選）呼叫 `GitHubTrust.baseline_approval`；最終 job 也 `needs` 它。核准後以「Re-run failed jobs」只重跑 gate 與最終 job。

代價是未核准的候選也會先在受限 runtime 中被評估。若採用，建議至少：approval-gate 之前只跑靜態檢查與文件檢查，把容器評估延到核准之後的 job；並重新檢查評估 job 的權杖與 artifact 在未核准時不得被發布程式採信。

### B. 維持現狀、優化流程

不改程式，只調整操作順序：作者先以 draft 推送，待審查者核准後再轉為可審查（`ready_for_review` 會觸發 `pull_request_target`），讓第一次正式 run 就帶著核准。仍需一次完整 run，但省去「先失敗一次」。前提是 GitHub 允許在草稿上送出核准（待實測，見下方未知點 4）；核准必須晚於 head 推送，草稿期間任何新推送都會使核准失效。若無法在草稿上核准，B 退回現行做法：核准後由作者立即重跑。

### C. 專用發布 App

發布程式已實作並在發布前即時重查審查（`publish` 重讀 `review_ids`）。部署後，App 可在收到審查事件時重新驗證最近一次成功的評估並發布 `epsilon/trusted-merge`，不需重跑 CI；搭配把 guard 改為只記錄差異（核准由 App 即時判定），否則 guard 證據的 `TRUSTED_GUARD` 仍會擋下。

## 建議

- **短期採 B**：零程式風險，立即可用，只需調整作者與審查者的操作順序。
- **中期採 C**：從根本免除重跑，且不讓未核准的候選先被執行；部署指南見[發布器部署文件](trusted-check-publisher.zh-TW.md)。
- **A 只在明確接受「未核准候選先行評估」時採用**，並落實上述額外防護。

## 需實測的未知點

以下行為未經本專案實測，實作 A 或 C 前須先驗證，不可臆測：

1. 「Re-run failed jobs」後，`actions/runs/<id>/attempts/<n>/jobs` 是否列出沿用的成功 job，及其 `run_attempt` 欄位。
2. 沿用 job 的 artifact 與 attestation subject 名稱是否保留舊 attempt 編號。
3. 規則集對沿用或略過（skipped）job 所產生必要檢查的判定。
4. 能否在草稿 PR 上送出核准；草稿轉為可審查時，`pull_request_target` 的 head 與核准時間的先後是否符合最後推送核准規則。

## 若採用 A 的實作與驗收清單

- 程式：`.github/workflows/security.yml`、`security_harness/workflow_contract.py`、`security_harness/guard_evidence.py`、`security_harness/trusted_publisher.py`（attempt 綁定）、`scripts/check_trusted_changes.py`、`scripts/verify_required_check.py`。
- 測試：合約測試逐 job 檢查新 job；發布程式在「評估 attempt 1、gate attempt 2」組合下接受，在證據與 gate 不同 run 時拒絕；不刪除或改名任何既有測試。
- 突變：新判斷函式納入突變目標，0 存活。
- 驗收：本機完整回歸含 base 對候選的文件檢查；在測試 PR 上實測「Re-run failed jobs」與規則集行為後才可合併。

<a id="en"></a>

# Approval gate design: avoiding a full rerun after approval

**Status: design proposal, not implemented.** This document answers finding A1 of the fifth architecture review, compares three approaches and recommends one. Any approach that changes the trusted workflow, the publisher or the trust boundary needs its own independent security review and the user's approval before it is implemented.

## Current state and cost

- The protected-change guard (`scripts/check_trusted_changes.py`) is step 6 of the evaluation job, before any candidate processing; without a qualifying approval it exits 1 and the whole run fails.
- `protected_changes()` returns every changed path, so every PR needs an independent approval.
- Submitting a review does not trigger `pull_request_target`; after approval the first run must finish and the whole run must be rerun.
- PRs #84–#88 (November 10–13, 2026) each went through the same loop: the first run blocked with `INDEPENDENT_APPROVAL_MISSING` → approval → a rerun of about 8 minutes (evaluation about 5 minutes, the mutation job about 6–7 minutes in parallel) → verify ALLOW → merge.
- Rerunning only the failed jobs does not work today: the publisher takes jobs, the artifact (`trusted-security-<run_id>-<attempt>`) and the attestation from the run's latest attempt, and requires ALLOW guard evidence (`guard_evidence.validate`).

## Invariants that must hold

1. An approval is bound to the exact head, an independent reviewer and the ruleset's last-push approval (`github_trust.review_decision`).
2. The ruleset judges the **latest** same-name required check on the head (observed November 11, 2026; see [trusted execution](trusted-execution.zh-TW.md#en)).
3. Events such as `pull_request_review` run the candidate's YAML and cannot trigger the trusted workflow.
4. The publisher's evidence, jobs and attestation must belong to one run attempt.
5. **The current guard stops before any candidate processing**: an unapproved PR never reaches candidate evaluation in the restricted runtime. This is a protection the current design provides; giving it up must be an explicit decision.

## Options

| | A. Separate approval-gate job | B. Keep the design, improve the process | C. Dedicated publisher App |
|---|---|---|---|
| Cost after approval | Rerun only the gate and final job (seconds) | Still a full rerun (about 8 minutes) | No CI rerun; the App republishes on the review event |
| Trust boundary | **Changes**: unapproved candidates are evaluated first | Unchanged | Unchanged (the App never runs candidates); the guard only records the diff |
| Changes needed | Workflow, `workflow_contract` (a fifth job), the publisher taking evidence and attestation from the evaluation job's attempt, guard evidence split into a diff record and an approval record, the verifier's attempt rule | No code change | Create and install the App, deploy the host, rebind the ruleset to `epsilon/trusted-merge`, adjust the guard evidence format |
| Risk | Medium: trust-boundary change, attempt binding rewritten | Low | Medium: external resources and deployment work |

### A. Separate approval-gate job

The guard step only records the diff and SHAs; a new `approval-gate` job (`needs: evaluation`, read-only token, no candidate checkout) calls `GitHubTrust.baseline_approval`, and the final job also needs it. After approval, "Re-run failed jobs" reruns only the gate and the final job.

The cost is that unapproved candidates are evaluated in the restricted runtime first. If adopted, at minimum run only static and documentation checks before the approval gate, move container evaluation into a job after approval, and recheck that the evaluation job's token and artifact cannot be accepted by the publisher while unapproved.

### B. Keep the design, improve the process

No code change; only the order of operations changes. The author pushes as a draft and marks it ready for review after the reviewer approves (`ready_for_review` triggers `pull_request_target`), so the first real run already carries the approval. One full run is still needed, but the guaranteed first failure goes away. This assumes GitHub accepts an approval on a draft (to be tested, see unknown 4 below); the approval must come after the head push, so any new push while drafting voids it. If a draft cannot be approved, B falls back to today's practice: the author reruns right after approval.

### C. Dedicated publisher App

The publisher is implemented and rechecks reviews live before publishing (`publish` rereads `review_ids`). Once deployed, the App can revalidate the latest successful evaluation on a review event and publish `epsilon/trusted-merge` without a CI rerun. This requires changing the guard to record only the diff (the App decides approval live); otherwise the guard evidence still blocks with `TRUSTED_GUARD`.

## Recommendation

- **Short term, B**: no code risk, usable now, only the author's and reviewer's order of operations changes.
- **Medium term, C**: removes the rerun at its root without evaluating unapproved candidates; see the [publisher deployment guide](trusted-check-publisher.zh-TW.md#en).
- **Adopt A only after explicitly accepting that unapproved candidates are evaluated first**, with the extra safeguards above.

## Unknowns to test

This project has not observed the following; verify them before implementing A or C rather than assuming:

1. After "Re-run failed jobs", whether `actions/runs/<id>/attempts/<n>/jobs` lists the reused successful jobs, and their `run_attempt` field.
2. Whether a reused job's artifact and attestation subject name keep the old attempt number.
3. How the ruleset judges the required check produced by reused or skipped jobs.
4. Whether an approval can be submitted on a draft PR, and when a draft is marked ready for review, whether the order of the `pull_request_target` head and the approval time satisfies the last-push approval rule.

## Implementation and acceptance checklist if A is adopted

- Code: `.github/workflows/security.yml`, `security_harness/workflow_contract.py`, `security_harness/guard_evidence.py`, `security_harness/trusted_publisher.py` (attempt binding), `scripts/check_trusted_changes.py`, `scripts/verify_required_check.py`.
- Tests: the contract test checks the new job block by block; the publisher accepts "evaluation attempt 1, gate attempt 2" and refuses evidence and a gate from different runs; no existing test is deleted or renamed.
- Mutation: new decision functions become mutation targets with zero survivors.
- Acceptance: full local regression including the base-versus-candidate documentation check; observe "Re-run failed jobs" and the ruleset behaviour on a test PR before merging.
