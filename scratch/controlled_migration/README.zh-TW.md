[正體中文](#zh-tw) | [English](#en)

<a id="zh-tw"></a>

# 受控遷移工具（controlled migration tool）

限定 `chinchiang/MultiAgentEpsilon`、PR #64、規則集 `24512048`，head 與 base 為 Q1–Q7 設計中的完整 SHA。工具已接入正式 GitHub 介接器（adapter），但本次只有離線測試，沒有遠端規則寫入或 PR 合併，也沒有取得正式操作授權。

## 目前可安全重現的檢查

在儲存庫根目錄執行：

```bash
.venv/bin/python scratch/controlled_migration/migration.py
.venv/bin/python -m pytest scratch/controlled_migration -q
.venv/bin/ruff check --isolated --select F,E9 scratch/controlled_migration
```

第一個命令預設離線乾跑（dry run），不呼叫 GitHub，也不建立操作紀錄。測試使用具狀態的外部 GitHub 替身、時鐘、檔案系統與子程序入口；不需要權杖。`mutation-success.fixture.json` 是既有本機完整突變測試報告的副本，作為獨立的成功範例，沒有認證資料。

## 唯讀查核命令（本次未執行）

```bash
.venv/bin/python scratch/controlled_migration/migration.py --preflight
.venv/bin/python scratch/controlled_migration/migration.py --verify-outcome
```

沿用既有 GitHub CLI credential store，不搜尋、不讀取或匯出 token，不呼叫登入功能，也不接受任意主機。刻意移除 `GH_TOKEN`／`GITHUB_TOKEN` 等注入變數，避免意外換用其他身分；若原環境只有環境變數認證，將停止並要求另外處理。登入身分須為 `chinchiang` 且具管理權限。

前置查核（preflight）檢查 main、PR head/base、完整原始設定、繼承規則及傳統分支保護、單檔 lock blob、有效且獨立的核准、最新工作流程及 run attempt。guard 證據必須來自指定工作流程；PR 歷史曾更換 base、最新 run 未完成、來源或分頁不完整，都會停止。CODEOWNERS 可核准身分固定為既有基準中的 CatGrocery、d98922036ntu，並排除 PR 作者、提交作者／提交者及 run actor。

唯讀驗收（verify outcome）先確認保護設定已完整恢復，再查合併內容、該 merge SHA 的正式 main push 工作、完整 206 個突變、七個基準、清理結果，以及 artifact 密碼學簽章（cryptographic signature）。`gh attestation verify` 查核 signer workflow、憑證身分、GitHub OIDC issuer 與 GitHub-hosted runner；再將已驗證 statement 綁定 artifact SHA-256、來源 URI／提交與精確 run attempt。缺證據時不能驗收成功。唯讀查核也會將原始 API 回應與驗證結果保存到 `scratch/controlled-migration-state/readonly-*/`。

## 正式執行前的人工準備

`authorization.template.json` 刻意維持 `authorized=false`、`expires_at=0`。它綁定完整範圍、審閱過的設定及四個執行模組的 SHA-256。工具不會自行將它改成已授權。

擁有者必須另外明確核准例外操作，重新查核上游安全公告，確認維護凍結、備援人員與獨立恢復連線；之後由操作人員將核准依據記入新的授權檔，設定十分鐘內的 Unix 到期時間及備援人員。授權檔須為目前使用者擁有的 regular file，權限 `0600`，不可是符號連結。範本不能直接通過；工具或設定變更後，舊授權也不能通過。不得把 Q1–Q7 的設計同意當成例外授權。

以下是**另行核准後**的命令格式，本次未執行：

```bash
.venv/bin/python scratch/controlled_migration/migration.py \
  --execute --authorization scratch/controlled_migration/authorization.approved.json
```

原始 API 回應、授權、計畫、恢復快照、操作意圖、讀回結果及最後報告會落在 `scratch/controlled-migration-state/<UTC>-<id>/`。每次寫入前先 `fsync` 操作意圖；停用前先將恢復快照落盤。`active.json` 記錄尚未結案的操作；有此檔案時拒絕新的前置查核／合併，避免覆蓋現場。程序互斥鎖（process lock）防止本工具同時啟動兩個操作。

## 恢復與備援交接

停用或合併請求逾時皆先恢復，最多送一次合併。停用後第 60 秒起停止新的合併嘗試；120 秒是恢復目標，不是保證。恢復失敗每隔兩秒重送同一原始設定並向 stderr 告警，超過 120 秒標為 `RECOVERY_INCIDENT`，不繼續合併。磁碟紀錄失效會阻擋新的停用／合併，但不阻擋必要恢復與讀回。

`SIGTERM` 轉為取消，由協調器進入恢復。恢復途中再次收到中斷則交接備援，保留 `active.json`，回報 `RECOVERY_REQUIRED`；不得宣稱已恢復。工具無法在 `SIGKILL`、整台主機斷線或 API 長期不可用時保證恢復。維護凍結與獨立備援仍為必要條件。

程序重啟後，只使用原核准檔與原操作紀錄恢復，不重送合併；原授權到期也不妨礙同範圍的必要恢復：

```bash
.venv/bin/python scratch/controlled_migration/migration.py \
  --execute --recover \
  --authorization scratch/controlled_migration/authorization.approved.json
```

此命令只能處理 `active.json` 指向的操作，不能指定任意規則或其他 PR。若能確認未曾記錄停用意圖，只讀回設定；紀錄不完整則保守視為可能已停用。恢復後完整讀回一致，才清除 active 標記。執行版本改變、紀錄損壞或原核准檔遺失時會停止，需備援管理者依保留的 `recovery.json` 審核恢復；不要刪除現場紀錄以繞過保護。

## 狀態與退出碼

| 結果 | 意義 |
| --- | --- |
| `DRY_RUN`／`READ_ONLY`，退出碼 0 | 乾跑或唯讀前置查核完成，沒有遠端寫入。 |
| `ACCEPTED`，退出碼 0 | 保護恢復、合併內容正確、正式 CI／完整突變／簽章全部成功。 |
| `RESTORED`，退出碼 0 | 恢復模式確認設定一致；不表示遷移已驗收。 |
| `PENDING_ACCEPTANCE`／`ACCEPTANCE_FAILED`，退出碼 3（保護已恢復） | 尚待證據或驗收失敗；保護保持啟用，不自動 revert。 |
| 退出碼 2 | 未授權、前置查核阻擋、程序鎖定、錯誤或需要恢復；查看輸出與 active 記錄。 |

正式 CI 完成後可重跑 `--verify-outcome`。不得用本機測試或 manual workflow 替代正式 push 證據，也不因驗收失敗再次停用規則或自動還原提交。

## 檔案與信任邊界

`migration.py` 負責協調，`github_adapter.py` 負責 GitHub 傳輸與來源驗證，`runtime.py` 負責持久化、鎖與訊號，`command.py` 負責模式、授權與重新啟動。只信任目前使用者控制的工作目錄與已安裝的 `gh`；本工具不防禦同帳號惡意修改程式或 credential store。GitHub merge API 只原子鎖定 head，無法原子鎖定 base，須靠維護凍結、即時查核與合併後 parents 驗證。

本目錄僅明確納入工具、測試、未授權範本與必要參考檔；執行紀錄與原始查核資料仍保留在忽略版控的 `scratch/`。工具另行提交至獨立分支，PR #64 仍只有 requirements.lock 修正。程式與離線測試已完成；真實環境的唯讀查核、備援演練與遠端執行仍未進行。GitHub 介接器不重新查詢 PyPI／OSV，正式操作前仍須另外確認上游安全公告與既有工程評估的有效性。

官方介面依據：[Rulesets REST API](https://docs.github.com/en/rest/repos/rules#update-a-repository-ruleset)、[GitHub CLI attestation verification](https://cli.github.com/manual/gh_attestation_verify)、[GitHub Actions provenance 格式](https://github.com/marketplace/actions/generate-build-provenance)。


<a id="en"></a>

# Controlled migration tool

This tool is restricted to PR #64, ruleset 24512048, and the exact repository/head/base recorded in `migration.py`. It defaults to an offline dry run. Implementation and offline tests are complete; no real ruleset write, PR merge, recovery timing measurement, or execution authorization is implied.

Run from the repository root:

```bash
.venv/bin/python scratch/controlled_migration/migration.py
.venv/bin/python -m pytest scratch/controlled_migration -q
.venv/bin/python scratch/controlled_migration/migration.py --preflight
```

Only the third command contacts GitHub, using the existing GitHub CLI credential store for read-only checks. It checks the exact PR/main state, independent review, guard workflow/attempt provenance, ruleset snapshot, absence of other protection, and expected lock blob. `--verify-outcome` requires restored protection and checks merge parents/content, formal main push CI, the full mutation campaign, and artifact signatures bound to the exact commit/run attempt.

Execution requires a separately approved private authorization file matching the plan and tool digests; `authorization.template.json` is intentionally unauthorized and expired. Confirm current upstream advisories, maintenance freeze, an independent recovery connection, and a backup operator first. The tool does not query PyPI or OSV itself.

Persistent snapshots and write intents are synced before mutation. A process lock and active-operation marker prevent a second coordinator. Only one exact-head merge request is permitted. Uncertain responses restore protection before outcome inspection; the 60-second merge cutoff and 120-second recovery target never justify abandoning recovery. Logging failures must not block restoration.

Restart recovery uses `--execute --recover --authorization <original-approved-file>`, only restores the active operation, and never retries a merge. Expired original authorization remains usable solely for necessary recovery. SIGTERM enters recovery; interruption during recovery requires backup handoff. SIGKILL, host loss, and prolonged API failure still require the independent recovery route. Exit code 0 denotes a successful dry run, read-only preflight, confirmed recovery, or fully accepted migration; 3 means restored but pending/failed acceptance; 2 indicates a blocker or required recovery. Raw responses and operation records remain local in ignored scratch directories. Only explicitly selected tool/test/reference files are versioned on the separate tools branch.
