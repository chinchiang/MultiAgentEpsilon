[正體中文](#zh-tw) | [English](#en)

<a id="zh-tw"></a>

# 第一個里程碑：實作狀態與驗收方式

本文件記錄**現況與可辨識的歷史驗收**（2026-10-14）。正式 main `d1f6d3a` 已合併 PR #27 至 #54（模型介接器與輸出預算、Bedrock 推理區塊、盲審綁定 supervisor 計畫摘要、發布程式的呼叫預算與權限查詢、guard 的最後推送核准檢查、隔離容器清掃、必要檢查來源核對，worker 驗證模型 RoE、文件檢查固定以 UTF-8 讀寫、合併保護稽核讀回合併方式與審查設定、必要檢查來源依 job 讀回 attempt、每個 live 介接器都依綁定的 RoE 授權、GitHub 讀取集中到 GitHub reader，以及 AWS CLI 子程序只收白名單內的 AWS 設定），合併後的 [CI 執行 38589352556](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/38589352556) 成功：1386 項測試，修正版 44 個案例／0 項缺陷為 ALLOW，指定缺陷版恰好 9 項缺陷為 BLOCK，突變測試、清理與真實簽章均通過，證據自我檢查為 PUBLISHABLE。前一基準 `e1989d2`（PR #27 至 #52，[CI 執行 38574147836](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/38574147836)，1383 項測試）、`9068e45`（PR #27 至 #48，[CI 執行 38495043615](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/38495043615)，1312 項測試）、`14e59ac`（PR #27 至 #44，[CI 執行 38407303792](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/38407303792)，1291 項測試）、`ded6624`（PR #27 至 #42，[CI 執行 38398930629](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/38398930629)，1290 項測試）、`e7d0c87`（PR #27 至 #36，[CI 執行 38350438520](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/38350438520)，1278 項測試）、`f9fa905`（PR #26，[CI 執行 38209419557](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/38209419557)，1195 項測試）、`9508a7c`（PR #21 至 #24，[CI 執行 38106362078](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/38106362078)，1150 項測試）、`28be2e0`（PR #20，930 項測試）與稽核當時的 1149 項本機證據保留於歷史。專用 GitHub App 部署與真實 LM Studio 驗收仍待完成。各批次的原始紀錄與當時數字保留於[里程碑歷史紀錄](milestone-history.zh-TW.md)。

## 遠端治理

- main 由規則集 24512048 保護：沒有 bypass、須經 PR 與 code owner 核准、推送新 commit 後舊核准失效、最後推送須另獲核准、未歸屬變更需額外核准，必要檢查為 GitHub Actions App 15368 的 `trusted-security-pilot`。最新狀態以 `python3 -I scripts/audit_merge_protection.py --pr <編號>` 讀回為準；該腳本也讀回允許的合併方式（`merge_commit_only`，多個規則集取交集）、討論串須解決（`review_thread_resolution_required`）與未歸屬變更額外核准（`unattributed_changes_extra_approval`）。2026-10-13 對 PR #45 讀回：後兩項為 true，規則集仍允許 merge、squash、rebase 三種合併方式，因此 `merge_commit_only` 為 false；squash 與 rebase 會改寫 commit，使已核准 head 與 main 上的 commit 不一致，政策上只應使用 merge commit。`docs/github-main-ruleset.json` 範本已限定為 `merge`，實際設定由擁有者調整，調整後再更新本段。
- 目前可信清單為 chinchiang、CatGrocery 與 d98922036ntu；CatGrocery 已接受協作邀請並具 write 權限（2026-10-07 讀回）。PR #14 已合併這項清單變更，三處設定一致；d98922036ntu 的 write 權限已於 2026-10-08 讀回確認。之後的 PR 原則上依規則合併，不停用規則集（唯一例外見下方 2026-10-11 的受控基準遷移）；涉及受保護路徑的 PR，guard 另需具寫入權限、非作者、未曾提交 PR 中任何 commit，且不是該次 run 的 actor／triggering actor 的基準審查者核准（審查者自己按重跑或「Ready for review」會使其核准不計入，應由作者操作、審查者只按 Approve）。作者為 chinchiang 的 PR 在這項變更合併後可由 CatGrocery 或 d98922036ntu 獨立核准。
- 首次基準遷移已於 2026-10-06 完成：擁有者暫時停用規則集，以 merge commit 合併 #6（`da567d8`）與 #7（`0ac31cb`）。文件 PR #10 也在規則集停用期間合併，沒有審查紀錄；之後規則集已恢復 active。
- 必要檢查仍可由其他 workflow 以同名產生。`pull_request_target` 執行的是 PR **base 分支**上的 workflow，run 中繼資料不記錄 base；因此審查者在核准或合併前執行 `python3 -I scripts/verify_required_check.py --pr <編號>`，它要求檢查來自 `pull_request_target`、run 的 head 分支與此 PR 相同，且同一 SHA／head repository／分支沒有其他 base 或曾改 base 的 PR（含已關閉者）；每個檢查的 attempt 由其 job 讀回，最新檢查須屬於 run 目前的 attempt。專用 App 的 `epsilon/trusted-merge` 尚未建立、部署或綁定。
- 第二次受控基準遷移（2026-10-11）：PR #21 合併後，main 上一項測試只接受 root 身分下的錯誤訊息，在非 root 的 runner 上必然失敗（[run 38095207581](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/38095207581)）。`pull_request_target` 以 base 上的測試判定，因此任何 PR（含修正 PR #22）都無法通過必要檢查。PR #22 已由 d98922036ntu 對 head `746c473` 獨立核准且 guard 放行，擁有者暫時解除規則集後合併為 `f1a640f`，隨即恢復；合併後 [CI 執行 38098147162](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/38098147162) 全部通過。
- 2026-10-11 合併保護稽核：擁有者以具 Administration 讀取權限的權杖執行 `audit_merge_protection.py --pr 22`，無讀取錯誤。規則集 active、bypass 名單為空、禁止刪除與強推、須獨立審查、必要檢查存在且為 strict、base CODEOWNERS 含獨立審查者；可用的獨立審查者與非管理者開發者為 CatGrocery、d98922036ntu。未通過的一項是必要檢查仍綁定共用 Actions App，未綁定專用 App（`source_binding` 為 NOT_VERIFIED）。六項行為探測（直接推送、未核准政策修改、同名假檢查、換版後舊核准、撤回核准、合法核准）仍為 NOT_RUN，需由非管理者開發者實測。
- 後續文件與工具 PR（2026-10-11）：PR #23 記錄基準遷移與稽核結果（`6b23491`），PR #24 讓 pytest 在 root 執行時顯示警告（CI 為非 root，推送前須以一般使用者重跑），並把「基準自身失效時的受控遷移」程序寫入 [trusted-execution](trusted-execution.zh-TW.md)；兩者皆依規則集合併，未停用規則，合併後 [run 38106362078](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/38106362078) 全部通過（1150 項測試）。
- 2026-10-11／10-12 的 PR：PR #25 把說明、文件與架構圖同步至 `9508a7c`（`3059642`）。PR #26 修正兩個假綠燈：ZIP／gzip 成員以外的位元組須對應已知結構，以及 AUTH oracle 須核對回應標頭，並新增第十種真實隔離缺陷變體。PR #26 由 d98922036ntu 對 head `80cb1f3` 獨立核准，作者重跑後 guard 放行，`verify_required_check.py` 為 ALLOW；之後依規則集以 merge commit 合併為 `f9fa905`，未停用規則，合併後的 run 38209419557 全部通過（1195 項測試）。
- 2026-10-12／10-13 的 PR：PR #27 把發布程式範本的測試下限提高到 1195；PR #28 至 #33 調整模型介接器（地端閘道、輸出預算、DeepSeek 停用、Bedrock 推理區塊）與文件；PR #34 讓盲審 worker 與 `finish()` 綁定 supervisor 的計畫摘要；PR #35 讓發布程式在呼叫預算耗盡時以 failure 取代舊綠燈；PR #36 讓 guard 讀回 main 的規則，未要求最後推送核准時以 `LAST_PUSH_APPROVAL` 阻擋。各 PR 均經 CatGrocery 或 d98922036ntu 獨立核准後以 merge commit 合併，未停用規則；PR #36 合併為 `e7d0c87`，合併後的 run 38350438520 全部通過（1278 項測試）。
- 2026-10-13 的 PR（續）：PR #37 把文件與發布程式範本同步至 `e7d0c87`（`64f613f`）；PR #38 讓 janitor 清掃 cleanup 之後才建立、超過 10 分鐘且不屬於存活執行的隔離容器（`e8612a5`）；PR #39 讓 `verify_required_check.py` 依建立順序取最新檢查，並阻擋 head 上同名的 commit status（`dc75d95`）；PR #40 讓 guard 讀取 head 分支的 Activity API，只採計 head 推送之後送出的核准，找不到推送紀錄時以 `LAST_PUSH_UNKNOWN` 阻擋（`3c6722b`）；PR #41 讓發布程式依登入帳號去重複查詢審查者權限（`508eb8b`）；PR #42 讓 worker 重新讀取的模型 RoE 也須完整驗證，且 RoE 雜湊須等於報告綁定值（`ded6624`）。PR #39 與 #40 起因於只合併 base 的 `update-branch` 推送：GitHub 不會讓舊核准失效，還會把它的 commit 改指新 head，使舊 guard 採計推送前的核准。PR #40 合併後，新 guard 第一次以 CI 權杖執行是在 PR #42（run 38390835409）：attempt 1 讀取 Activity API 無錯誤，並以 BLOCK 排除推送前的核准；重新核准後，attempt 2 只採計推送後的核准而放行。各 PR 均經 d98922036ntu 獨立核准後以 merge commit 合併，未停用規則；PR #42 合併後的 run 38398930629 全部通過（1290 項測試）。規則集要求分支須與 main 同步（strict），每次 `update-branch` 後都須重新核准。PR #43 把文件與發布程式範本同步至 `ded6624`，範本下限改為 1290（`fbab705`）；PR #44 讓 `check_docs.py` 的所有讀寫固定以 UTF-8 進行，不再由系統語系決定（例如 Windows 的 cp950 或非 UTF-8 的 Linux 語系），並新增把 `EncodingWarning` 視為錯誤來執行檢查程式的 CLI 測試（`14e59ac`）。兩者均經 d98922036ntu 獨立核准後以 merge commit 合併，未停用規則；PR #44 合併後的 run 38407303792 全部通過（1291 項測試）。PR #45 把文件與發布程式範本同步至 `14e59ac`，範本下限改為 1291（`abb5bf7`）；PR #46 讓 `audit_merge_protection.py` 讀回允許的合併方式（`merge_commit_only`）、討論串須解決與未歸屬變更額外核准三項設定（`c070615`）。兩者均經 d98922036ntu 獨立核准後以 merge commit 合併，未停用規則；PR #46 合併後的 run 38476170355 全部通過（1305 項測試）。PR #48 讓 `verify_required_check.py` 從每個檢查的 job 讀回 attempt：重跑後舊 attempt 的檢查不再被標成新 attempt，job 與檢查不符時為 `CHECK_ATTEMPT_UNRESOLVED`，最新檢查不屬於 run 目前的 attempt 時為 `LATEST_CHECK_STALE_ATTEMPT`（`9068e45`）。PR #48 同樣經 d98922036ntu 獨立核准後以 merge commit 合併，合併後的 run 38495043615 全部通過（1312 項測試）。PR #47 把文件與發布程式範本同步至 `9068e45`，範本下限改為 1312（`7cf22fa`）；PR #49 讓每個 live 介接器（含 Gemini、Bedrock 與 loopback 的 LM Studio）建立前都經同一個授權函式：只讀一次 RoE、雜湊須等於報告綁定值（smoke 與盲審 worker 皆同）、重新驗證該供應商，遠端主機也取自同一次讀取（`6557e21`，1321 項測試）；PR #51 把 GitHub 讀取集中到綁定單一儲存庫的 GitHub reader，每個列表都讀完所有頁並核對總數，`verify_required_check.py`、`audit_merge_protection.py` 與發布程式改用它，並新增雙語名詞表 `GLOSSARY.md`（`a5331b0`，1379 項測試）；PR #52 讓 guard 也改用 GitHub reader、不再需要 gh CLI，讀取被拒時 `approval_error` 記為 `Denied:<錯誤碼>`；repository activity 以 cursor 分頁且忽略 page，guard 只讀由新到舊的第一頁，head 推送不在第一頁即為 `LAST_PUSH_UNKNOWN`（`e1989d2`）。PR #52 合併前以同一組權杖與 run 比對新舊 guard 的輸出，核准前後四種情況均一致。四者均經 d98922036ntu 獨立核准後以 merge commit 合併，未停用規則；PR #52 合併後的 run 38574147836 全部通過（1383 項測試）。PR #53 把文件與發布程式範本同步至 `e1989d2`，範本下限改為 1383（`3208480`），這也是新版 guard 首次實際執行，核准前判 BLOCK、核准後判 ALLOW；PR #54 讓 AWS CLI 子程序只收白名單內的 7 個 AWS 設定（profile、設定檔與憑證檔路徑、臨時憑證三件組）及基本程序、代理與 CA 變數，再套上強制值，其他 `AWS_*` 一律丟掉，region 仍由 `--region` 指定；測試也涵蓋經過 `scripts/model_process.py` 再執行 CLI 的路徑（`d1f6d3a`）。兩者均經 d98922036ntu 獨立核准後以 merge commit 合併，未停用規則；PR #54 合併後的 run 38589352556 全部通過（1386 項測試）。

### 遷移後的真實流程驗收（2026-10-06）

| 情境 | run | 結果 |
|---|---|---|
| #7 改以 main 為 base（第一次真實 `pull_request_target`） | [37446641158](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37446641158) | workflow 取自 main、evaluator 為 base `da567d8`；guard 偵測 29 個受保護變更且無獨立核准而 BLOCK，未執行任何候選步驟；檢查掛在 PR head |
| main 合併後（push，`0ac31cb`） | [37446694680](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37446694680) | 532 項測試全過；修正版 18／0 ALLOW；缺陷版恰好 6 個 seeded findings；證據自我檢查 PUBLISHABLE |
| 驗證 PR #8：admin 寫入越過租戶邊界 | [37447163081](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37447163081) | guard 放行（只改 fixture）；evaluator 自我測試 532 項全過；候選恰好出現 `admin cross-tenant write denied without side effect` 一個 finding，BLOCK |
| 驗證 PR #9：政策移除 AUTH 閘門 | [37447183081](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37447183081) | guard 以 `security/policy.json` 受保護且未獲核准而 BLOCK |
| PR #10（只改 Markdown） | [37448552469](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37448552469) | 正向驗證：guard 放行，完整可信流程成功；合併時規則集仍停用，沒有審查紀錄 |

`verify_required_check.py` 也以真實 GitHub 資料核對過：PR #5 舊 head `9a47966` 上手動觸發、候選自評的綠燈判為 `UNTRUSTED_CHECK_SOURCE`；#7 head 上真正的 `pull_request_target` 檢查來源可信，但因結果失敗判為 `LATEST_CHECK_NOT_SUCCESS`。2026-10-07 另以真實 run 確認：#10 自己的 run 通過 base 綁定，#7 的 run 不能當成 #10 的來源（`RUN_HEAD_BRANCH`）。

## 2026-10-07 審查修正

深入審查後修正的項目（均附回歸測試）。驗收：commit `607b8c6` 的遠端手動 [run 37567019081](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37567019081)（`manual-security-evaluation`）共 610 項測試全過、0 失敗；修正版 18／0 ALLOW、缺陷版恰好 6 個 seeded findings BLOCK，兩者的 G2 `history_head` 都是候選自己的 commit；證據自我檢查 PUBLISHABLE（610 項）。之後的 commit 只改文件。

PR #12 已由 CatGrocery 對最新 head `58d9bc0` 獨立核准，正式 [run 37568335787／attempt 2](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37568335787/attempts/2) 執行舊 main 基準的 532 項測試全過，來源／digest／18 個正例及 6 個指定缺陷／清理均已核對。2026-10-07 在規則集維持 active、無 bypass 的情況下合併為 `41339c6`；合併後 main [run 37598381087](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37598381087) 執行新基準的 610 項測試全過，證據自我檢查 PUBLISHABLE。532 與 610 分別屬於舊基準與新基準，不能混用。

- **候選 git 設定不能在 host 執行程式：** 所有對候選儲存庫 的 git 呼叫改經 `security_harness/candidate_git.py`，停用 fsmonitor／hooks／transport、清除 `GIT_*` 環境變數，並以明確 `--git-dir` 限定候選自己的 `.git` 目錄。
- **G2 必須涵蓋候選自己的歷史：** 政策新增 `history_required`；沒有 `.git`、沒有 commit，或位於外層儲存庫 內的子目錄都不能 ALLOW。
- **壓縮檔中繼資料：** zip／gzip 的註解、檔名與 extra 欄位一併掃描；zip 中未列出的位元組、帶資料的目錄項目，以及 tar 結尾後的資料一律阻擋。
- **`expect_block.py`：** 要求整個 run 完成且無錯誤、清理完成；改為可測試的函式並新增回歸。
- **supervisor 與 janitor：** worker 未經清理交接就回報決策時一律 ERROR；janitor 回收舊 run 時不再改寫 `artifacts/latest.txt`。
- **必要檢查來源：** 發布程式與 `verify_required_check.py` 把 `pull_request_target` run 綁定到此 PR（見上方「遠端治理」），並修正「一定執行預設分支 workflow」的錯誤註解。
- **核准排除：** guard 與發布程式排除 PR 中**任一** commit 的作者／提交者；PR commit 清單達 GitHub 上限 250 筆時拒絕。
- **模型 RoE：** `max_calls_per_run` 實際與規劃的 live 呼叫數比較；worker 在送出任何呼叫前核對案例目錄雜湊；supervisor 停止原因列入固定錯誤分類；`.env.example` 的佔位值判為 `CONFIGURATION`；報告新增遮蔽 ARN／帳號的 `model_label`。
- **測試安全：** CLI 超額測試改以不含任何模型憑證的環境執行；測試清理只刪除全為 mock 供應商的證據。
- **其他：** workflow 的 concurrency 依事件分組，手動執行不會取消 main 的 push run；掃描與隔離複製以不跟隨 symlink 的方式讀檔；所有 Docker 呼叫固定同一 daemon；worker 資源限額只定義一次；移除未使用的 `scripts/auth_worker.py`；公開文件移除 AWS 帳號識別資訊。

## 2026-10-07 部署準備補強

- 發布成功檢查前再次讀取同一 head 範圍的 PR 與 timeline，核對 head 分支、repository 與 base 綁定；驗證途中新增同 head、不同 base 的 PR（包含已關閉者）也不能放行。
- live 設定使用逐層目錄 descriptor，拒絕可替換上層目錄與中途 symlink，保留 root 持有、唯讀的檔案要求。
- `scripts/prepare_publisher_deployment.py` 產生固定 SHA 的部署封存、評估器／政策摘要與 SHA256SUMS；工作樹須乾淨，既有輸出不可覆寫，封存實際清冊須與評估器相同。App 識別值未提供時保留缺值。
- 本輪新增 17 項回歸，完整基準下限為 627。部署資料產生、離線測試及手動 CI 均不能代替獨立審查、正式 App 部署或遠端繞過驗收。

## 仍待完成

**需擁有者決定或操作：**

1. **決定是否清除 git 歷史中的 AWS 帳號識別資訊。** 目前文件已移除，但 commit `2158448` 起的歷史仍含該帳號 ID 與權限集名稱；帳號 ID 不是 API 金鑰；完全移除需另行核准的歷史改寫與協作安排，本輪不暫停規則集或強推，且公開期間可能已被快取。清除後可加入針對帳號 ID 的 Gitleaks 規則（歷史仍含該值時，加入規則會使每次掃描 BLOCK）。
2. **開啟儲存庫的 Secret scanning、Push Protection、Dependabot alerts 與 Private vulnerability reporting**（`SECURITY.md` 指向此回報管道）。
3. 把 fork PR 的 workflow 核准政策改為所有外部貢獻者都需核准；開啟 Actions 的 SHA pinning 強制。
4. **建立並部署專用 App。** main 的簽章已在真實遠端驗證；待辦是受控主機上的 App 消費、把 `epsilon/trusted-merge` 加入規則集，並以普通開發者身分完成拒絕與繞過探測，不能與已完成的簽章生成混為一談。
5. 選定授權條款（目前沒有 LICENSE，公開程式碼等同保留所有權利）。
6. 在 GitHub 規則集把允許的合併方式限縮為 merge commit（現況為 merge／squash／rebase）。
7. 以非管理者開發者身分完成六項行為探測（目前皆為 NOT_RUN）。

**模型面：** 跨家族盲審改以 Gemini、GLM 與 Claude 三個家族進行（GLM 走地端公司 LLM 閘道，Gemini 與 Claude 為測試期間保留的雲端供應商），並擴大 v3（B13–B16）真實樣本。2026-10-12／13 的 GLM 小樣本實測（main `ee897f3`／`b86277c`）：B13（有漏洞）兩次、B14 與 B16（無漏洞）各一次全部正確；B15（有漏洞）在 2048 與 4096 輸出預算下都被截斷，尚無結果。2026-10-13 以 main `73a9aa9` 執行三家族盲審（Gemini、GLM、Claude 各一次、每次 2048 輸出預算、同一輪），B13（有漏洞，run `e5b7b508`）、B14（無漏洞，run `4da78c7a`）與 B16（無漏洞，run `1f9a0e14`）共 9 次審查全部正確、0 分歧，裁決皆為 `REFERENCE_MATCH`；B15 與多輪穩定性仍待執行。LM Studio 已可經臨時通道連線，但目前主機只能以 CPU 推論（約每秒 1.7 個 token），Nemotron 盲審逾時，改到可獨立執行 LM Studio、具獨立 GPU 的機器後再驗收，詳見 [LM Studio 指南](lmstudio.zh-TW.md)。DeepSeek 呼叫成功但漏洞證據常未逐字引用原始碼（4096 預算下 B13 四次有三次 `EVIDENCE_MISMATCH`），依使用者決定已自模型 RoE 停用，介接器程式與離線測試保留。雲端供應商在測試期間保留，但不再是必要條件。

**功能面：** G3、完整 G5、其他生態系的 SBOM／SCA／CVE、ASVS 產品適用性判定、正式發布、GLM 的原生結構化輸出、較大樣本的跨家族穩定性與偏誤實驗，以及 W15–W25。

**已知限制：** 本地完整流程僅支援 Linux x86_64、Python 3.12 與 Docker（Windows 需使用 WSL）。開發用 oracle 已改為本機 loopback 真實 HTTP，不再使用棄用的 TestClient；pytest 現在把任何警告視為失敗。

## 可重現驗收

依 README 順序執行，結果保存在 `artifacts/`：

- `pytest.xml`：政策、套件 metadata、真實 Gitleaks、歷史機密、RoE、基準變更及 PostgreSQL 正反例。
- `http-smoke.json`：真實 loopback HTTP 健康、登入、合法讀取及同角色非法讀取。
- `<run-id>/report.json`：每次新 run 的 G1、G2、AUTH 結果及 ALLOW／BLOCK；本輪候選缺陷版預期恰好 9 個政策指定的 AUTH findings，修正版預期 0。
- `latest.txt`：最新 run 的索引。檢查 report 的 subject／policy digest 與當次原始碼，不能將舊報告當成本次結果。

`expect_block.py` 要求整個 run 的 `execution` 為 COMPLETED、沒有任何 errors、清理完成、variant 為 vulnerable、三項 gate 都確實完成、G1／G2 無 findings，且 44 個授權案例中失敗的恰好是政策 `seeded_defect_case_ids` 列出的 9 個；工具 ERROR、清理失敗、來源在執行中變動、沒有案例或換成其他案例失敗都會使驗收失敗。

測試數量以 pytest 收集的項目計算（含 parametrize 展開），不是 `def test_` 的函式數。

## 實作待辦對照

W 編號與 G0–G6 閘門編號都來自本地保留的原始規劃。依公開文件的用法：G0／G4 為範圍、授權矩陣與威脅，G1 為依賴，G2 為機密，G5 為 Web／API 授權與黑箱測試，G6 為多模型審查；G3 尚未實作，定義見原始規劃。

| 原待辦 | 現在狀態 | 剩餘工作 |
|---|---|---|
| W01、W07 | 試點範圍完成 | 正式產品盤點、owner 與 ASVS 等級指定。 |
| W02 | 公開程式碼與操作文件已發布 | 內部參考資料保留本地。 |
| W03 | 固定 checksum／digest、wheel-only、DB 限權、候選 git 強化 | 不受信 PR／惡意套件的強隔離（VM／microVM）尚未驗證。 |
| W04 | 嚴格狀態、必要 coverage 與歷史、subject／policy 綁定；main 真實簽章已驗證 | 專用 App 消費與正式發布。 |
| W05、W09 | main 已有 32 案例／七種變體；本次審視擴為 44 案例／九種變體 | 完整 G5。 |
| W06、W20 | G1 metadata、鎖定檔 SBOM／OSV SCA 與 G2 | G1 行為分析、安裝映像及其他生態系、G3。 |
| W08 | main 規則集 active、遠端正反例、run 與 PR base 綁定、全 commit 核准排除 | 專用可信檢查來源與普通開發者繞過驗收；main artifact attestation 已驗證。 |
| W10–W14 | gateway、模型 adapter、盲測與多輪框架；Gemini／Claude 真實小樣本驗收；LM Studio 文字介接器 | 地端模型（Nemotron、Qwen、GLM）真實推論、較大樣本的穩定性與偏誤實驗；DeepSeek 已停用。 |
| W15–W19 | 待完成 | 產品適用性、簽章證據、完整 release、營運與正式資料／預算治理。 |
| W21 | 限縮本地 RoE；模型 RoE 呼叫上限實際執行 | 任意網路掃描、redirect／DNS／工具委派與外部資產授權。 |
| W22–W25 | 待完成 | 一手來源查核、組織成熟度評分、供應商驗收及產品弱點處理。 |

## 2026-10-08 安全邊界修正

本輪完整 703 項回歸通過，新增歷程／混合審查／重跑者／fork 身分／預留／程序與掃描範圍等變體，並備妥獨立簽署與固定驗證器。完整對照、真實模型結果及外部待辦見[安全邊界修正](security-boundaries-20261008.zh-TW.md)。上述 627 等數字屬各段歷史基準，不是本輪測試下限；專用 App 尚未部署的狀態維持不變。

## 2026-10-08 後續擴充（已合併）

本輪候選版本將 G1 擴充為鎖定檔 CycloneDX 1.6 清冊與 OSV 精確版本查詢，AUTH 增至 32 案例／9 個指定缺陷；目錄版本為 synthetic-review-v3，增加 B13–B16。該輪已合併至正式 main `438d7a4`，基準為 787 項測試及 32／9 AUTH 契約；704 與 18／6 僅屬先前基準。歷史段落的 627／703 數字保留供辨識批次，不是目前下限。完整新增驗收與外部缺口見[後續擴充紀錄](security-expansion-20261008.zh-TW.md)。

<a id="en"></a>

# Milestone status and acceptance

Current reviewed main is `d1f6d3a` (2026-10-14), including PRs #27–#54 (model adapters and output budgets, Bedrock reasoning blocks, blind reviews bound to the supervisor's plan digest, the publisher's call budget and permission lookups, the guard's last-push approval checks, isolated-container sweeping, required-check source verification, worker validation of the model RoE, UTF-8 documentation checks, merge-protection audit readback of merge methods and review settings, per-check attempt readback for required-check sources, authorization of every live adapter against the bound RoE, all GitHub reads through the GitHub reader, and an allowlisted AWS CLI subprocess environment). Post-merge [run 38589352556](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/38589352556) succeeded with 1386 tests, fixed 44/0 ALLOW, seeded exactly 9 findings BLOCK, mutation tests, cleanup, real signatures and PUBLISHABLE evidence. The previous `e1989d2` baseline (PRs #27–#52, [run 38574147836](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/38574147836), 1383 tests), the `9068e45` baseline (PRs #27–#48, [run 38495043615](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/38495043615), 1312 tests), the `14e59ac` baseline (PRs #27–#44, [run 38407303792](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/38407303792), 1291 tests), the `ded6624` baseline (PRs #27–#42, [run 38398930629](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/38398930629), 1290 tests), the `e7d0c87` baseline (PRs #27–#36, [run 38350438520](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/38350438520), 1278 tests), the `f9fa905` baseline (PR #26, [run 38209419557](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/38209419557), 1195 tests), the `9508a7c` baseline (PRs #21–#24, [run 38106362078](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/38106362078), 1150 tests), the `28be2e0` baseline (PR #20, 930 tests) and the audit-time 1149-test local evidence remain in history. Dedicated GitHub App deployment and real LM Studio acceptance remain pending. Original dated totals remain in [history](milestone-history.zh-TW.md#en).

## Remote governance

Main ruleset 24512048 is active/no bypass, with PR/CODEOWNER review, stale-approval dismissal, other-person last-push approval, additional approval for unattributed changes, and required trusted-security-pilot from shared Actions App 15368. Read current state with audit_merge_protection.py. Baseline reviewers are chinchiang, CatGrocery, d98922036ntu; CatGrocery write confirmed October 7, d98922036ntu October 8. PR #14 synchronized all three lists. Future PRs use normal rules without disabling them, except the controlled October 11 baseline migration below; author/any-commit identities/run actors and triggering actors cannot count as independent reviewers (a reviewer who reruns or marks the PR ready invalidates their own approval for that run; the author does those, reviewers only Approve). audit_merge_protection.py also reads back the allowed merge methods (`merge_commit_only`, intersected across layered rulesets), thread resolution (`review_thread_resolution_required`) and the unattributed-change extra approval (`unattributed_changes_extra_approval`). The October 13 readback for PR #45 found the latter two true, while the ruleset still allows merge, squash and rebase, so `merge_commit_only` is false; squash/rebase rewrite commits so the approved head differs from main, hence only merge commits should be used. The `docs/github-main-ruleset.json` template now restricts methods to `merge`; the owner applies the live setting and this text is then updated.

Initial October 6 migration temporarily disabled rules and merged #6 da567d8 and #7 0ac31cb; #10 also merged without reviews in that interval. Enforcement was restored. Same-name checks can still originate from other workflows. Before approval/merge, verify_required_check.py --pr <number> binds pull_request_target, exact head repository/branch, and all related PR/base timelines including closed PRs; each check's attempt is read from its job, and the latest check must belong to the run's current attempt. Dedicated epsilon/trusted-merge App/service/binding remain absent.

Second controlled baseline migration (October 11): after PR #21 merged, one main test accepted only the root-only denial message and always failed on the non-root runner ([run 38095207581](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/38095207581)). Because `pull_request_target` judges with the base tests, no PR, including fix PR #22, could pass the required check. PR #22 had d98922036ntu's independent approval of head `746c473` and passed the guard; the owner temporarily lifted the ruleset, merged it as `f1a640f`, and restored enforcement. Post-merge [run 38098147162](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/38098147162) passed every job.

Follow-up documentation and tooling PRs (October 11): PR #23 recorded the baseline migration and audit (`6b23491`); PR #24 made pytest warn when run as root (CI is non-root, so rerun as an ordinary user before pushing) and wrote the controlled-migration procedure for a failing baseline into [trusted-execution](trusted-execution.zh-TW.md#en). Both merged under the ruleset without disabling it; post-merge [run 38106362078](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/38106362078) passed with 1150 tests.

October 11–12 PRs: PR #25 synchronized the README, docs and diagrams with `9508a7c` (`3059642`). PR #26 fixed two false passes: ZIP/gzip bytes outside members must map to known structures, and the AUTH oracle checks response headers, with a tenth real-isolation defect variant. d98922036ntu independently approved head `80cb1f3`; after the author reran the workflow the guard passed and `verify_required_check.py` returned ALLOW. It was merged under the ruleset with a merge commit as `f9fa905`, without disabling rules, and post-merge run 38209419557 passed every job (1195 tests).

October 12–13 PRs: PR #27 raised the publisher template's test floor to 1195; PRs #28–#33 adjusted the model adapters (on-prem gateway, output budgets, DeepSeek disabled, Bedrock reasoning blocks) and docs; PR #34 bound blind-review workers and `finish()` to the supervisor's plan digest; PR #35 made the publisher replace an earlier green with failure when its call budget runs out; PR #36 made the guard read back main's rules and block with `LAST_PUSH_APPROVAL` unless last-push approval is still required. Each was independently approved by CatGrocery or d98922036ntu and merged with a merge commit without disabling rules; PR #36 merged as `e7d0c87` and post-merge run 38350438520 passed every job (1278 tests).

October 13 PRs (continued): PR #37 synchronized docs and the publisher template with `e7d0c87` (`64f613f`); PR #38 made the janitor sweep isolated containers created after cleanup, older than 10 minutes and owned by no live run (`e8612a5`); PR #39 made `verify_required_check.py` take the newest check by creation order and block a same-named commit status on the head (`dc75d95`); PR #40 made the guard read the head branch's Activity API, count only approvals submitted after the head was pushed, and block with `LAST_PUSH_UNKNOWN` without a push record (`3c6722b`); PR #41 deduplicated the publisher's reviewer permission lookups by login (`508eb8b`); PR #42 made the worker fully validate the model RoE it rereads and require its digest to equal the value bound in the report (`ded6624`). PRs #39 and #40 followed from base-only `update-branch` pushes: GitHub keeps earlier approvals and re-points their commit to the new head, so the old guard counted a pre-push approval. The new guard's first run with the CI token was on PR #42 (run 38390835409): attempt 1 read the Activity API without error and blocked, excluding the pre-push approval; after re-approval, attempt 2 counted only the post-push approval and passed. Each was independently approved by d98922036ntu and merged with a merge commit without disabling rules; post-merge run 38398930629 passed every job (1290 tests). The ruleset requires branches to be up to date with main (strict), so every `update-branch` needs a fresh approval. PR #43 synchronized docs and the publisher template with `ded6624` and set the template floor to 1290 (`fbab705`); PR #44 made every `check_docs.py` read and write use UTF-8 instead of letting the locale decide (such as cp950 on Windows or a non-UTF-8 Linux locale), with a CLI test that runs the checker with `EncodingWarning` raised as an error (`14e59ac`). Both were independently approved by d98922036ntu and merged with a merge commit without disabling rules; post-merge run 38407303792 passed every job (1291 tests). PR #45 synchronized docs and the publisher template with `14e59ac` and set the template floor to 1291 (`abb5bf7`); PR #46 made `audit_merge_protection.py` read back the allowed merge methods (`merge_commit_only`), thread resolution and the unattributed-change extra approval (`c070615`). Both were independently approved by d98922036ntu and merged with a merge commit without disabling rules; post-merge run 38476170355 passed every job (1305 tests). PR #48 made `verify_required_check.py` read each check's attempt from its job: after a rerun, older-attempt checks are no longer labeled with the new attempt, a job that does not match its check is `CHECK_ATTEMPT_UNRESOLVED`, and a latest check outside the run's current attempt is `LATEST_CHECK_STALE_ATTEMPT` (`9068e45`). PR #48 was likewise independently approved by d98922036ntu and merged with a merge commit; post-merge run 38495043615 passed every job (1312 tests). PR #47 synchronized docs and the publisher template with `9068e45` and set the template floor to 1312 (`7cf22fa`); PR #49 built every live adapter (including Gemini, Bedrock and loopback LM Studio) through one authorization function that reads the RoE once, requires the digest bound in the report (for both the smoke and blind-review workers), revalidates it for the provider and takes remote hosts from the same read (`6557e21`, 1321 tests); PR #51 moved GitHub reads onto one repository-bound GitHub reader that reads every page of every listing and checks its totals, used by `verify_required_check.py`, `audit_merge_protection.py` and the publisher, and added the bilingual glossary `GLOSSARY.md` (`a5331b0`, 1379 tests); PR #52 moved the guard onto the GitHub reader as well, so it no longer needs the gh CLI and records a refused read as `approval_error` `Denied:<code>`; repository activity is cursor-paged and ignores page, so the guard reads only the newest-first first page, and a head push beyond it is `LAST_PUSH_UNKNOWN` (`e1989d2`). Before PR #52 merged, the old and new guard outputs were compared with the same token and run, and all four cases matched before and after approval. All four were independently approved by d98922036ntu and merged with a merge commit without disabling rules; post-merge run 38574147836 passed every job (1383 tests). PR #53 synchronized docs and the publisher template with `e1989d2` and set the template floor to 1383 (`3208480`); it was also the new guard's first real run, which blocked before approval and allowed after it. PR #54 passed the AWS CLI subprocess only seven allowlisted AWS settings (profile, config and credential file paths, and the temporary credential triple) plus basic process, proxy and CA variables, then the forced values; every other `AWS_*` is dropped and the region still comes from `--region`. Its tests also cover the path that runs the CLI through `scripts/model_process.py` (`d1f6d3a`). Both were independently approved by d98922036ntu and merged with a merge commit without disabling rules; post-merge run 38589352556 passed every job (1386 tests).

October 11 merge-protection audit: the owner ran `audit_merge_protection.py --pr 22` with a token holding Administration read, with no read errors. The ruleset is active with an empty bypass list, deletion and force push are blocked, independent review is required, the required check is present and strict, and base CODEOWNERS include independent reviewers; CatGrocery and d98922036ntu are available independent reviewers and non-admin developers. The one failing item is that the required check is still bound to the shared Actions App rather than a dedicated App (`source_binding` NOT_VERIFIED). The six behavioral probes (direct push, unapproved policy change, forged same-name check, stale-head approval, dismissed approval, legitimate approval) remain NOT_RUN and need a non-admin developer.

| Historical October 6 scenario | Run | Result |
|---|---|---|
| #7 retargeted to main | 37446641158 | Base da567d8 evaluator;29 protected changes/no independent approval blocked before candidate execution; check on head |
| Main push 0ac31cb | 37446694680 |532 tests;18/0 ALLOW, exact 6 seeded BLOCK; PUBLISHABLE |
| #8 admin cross-tenant mutation | 37447163081 | Then-current fixture exemption allowed guard;532 evaluator tests, one precise candidate AUTH finding/BLOCK |
| #9 removes AUTH policy | 37447183081 | Protected-policy guard BLOCK |
| #10 Markdown-only | 37448552469 | Then-current guard passed, full trusted run succeeded; merge occurred while rules disabled without reviews |

Historical exemptions no longer apply: all paths now need review. Live source verification rejected #5 head 9a47966's manual candidate green as UNTRUSTED_CHECK_SOURCE; #7's real but failed run as LATEST_CHECK_NOT_SUCCESS. October 7 readback accepted #10's base binding and rejected #7-as-#10 with RUN_HEAD_BRANCH.

## October 7 implementation/acceptance

Manual candidate 607b8c6 run 37567019081:610 passes/no failures, 18/0 ALLOW, exact 6 BLOCK, own-candidate G2 history heads, PUBLISHABLE 610. PR #12 received CatGrocery exact-head58d9bc0 approval. Formal run 37568335787 attempt 2 used old main's532 tests and verified source/digests/18 positive/six seeded/cleanup. It merged under active/no-bypass rules as 41339c6; main run 37598381087 used new 610-test baseline/PUBLISHABLE. Old/new test totals must not be mixed.

Fixes hardened candidate Git configuration/hooks/transports/environment/.git discovery; required candidate-owned history; scanned archive metadata/unlisted payload/trailing bytes; required exact clean expect_block completion; blocked worker decisions without cleanup handoff; preserved latest index during janitor; bound required checks to PR source; excluded every PR commit author/committer with 250-list fail-closed cap; enforced actual live RoE count/catalog binding/fixed stop reasons/placeholder rejection/redacted model labels. Credential-free CLI overbudget tests cannot make paid calls, and cleanup removes only all-mock evidence. Event-specific workflow concurrency, no-follow reads, fixed Docker daemon, centralized rlimits, removed unused worker, and public account-ID redaction completed related fixes.

Publisher rechecks mutable same-head PRs/timelines immediately before green, opens root-owned configuration through protected directory descriptors, and prepares immutable clean-checkout archives with exact evaluator/policy digests and SHA256SUMS. Seventeen new regressions brought that historical baseline to 627. Preparation/offline/manual CI is not independent approval or live deployment.

## Remaining external work

Owner decisions/actions: restrict the live ruleset's allowed merge methods to merge commits; run the six behavioral probes as a non-admin developer; whether to separately authorize rewriting historical AWS account identifiers (not API secrets; may already be cached); enable/verify Secret scanning, Push Protection, Dependabot and private reporting with capable administrative access; require approval for all outside-contributor fork workflows and enforce Actions SHA pinning; choose a source license; provision dedicated App/installation/key/controlled Linux host and perform developer-role source/merge denial acceptance. Never paste credentials, disable rules, force-push history, or treat connector 403 as an automatic-review denial. Current private-reporting enable attempt still returns 403.

Deployment must use approved merged main and explicit regenerated evaluator/policy pins, not a candidate. Reviewed main `d1f6d3a` is the accepted source for preparing a new deployment bundle; this does not update existing deployment pins or deploy the service. Cross-family blind reviews now use three families: Gemini, GLM and Claude (GLM through the on-prem IEC gateway; Gemini and Claude are cloud providers kept during the test period), with larger v3 (B13–B16) samples still pending. Small GLM live runs on 2026-10-12/13 (main `ee897f3`/`b86277c`) were correct on B13 twice and on B14 and B16 once each; B15 truncated at both 2,048 and 4,096 output tokens. On 2026-10-13, three-family blind reviews on main `73a9aa9` (Gemini, GLM and Claude once each, 2,048 output tokens, one round per item) were correct in all nine reviews of B13 (vulnerable, run `e5b7b508`), B14 (not vulnerable, run `4da78c7a`) and B16 (not vulnerable, run `1f9a0e14`), with zero disagreements and every verdict `REFERENCE_MATCH`; B15 and multi-round stability remain pending. LM Studio was reached through a temporary tunnel, but the current host infers only on CPU (about 1.7 tokens/s) and Nemotron reviews timed out, so LM Studio acceptance moves to a machine with a discrete GPU that can run it on its own; see the [LM Studio guide](lmstudio.zh-TW.md#en). DeepSeek is disabled in the model RoE.

Known limits: the complete local flow supports Linux x86_64, Python 3.12 and Docker only (use WSL on Windows). The development oracle now uses real loopback HTTP instead of the deprecated TestClient, and pytest treats every warning as an error.

## Local acceptance and evidence

```bash
python3 -I scripts/bootstrap.py
python3 -I scripts/install_test_tools.py
python3 -I scripts/build_runtime.py
python3 -I scripts/dev_db.py start
.venv/bin/python -m pytest --junitxml=artifacts/pytest.xml
.venv/bin/python -I scripts/smoke_http.py
.venv/bin/python -I scripts/expect_block.py
.venv/bin/python -I scripts/run_security.py
python3 -I scripts/dev_db.py stop
```

pytest.xml records collected parametrized items, not test-function count. http-smoke.json verifies real loopback health/login/allowed and cross-owner reads. Each run report binds current subject/policy; latest.txt is only an index. expect_block requires COMPLETED/no errors/cleanup/vulnerable variant/all gates complete/G1-G2 clean/exact nine seeded IDs among 44 AUTH cases. Tool errors, source drift, empty/different cases, or cleanup failure are failed negative acceptance.

| Roadmap item | Implemented scope | Remaining |
|---|---|---|
| W01/W07 | Synthetic pilot scope | Product inventory/owners/ASVS level |
| W02 | Public code/docs | Private references stay local |
| W03 | Checksums, wheel-only, DB least privilege, Git hardening | Hostile multi-tenant VM/microVM isolation |
| W04 | Strict state/coverage/history/digest and main signatures | Dedicated publisher operation |
| W05/W09 | 32 AUTH cases/seven real mutations on main; 44/nine in the October 10 change | Full G5 |
| W06/W20 | G1 provenance/lock SBOM/OSV and G2 | Behavior/installed images/other ecosystems/G3 |
| W08 | Active rules, remote positive/negative CI, run/base binding, all-commit exclusions | Dedicated source and actual non-admin anti-bypass probes |
| W10–W14 | Gateway/adapters/blind/repeated framework; small Gemini/Claude live samples; LM Studio text adapter | Real on-prem inference (Nemotron, Qwen, GLM), larger stability/bias experiments; DeepSeek disabled |
| W15–W19 | Roadmap | Product applicability, long-term signed evidence/release/operations/data-budget governance |
| W21 | Bounded local/model RoE and actual caps | Arbitrary assets/network scans/DNS/redirect/tool delegation authorization |
| W22–W25 | Roadmap | Primary-source checks, maturity scoring, supplier acceptance, product vulnerability handling |

W/G numbering originates from retained private planning: G0/G4 scope/authorization/threats, G1 dependencies, G2 secrets, G5 web/API authorization, G6 models; G3 remains unimplemented. No private planning is republished.

October 8 boundary work had 703 then 704 tests; see [boundary record](security-boundaries-20261008.zh-TW.md#en). Expansion added CycloneDX 1.6/exact-version OSV, 32/9 AUTH, and v3 B13–B16, merged as 438d7a4 with 787 tests; see [expansion](security-expansion-20261008.zh-TW.md#en). Historical 627/703/704 and 18/6 figures are not current minimums.
