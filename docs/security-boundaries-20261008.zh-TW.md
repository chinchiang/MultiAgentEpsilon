[正體中文](#zh-tw) | [English](#en)

<a id="zh-tw"></a>

# 2026-10-08 安全邊界修正與驗收

本輪依 `main` 的 `ba05e1c` 確認結果修正，公開分支只繼承既有公開歷史。私人附件及舊 `work` 歷史不納入 PR。此文件區分程式修正、測試結果與仍需外部資源的部署驗收。

## 修正對照

| 問題 | 修正後行為 | 回歸或驗收 |
|---|---|---|
| PR 改 base 後沿用舊 run | 比對完整 timeline；同一 SHA／head repository／分支曾改 base 即拒絕；`edited` 會觸發檢查 | 缺失、畸形、改走再改回的歷程皆拒絕；發布前再次讀回 |
| 報告或檢查名稱冒充來源 | 獨立工作簽署 ZIP 摘要；固定 CLI 驗證簽章、workflow SHA／main ref／GitHub runner／run／attempt／digest | 官方樣本六種驗收符合預期；遠端 run 37731214649 的實際簽章／digest 通過分支驗證，main 來源政策拒絕該手動分支證據 |
| fixture／文件排除可信審查 | 所有變更路徑均須可信、具寫入權限的精確 head 核准 | fixture 改名、README 與文件均納入保護 |
| 混合核准／要求修改、重跑者核准 | guard 與 publisher 共用審查契約；寫入者要求修改會阻擋；排除 run actor／triggering actor 及所有 PR commit 身分 | 寫入／維護／管理／唯讀角色與完整 API 查詢回歸 |
| 相同 SHA 的其他 fork 或分支造成誤擋 | 相關 PR、最新 run 依 repository ID 與分支分開判定 | 不同 fork／分支不取代此 run，同範圍仍嚴格拒絕 |
| 核心 janitor 跨開機訊號與登記空窗 | 先查 boot ID；子程序收到持久化登記後的握手才執行 | 跨開機 PID、登記失敗、真實取消與 SIGKILL 回收 |
| 清理證據不足 | 檢查非殭屍程序群組已消失，目錄是否實際移除，失敗保留回收清冊 | 真實 Docker／程序／取消與孤兒回收測試 |
| 強制終止遺失呼叫預留 | 呼叫前同步寫入 call ID、請求摘要及預留；完成後再更新 | 實際送出模擬請求後 SIGKILL，仍有 IN_FLIGHT／預留／未知用量 |
| 報告 budget／limits 可竄改 | 重新計算精確規劃、總期限及逐筆預留；成功呼叫不能刪除預留 | 個別欄位及整批預留竄改皆拒絕，重複輪次共享預算 |
| 基底 pin 與執行權限摘要 | 啟動前核對工具鎖定的映像；manifest 使用 Git 的擁有者執行分類 | stale pin 在候選或容器啟動前拒絕；不同 umask 的分類一致 |
| 歷史機密範圍缺漏 | 掃描提交訊息／作者／提交者及標籤名稱／附註 | 五種中繼資料 canary 均被偵測且不寫入報告 |
| 分頁與 403 分類 | 完整頁另查下一頁；上限 10,000；一般權限 403 與限流區分 | 1,000／10,000 正常、10,001 拒絕；首個查詢限流也退避 |
| CODEOWNERS 審核粗略 | 規則集與協作者分頁；所有有效 owner 規則採保守交集 | 分路徑 owner 不會被誤報為全檔案 owner；原生每路徑審查仍必要 |
| 模型逐案類別提示及 RoE 綁定 | 目錄升為 v2、移除逐案 CWE 提示、綁定模型 RoE 摘要 | 舊版指標不與新版混算；兩家收到相同內容 |
| 結構化輸出與不可見字元 | 按供應商支援 schema 設定，保留嚴格本機引用／行號／文字驗證 | Bedrock 不傳不支援關鍵字；格式合法但引用偽造仍拒絕 |
| 未知供應商及缺少 AWS CLI | 呼叫前判為 CONFIGURATION | 不會預設送往 Bedrock 或消耗呼叫預留 |
| 未使用的 helper／清單／文件 | 註記增加實際讀取驗證；移除未使用模型清單與 imports；合併重複狀態說明 | 註記與修改後報告不能混用；文件明列揭盲後裁決 |
| 重複 seed 契約 | 維持可信 oracle 與 app 分開實作，以契約回歸防止漂移 | 比對兩者的 schema、資料列及認證設定；不從候選匯入可信 seed |
| GLM 缺少完整離線路徑 | 模擬 HTTP 走實際 adapter、盲審 worker、評分與清理 | 完整離線驗收；依使用者指示不連線內網 |
| 固定 Actions／工具版本 | checkout 7.0.1、setup-python 7.0.0、upload-artifact 7.0.2、attest 4.2.2 固定 SHA；CLI 固定雜湊 | AWS CLI 2.37.10 官方 PGP 驗證後鎖定；簽章驗證 CLI 2.102.0 |

`base_ref_changed` 採保守拒絕，包含主分支來回切換後的重跑。若要重新評估，使用新的 head 分支建立 PR；不以時間戳推測已排隊事件的 workflow 來源。共用 Actions 同名必要檢查的人工驗證仍採保守阻擋；專用 App 來源正式綁定後，才可消除共用來源的限制。

## 本機驗收

- 最新完整回歸：704 項通過、0 失敗／錯誤／跳過，包含資料庫、無網路容器、真實取消清理與 Bedrock 四項合法 finding 超額拒絕；保留一項既有 Starlette 棄用警告。結果由 JUnit 記錄，遠端 CI 另行核對。先前提交 6005ebb 的 703 項本機及遠端 run 37731214649 均通過。
- 第一輪完整回歸：686 項通過；後續增加註記消費、seed 契約、GLM 全路徑、缺少 CLI、映像 pin、owner、重跑者、預留竄改及安裝封存變體。
- 修正版安全測試：18 個授權案例、0 findings、ALLOW；缺陷版恰好政策指定 6 個 findings、BLOCK，G1／G2 無 findings，兩者清理完成。
- HTTP smoke：資料庫健康、登入、合法讀取與跨 owner 拒絕通過。
- 官方 CLI 簽章樣本：合法、竄改 artifact、錯誤 signer digest、錯誤 ref、無效簽章及缺少驗證材料，六種結果符合預期。此為驗證工具驗收，不是專用 App 已部署的證明。
- 模型新版目錄一輪八次呼叫（報告 `a7b33efc-9e72-44bf-944e-eb2a1d132690`）：Gemini 三個回答通過，一個 DEADLINE；Claude 受重建後缺少 CLI／profile 影響，未取得有效推論。該報告 INCOMPLETE、預留八次／8192 輸出詞元、用量不完整、清理完成。不能作為配對成功或偏誤降低證據。
- 新的單案 Gemini B09 驗收（報告 `ca84cbef-0829-4fe3-8f00-74f4bfdeb112`）成功且清理完成；為另一次有界驗收，不把不同批次拼接成完整配對。
- AWS CLI 已安裝並補回非機密 profile；STS 最初確認 ExpiredToken。使用者更新臨時憑證後，STS 已確認指定帳號與角色有效。
- 更新後第一批 `66d86091-639e-4b25-b74f-94c2d6c0358f`：Gemini 四次有效，Claude 四次 `OUTPUT_CONFIGURATION`，報告 INCOMPLETE、清理完成。移除 Bedrock 不支援的 `maxItems`，保持本機三項 finding 上限；Claude B10 單案 `2fcffea2-53a1-4c02-8697-04009d240950` 成功。
- 修正後同批 B09～B12 的 Gemini／Claude 真實配對 `edf879a8-390d-4bc0-bcfb-0234325871c3`：八次全部有效，每家兩個真陽性、兩個真陰性、零誤報／漏報，弱點行號全部命中；四組配對無分歧，預留八次／8192 輸出詞元，清理完成。詳見[結構化輸出驗收](structured-output.zh-TW.md)。不混算舊目錄或失敗批次，不宣稱偏誤降低。

## 部署與外部待辦

1. 專用 GitHub App、Installation、私鑰與受控 Linux 主機仍缺。程式及安裝步驟已備妥，依[部署文件](trusted-check-publisher.zh-TW.md)安裝固定工具與設定後，才能驗證 App 發布及 Ruleset 綁定。
2. `main` 規則集 24512048 仍 active、無 bypass，必要來源仍為共用 Actions App 15368。未核准、檢查失敗、偽造或過期證據的實際合併阻擋，需在隔離驗收 PR 由普通開發者身分確認；本輪不對 main 做可能成功的合併探測。
3. Actions 管理 API 回應 403，無法設定 fork 核准政策與全域 SHA pinning。私人弱點回報讀取為 disabled，啟用操作也回應 403。由儲存庫擁有者的管理連線處理；不是沙箱或使用者身分被拒絕。Secret scanning／Push Protection／Dependabot 的設定未取得完整驗收，保留未知狀態。
4. 授權條款尚待擁有者決定；本輪不自行授予公開原始碼授權。歷史 AWS 帳號 ID 是識別資訊，沒有以停用 main 規則集或強推改寫歷史。
5. G3、完整 G5、SBOM／SCA／CVE（鎖定檔 SBOM 與 OSV 查詢已於其後的擴充實作）、產品 ASVS 適用性、較大模型樣本與 W15–W25 保留原路線圖。這些擴充功能不屬於本輪缺陷已修復的聲明。

Starlette 的 httpx 棄用警告仍須在後續相依套件遷移時處理；本輪沒有修改套件鎖定或降低隔離限制。

<a id="en"></a>

# Security-boundary fixes and acceptance: 2026-10-08

This historical round started from main ba05e1c and inherited only public history, excluding private attachments and the old work branch. It separates implementation/testing from externally blocked deployment. Current expansion/status records supersede its old test and case totals.

| Issue | Corrected behavior and evidence |
|---|---|
| Retargeted PR reuses old run | Complete timelines reject missing/malformed/base-changed history, including change-away-and-back; edited triggers checks; re-read before publish |
| Report/check-name source spoofing | Separate job signs ZIP digest; pinned CLI verifies signer workflow SHA/main ref/hosted runner/run/attempt/digest. Six official-sample cases passed; run 37731214649's real branch signature verified but main-source policy correctly rejected branch evidence |
| Fixture/docs escape trusted review | Every changed path needs trusted write-capable exact-head approval, including renamed fixtures and README |
| Mixed approvals/change requests/rerun actor | Shared review contract; writer change requests block; run/triggering actors and all PR commit identities excluded; permission/API regressions |
| Same SHA across forks/branches | Related PR/latest run selection binds repository ID and branch; unrelated scope does not supersede a valid run |
| Janitor across boots/registration gap | Check boot ID first; children await handshake after persistent registration; registration failure and real kill/cancel tests |
| Inadequate cleanup proof | Verify non-zombie groups gone and directories removed; preserve recovery inventory on failure; real Docker/process tests |
| SIGKILL loses reservations | Persist call ID/request digest/reservation before dispatch; killed synthetic requests retain IN_FLIGHT and unknown usage |
| Tampered budgets/limits | Recompute exact plan/deadline/per-call reservations; successful calls cannot lose reservations; rounds share caps |
| Runtime pin/executable manifest | Verify locked base image before launching; use Git owner-executable classification, independent of umask |
| Historical secret metadata gaps | Scan reachable commit messages/authors/committers and tag names/annotations; five canaries detected without raw retention |
| Pagination/403 classification | Fetch next page after full pages, cap 10,000, reject 10,001; distinguish ordinary forbidden from rate limits and back off even on first lookup |
| Coarse CODEOWNERS audit | Paginated rules/collaborators; conservative intersection of effective owners, without claiming path-specific owners cover every file |
| Per-case model hints/RoE | Catalog v2 removes CWE hints, binds model RoE; both providers see identical content; old metrics stay separate |
| Schema/invisible characters | Provider-supported schema plus strict local quotation/location/text checks; unsupported Bedrock keywords removed without weakening semantic validation |
| Unknown provider/missing AWS CLI | CONFIGURATION before calls/reservations; never defaults unknown names to Bedrock |
| Unused helpers/lists/docs | Validated note reader, removed unused imports/model list, consolidated status; adjudication explicitly unblinded |
| Duplicate seed contract | Trusted oracle and candidate remain separately implemented; schema/rows/auth contract regressions prevent drift without importing candidate seed |
| GLM missing full offline path | Mock HTTP exercises adapter, worker, scoring, cleanup; no internal live connection |
| Tool/Action pinning | checkout 7.0.1, setup-python 7.0.0, upload-artifact 7.0.2, attest 4.2.2 pinned to SHAs; AWS CLI 2.37.10 verified by official PGP, verifier CLI 2.102.0 by hashes |

base_ref_changed is conservatively rejected even after retargeting back and rerunning. Use a new head branch/PR; timestamps cannot establish queued workflow source. Shared-Actions same-name checks remain conservatively blocked until dedicated source binding.

## Historical local acceptance

- Final round: 704 passes, no failures/errors/skips; database, networkless containers, real cancellation, and four-otherwise-valid Bedrock findings rejected by the three-finding cap. One existing Starlette warning remained. Earlier 6005ebb and remote run 37731214649 had 703 passes; initial round had 686.
- Fixed pipeline: 18 AUTH cases, zero findings, ALLOW. Seeded variant: exact policy six findings, BLOCK. G1/G2 clean and cleanup complete. Later expansion supersedes these totals with 32/9.
- HTTP smoke covered DB health, login, permitted read, cross-owner denial.
- Official signature samples: valid, altered artifact, wrong signer digest, wrong ref, invalid signature, missing material produced expected outcomes; not dedicated-App deployment proof.
- v2 eight-call report a7b33efc-9e72-44bf-944e-eb2a1d132690: Gemini three valid/one DEADLINE; Claude lacked CLI/profile after rebuild. INCOMPLETE, eight/8,192 reserved, partial usage, cleanup done. Separate Gemini B09 ca84cbef-0829-4fe3-8f00-74f4bfdeb112 succeeded; never splice batches into a successful pair.
- Installed AWS CLI/restored nonsecret profile; STS first returned ExpiredToken. After secure user refresh, STS validated intended account/role.
- Report 66d86091-639e-4b25-b74f-94c2d6c0358f: four valid Gemini, four Claude OUTPUT_CONFIGURATION, INCOMPLETE/cleaned. Removing unsupported Bedrock maxItems while retaining local bounds enabled B10 diagnostic 2fcffea2-53a1-4c02-8697-04009d240950.
- B09–B12 rerun edf879a8-390d-4bc0-bcfb-0234325871c3: eight valid, each provider 2 TP/2 TN/zero FP/FN, all locations correct, four agreeing pairs, same eight/8,192 cap, cleanup done. See [structured output](structured-output.zh-TW.md#en). No mixed catalogs/failures or bias-reduction claim.

## External work and limitations

Dedicated App/installation/private key/controlled Linux host remain missing; use the [deployment guide](trusted-check-publisher.zh-TW.md#en) before live publication/source binding. Ruleset 24512048 remains active/no bypass with shared App 15368. Ordinary-developer denial of unapproved, failed, forged, or stale evidence needs an isolated acceptance PR, not dangerous main probes.

Actions administration returned 403, preventing fork-approval/global-SHA settings. Private vulnerability reporting was disabled and enabling also returned 403. Owner administrative access must resolve these; they are not sandbox denials. Secret scanning/Push Protection/Dependabot settings are not fully accepted and remain unknown. License choice belongs to the owner; no license was invented. Historical AWS account identifiers were not removed by disabling rules or rewriting history.

G3, full G5, product ASVS applicability, larger model samples, and W15–W25 remain roadmap items. The later expansion implements bounded Python OSV SCA/CycloneDX, superseding this round's earlier SCA gap, without claiming full product coverage. The Starlette/httpx deprecation warning awaits a deliberate dependency migration; locks/isolation were not weakened.
