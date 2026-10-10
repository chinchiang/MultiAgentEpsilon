[正體中文](#zh-tw) | [English](#en)

<a id="zh-tw"></a>

# 里程碑歷史紀錄

本文件依日期保存歷次批次的原始紀錄，內容只代表當時狀態（例如「main 未受保護」、14／16 個授權案例、5 個 findings、81／103／125／431／532 項測試）。現況與剩餘工作以[里程碑狀態](milestone-status.zh-TW.md)為準。

## 2026-10-06 驗收（commit `2158448`，遠端手動 [run 37441975087](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37441975087)；之後的 commit 只改文件與範本測試下限）

- 532 項測試全數通過，0 失敗／錯誤／略過（其中可信閘門 PR 單獨為 266 項，見 [run 37407823134](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37407823134)）。
- 修正版 18 個授權案例、0 findings、ALLOW；缺陷版恰好是政策 `seeded_defect_case_ids` 指定的 6 個案例失敗，BLOCK。
- CI 以發布程式的同一套證據契約自我檢查，結果為 PUBLISHABLE。
- 手動 run 的檢查名稱為 `manual-security-evaluation`；該 head 上沒有 `trusted-security-pilot`。
- 本機 WSL 另跑過不含 Docker 隔離的完整子集，以及 admin 跨租戶寫入等真實隔離 mutation；WSL 的 Docker 延遲高，本機驗證時曾暫時放寬 Docker 逾時，提交的程式維持原時限，並以遠端 run 為準。


## 2026-10-06 修正

- 手動執行不再以必要檢查名稱回報；新增審查者用的檢查來源核對工具。
- guard 只採計具寫入權限者的基準核准，並排除 head commit 的作者／提交者。
- 授權 oracle 補上 admin 同租戶寫入（允許）與跨租戶寫入（拒絕且無副作用）；缺陷版改為比對精確案例集合。
- 發布程式：負例綁定 evaluator 摘要與 evaluator SHA；run 綁定 PR head；以 head SHA 判定較新的 run，外部 fork PR 不能再阻斷發布；結果改變才發布 completed 檢查；blob 快取、節流退避、用後撤銷安裝權杖；設定須由 root 擁有、私鑰經 systemd `LoadCredential` 提供，unit 加強隔離。
- 合併保護稽核：看不到 `bypass_actors` 時視為未知而非沒有；必要檢查須核對 integration ID；另查專用 App 檢查與 base 分支 CODEOWNERS。
- G2：二進位內容須經審查列入 `security/binary-allowlist.json`（以 SHA-256 識別），之後仍以可讀字串掃描內嵌機密；未審查者照樣阻擋。
- janitor 單一 run 回收失敗不再中斷其他 run；模型 supervisor 回收逾時不再跳過收尾；容器清理逾時放寬為 30 秒。
- 模型：review 須能由原始回應重新導出並符合該次呼叫的回應雜湊；拒絕控制、格式（bidi、零寬）與分隔字元；補 Gemini 推理用量缺口；記錄供應商回報的服務模型以偵測別名漂移，模型識別改為每 run 金鑰化；AWS 子程序只取得 allowlist 環境變數，失敗時依固定分類記錄原因（不保存原文）；人工裁決須核對儲存的分析；live 呼叫另需 `security/model-roe.json`。


## 2026-10-05 固定預算多輪盲測與診斷

已加入不含原文的錯誤分類、一至四輪共用總預算的盲測、逐輪與合併指標、失敗分母及跨輪穩定性。新增 32 項回歸；Gemini 兩案各兩輪取得四個有效且符合標準答案的結果。AWS 暫時憑證已到期，因此未做雙模型重複驗收。詳見 [多輪盲測與限制](repeated-review.zh-TW.md)。

## 2026-10-05 第二個真實模型與合併保護前置驗收

Bedrock Claude 固定回覆已成功。修正真實 AWS CLI 的管線 JSON 解析問題，改用封存的匿名記憶體檔案，並移除模型不接受的固定溫度參數。Gemini／Claude 四案配對取得七個有效回應，整批保留未完成；Claude 的一案獨立診斷通過，不覆蓋原始失敗。詳見 [盲測驗收](blind-review.zh-TW.md) 與 [介面修正](model-gateway.zh-TW.md)。獨立審查者設定已加入候選分支，但遠端管理權限、審查者寫入權限、可信必要檢查來源及實際核准仍未完成。

## 2026-10-05 多模型盲測與裁決框架

已加入 12 個合成案例（預設注入組及新增邊界組各 6 案）及獨立 oracle、盲測 payload、嚴格 JSON／引用驗證、誤報／漏報／定位／覆蓋率及分歧指標，並提供綁定 report digest 的追加人工註記流程。模型多數決不影響安全 gate；只有單一真實模型或 mock 結果不代表偏誤降低。原有 43 項盲測回歸加上 44 項邊界案例回歸；ASVS 條文均只標記部分涵蓋，見 [覆蓋對照](asvs-coverage.zh-TW.md)。操作界線見 [盲測文件](blind-review.zh-TW.md)。

## 2026-10-05 模型取消與孤兒回收

模型 runner 已接入 supervisor 與共用 janitor，登記後才啟動 worker／AWS CLI，成功結果須待清理完成才發布。新增 29 項離線生命週期回歸；報告 schema 2 與中斷恢復方式見 [模型 gateway 文件](model-gateway.zh-TW.md)。本輪只處理生命週期，不新增付費模型呼叫；Bedrock／GLM 真實串接及合併保護仍分別待驗收。

## 2026-10-04 模型 gateway 更新

已加入共用 gateway、離線 mock、Gemini／Bedrock／GLM adapter，以及 56 項離線契約／安全回歸。Gemini 實際合成 ACK 推論成功；GLM 的 proxy CONNECT 403 與 Bedrock 的 AWS profile／模型設定仍阻擋真實推論。模型輸出僅供參考，不改變既有安全 gate 或候選容器權限。操作、證據及後續盲測界線見 [模型 gateway 文件](model-gateway.zh-TW.md)。下方多模型尚未實作的敘述為先前批次的歷史狀態。

## 2026-10-04 掃描覆蓋與生命週期更新

本輪本地回歸為 **125 passed、0 failed、0 skipped**，含真實取消與孤兒容器回收。G2 支援限額 gzip／zip／tar 展開及 HEAD 可達歷史 blobs；未知內容、超限或覆蓋不完整均 BLOCK。管線由 supervisor 管理總期限與每程序資源限制，清理成功後才允許 ALLOW。完整界線與遠端尚缺條件見 [覆蓋與生命週期驗收](coverage-lifecycle-acceptance.zh-TW.md)。下方為先前批次的歷史驗收。

## 2026-10-04 核心判定與隔離修正（目前工作目錄）

本輪本地回歸為 **103 passed、0 failed、0 skipped**，保留 1 項既有 Starlette TestClient 棄用警告。新增四種真實容器缺陷變體，確認錯誤密碼登入、404 洩漏、匯出夾帶跨租戶資料、拒絕寫入卻修改其他資料列皆產生指定 findings。

AUTH 更新為 16 案例，核對完整合成 JSON 契約及 users／items／sessions 狀態；subject 改為 `worktree-manifest-v1`、gate 證據 schema 3，拒絕舊版。已補受保護路徑改名兩端判定、不可讀目錄阻擋及 candidate lock／runtime lock 一致性檢查。

HTTP socket 移入容器限額 tmpfs，host 透過限時限量 Docker exec bridge 接收不可信 HTTP 回應；不再使用候選可寫的 host HTTP 目錄。socket 改指向 host 端點的回歸確認沒有連線到該端點。依賴差異尚採拒絕策略，未實作任意候選 lock 的可信映像建置。

驗收標準：完整管線正常版本為 16 cases／0 findings／ALLOW，原始缺陷版本為 16 cases／5 findings／BLOCK。每次實際結果應讀取當次 `artifacts/<run-id>/report.json`，不沿用下方歷史 digest 或遠端 run 作為本輪證明。本輪尚未更新遠端 PR／CI；合併保護、多模型及完整 ASVS 範圍仍未完成。

## 2026-10-04 修正分支更新

此版本已修正必要案例集合與 run 綁定、掃描／雜湊範圍、初始化錯誤證據，並以無網路容器隔離候選程式，改由外部 HTTP／資料庫 oracle 評分。完整本地回歸為 **81 passed、0 failed、0 skipped**；缺陷版 14 案例／5 findings／BLOCK，修正版 14 案例／0 findings／ALLOW；真實 HTTP smoke 通過。保留 1 項既有 Starlette 開發用 TestClient 棄用警告。

已加入精確 head SHA 的獨立基準核准流程及 base evaluator 的 `pull_request_target` workflow。[PR #5](https://github.com/chinchiang/MultiAgentEpsilon/pull/5) 尚待採納；首輪手動遠端 [run 37184958648](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37184958648) 已成功，測試與隔離安全閘門均通過。手動 run 不會執行 PR 審核 guard；另外已對真實 PR 查詢審核資料，確認未核准基準變更為 BLOCK。最後 head 的驗證結果見 PR 說明。

ruleset 管理 API 再次回覆 HTTP 403，main 仍未受保護；獨立可信檢查來源與一般開發者繞過驗收未完成。PR 作者目前也是唯一基準 reviewer，仍需有合格的獨立 reviewer，不能自我核准。操作及基準遷移見 [可信執行文件](trusted-execution.zh-TW.md)。下文保留先前 main 基線的歷史紀錄。

（首版紀錄，2026-10-04）本文件記錄公開程式碼試點的實作狀態。使用者原始參考文件與內部規劃留在本地。首版已建立可在本地執行的 Python harness、PyPI 安裝前預檢、真實 Gitleaks、PostgreSQL fixture、14 個授權案例、政策負例與 GitHub Actions 工作流程。

首版當時完成合成 fixture 的本地及遠端 CI 試點。當時遠端基線有 51 項測試通過，PR 正反例與早期 BLOCK 證據已驗證；main 的規則管理寫入仍被整合權限拒絕。詳見 [遠端紀錄](remote-ci-validation.zh-TW.md)。ASVS 345 項清冊仍未做真實產品適用性判定，不把示範案例寫成完整條文通過。雲地模型端點仍為 UNVERIFIED。

## 首輪本地基線結果（2026-10-04）

- 清空重建 Python virtualenv、重新核對下載／安裝，並停止後新建 PostgreSQL：成功。
- pytest：50 passed，0 failed／error／skipped；包含真正執行 Gitleaks 與 PostgreSQL 的測試。
- 真實 HTTP smoke：4 項檢查通過。
- 缺陷版：G1 23 套件完成、G2 完成，14 個授權案例中觀測到 5 個違規，決策 BLOCK。
- 修正版：相同 14 個授權案例無違規，決策 ALLOW；只代表本地有限試點。
- 相同工作流程已在資料庫重建前後跑通；各 run 使用不同 run ID 與獨立 schema。
- 依賴相容性檢查通過。Starlette 對 TestClient 使用 httpx 發出 1 個棄用警告；未影響此次執行，後續應以相容性 PoC 評估 adapter 遷移，不自行安裝名稱相近的新套件。
- workflow 已做 YAML 結構、固定 action SHA、權限及文件連結檢查；未在 GitHub Actions 遠端執行。

最新證據請依 `artifacts/latest.txt` 回查，而非把此人工摘要當作發布證明。

## 遠端阻礙與後續順序

Git HTTPS、PR 與 Actions 結果的讀取／交付已成功；ruleset 寫入明確回覆 `Resource not accessible by integration`。此管理權限不足阻止合併保護生效，不影響已完成的 CI 執行證據。可套用設定見 `github-main-ruleset.json`。

下一步是建立遠端可信 PR 閘門，驗證普通開發者無法更改評分規則、跳過 required workflow 或以偽造同名 status 放行。其後再擴 G3／完整 G5，盤點一雲一地與至少兩模型家族，逐步串接 G6。安全憑證透過環境設定提供，不寫入原始碼或聊天。

<a id="en"></a>

# Milestone history

These dated records preserve original batch observations, including unprotected-main statements and older 14/16/18-case, five/six-finding, and 50–532-test totals. They are not current claims. See [current status](milestone-status.zh-TW.md#en).

## 2026-10-06 acceptance and fixes

Commit 2158448, manual run 37441975087: 532 passed/no failures/errors/skips; trusted-gate-only PR run 37407823134 had 266. Fixed 18/0 ALLOW; seeded exact six policy IDs BLOCK; shared publisher contract PUBLISHABLE. Manual check was manual-security-evaluation, not trusted-security-pilot. WSL also tested non-Docker subsets and real admin cross-tenant mutations; temporary local Docker timeout relaxation was not committed, and remote original-limit results are authoritative. Subsequent commits then changed only docs/template minimums.

Fixes separated manual names/source verification, required write-capable base approval excluding head authors/committers, added admin same-tenant allow/cross-tenant no-side-effect denial, and matched seeded exact sets. Publisher bound negative evidence to evaluator and runs to head; unrelated forks stopped superseding runs; published completed checks only on changes; added blob cache/backoff/token revocation/root settings/LoadCredential/unit hardening. Merge audit treated absent bypass data as unknown and checked integration ID/dedicated source/base CODEOWNERS. G2 required reviewed binary hashes but still scanned readable strings. Janitor continued after per-run failure, supervisor retained cleanup after timeout, and container cleanup allowed 30 seconds. Models rederived reviews from hashed raw responses, rejected unsafe Unicode, accounted for Gemini thinking, tracked keyed per-run serving identities, restricted AWS environment, retained fixed error categories, revalidated adjudication analysis, and required separate model RoE.

## 2026-10-05 repeated reviews and second model

Added one-to-four shared-budget rounds, fixed redacted diagnostics, per-round/pooled metrics, failure denominators, and stability; 32 new regressions. Gemini two cases/two rounds returned four valid reference matches; expired AWS credentials prevented repeated pairing then. See [repeated reviews](repeated-review.zh-TW.md#en).

Bedrock ACK later worked after replacing CLI pipe JSON with sealed anonymous memory and omitting unsupported fixed temperature. Four-case Gemini/Claude pair returned seven valid; batch stayed incomplete, separate Claude diagnostic did not overwrite it. Independent reviewer names in a candidate did not yet prove remote write/administrative/source permissions or actual approval. See [blind review](blind-review.zh-TW.md#en) and [gateway](model-gateway.zh-TW.md#en).

The blind framework added twelve synthetic cases (six injection/six boundaries), separate oracle, opaque payloads, strict JSON/quotes, classification/location/coverage/disagreement metrics, and append-only report-bound human notes. Majority never changed gates. Initial 43 blind plus 44 boundary regressions did not establish bias reduction or complete ASVS. Model supervisor/registered worker/AWS/janitor integration added 29 lifecycle regressions; schema 2 awaited cleanup before success. That lifecycle round made no paid calls and left Bedrock/GLM/protection live acceptance separate.

## 2026-10-04 gateway, coverage, and core boundaries

Gateway/mocks/Gemini/Bedrock/GLM plus 56 offline tests were added. Gemini ACK worked; GLM proxy CONNECT 403 and Bedrock profile/model settings blocked inference then. Opinions remained advisory and isolated from deterministic gates. Later updates supersede those connection statuses.

Coverage/lifecycle round: 125 passes/no failures/skips, real cancellation/orphan cleanup, bounded gzip/ZIP/TAR expansion and HEAD-reachable blobs, unknown/overlimit/incomplete input BLOCK, supervisor process/deadline limits, cleanup-before-ALLOW. See [coverage acceptance](coverage-lifecycle-acceptance.zh-TW.md#en).

Core round: 103 passes and one Starlette warning, four real-container mutations (wrong password, 404 disclosure, cross-tenant export, hidden unrelated-row change) producing intended findings. AUTH became 16 cases with full JSON and users/items/sessions state; worktree-manifest-v1/schema 3 rejected old evidence. Rename endpoints/unreadable directories/runtime-lock mismatch blocked. HTTP sockets moved into bounded container tmpfs, host used timed Docker exec bridge, and host-socket redirection contacted nothing. Arbitrary candidate dependency builds stayed unsupported. Fixed 16/0 ALLOW, original seeded 16/5 BLOCK; use each run's actual report, not older hashes/remote runs. No new remote PR/CI acceptance was claimed in that local batch.

Earlier isolation round: 81 passes, 14/5 seeded BLOCK, 14/0 fixed ALLOW, real HTTP smoke, one warning. Added exact-head independent review/base-evaluator pull_request_target. PR #5 awaited adoption; manual run 37184958648 passed but did not exercise PR-review guard. Separate live PR lookup correctly blocked unapproved baseline changes. Rules API still returned 403; main unprotected, author-only reviewer and dedicated-source/developer denial gaps remained. No self-approval substituted.

## First local/public baseline

Original private references/planning stayed local. Public pilot implemented Python harness, preinstall PyPI checks, real Gitleaks, PostgreSQL fixture, 14 AUTH cases, negative policy case, and Actions. Remote baseline later had 51 passes and PR positive/negative/early-BLOCK evidence; rules writes remained forbidden. ASVS's345 requirements had no product applicability determination, endpoints were UNVERIFIED. See [historical remote record](remote-ci-validation.zh-TW.md#en).

Fresh virtualenv/download/hash verification and fresh PostgreSQL rebuild succeeded. Initial local pytest 50/no failures/errors/skips included real Gitleaks/PostgreSQL; HTTP smoke passed four checks. Both before/after DB rebuild, separate run IDs/schemas produced G1 23 packages complete/G2 complete, vulnerable 14/5 BLOCK and fixed 14/0 ALLOW. Dependency compatibility passed with one Starlette TestClient/httpx warning; no similarly named package was installed as a speculative fix. YAML/action SHA/permissions/links were checked locally before remote Actions existed. artifacts/latest.txt and exact reports remain evidence; this prose is not publication proof.

Git HTTPS/PR/Actions delivery worked while ruleset administration returned Resource not accessible by integration. The historical next sequence was trusted remote PR gates/developer anti-bypass acceptance, then G3/full G5, cloud/local families, and G6. Later status supersedes implemented items. Credentials remain in secure settings, never source/chat.
