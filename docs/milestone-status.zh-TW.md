# 第一個里程碑：實作狀態與驗收方式

## 目前狀態（2026-10-06，以此節為準）

下方各節依日期記錄歷次批次。其中「main 未受保護」、14／16 個授權案例、5 個 findings、81／103／125／431 項測試等描述只代表當時狀態，不是現況。

### 遠端治理

- main 由規則集 24512048 保護：沒有 bypass、須經 PR 與 code owner 核准、推送新 commit 後舊核准失效、最後推送須另獲核准，必要檢查為 GitHub Actions App 15368 的 `trusted-security-pilot`。2026-10-06 為首次基準遷移由擁有者暫時停用，本文件合併後恢復為 active；最新狀態以 `python3 scripts/audit_merge_protection.py` 讀回為準。
- 這個必要檢查仍可由任何 workflow 以同名產生。專用 App 的 `epsilon/trusted-merge` 尚未建立、部署或綁定；過渡期間，審查者在核准或合併前以 `scripts/verify_required_check.py --pr <編號>` 核對檢查來源。
- **首次基準遷移已完成（2026-10-06）：** 擁有者暫時停用規則集後，以 merge commit 合併 [#6](https://github.com/chinchiang/MultiAgentEpsilon/pull/6)（`da567d8`）與 [#7](https://github.com/chinchiang/MultiAgentEpsilon/pull/7)（`0ac31cb`）。之後的 PR 由 main 上的新 evaluator 以 `pull_request_target` 評估。
- **仍缺獨立審查者：** CODEOWNERS 已列 chinchiang 與 CatGrocery，但 CatGrocery 尚不是具寫入權限的協作者。規則集恢復後，作者為 chinchiang 的 PR 仍需另一位具寫入權限的 code owner 核准才能合併；涉及受保護路徑的 PR 另需 `security/trust-policy.json` 中非作者的基準審查者核准，guard 才會放行。

### 遷移後的真實流程驗收（2026-10-06）

| 情境 | run | 結果 |
|---|---|---|
| #7 改以 main 為 base（第一次真實 `pull_request_target`） | [37446641158](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37446641158) | workflow 取自 main、evaluator 為 base `da567d8`；guard 偵測 29 個受保護變更且無獨立核准而 BLOCK，未執行任何候選步驟；檢查掛在 PR head |
| main 合併後（push，`0ac31cb`） | [37446694680](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37446694680) | 532 項測試全過；修正版 18／0 ALLOW；缺陷版恰好 6 個 seeded findings；證據自我檢查 PUBLISHABLE |
| 驗證 PR #8：admin 寫入越過租戶邊界 | [37447163081](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37447163081) | guard 放行（只改 fixture）；evaluator 自我測試 532 項全過；候選恰好出現 `admin cross-tenant write denied without side effect` 一個 finding，BLOCK |
| 驗證 PR #9：政策移除 AUTH 閘門 | [37447183081](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37447183081) | guard 以 `security/policy.json` 受保護且未獲核准而 BLOCK |
| 本文件 PR（只改 Markdown） | 見 PR 說明 | 正向驗證：guard 放行，完整可信流程成功 |

`verify_required_check.py` 也以真實 GitHub 資料核對：PR #5 舊 head `9a47966` 上手動觸發、候選自評的綠燈判為 `UNTRUSTED_CHECK_SOURCE`；#7 head 上真正的 `pull_request_target` 檢查來源可信，但因結果失敗判為 `LATEST_CHECK_NOT_SUCCESS`。#8、#9 驗證後已關閉、未合併，分支已刪除。

### 本版驗收（commit `2158448`，遠端手動 [run 37441975087](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37441975087)；之後的 commit 只改文件與範本測試下限）

- 532 項測試全數通過，0 失敗／錯誤／略過（其中可信閘門 PR 單獨為 266 項，見 [run 37407823134](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37407823134)）。
- 修正版 18 個授權案例、0 findings、ALLOW；缺陷版恰好是政策 `seeded_defect_case_ids` 指定的 6 個案例失敗，BLOCK。
- CI 以發布程式的同一套證據契約自我檢查，結果為 PUBLISHABLE。
- 手動 run 的檢查名稱為 `manual-security-evaluation`；該 head 上沒有 `trusted-security-pilot`。
- 本機 WSL 另跑過不含 Docker 隔離的完整子集，以及 admin 跨租戶寫入等真實隔離 mutation；WSL 的 Docker 延遲高，本機驗證時曾暫時放寬 Docker 逾時，提交的程式維持原時限，並以遠端 run 為準。

### 本版修正（2026-10-06）

- 手動執行不再以必要檢查名稱回報；新增審查者用的檢查來源核對工具。
- guard 只採計具寫入權限者的基準核准，並排除 head commit 的作者／提交者。
- 授權 oracle 補上 admin 同租戶寫入（允許）與跨租戶寫入（拒絕且無副作用）；缺陷版改為比對精確案例集合。
- 發布程式：負例綁定 evaluator 摘要與 evaluator SHA；run 綁定 PR head；以 head SHA 判定較新的 run，外部 fork PR 不能再阻斷發布；結果改變才發布 completed 檢查；blob 快取、節流退避、用後撤銷安裝權杖；設定須由 root 擁有、私鑰經 systemd `LoadCredential` 提供，unit 加強隔離。
- 合併保護稽核：看不到 `bypass_actors` 時視為未知而非沒有；必要檢查須核對 integration ID；另查專用 App 檢查與 base 分支 CODEOWNERS。
- G2：二進位內容須經審查列入 `security/binary-allowlist.json`（以 SHA-256 識別），之後仍以可讀字串掃描內嵌機密；未審查者照樣阻擋。
- janitor 單一 run 回收失敗不再中斷其他 run；模型 supervisor 回收逾時不再跳過收尾；容器清理逾時放寬為 30 秒。
- 模型：review 須能由原始回應重新導出並符合該次呼叫的回應雜湊；拒絕控制、格式（bidi、零寬）與分隔字元；補 Gemini 推理用量缺口；記錄供應商回報的服務模型以偵測別名漂移，模型識別改為每 run 金鑰化；AWS 子程序只取得 allowlist 環境變數，失敗時依固定分類記錄原因（不保存原文）；人工裁決須核對儲存的分析；live 呼叫另需 `security/model-roe.json`。

### 仍待完成

- **需擁有者操作：** 邀請獨立審查者並取得寫入權限（之後的 PR 才能依規則合併）、建立並部署專用 App、把 `epsilon/trusted-merge` 加入規則集，並以普通開發者身分完成繞過驗收。首次基準遷移已於 2026-10-06 完成。
- **功能面：** G3、完整 G5、SBOM／SCA／CVE、ASVS 產品適用性判定、證據簽章與正式發布、GLM 真實推論與結構化輸出、較大樣本的跨家族穩定性與偏誤實驗（2026-10-06 已完成 B07／B08 兩輪的雙模型小樣本驗收，見 [多輪盲測](repeated-review.zh-TW.md)），以及 W15–W25。
- 本地完整流程僅支援 Linux x86_64 與 Docker；Windows 需使用 WSL。

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

## 可重現驗收

依 README 順序執行，結果保存在 `artifacts/`：

- `pytest.xml`：政策、套件 metadata、真實 Gitleaks、歷史機密、RoE、基準變更及 PostgreSQL 正反例。
- `http-smoke.json`：真實 loopback HTTP 健康、登入、合法讀取及同角色非法讀取。
- `<run-id>/report.json`：每次新 run 的 G1、G2、AUTH 結果及 ALLOW／BLOCK；缺陷版預期恰好 6 個政策指定的 AUTH findings，修正版預期 0。
- `latest.txt`：最新 run 的索引。檢查 report 的 subject／policy digest 與當次原碼，不能將舊報告當成本次結果。

`expect_block.py` 要求三項 gate 都確實完成、G1／G2 無 findings，且 18 個授權案例中失敗的恰好是政策 `seeded_defect_case_ids` 列出的 6 個；工具 ERROR、沒有案例或換成其他案例失敗都會使驗收失敗。

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

## 實作待辦對照

| 原待辦 | 現在狀態 | 實作或剩餘工作 |
|---|---|---|
| W01、W07 | 試點範圍完成；產品盤點仍待做 | 合成資料、身分、授權矩陣與威脅已記錄；沒有替正式產品指定 owner／ASVS 等級。 |
| W02 | 原碼與規劃已整理於 repo | 公開程式碼與操作文件已發布，內部參考資料保留本地。 |
| W03 | 本地工具／fixture 環境已實作 | 固定 checksum／digest、wheel-only、DB 限權與可清理；不受信 PR／惡意套件的強隔離尚未驗證。 |
| W04 | 最小政策契約已實作 | 嚴格狀態、必要 coverage、錯 subject／policy、過期／重複／缺 gate；外部可信證據與發布還未完成。 |
| W05、W09 | 授權 fixture 子集已實作 | 缺陷與修正版使用相同 oracle；完整 G5 尚待擴充。 |
| W06、W20 | G1 metadata 與 G2 已實作 | G1 行為分析、SBOM／SCA、G3 尚未實作。 |
| W08 | 遠端 main／PR 正反例與 guard 證據已驗證；main 已由規則集 24512048 保護 | 專用可信檢查來源、具寫入權限的獨立審查者、首次基準遷移及普通開發者繞過驗收仍未完成。 |
| W10–W14 | 受限 gateway、三種 adapter、合成盲測與多輪框架已實作；Gemini／Claude 已有真實推論與兩輪雙模型小樣本驗收 | GLM 真實推論與結構化輸出、較大樣本的跨家族穩定性及偏誤實驗仍未完成。 |
| W15–W19 | 待完成 | 產品適用性、簽章證據、完整 release、營運與正式資料／預算治理。 |
| W21 | 限縮本地 RoE 已實作 | 任意網路掃描、redirect／DNS／工具委派與外部資產授權尚未實作。 |
| W22–W25 | 待完成 | 一手來源查核、組織成熟度評分、供應商驗收及產品弱點處理。 |

本地完整待辦保留各項規劃與驗收要求；上表列出此公開試點已完成的子集及缺口。

## 遠端阻礙與後續順序

Git HTTPS、PR 與 Actions 結果的讀取／交付已成功；ruleset 寫入明確回覆 `Resource not accessible by integration`。此管理權限不足阻止合併保護生效，不影響已完成的 CI 執行證據。可套用設定見 `github-main-ruleset.json`。

下一步是建立遠端可信 PR 閘門，驗證普通開發者無法更改評分規則、跳過 required workflow 或以偽造同名 status 放行。其後再擴 G3／完整 G5，盤點一雲一地與至少兩模型家族，逐步串接 G6。安全憑證透過環境設定提供，不寫入原碼或聊天。
