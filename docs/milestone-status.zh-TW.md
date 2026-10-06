# 第一個里程碑：實作狀態與驗收方式

## 目前狀態（2026-10-06，以此節為準）

下方各節依日期記錄歷次批次。其中「main 未受保護」、14／16 個授權案例、5 個 findings、81／103／125／431 項測試等描述只代表當時狀態，不是現況。

### 遠端治理

- main 已由規則集 24512048 保護：active、沒有 bypass、須經 PR 與 code owner 核准、推送新 commit 後舊核准失效、最後推送須另獲核准，必要檢查為 GitHub Actions App 15368 的 `trusted-security-pilot`。
- 這個必要檢查仍可由任何 workflow 以同名產生。專用 App 的 `epsilon/trusted-merge` 尚未建立、部署或綁定；過渡期間，審查者在核准或合併前以 `scripts/verify_required_check.py --pr <編號>` 核對檢查來源。
- **合併死結：** 儲存庫只有一位 collaborator（chinchiang，同時是 PR 作者），main 的 CODEOWNERS 只列 chinchiang，而 GitHub 不允許作者核准自己的 PR；CatGrocery 尚不是具寫入權限的協作者。完成擁有者授權的首次基準遷移前，任何 PR 都無法依規則合併。
- 新的 `pull_request_target` workflow 必須先成為 main 的內容，才會對 PR 自動執行；在此之前，PR 上不會出現可信的必要檢查。

### 本版驗收（commit `e79c5cd`，遠端手動 [run 37404856995](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37404856995)）

- 525 項測試全數通過，0 失敗／錯誤／略過。
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
- janitor 單一 run 回收失敗不再中斷其他 run；容器清理逾時放寬為 30 秒。

### 仍待完成

- **需擁有者操作：** 邀請獨立審查者並取得寫入權限、執行擁有者授權的首次基準遷移（見 [可信執行文件](trusted-execution.zh-TW.md)）、建立並部署專用 App、把 `epsilon/trusted-merge` 加入規則集，並以普通開發者身分完成繞過驗收。
- **功能面：** G3、完整 G5、SBOM／SCA／CVE、ASVS 產品適用性判定、證據簽章與正式發布、多模型 gateway 與盲測（後續 PR），以及 W15–W25。
- 本地完整流程僅支援 Linux x86_64 與 Docker；Windows 需使用 WSL。

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
| W10–W14 | 端點盤點範本已記錄；受限 gateway、adapter 與合成盲測在後續的多模型 PR | 模型推論、gateway、兩個模型家族的多輪穩定性及偏誤實驗仍未併入本 PR。 |
| W15–W19 | 待完成 | 產品適用性、簽章證據、完整 release、營運與正式資料／預算治理。 |
| W21 | 限縮本地 RoE 已實作 | 任意網路掃描、redirect／DNS／工具委派與外部資產授權尚未實作。 |
| W22–W25 | 待完成 | 一手來源查核、組織成熟度評分、供應商驗收及產品弱點處理。 |

本地完整待辦保留各項規劃與驗收要求；上表列出此公開試點已完成的子集及缺口。

## 遠端阻礙與後續順序

Git HTTPS、PR 與 Actions 結果的讀取／交付已成功；ruleset 寫入明確回覆 `Resource not accessible by integration`。此管理權限不足阻止合併保護生效，不影響已完成的 CI 執行證據。可套用設定見 `github-main-ruleset.json`。

下一步是建立遠端可信 PR 閘門，驗證普通開發者無法更改評分規則、跳過 required workflow 或以偽造同名 status 放行。其後再擴 G3／完整 G5，盤點一雲一地與至少兩模型家族，逐步串接 G6。安全憑證透過環境設定提供，不寫入原碼或聊天。
