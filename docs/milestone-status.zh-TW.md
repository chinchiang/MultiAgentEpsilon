# 第一個里程碑：實作狀態與驗收方式

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

本文件記錄公開程式碼試點的實作狀態。使用者原始參考文件與內部規劃留在本地。首版已建立可在本地執行的 Python harness、PyPI 安裝前預檢、真實 Gitleaks、PostgreSQL fixture、14 個授權案例、政策負例與 GitHub Actions 工作流程。

目前完成合成 fixture 的本地及遠端 CI 試點。遠端最新基線有 51 項測試通過，PR 正反例與早期 BLOCK 證據已驗證；main 的規則管理寫入仍被整合權限拒絕。詳見 [遠端紀錄](remote-ci-validation.zh-TW.md)。ASVS 345 項清冊仍未做真實產品適用性判定，不把示範案例寫成完整條文通過。雲地模型端點仍為 UNVERIFIED。

## 可重現驗收

依 README 順序執行，結果保存在 `artifacts/`：

- `pytest.xml`：政策、套件 metadata、真實 Gitleaks、歷史機密、RoE、基準變更及 PostgreSQL 正反例。
- `http-smoke.json`：真實 loopback HTTP 健康、登入、合法讀取及同角色非法讀取。
- `<run-id>/report.json`：每次新 run 的 G1、G2、AUTH 結果及 ALLOW／BLOCK；缺陷版預期 5 個 AUTH findings，修正版預期 0。
- `latest.txt`：最新 run 的索引。檢查 report 的 subject／policy digest 與當次原碼，不能將舊報告當成本次結果。

`expect_block.py` 要求三項 gate 都確實完成、G1／G2 無 findings、14 個授權案例中有指定數量的違規；工具 ERROR 或沒有案例會使驗收失敗。完整的已知違規集合另由 pytest 精確比對。

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
| W08 | 遠端 main／PR 正反例與 guard 證據已驗證 | ruleset 寫入 HTTP 403；main 未受保護。可信來源綁定及普通開發者繞過驗收仍未完成。 |
| W10–W14 | 已記錄兩個優先模型候選；其餘待完成 | 已作有限連線檢查；雲端認證／正式 model ID 與地端受允許連線尚未具備，未做模型推論、gateway 或偏誤實驗。 |
| W15–W19 | 待完成 | 產品適用性、簽章證據、完整 release、營運與正式資料／預算治理。 |
| W21 | 限縮本地 RoE 已實作 | 任意網路掃描、redirect／DNS／工具委派與外部資產授權尚未實作。 |
| W22–W25 | 待完成 | 一手來源查核、組織成熟度評分、供應商驗收及產品弱點處理。 |

本地完整待辦保留各項規劃與驗收要求；上表列出此公開試點已完成的子集及缺口。

## 遠端阻礙與後續順序

Git HTTPS、PR 與 Actions 結果的讀取／交付已成功；ruleset 寫入明確回覆 `Resource not accessible by integration`。此管理權限不足阻止合併保護生效，不影響已完成的 CI 執行證據。可套用設定見 `github-main-ruleset.json`。

下一步是建立遠端可信 PR 閘門，驗證普通開發者無法更改評分規則、跳過 required workflow 或以偽造同名 status 放行。其後再擴 G3／完整 G5，盤點一雲一地與至少兩模型家族，逐步串接 G6。安全憑證透過環境設定提供，不寫入原碼或聊天。
