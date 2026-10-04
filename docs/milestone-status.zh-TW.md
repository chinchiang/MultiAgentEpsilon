# 第一個里程碑：實作狀態與驗收方式

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
