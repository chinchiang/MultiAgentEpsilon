# 第一個試點：範圍與授權

本輪由使用者批准採用 Python／FastAPI、PostgreSQL、GitHub Actions 參考方案。只測工作區內自行建立的合成 fixture；第三方、正式產品及外部模型均不在本輪主動測試範圍。執行限制見 `security/roe.json`；runner 固定 loopback、120 秒 worker deadline 及最多 50 個案例，不接受任意目的地輸入或重新導向。

資料流：測試程式 → HTTP／ASGI → FastAPI 服務端授權 → PostgreSQL。Gitleaks／registry 回應是分析輸入，不能更改政策；模型與文件內指令不參與 gate 裁決。依賴預檢只連 PyPI，套件只從核准 index 下載；固定 scanner 與 PostgreSQL 來自其已核對來源。

| 身分 | 租戶／角色 | 可以 | 不可以 |
|---|---|---|---|
| 匿名／偽造 token | 無 | 健康檢查、提交登入資料 | 讀寫資料、匯出 |
| alice | t1／member | 讀寫 item 1 | 讀寫 bob／t2 資料、改 owner、管理匯出 |
| bob | t1／member | 讀寫 item 2 | 讀寫 alice／t2 資料、管理匯出 |
| carol | t2／member | 讀寫 item 3 | 讀寫 t1 資料 |
| admin | t1／admin | 依委派讀寫 t1 資料、匯出 t1 | 讀寫或匯出 t2 資料 |

登入憑證隨每次 schema 產生；session 使用隨機 opaque token，資料庫只存 token hash，15 分鐘到期，登出即刪除。這是 fixture 的最小認證，不是完整登入安全方案，尚未驗證 MFA、防暴力破解或生產等級 session 政策。HTTP 僅本機，沒有 TLS 合規聲明。

受測操作為讀取、更新及租戶匯出，未提供建立／刪除等完整產品 CRUD。更新採單一具 tenant／owner／role 條件的 SQL，避免先查後寫的授權窗口。測試包含 18 個案例（含 admin 同租戶寫入與跨租戶寫入），會查 PostgreSQL 真實副作用；另有真實 HTTP 啟動／登入 smoke。可信 CI 在無網路容器中執行候選 fixture，由容器外的 oracle 經受限 HTTP bridge 與獨立資料庫查詢評分；本機開發另有 in-process HTTP／ASGI 版本。兩者都屬灰箱，不能稱為完整純黑箱 DAST。

刻意缺陷版只省略物件存取的 tenant／owner 約束，保留相同測試介面。預期抓到 bob／carol 的非法讀寫各一次，加上 admin 跨租戶讀取與跨租戶寫入，共 6 個違規；這組精確案例記錄在政策的 `seeded_defect_case_ids`，數量相同但換成其他案例失敗也不算通過。正式 server 腳本只允許 fixed variant；測試程式必須明確指定 vulnerable。

| 主要威脅 | 目前控制與證據 | 仍有限制 |
|---|---|---|
| 幻覺／來源切換／lock 污染 | 核准套件清單、PyPI 身分／hash、冷卻期、wheel-only；故障即停 | 未做套件行為沙箱或漏洞資料庫比對 |
| 機密進入原碼／歷史 | 真實 Gitleaks、合成 canary 的發現／清除／歷史測試 | 沒有真正撤銷任何金鑰；不測金鑰活性 |
| BOLA／跨租戶／欄位或管理者越權 | 上表、伺服器端 SQL 約束、正反例及資料庫副作用 | 非完整 ASVS 存取控制驗證 |
| 掃描失敗被當成功 | policy 契約及 ERROR／TIMEOUT／零目標／錯 subject 等負例 | 仍缺外部可信簽章與發布端驗證 |
| PR 更改自己的評分規則 | 基準版保護檔案檢查；敏感變更阻擋 | 遠端可信 workflow／ruleset 尚未部署驗證 |
| 惡意測試標的／外連 | 本輪只執行已審查的合成程式；DB 資源與 loopback 限制 | 未驗證任意不受信 PR、惡意 wheel 或多租戶 runner 的隔離 |

示範案例與 ASVS v5.0.0-8.2.1、8.2.2、8.2.3、8.3.1 的部分目的相關；僅為方法示例，未證明全部條文、所有路徑或任何等級符合。正式產品的資料分級、適用性、SLA、具名 owner／核准者及風險目標仍待盤點；本輪不替使用者指定。
