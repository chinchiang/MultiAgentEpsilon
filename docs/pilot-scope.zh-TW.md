[正體中文](#zh-tw) | [English](#en)

<a id="zh-tw"></a>

# 第一個試點：範圍與授權

本輪由使用者批准採用 Python／FastAPI、PostgreSQL、GitHub Actions 參考方案。只測工作區內自行建立的合成 fixture；第三方與正式產品不在本輪主動測試範圍；模型僅依獨立的 model RoE 執行固定合成案例。執行限制見 `security/roe.json`；runner 固定 loopback、120 秒 worker deadline 及最多 50 個案例，不接受任意目的地輸入或重新導向。

資料流：測試程式 → HTTP／ASGI → FastAPI 服務端授權 → PostgreSQL。Gitleaks／registry 回應是分析輸入，不能更改政策；模型與文件內指令不參與 gate 裁決。依賴來源預檢連 PyPI，漏洞查詢連固定 OSV API，套件只從核准 index 下載；固定 scanner 與 PostgreSQL 來自其已核對來源。

| 身分 | 租戶／角色 | 可以 | 不可以 |
|---|---|---|---|
| 匿名／偽造 token | 無 | 健康檢查、提交登入資料 | 讀寫資料、匯出 |
| alice | t1／member | 讀寫刪除 item 1 | 讀寫刪除 bob／t2 資料、改 owner、管理匯出 |
| bob | t1／member | 讀寫刪除 item 2 | 讀寫刪除 alice／t2 資料、管理匯出 |
| carol | t2／member | 讀寫刪除 item 3 | 讀寫刪除 t1 資料 |
| admin | t1／admin | 依委派讀寫刪除 t1 資料、匯出 t1 | 讀寫刪除或匯出 t2 資料 |

登入憑證隨每次 schema 產生；session 使用隨機 opaque token，資料庫只存 token hash，15 分鐘到期，登出即刪除。這是 fixture 的最小認證，不是完整登入安全方案，尚未驗證 MFA、防暴力破解或生產等級 session 政策。HTTP 僅本機，沒有 TLS 合規聲明。

受測操作為讀取、更新、刪除及租戶匯出，尚未提供建立等完整產品 CRUD。更新採單一具 tenant／owner／role 條件的 SQL，避免先查後寫的授權窗口。測試包含 32 個案例（含刪除、過期工作階段與輸入負例），會查 PostgreSQL 真實副作用；另有真實 HTTP 啟動／登入 smoke。可信 CI 在無網路容器中執行候選 fixture，由容器外的 oracle 經受限 HTTP bridge 與獨立資料庫查詢評分；本機開發另有 in-process HTTP／ASGI 版本。兩者都屬灰箱，不能稱為完整純黑箱 DAST。

刻意缺陷版只省略物件存取的 tenant／owner 約束，保留相同測試介面。預期抓到 bob／carol 的非法讀寫刪除各一次，加上 admin 跨租戶讀取、寫入與刪除，共 9 個違規；這組精確案例記錄在政策的 `seeded_defect_case_ids`，數量相同但換成其他案例失敗也不算通過。正式 server 腳本只允許 fixed variant；測試程式必須明確指定 vulnerable。

| 主要威脅 | 目前控制與證據 | 仍有限制 |
|---|---|---|
| 幻覺／來源切換／lock 污染 | 核准套件清單、PyPI 身分／hash、冷卻期、wheel-only；故障即停 | 已做 OSV 精確版本查詢；未做套件行為沙箱 |
| 機密進入原始碼／歷史 | 真實 Gitleaks、合成 canary 的發現／清除／歷史測試 | 沒有真正撤銷任何金鑰；不測金鑰活性 |
| BOLA／跨租戶／欄位或管理者越權 | 上表、伺服器端 SQL 約束、正反例及資料庫副作用 | 非完整 ASVS 存取控制驗證 |
| 掃描失敗被當成功 | policy 契約及 ERROR／TIMEOUT／零目標／錯 subject 等負例 | 已有 GitHub 簽章驗收；專用發布端部署未完成 |
| PR 更改自己的評分規則 | 基準版保護檔案檢查；敏感變更阻擋；main 規則集 24512048 已啟用 | 必要檢查仍由共用 Actions App 發布，專用 App 未部署；普通開發者負向驗收未執行 |
| 惡意測試標的／外連 | 本輪只執行已審查的合成程式；DB 資源與 loopback 限制 | 未驗證任意不受信 PR、惡意 wheel 或多租戶 runner 的隔離 |

AUTH fixture 的示範案例與 ASVS v5.0.0-8.2.1、8.2.2、8.2.3、8.3.1 的部分目的相關（盲測邊界案例 B07–B12 另有對照，見 [ASVS 覆蓋對照](asvs-coverage.zh-TW.md)）；僅為方法示例，未證明全部條文、所有路徑或任何等級符合。正式產品的資料分級、適用性、SLA、具名 owner／核准者及風險目標仍待盤點；本輪不替使用者指定。

<a id="en"></a>

# Pilot scope and authorization

The approved reference implementation uses Python/FastAPI, PostgreSQL, and GitHub Actions. Active security tests target only locally created synthetic fixtures, not third parties or production products. Model calls have separate reviewed model rules of engagement and fixed synthetic cases. `security/roe.json` restricts the security runner to loopback, a 120-second worker deadline, and at most 50 cases, without arbitrary targets or redirects.

Flow: test → HTTP/ASGI → server-side authorization → PostgreSQL. Scanner/registry responses are analysis inputs, never policy instructions. Instructions inside model output or documents do not decide gates. Package provenance uses PyPI; vulnerability queries use the fixed OSV API. Scanner and database artifacts have separately verified sources.

| Identity | Tenant/role | Allowed | Denied |
|---|---|---|---|
| Anonymous/forged token | None | Health and login submission | Data operations and export |
| alice | t1/member | Read/update/delete item 1 | Other owners/tenants, owner changes, admin export |
| bob | t1/member | Read/update/delete item 2 | Alice/t2 data and admin export |
| carol | t2/member | Read/update/delete item 3 | t1 data |
| admin | t1/admin | Delegated t1 operations and t1 export | t2 reads, changes, deletion, and export |

Credentials are generated per schema; opaque random sessions are stored as hashes, expire after 15 minutes, and are deleted on logout. This minimal fixture authentication does not establish MFA, brute-force resistance, production session policy, or TLS compliance.

The API supports read/update/delete and tenant export, not complete product CRUD. Conditional SQL binds tenant/owner/role in one write, avoiding an authorization gap between checking and changing data. The 32-case oracle includes deletion, expired sessions, input negatives, and real PostgreSQL side effects, with a real HTTP login smoke test. CI runs candidate fixtures in networkless containers; an external oracle uses a bounded HTTP bridge and independent database queries. The in-process developer variant and isolated version are gray-box tests, not complete black-box DAST.

The vulnerable variant removes object-level owner/tenant checks while retaining the interface. Exactly nine specified violations must appear: bob/carol unauthorized read/write/delete and admin cross-tenant read/write/delete. Same-count substitutions do not pass. The server entry point permits only the fixed variant; tests explicitly select the vulnerable one.

Threat controls include reviewed packages and hashes, cooling and wheels, OSV checks, Gitleaks canaries/history, server-side authorization and side effects, strict failure/coverage/subject contracts, protected changes, container isolation, and an active main ruleset. Limits remain: no malicious-package behavioral sandbox or key revocation/activity test; no complete product ASVS evaluation; no dedicated App deployment or developer-role denial acceptance; no claim of resistance to arbitrary hostile multi-tenant workloads, malicious wheels, or kernel/runtime vulnerabilities. CI signatures are implemented, but publisher deployment remains pending.

AUTH demonstrates parts of ASVS v5.0.0-8.2.1, 8.2.2, 8.2.3, and 8.3.1; see the [case mapping](asvs-coverage.zh-TW.md#en). This does not prove every requirement, route, or level. Product data classification, applicability, SLA, named owners/approvers, and risk goals still require a product-specific inventory and review.
