# MultiAgentEpsilon

Vibe Coding 資安測試框架的第一個可執行試點：Python 3.12、FastAPI、PostgreSQL、Gitleaks 與確定性政策判定。使用合成資料驗證「缺陷能被攔截、修正版能通過、工具故障不能假綠」。

目前支援 Linux x86_64 與可用的 Docker daemon。這是測試平台與刻意含缺陷的測試標的；不應部署成正式服務，也未完成 ASVS、G0–G6 或多模型驗收。

## 開始執行

在專案目錄執行：

```bash
python3 scripts/bootstrap.py
python3 scripts/dev_db.py start
.venv/bin/python -m pytest --junitxml=artifacts/pytest.xml
.venv/bin/python scripts/smoke_http.py
.venv/bin/python scripts/expect_block.py
.venv/bin/python scripts/run_security.py
```

`bootstrap.py` 先核對 PyPI 套件、固定版本、所有 lock 雜湊、7 天冷卻期與 wheel 可用性；驗證 Gitleaks 官方 release checksum 及固定 binary digest，再跑 G2。成功後才下載與安裝 hash-verified wheels，禁用 source builds、額外 index 與隱含依賴解析。首版使用明確核准的 23 個套件；依賴更新需重新審查，不自動擴充 allowlist。

`dev_db.py` 只管理帶本專案 label 的容器。資料庫以非 root、唯讀根檔案系統、tmpfs、資源限制及 loopback port 55432 執行；密碼每次新建時產生，保存在忽略版控的 `.state/db.json`。這是本地 fixture 的隔離設定，尚非惡意程式碼／多租戶 runner 的安全認證；bridge 網路也未提供全面出向封鎖。

`expect_block.py` 會確認缺陷版的 **5 個授權違規**被觀測到；任意工具錯誤並不算成功。`run_security.py` 預設跑修正版，回傳碼 0 表示這次有限試點 ALLOW，1 表示 BLOCK。`ERROR`、`TIMEOUT`、必要零目標、缺 gate、過期或不同 subject／policy 的證據都不能 ALLOW。正向操作及資料庫副作用也會一起驗證。

每次執行寫入新的 `artifacts/<run-id>/report.json`；`artifacts/latest.txt` 只供尋找最新 run，不是可信 attestation。報告記錄 subject／policy digest、案例及工具版本，沒有真實模型呼叫或生產資料。停止並刪除自己建立的測試資料：

```bash
python3 scripts/dev_db.py stop
```

## 試點範圍

| 元件 | 已實作範圍 | 尚未涵蓋 |
|---|---|---|
| G0／G4 | [試點授權矩陣與威脅](docs/pilot-scope.zh-TW.md) | 真實應用 owner、完整威脅建模及適用性核准 |
| G1 | PyPI metadata、固定版本／hash、來源、冷卻期、wheel-only 安裝 | CVE／KEV／EPSS、SBOM、惡意套件行為、所有生態系 |
| G2 | 真實 Gitleaks、遮罩、工作樹及本地可得完整 Git refs | 服務端 Push Protection、遠端不可得歷史／快取、金鑰撤銷 |
| 授權回歸 | 同角色、跨租戶、管理者、欄位限制、登出及寫入副作用；14 個案例 | 完整 G5／Web/API 黑箱掃描、TLS／CSRF／JWT／SSRF |
| 政策 | 嚴格結果格式、故障阻擋、subject／policy digest、基準變更檢查 | 簽章／可信發布、例外生命週期、不可繞過的遠端設定 |
| CI | 固定 actions SHA、最小 token 權限、完整 checkout、證據保存及清理 | 遠端執行、required workflow／ruleset 與一般開發者繞過驗收 |
| 多模型 | [端點盤點範本](security/models.example.json)，所有端點 UNVERIFIED | 雲地串接、mock gateway、G6、家族獨立審查及偏誤實驗 |

G2 掃描排除 `.git` 的原始檔、`.venv`、`.tools`、`.state`、`artifacts` 與快取；Git 歷史由 `gitleaks git --log-opts=--all` 另處理。淺層 clone 會失敗；未有第一個 commit 時明列 history NOT_AVAILABLE。排除的依賴／暫存內容不宣稱已掃描，fixture 密碼及未遮罩診斷不能提交或上傳。

## CI 啟用界線

[security.yml](.github/workflows/security.yml) 可在 main push、PR 或手動觸發。PR 使用 base SHA 的檢查程式，對 workflow、policy、harness、測試、bootstrap 及 lock 等敏感變更先阻擋，等候獨立審查。首次空分支沒有基準，應先由維護者建立可信基線。

**PR 自己可以修改 YAML，因此 YAML 內的檢查不足以保護該工作流程。** 必須在 GitHub 設定外部可信 required workflow／ruleset（依方案可用性），限制 bypass、直接 push 及保護檔案變更，並實際嘗試繞過。一般 required status 的名稱相同也不保證來自可信 evaluator。敏感變更須經獨立可信流程審查後更新基準，不能刪掉 guard 讓 PR 自行通過。

目前只驗證本地流程；GitHub API 已可讀取 repo，但部分 Actions 管理操作仍回覆整合權限不足；遠端部署與保護驗收結果會另記於 milestone status。啟用前也須評估不受信 PR 的 runner／網路／憑證隔離；本試點不使用 `pull_request_target`、部署憑證或模型金鑰。

## 文件與來源

- [試點範圍、授權矩陣與限制](docs/pilot-scope.zh-TW.md)
- [實際執行與剩餘待辦](docs/milestone-status.zh-TW.md)

公開版本只包含程式碼、合成測試及操作文件。使用者提供的附件、內部研究／治理文件及其衍生表單保留於本地，不包含於公開 Git 歷史。當前完成度以 milestone status 為準；少量示範案例不代表符合完整 [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)。
