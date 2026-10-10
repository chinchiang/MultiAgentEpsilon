[正體中文](#zh-tw) | [English](#en)

<a id="zh-tw"></a>

# 2026-10-08 後續擴充與驗收

本文件保留 2026-10-08 擴充過程。後續 PR #16／#17 已獨立核准並合併，正式 main `438d7a4` 的 787 項測試、正反例與真實簽章已驗收（[run 37853277868](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37853277868)）。下方私人儲存庫失敗屬歷史批次。

## 依賴漏洞閘門

G1 在 PyPI 固定版本、SHA-256、來源與冷卻期查核之外，加入 OSV 精確版本查詢。每個鎖定套件都必須完成查詢；任何已回報漏洞均阻擋，包括沒有嚴重度的項目，不設自動忽略清單。OSV 沒有回報漏洞只表示當次資料庫查詢結果，不能證明套件安全。

每批最多 128 個套件、4 個並行查詢，每次 20 秒、回應上限 1 MiB。固定 HTTPS 目的地、保持 TLS 驗證、不跟隨重新導向、不重試、不讀取候選提供的網址或安裝套件。回應包含分頁游標、重複 JSON key、錯誤套件、撤回或重複 advisory、回應過大及資料庫不可用時，均不能當成完整查詢。

`report.json` 的 G1 記錄保留精確套件／版本、查詢時間、每筆回應摘要、advisory ID／CVE 別名及完整性。失敗保留 ERROR 查詢與已取得的 findings，不能抹掉未完成的分母。決策器與發布器要求 G1 的 SBOM、套件清冊、查詢清冊及 findings 相符且未過期；缺少 SCA 的舊式 G1 記錄不能在新政策下放行。

`sbom.cdx.json` 為 CycloneDX 1.6，清冊描述 **requirements.lock 宣告的套件與允許的 artifact 雜湊**；尚未聲稱是已安裝 wheel、容器映像或完整產品的物料清單。OSV 使用的漏洞資料、查詢摘要也不是由 OSV 簽署的證據。沒有實作 KEV／EPSS、惡意套件行為分析及其他生態系。

## 灰箱授權與工作階段

AUTH 必要案例由 18 增至 32：新增過期工作階段讀取／登出／刪除、匿名與偽造身分刪除、同角色／跨租戶刪除、擁有者及同租戶管理者合法刪除、重複刪除、偽造身分登出，以及 SQL 類字串登入／更新。

每個案例仍核對完整 HTTP 回應及 users／items／sessions 快照。合法刪除只允許指定資料消失，拒絕操作不得變更其他資料。容器橋接增加 DELETE；候選資料庫角色僅新增合成 items 表的 DELETE 權限，users 仍只能 SELECT，無權建立物件或改權限。

缺陷版必須恰好違反政策指定的 9 個讀／寫／刪除案例。新增的過期工作階段缺陷及管理者刪除跨租戶缺陷，連同既有五種變體，都由真實無網路容器及外部 PostgreSQL oracle 回歸；工具錯誤或其他案例失敗不算驗收成功。此試點仍沒有一般產品的端點探索、CSRF、JWT、密碼復原或完整 ASVS 適用性判定。

## 多模型變體與重複比較

合成目錄更新為 `synthetic-review-v3`，B01–B12 原始程式保持不變，新增 B13–B16：錯誤路徑字串前綴防護／相對路徑防護，以及只檢查 hostname／固定完整目的地的 SSRF 防護。標準答案有可執行反例：實際暫存檔讀取及 `httpx.MockTransport` 請求觀察，不呼叫真實內網。

新增 `variants` 套件。維持每批最多 16 次呼叫、8,192 個預留輸出詞元、130 秒總期限、不重試，模型結果只供參考。以兩個案例、兩個模型、兩輪構成每批 8 次呼叫，可以保留每次 1,024 個輸出詞元，避免擴大樣本時重新縮小輸出上限。

```bash
.venv/bin/python -I scripts/model_review.py --suite variants
.venv/bin/python -I scripts/model_review.py --provider gemini --provider bedrock \
  --case B13 --case B14 --rounds 2 --output-tokens 1024 --live
.venv/bin/python -I scripts/model_review.py --provider gemini --provider bedrock \
  --case B15 --case B16 --rounds 2 --output-tokens 1024 --live
```

舊 v2 真實模型報告保存為歷史證據；目錄及標準答案摘要不同，不能混入 v3 成績或以新版評分器重新背書。GLM 真實連線維持暫停。較大樣本與重複結果也不足以單獨證明偏誤降低。

## 可信檢查部署與遠端缺口

唯讀治理工具改用受限 GitHub HTTPS API，支援環境現有代理伺服器身分及既有 GH_TOKEN／GITHUB_TOKEN，不需額外登入或取得權杖。仍保留有上限的分頁、回應大小、期限及嚴格 JSON。工具不能發出寫入請求，也不能把管理者讀回結果冒充普通開發者的實際拒絕驗收。

```bash
python3.12 -I scripts/audit_merge_protection.py --pr <本輪PR> \
  --output artifacts/merge-protection-audit.json
python3.12 -I scripts/verify_required_check.py --pr <本輪PR>
```

本輪讀回 main 規則集 active、無 bypass、須獨立核准，必要檢查仍是共用 Actions App 15368。CatGrocery 與 d98922036ntu 具備審查權限。專用 App／Installation ID／受控 Linux 主機尚未提供，不能假填、用一般工作流程冒充 App，或在 Codex 暫存環境聲稱正式部署。

部署管理者依[部署步驟](trusted-check-publisher.zh-TW.md)建立 App 與主機後，使用已審查、合併、正式 CI 驗收的 main 產生部署包；候選部署包不會自動取得信任。綁定專用 App 必要檢查後，由普通開發者在隔離驗收 PR 驗證未核准、檢查失敗、同名偽造檢查及舊 head 核准皆不能合併，再驗證合法獨立核准可以合併。這些探測尚未執行。

## 驗收紀錄

結果以本輪實際 JUnit、正反例報告與 CI run 記錄為準；尚未完成的真實模型呼叫或部署不列為通過。

已完成的直接觀察：目前鎖定檔 23 個套件的 OSV 查詢完整、0 findings；未安裝的 urllib3 1.25.11 真實負例查詢取得 20 筆 advisory／20 個 CVE 別名，判為 BLOCK。B13–B16 兩個 mock 審查者各兩輪，共 16 次呼叫／8,192 預留輸出詞元全部完成，兩家各 4 TP／4 TN、0 FP／FN、8 組可比較結果零分歧，清理完成。這些 mock 成績不是 Gemini／Claude 成績。

AWS STS 經既有非機密設定選擇器確認回覆 ExpiredToken；已要求經安全環境設定更新臨時憑證。沒有自動切換付費模型、呼叫 GLM 或把未執行的 v3 真實配對列為成功。

## 簽章失敗不能留下可合併的綠燈

候選 CI [37781203657](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37781203657) 的評估工作完成 760 項回歸及正反例，但簽章工作因 GitHub 回覆「個人私人儲存庫不支援 artifact attestation」而失敗。這是失敗批次，不能列為完整 CI 成功或正式簽章驗收。當時連線修改可見度回覆 403；其後擁有者已恢復公開，完整重跑及簽章成功，未移除簽章要求。

本輪進一步將原評估工作的顯示名稱改為 `trusted-security-evaluation`，新增無權杖、無 checkout、無寫入權限的最終工作 `trusted-security-pilot`，依賴評估與簽章兩個工作。最終工作使用 `always()`，只有兩項結果都是 success 才通過；failure／cancelled／skipped 都失敗。手動執行使用 `manual-security-completion`，不能冒充必要檢查。

發布器要求評估、簽章、最終關卡三個工作及指定步驟全部成功。過渡期來源驗證器也重新讀取整個 workflow 的最新狀態及 attempt，防止既有 main 的評估綠燈掩蓋簽章失敗。16 種上游結果組合以實際 shell 回歸，另有整體 workflow 失敗、簽章失敗、最終工作缺失／跳過及缺少必要步驟等反例。

此修改已經獨立核准並合併，現行 main 包含最終關卡。合併仍須核對整體工作流程與來源；失敗批次保留，成功證據來自之後的完整重跑。

<a id="en"></a>

# Security expansion: 2026-10-08

This records the expansion later merged into main 438d7a4: 787 tests, fixed 32/0 and seeded 32/9 AUTH results, cleanup, and real signature verification in run 37853277868. Earlier candidate/private-repository failures remain historical, not the final result.

## G1: locked-package SBOM and OSV

CycloneDX 1.6 describes declared pinned Python lock contents and approved hashes, not installed runtime/image contents. OSV queries exact package versions at fixed HTTPS endpoints, up to 128 packages/four workers/20-second requests/1 MiB responses, with no redirects/retries/arbitrary URLs. Every advisory blocks regardless of missing severity. Partial pagination, duplicate/wrong packages, withdrawn or duplicate advisories, oversized/unavailable responses produce incomplete/error evidence.

G1 retains package/version/hash, query/advisory/CVE metadata, coverage, and partial-error evidence. Fresh SBOM/queries/provenance/findings must agree; old G1 evidence cannot pass. OSV is unsigned, not KEV/EPSS/behavioral analysis or other-ecosystem coverage. Package provenance verification remains part of G1.

## AUTH and review variants

AUTH expanded from 18 to 32 cases: session expiration/logout, anonymous/forged sessions, owner/tenant deletion, allowed owner/admin paths, repeat deletion, and SQL-like input. HTTP JSON and full database snapshots are checked. The bridge supports DELETE only as needed; app privileges grant items DELETE/users SELECT without schema-creation authority. Seeded variant must produce exactly nine IDs; seven additional real-container mutations must produce intended findings, never merely tool failures. This is not full-product DAST/CSRF/JWT-reset/ASVS coverage.

Catalog v3 preserves B01–B12 and adds B13–B16: sibling-path-prefix and hostname-only SSRF checks, paired with fixed full-boundary checks. Real temporary-file behavior and MockTransport verify these without internal traffic. Existing v2 model results are not v3 evidence. GLM live remains paused; bias reduction remains unestablished.

```bash
.venv/bin/python -I scripts/model_review.py --suite variants
.venv/bin/python -I scripts/model_review.py --live --provider gemini --provider bedrock --case B13 --case B14 --rounds 2 --output-tokens 1024
.venv/bin/python -I scripts/model_review.py --live --provider gemini --provider bedrock --case B15 --case B16 --rounds 2 --output-tokens 1024
```

Two cases/two providers/two rounds use eight calls and 8,192 reserved output tokens, under 16 calls/130 seconds. No increased budgets or silent retries.

## GitHub and historical acceptance

Native read-only GitHub proxy access needs no repository PAT; authorized mutations stay bounded. Audit BLOCK is not ordinary-developer behavioral proof. Main rules are active and both independent reviewers have write access, but dedicated App/installation/host remain missing. Deploy only independently approved main, not a successful candidate branch.

The locked 23-package set returned zero advisories. A deliberately uninstalled urllib3 1.25.11 negative fixture returned 20 advisories/20 aliases; it was queried, not installed. Offline variant collection used 16 calls/8,192 reserved tokens: each mock had four TP/four TN, zero FP/FN, eight comparable agreeing pairs, cleanup complete. These prove mechanics, not model quality.

AWS STS returned ExpiredToken for v3 live acceptance, which remained pending. Historical candidate run 37781203657 had 760 passing tests but failed artifact signing because GitHub did not support that personal private repository's attestations; evaluation alone was not a complete pass. The owner later restored public visibility; full main run 37853277868 succeeded with verified signatures and 787 tests. Signatures were not removed to bypass platform eligibility.

The final trusted-security-pilot job has no permissions/checkout and runs always, succeeding only if evaluation and signing both succeed. Manual runs use distinct names. Publisher validates all three jobs/steps, full workflow source, attempt, and signed artifact. All 16 upstream status combinations were tested in shell regressions. This final gate is merged, not merely a candidate proposal. Remaining work includes dedicated-App deployment/binding, actual developer-role negative acceptance, v3 live model samples, product applicability, broader languages/installed SBOMs, and operational governance.
