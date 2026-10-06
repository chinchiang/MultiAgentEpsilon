# MultiAgentEpsilon

Vibe Coding 資安測試框架的第一個可執行試點：Python 3.12、FastAPI、PostgreSQL、Gitleaks 與確定性政策判定。使用合成資料驗證「缺陷能被攔截、修正版能通過、工具故障不能假綠」。

目前支援 Linux x86_64 與可用的 Docker daemon。這是測試平台與刻意含缺陷的測試標的；不應部署成正式服務，也未完成 ASVS、G0–G6 或多模型驗收。

## 開始執行

在專案目錄執行：

```bash
python3 scripts/bootstrap.py
python3 scripts/build_runtime.py
python3 scripts/dev_db.py start
.venv/bin/python -m pytest --junitxml=artifacts/pytest.xml
.venv/bin/python scripts/smoke_http.py
.venv/bin/python scripts/expect_block.py
.venv/bin/python scripts/run_security.py
```

`bootstrap.py` 先核對 PyPI 套件、固定版本、所有 lock 雜湊、7 天冷卻期與 wheel 可用性；驗證 Gitleaks 官方 release checksum 及固定 binary digest，再跑 G2。成功後才下載與安裝 hash-verified wheels，禁用 source builds、額外 index 與隱含依賴解析。首版使用明確核准的 23 個套件；依賴更新需重新審查，不自動擴充 allowlist。

`build_runtime.py` 以固定 digest 的 Python 映像及已核對 hash 的 wheels 離線建立容器 runtime。`run_security.py` 在無網路、非 root、唯讀根檔案系統的容器執行候選程式。HTTP socket 位於容器的限額 tmpfs，由容器內 bridge 連線，透過有時間／大小限制的 Docker exec 通道傳回不可信回應；host 不解析候選控制的 socket 路徑。可信評分器在容器外核對回應與資料庫副作用。候選 lock 必須與受測 runtime 一致；依賴變更須先更新可信基準並重建。詳見 [可信執行與合併保護](docs/trusted-execution.zh-TW.md)。

`dev_db.py` 的 loopback 資料庫供本地開發與可信基準測試使用；隔離評分會另外建立無網路資料庫與最低所需權限的應用帳號，完成後移除。所有資料均為合成資料。

`expect_block.py` 會確認缺陷版**恰好**違反政策 `seeded_defect_case_ids` 指定的 **6 個授權案例**（bob／carol 越權讀寫各一、admin 跨租戶讀取與寫入）；數量相同但換成別的案例、或任意工具錯誤都不算成功。`run_security.py` 預設跑修正版，回傳碼 0 表示這次有限試點 ALLOW，1 表示 BLOCK。`ERROR`、`TIMEOUT`、必要零目標、缺 gate、過期或不同 subject／policy 的證據都不能 ALLOW。正向操作及資料庫副作用也會一起驗證。

結果 schema 為第 3 版，拒絕舊版 gate 證據：每筆 gate 綁定相同 run ID、subject 與 policy digest。subject 使用 `worktree-manifest-v1`，雜湊明確編碼的逐檔路徑、型態、執行權限、大小及內容 SHA-256。AUTH 必須包含政策指定的唯一案例集合；缺漏、重複、未知 ID 或彙總不一致均 BLOCK。

AUTH 有 18 個必要案例，包含錯誤密碼及不存在帳號，以及 admin 的同租戶寫入（允許）與跨租戶寫入（拒絕且無副作用）。拒絕回應、讀取及匯出依合成 API 契約比對完整 JSON，拒絕重複 key；每個案例核對完整 users／items／sessions 快照與允許的變更。這是合成 fixture 的契約，不是任意 API 的通用回應規則。五種已重現缺陷（含 admin 寫入條件越過租戶邊界）的真實隔離回歸見 `tests/test_adversarial_authorization.py`。

每次執行在解析設定前建立 `artifacts/<run-id>/report.json`；錯誤只保存階段與例外類型，不記錄敏感例外文字。`artifacts/latest.txt` 是 security run 索引；bootstrap、preflight 與 runtime-build 使用各自的索引。這些是未簽章的執行證據，不是可信 attestation。停止並刪除本地開發資料庫：

```bash
python3 scripts/dev_db.py stop
```

## 試點範圍

| 元件 | 已實作範圍 | 尚未涵蓋 |
|---|---|---|
| G0／G4 | [試點授權矩陣與威脅](docs/pilot-scope.zh-TW.md) | 真實應用 owner、完整威脅建模及適用性核准 |
| G1 | PyPI metadata、固定版本／hash、來源、冷卻期、wheel-only 安裝 | CVE／KEV／EPSS、SBOM、惡意套件行為、所有生態系 |
| G2 | 真實 Gitleaks、遮罩、工作樹及候選 HEAD 可達 blobs、限額 gzip／zip／tar 展開 | 服務端 Push Protection、遠端不可得歷史／快取、金鑰撤銷 |
| 授權回歸 | 登入負例、同角色、跨租戶、管理者讀寫、欄位限制、登出及完整 fixture 狀態；18 個案例 | 完整 G5／Web/API 黑箱掃描、TLS／CSRF／JWT／SSRF |
| 政策 | 嚴格結果格式、故障阻擋、subject／policy digest、基準變更檢查 | 簽章／可信發布、例外生命週期、不可繞過的遠端設定 |
| CI | 遠端 main／PR 正反例、固定 actions SHA、最小權限、早期拒絕證據與清理；main 規則已讀回 | 專用可信來源尚未部署，普通開發者繞過驗收仍未完成 |
| 多模型 | [受限 gateway 與三種 adapter](docs/model-gateway.zh-TW.md)、[合成盲測與裁決試點](docs/blind-review.zh-TW.md) | GLM 真實推論、兩個真實家族的多輪穩定性、完整 G6／偏誤驗收 |

[結構化輸出驗收](docs/structured-output.zh-TW.md)已完成 Gemini／Claude 對 B09～B12 的一輪真實配對：八個回應有效，分類與弱點行號皆符合標準答案；這不等於多輪穩定性或偏誤改善。

模型 runner 也由 supervisor 管理，成功結果需待清理完成才發布；SIGKILL 後使用 `scripts/cleanup_runs.py` 回收登記的 worker／AWS 程序群組。正式證據位於 `artifacts/<run-id>/report.json`，模型結果仍僅供參考。

G2 與 subject digest 共用輸入清冊：生成物名稱只在 repository 根目錄排除，巢狀同名來源仍納入；Python／pytest 快取另行排除，任何已追蹤的保留生成路徑會拒絕執行。來源 symlink、不可讀目錄、輸入超限及雜湊時檔案變動會拒絕。Gitleaks 的掃描快照重新命名並映射回原路徑，避免工具的隱含目錄排除縮減範圍，且不接受候選的 inline allow 註解。Git 歷史以候選 HEAD 可達的全部 blobs 為範圍，淺層 clone 會失敗。gzip／zip／tar 依限額展開；不支援、損壞、加密或超限內容會阻擋。二進位檔預設阻擋；需先把內容的 SHA-256 經審查加入 evaluator 端受保護的 `security/binary-allowlist.json`，之後仍以 ASCII／UTF-16LE 可讀字串掃描內嵌機密，內容一改就需重新審查。排除的依賴／暫存內容與其他 refs 不宣稱已掃描。

## CI 啟用界線

[security.yml](.github/workflows/security.yml) 改用 `pull_request_target`，只執行 base SHA 的 evaluator、安裝程序與測試；候選 checkout 僅作資料，只有限定的 `fixture_app` 來源會送入無網路容器。token 權限為 contents/read 與 pull-requests/read，不提供模型或部署金鑰。main push 與手動執行亦使用同一評分路徑；手動選取的 workflow ref 代表維護者選定的 evaluator，不能自動當成已核准基準。因此手動執行的檢查名稱固定為 `manual-security-evaluation`、artifact 為 `manual-security-*`，永遠不會滿足必要檢查 `trusted-security-pilot`。執行完畢前，CI 會用發布程式的同一套證據契約自我檢查（`check_publishable_evidence.py`），證據與契約不一致時該 run 直接失敗。

新執行入口預設受保護。基準更新需由可信 reviewer 對目前 head SHA 獨立核准；guard 即時查核 GitHub PR／reviews，撤回核准、換版或作者自行核准皆不放行。此 run 仍以舊基準判定，合併後才成為下一輪基準。

**main 規則集 24512048 已啟用並讀回確認。** 必要檢查仍使用共用 GitHub Actions App 15368；名稱與 App ID 無法唯一識別可信 workflow，任何有推送權限者都能以自己的 workflow 產生同名綠燈。專用 App 綁定前，審查者在核准或合併前應執行 `python3 scripts/verify_required_check.py --pr <編號>`：它以 GitHub 的 run 中繼資料確認 PR head 上每一個 `trusted-security-pilot` 都來自可信 workflow 路徑的 `pull_request_target` run，有任何一個來源不符即 BLOCK。[專用 App 發布程式與部署範本](docs/trusted-check-publisher.zh-TW.md)已準備，App 與服務尚未部署。基準遷移程序見 [操作文件](docs/trusted-execution.zh-TW.md)，先前遠端基線見 [驗收紀錄](docs/remote-ci-validation.zh-TW.md)。

## 文件與來源

- [試點範圍、授權矩陣與限制](docs/pilot-scope.zh-TW.md)
- [實際執行與剩餘待辦](docs/milestone-status.zh-TW.md)
- [遠端 CI 驗收及可套用的保護規則](docs/remote-ci-validation.zh-TW.md)

公開版本只包含程式碼、合成測試及操作文件。使用者提供的附件、內部研究／治理文件及其衍生表單保留於本地，不包含於公開 Git 歷史。當前完成度以 milestone status 為準；少量示範案例不代表符合完整 [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)。

掃描格式、總資源限制、SIGTERM／SIGINT／SIGKILL 清理回歸，以及遠端合併保護尚缺的前提，見 [覆蓋與生命週期驗收](docs/coverage-lifecycle-acceptance.zh-TW.md)。

新增越權、路徑穿越及 SSRF 的合成配對案例可用 `scripts/model_review.py --suite boundaries` 離線執行；行為反例、ASVS 5.0.0 對照與未涵蓋範圍見 [覆蓋對照](docs/asvs-coverage.zh-TW.md)。這些案例不代表正式應用已完成相同驗證。

可用 `--rounds` 在同一總預算內執行重複盲測；逐輪結果、失敗分類與穩定性判讀見 [多輪盲測文件](docs/repeated-review.zh-TW.md)。
