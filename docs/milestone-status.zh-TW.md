# 第一個里程碑：實作狀態與驗收方式

本文件記錄**現況與可辨識的歷史驗收**（2026-10-08）。各批次的原始紀錄與當時的數字移至[里程碑歷史紀錄](milestone-history.zh-TW.md)。

## 遠端治理

- main 由規則集 24512048 保護：沒有 bypass、須經 PR 與 code owner 核准、推送新 commit 後舊核准失效、最後推送須另獲核准、未歸屬變更需額外核准，必要檢查為 GitHub Actions App 15368 的 `trusted-security-pilot`。最新狀態以 `python3 scripts/audit_merge_protection.py` 讀回為準。
- 目前可信清單為 chinchiang、CatGrocery 與 d98922036ntu；CatGrocery 已接受協作邀請並具 write 權限（2026-10-07 讀回）。PR #14 已合併這項清單變更，三處設定一致；d98922036ntu 的 write 權限已於 2026-10-08 讀回確認。之後的 PR 依規則合併，不需再停用規則集；涉及受保護路徑的 PR，guard 另需具寫入權限、非作者、且未曾提交 PR 中任何 commit 的基準審查者核准。作者為 chinchiang 的 PR 在這項變更合併後可由 CatGrocery 或 d98922036ntu 獨立核准。
- 首次基準遷移已於 2026-10-06 完成：擁有者暫時停用規則集，以 merge commit 合併 #6（`da567d8`）與 #7（`0ac31cb`）。文件 PR #10 也在規則集停用期間合併，沒有審查紀錄；之後規則集已恢復 active。
- 必要檢查仍可由其他 workflow 以同名產生。`pull_request_target` 執行的是 PR **base 分支**上的 workflow，run 中繼資料不記錄 base；因此審查者在核准或合併前執行 `python3 scripts/verify_required_check.py --pr <編號>`，它要求檢查來自 `pull_request_target`、run 的 head 分支與此 PR 相同，且同一 SHA／head repository／分支沒有其他 base 或曾改 base 的 PR（含已關閉者）。專用 App 的 `epsilon/trusted-merge` 尚未建立、部署或綁定。

### 遷移後的真實流程驗收（2026-10-06）

| 情境 | run | 結果 |
|---|---|---|
| #7 改以 main 為 base（第一次真實 `pull_request_target`） | [37446641158](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37446641158) | workflow 取自 main、evaluator 為 base `da567d8`；guard 偵測 29 個受保護變更且無獨立核准而 BLOCK，未執行任何候選步驟；檢查掛在 PR head |
| main 合併後（push，`0ac31cb`） | [37446694680](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37446694680) | 532 項測試全過；修正版 18／0 ALLOW；缺陷版恰好 6 個 seeded findings；證據自我檢查 PUBLISHABLE |
| 驗證 PR #8：admin 寫入越過租戶邊界 | [37447163081](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37447163081) | guard 放行（只改 fixture）；evaluator 自我測試 532 項全過；候選恰好出現 `admin cross-tenant write denied without side effect` 一個 finding，BLOCK |
| 驗證 PR #9：政策移除 AUTH 閘門 | [37447183081](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37447183081) | guard 以 `security/policy.json` 受保護且未獲核准而 BLOCK |
| PR #10（只改 Markdown） | [37448552469](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37448552469) | 正向驗證：guard 放行，完整可信流程成功；合併時規則集仍停用，沒有審查紀錄 |

`verify_required_check.py` 也以真實 GitHub 資料核對過：PR #5 舊 head `9a47966` 上手動觸發、候選自評的綠燈判為 `UNTRUSTED_CHECK_SOURCE`；#7 head 上真正的 `pull_request_target` 檢查來源可信，但因結果失敗判為 `LATEST_CHECK_NOT_SUCCESS`。2026-10-07 另以真實 run 確認：#10 自己的 run 通過 base 綁定，#7 的 run 不能當成 #10 的來源（`RUN_HEAD_BRANCH`）。

## 2026-10-07 審查修正

深入審查後修正的項目（均附回歸測試）。驗收：commit `607b8c6` 的遠端手動 [run 37567019081](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37567019081)（`manual-security-evaluation`）共 610 項測試全過、0 失敗；修正版 18／0 ALLOW、缺陷版恰好 6 個 seeded findings BLOCK，兩者的 G2 `history_head` 都是候選自己的 commit；證據自我檢查 PUBLISHABLE（610 項）。之後的 commit 只改文件。

PR #12 已由 CatGrocery 對最新 head `58d9bc0` 獨立核准，正式 [run 37568335787／attempt 2](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37568335787/attempts/2) 執行舊 main 基準的 532 項測試全過，來源／digest／18 個正例及 6 個指定缺陷／清理均已核對。2026-10-07 在規則集維持 active、無 bypass 的情況下合併為 `41339c6`；合併後 main [run 37598381087](https://github.com/chinchiang/MultiAgentEpsilon/actions/runs/37598381087) 執行新基準的 610 項測試全過，證據自我檢查 PUBLISHABLE。532 與 610 分別屬於舊基準與新基準，不能混用。

- **候選 git 設定不能在 host 執行程式：** 所有對候選 repository 的 git 呼叫改經 `security_harness/candidate_git.py`，停用 fsmonitor／hooks／transport、清除 `GIT_*` 環境變數，並以明確 `--git-dir` 限定候選自己的 `.git` 目錄。
- **G2 必須涵蓋候選自己的歷史：** 政策新增 `history_required`；沒有 `.git`、沒有 commit，或位於外層 repo 內的子目錄都不能 ALLOW。
- **壓縮檔中繼資料：** zip／gzip 的註解、檔名與 extra 欄位一併掃描；zip 中未列出的位元組、帶資料的目錄項目，以及 tar 結尾後的資料一律阻擋。
- **`expect_block.py`：** 要求整個 run 完成且無錯誤、清理完成；改為可測試的函式並新增回歸。
- **supervisor 與 janitor：** worker 未經清理交接就回報決策時一律 ERROR；janitor 回收舊 run 時不再改寫 `artifacts/latest.txt`。
- **必要檢查來源：** 發布程式與 `verify_required_check.py` 把 `pull_request_target` run 綁定到此 PR（見上方「遠端治理」），並修正「一定執行預設分支 workflow」的錯誤註解。
- **核准排除：** guard 與發布程式排除 PR 中**任一** commit 的作者／提交者；PR commit 清單達 GitHub 上限 250 筆時拒絕。
- **模型 RoE：** `max_calls_per_run` 實際與規劃的 live 呼叫數比較；worker 在送出任何呼叫前核對案例目錄雜湊；supervisor 停止原因列入固定錯誤分類；`.env.example` 的佔位值判為 `CONFIGURATION`；報告新增遮蔽 ARN／帳號的 `model_label`。
- **測試安全：** CLI 超額測試改以不含任何模型憑證的環境執行；測試清理只刪除全為 mock 供應商的證據。
- **其他：** workflow 的 concurrency 依事件分組，手動執行不會取消 main 的 push run；掃描與隔離複製以不跟隨 symlink 的方式讀檔；所有 Docker 呼叫固定同一 daemon；worker 資源限額只定義一次；移除未使用的 `scripts/auth_worker.py`；公開文件移除 AWS 帳號識別資訊。

## 2026-10-07 部署準備補強

- 發布成功檢查前再次讀取同一 head 範圍的 PR 與 timeline，核對 head 分支、repository 與 base 綁定；驗證途中新增同 head、不同 base 的 PR（包含已關閉者）也不能放行。
- live 設定使用逐層目錄 descriptor，拒絕可替換上層目錄與中途 symlink，保留 root 持有、唯讀的檔案要求。
- `scripts/prepare_publisher_deployment.py` 產生固定 SHA 的部署封存、評估器／政策摘要與 SHA256SUMS；工作樹須乾淨，既有輸出不可覆寫，封存實際清冊須與評估器相同。App 識別值未提供時保留缺值。
- 本輪新增 17 項回歸，完整基準下限為 627。部署資料產生、離線測試及手動 CI 均不能代替獨立審查、正式 App 部署或遠端繞過驗收。

## 仍待完成

**需擁有者決定或操作：**

1. **決定是否清除 git 歷史中的 AWS 帳號識別資訊。** 目前文件已移除，但 commit `2158448` 起的歷史仍含該帳號 ID 與權限集名稱；帳號 ID 不是 API 金鑰；完全移除需另行核准的歷史改寫與協作安排，本輪不暫停規則集或強推，且公開期間可能已被快取。清除後可加入針對帳號 ID 的 Gitleaks 規則（歷史仍含該值時，加入規則會使每次掃描 BLOCK）。
2. **開啟 repository 的 Secret scanning、Push Protection、Dependabot alerts 與 Private vulnerability reporting**（`SECURITY.md` 指向此回報管道）。
3. **合併並驗收本輪簽章與固定 Actions 更新。** 獨立工作與消費端驗證已備妥；仍須透過受保護 PR 審查、確認真實遠端簽章與專用 App 消費結果，見[本輪修正](security-boundaries-20261008.zh-TW.md)。
5. 把 fork PR 的 workflow 核准政策改為所有外部貢獻者都需核准；開啟 Actions 的 SHA pinning 強制。
6. 建立並部署專用 App、把 `epsilon/trusted-merge` 加入規則集，並以普通開發者身分完成繞過驗收。
7. 選定授權條款（目前沒有 LICENSE，公開程式碼等同保留所有權利）。

**功能面：** G3、完整 G5、SBOM／SCA／CVE、ASVS 產品適用性判定、證據簽章與正式發布、GLM 真實推論與結構化輸出（依使用者指示暫停）、較大樣本的跨家族穩定性與偏誤實驗，以及 W15–W25。

**已知限制：** 本地完整流程僅支援 Linux x86_64、Python 3.12 與 Docker（Windows 需使用 WSL）；Starlette TestClient 仍有一項 httpx 棄用警告，遷移前需先做相容性評估。

## 可重現驗收

依 README 順序執行，結果保存在 `artifacts/`：

- `pytest.xml`：政策、套件 metadata、真實 Gitleaks、歷史機密、RoE、基準變更及 PostgreSQL 正反例。
- `http-smoke.json`：真實 loopback HTTP 健康、登入、合法讀取及同角色非法讀取。
- `<run-id>/report.json`：每次新 run 的 G1、G2、AUTH 結果及 ALLOW／BLOCK；缺陷版預期恰好 6 個政策指定的 AUTH findings，修正版預期 0。
- `latest.txt`：最新 run 的索引。檢查 report 的 subject／policy digest 與當次原碼，不能將舊報告當成本次結果。

`expect_block.py` 要求整個 run 的 `execution` 為 COMPLETED、沒有任何 errors、清理完成、variant 為 vulnerable、三項 gate 都確實完成、G1／G2 無 findings，且 18 個授權案例中失敗的恰好是政策 `seeded_defect_case_ids` 列出的 6 個；工具 ERROR、清理失敗、來源在執行中變動、沒有案例或換成其他案例失敗都會使驗收失敗。

測試數量以 pytest 收集的項目計算（含 parametrize 展開），不是 `def test_` 的函式數。

## 實作待辦對照

W 編號與 G0–G6 閘門編號都來自本地保留的原始規劃。依公開文件的用法：G0／G4 為範圍、授權矩陣與威脅，G1 為依賴，G2 為機密，G5 為 Web／API 授權與黑箱測試，G6 為多模型審查；G3 尚未實作，定義見原始規劃。

| 原待辦 | 現在狀態 | 剩餘工作 |
|---|---|---|
| W01、W07 | 試點範圍完成 | 正式產品盤點、owner 與 ASVS 等級指定。 |
| W02 | 公開程式碼與操作文件已發布 | 內部參考資料保留本地。 |
| W03 | 固定 checksum／digest、wheel-only、DB 限權、候選 git 強化 | 不受信 PR／惡意套件的強隔離（VM／microVM）尚未驗證。 |
| W04 | 嚴格狀態、必要 coverage 與歷史、subject／policy 綁定 | 外部可信證據與發布（簽章）。 |
| W05、W09 | 18 案例授權 fixture 與五種真實缺陷變體 | 完整 G5。 |
| W06、W20 | G1 metadata 與 G2（含壓縮檔中繼資料與歷史） | G1 行為分析、SBOM／SCA、G3。 |
| W08 | main 規則集 active、遠端正反例、run 與 PR base 綁定、全 commit 核准排除 | 專用可信檢查來源、artifact attestation、普通開發者繞過驗收。 |
| W10–W14 | gateway、三種 adapter、盲測與多輪框架；Gemini／Claude 真實小樣本驗收 | GLM 真實推論、較大樣本的穩定性與偏誤實驗。 |
| W15–W19 | 待完成 | 產品適用性、簽章證據、完整 release、營運與正式資料／預算治理。 |
| W21 | 限縮本地 RoE；模型 RoE 呼叫上限實際執行 | 任意網路掃描、redirect／DNS／工具委派與外部資產授權。 |
| W22–W25 | 待完成 | 一手來源查核、組織成熟度評分、供應商驗收及產品弱點處理。 |

## 2026-10-08 安全邊界修正

本輪完整 703 項回歸通過，新增歷程／混合審查／重跑者／fork 身分／預留／程序與掃描範圍等變體，並備妥獨立簽署與固定驗證器。完整對照、真實模型結果及外部待辦見[安全邊界修正](security-boundaries-20261008.zh-TW.md)。上述 627 等數字屬各段歷史基準，不是本輪測試下限；專用 App 尚未部署的狀態維持不變。
