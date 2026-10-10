[正體中文](#zh-tw) | [English](#en)

<a id="zh-tw"></a>

# 離線突變測試與性質測試

現有九種人工授權缺陷變體持續保留。新增 `scripts/mutation_check.py` 自動以 Python AST 產生單一條件變更，檢驗測試是否確實攔截退化；Hypothesis 則產生輸入並縮減失敗反例。兩者用途不同，測試階段皆不需要外部服務、模型金鑰或 E2B。

## 安裝與執行

先依 README 建立 Python 3.12 環境，再安裝測試專用依賴：

```bash
python3 -I scripts/install_test_tools.py
.venv/bin/python -m pytest tests/test_security_properties.py tests/test_mutation_runner.py
.venv/bin/python -I scripts/mutation_check.py
```

首次安裝需要 PyPI、套件下載與 OSV 網路連線。`requirements-test.lock` 固定 Hypothesis／sortedcontainers／ruff 版本及 wheel SHA-256；安裝前核對名稱、來源、七天冷卻期、未撤回版本與漏洞結果，再以 wheel-only、no-deps、require-hashes 安裝。測試工具獨立於應用的 `requirements.lock`，不加入候選執行映像。安裝後突變與性質測試不使用網路；不是宣稱整套 G1／G2 安裝及安全管線均能離線運作。

## 範圍與判定

| 目標 | 自動突變範圍 |
|---|---|
| `security_harness/results.py` | `validate_cases`、`seeded_defects`、`decide` |
| `security_harness/trusted_publisher.py` | `strict_json`，不是整個發布器 |
| `security_harness/preflight.py` | `validate_package_policy`、`check_metadata` |
| `security_harness/authorization.py` | `same`（oracle 的型別嚴格 JSON 比對） |
| `security_harness/isolation.py` | `verify_container` |
| `security_harness/scope.py` | `valid_remote_hosts`、`validate_model_roe` |
| `security_harness/llm/benchmark.py` | `bounded_text`、`validate_review`、`parse_review` |

運算子涵蓋比較反轉、成員（`in`／`not in`）與身分（`is`／`is not`）反轉、含等號／不含等號的邊界、`and`／`or` 交換與否定條件反轉。突變節點以 AST 走訪順序定位，巢狀且起點相同的同型節點（例如 `a and b or c`）不會混淆。只變更指定函式，每次只有一個突變；來源與測試先複製為固定快照，原始工作目錄不被改寫。未涵蓋任意 AST 節點、任意程式或整個儲存庫。

突變子程序只選取純函式測試，模型命令列的子程序整合測試由完整 pytest 保留執行，不在禁止外部程序的突變子程序中重跑。

每個目標先執行未修改的基準，以及只經 AST 重新格式化、沒有突變的對照；兩者必須通過且案例識別一致，否則停止，避免把格式差異當成成功攔截。突變測試的 JUnit 必須完整、案例數與基準相同且沒有錯誤／跳過。退出碼 1 且有測試失敗才記為 `KILLED`；正常全過為 `SURVIVED`，逾時為 `TIMEOUT`，收集失敗、缺少證據等為 `ERROR`。逾時與工具故障均不算攔截，任何存活、逾時或錯誤都使命令及 CI 失敗；空清單或超過 256 個突變也失敗，不截斷成假綠。

每個子程序最多 30 秒、CPU 25 秒、位址空間 2 GiB、資料段 1 GiB、輸出檔案 2 MiB、128 個檔案描述元，禁用核心傾印；整批上限 20 分鐘。子程序使用隔離 Python、清空繼承憑證，並以 audit hook 禁止 socket 連線／綁定／DNS，以及 `subprocess`、`os.system`、`exec`、`posix_spawn`、`fork` 等所有外部程序啟動途徑。命令退出碼：0 全數攔截、1 有存活或逾時、2 參數錯誤、3 基礎設施錯誤。取消及逾時回收程序群組，暫存快照隨工作結束刪除。這是可信原始碼與固定運算子的測試護欄，**不是惡意候選程式的安全沙箱**。

## 證據與持續整合

報告位於 `artifacts/mutations/report.json`，含目標範圍、快照與來源雜湊、每個突變 ID／內容雜湊／結果、基準測試數、總數及分數。未完成時先保存 `INCOMPLETE`，正常完成才有 `COMPLETE` 與清理成功標記；工具錯誤記為 `ERROR`。原始分數為成功攔截數除以全部產生的突變數，不是產品安全分數或完整測試覆蓋率。等價突變亦須檢視原因，不能默默排除或算為成功攔截。

CI 在獨立的 `trusted-mutation-tests` job（30 分鐘上限）只執行可信評估器版本的突變測試，不取得候選檔案；最終必要檢查與發布器都要求該 job 成功，報告另存為 `trusted-mutations-*` artifact。本機報告本身未簽章。主機程序遭 SIGKILL／主機中斷時，報告可能停留 INCOMPLETE，不能當成成功。

Hypothesis 使用固定可重現設定、每項性質最多 80 個案例、停用範例資料庫；測試本身不連線。可重現反例另外寫成固定回歸。首輪已重現發布器接受浮點溢位 `1e309` 的問題，修正為拒絕巢狀非有限浮點數；並補上空白案例 ID、零覆蓋、精確有效期限、三項 finding、16 KiB 回應及 Unicode 變體選擇符邊界。

<a id="en"></a>

# Offline mutation and property testing

The existing nine hand-authored authorization mutations remain. `scripts/mutation_check.py` adds automatic single-predicate Python AST mutations to check whether tests detect regressions. Hypothesis generates inputs and shrinks failing examples. Neither test phase needs external services, model keys, or E2B.

## Installation and execution

After the README's Python 3.12 bootstrap, run the three commands in the Chinese section's command block (`install_test_tools.py`, the property/runner tests, `mutation_check.py`). Initial installation needs PyPI, wheel downloads, and OSV connectivity. `requirements-test.lock` pins Hypothesis/sortedcontainers/ruff and wheel SHA-256 hashes. Installation checks identity, origin, seven-day cooling, yanked artifacts, and vulnerabilities, then uses wheel-only/no-deps/require-hashes. Test tooling is separate from the application's requirements.lock and is not installed into the candidate runtime image. Subsequent mutation/property runs are offline; the entire dependency/security pipeline is not claimed to be offline.

## Scope and outcomes

Targets are results.py's validate_cases/seeded_defects/decide, trusted_publisher.py's strict_json, preflight.py's validate_package_policy/check_metadata, authorization.py's typed JSON comparison `same`, isolation.py's verify_container, scope.py's valid_remote_hosts/validate_model_roe, and benchmark.py's bounded_text/validate_review/parse_review. This is not the entire publisher or repository. Operators invert comparisons/membership/identity, change inclusive boundaries, swap and/or, and invert negation. Mutated nodes are located by AST walk position, so nested same-type nodes starting at one column (such as `a and b or c`) are not confused. One mutation is applied at a time to a fixed source/test snapshot; the working checkout stays unchanged.

The mutation worker selects pure-function tests; the model CLI subprocess integration test remains in full pytest but is deselected inside the process-denying mutation worker.

Each target first passes both its original baseline and an AST-normalized, nonmutated control with identical test identities. Failure of either stops the campaign, preventing formatting-only false kills. JUnit must exist, preserve baseline case counts, and contain no errors/skips. Exit 1 with failing tests is KILLED; a clean pass is SURVIVED. Timeouts are TIMEOUT; collection failures/missing evidence are ERROR. Neither infrastructure failures nor timeouts count as kills. Any survivor/timeout/error fails the command and CI. Empty or more-than-256 inventories fail rather than being silently truncated.

Each child has a 30-second wall deadline, 25-second CPU limit, 2 GiB address space, 1 GiB data segment, 2 MiB file limit, 128 descriptors, and no core dumps. Campaign deadline is 20 minutes. Isolated Python receives no inherited credentials; an audit hook denies socket connect/bind/DNS and every external process-launch path (subprocess, os.system, exec, posix_spawn, fork). Exit codes: 0 all killed, 1 survivors or timeouts, 2 usage error, 3 infrastructure error. Cancellation/timeouts terminate the process group, and temporary snapshots are removed. These are guards for trusted code and fixed operators, **not a hostile-candidate sandbox**.

## Evidence and CI

artifacts/mutations/report.json records scope, snapshot/source hashes, mutant IDs/content hashes/outcomes, baseline counts, totals, and score. INCOMPLETE is written first; normal completion records COMPLETE and successful cleanup, while tool errors record ERROR. Raw score is killed/generated, not product security or full coverage. Equivalent mutations must be investigated, not silently excluded or counted as killed. SIGKILL/host failure can leave INCOMPLETE evidence, never a pass.

CI runs only the trusted evaluator's mutation tool in a separate `trusted-mutation-tests` job (30-minute limit) without the candidate; the final required check and the publisher require that job, and its report is kept as a `trusted-mutations-*` artifact. Local reports are unsigned. Hypothesis uses deterministic settings, at most 80 examples per property, and no example database or network. Reproduced failures also become fixed regressions. The first campaign reproduced publisher acceptance of floating-point overflow 1e309, now rejected even when nested, and added empty-case-ID, zero-coverage, exact-expiry, three-finding, 16 KiB, and Unicode variation-selector boundary regressions.
