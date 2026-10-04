# 可信執行、基準更新與合併保護

此版本修正覆蓋判定、掃描範圍與早期錯誤證據，並將候選程式移出評分器行程。主分支是否受到 GitHub 保護必須另行讀回驗證；本文件與規則 JSON 不構成已啟用的證據。

## 執行邊界

1. PR 工作流程由 `pull_request_target` 觸發，從 base SHA checkout evaluator。候選 head SHA checkout 到另一目錄，僅由可信工具讀取，不能在 runner 上直接執行候選 bootstrap、pytest、conftest、Dockerfile 或程式。
2. 可信 bootstrap 安裝基準 lock 的 wheels；runtime 以固定 Python image digest、離線網路及 `--require-hashes` 建置。候選來源不能提供建置指令。runtime 記錄 image ID 及 lock／entrypoint／builder 的 hash；修改後須重建。
3. AUTH 將限定的 Python fixture 來源複製成唯讀快照，容器使用非 root UID、唯讀 root filesystem、cap-drop、no-new-privileges、CPU／記憶體／PID 限制與 `--network=none`。
4. 候選只能讀取合成 app 設定、使用唯讀掛載的 PostgreSQL Unix socket，及在獨立目錄建立 HTTP Unix socket。它不取得 DB 管理員密碼、評分器、報告、GitHub token、模型憑證或 Docker socket。
5. PostgreSQL 在另一個無網路容器中使用 SCRAM 認證；app 帳號僅有指定 schema/table 所需權限。可信 host oracle 獨立建置資料與查詢副作用，透過 Unix socket 發送真實 HTTP 請求；拒絕重新導向與壓縮回應，限制回應大小及 timeout。
6. AUTH 超時／取消後，父程序依唯一 run label 清除本次容器；普通結束亦在 finally 清除。錯誤及未完成 gate 保存為 BLOCK。來源或 evaluator 在執行期間持續變動也會 BLOCK。

這是 Linux 容器邊界，仍共用 host kernel，不能宣稱抵抗 kernel／runtime 漏洞。正式敵意多租戶使用仍應採專用短生命週期 VM／microVM、受控 worker 身分與平台隔離。候選合成 app 可以破壞自己的資料或服務，這會導致測試失敗，不可把 app 自報結果當 oracle。

## 案例、輸入與錯誤證據

- `security/policy.json` 的 `gate_contracts` 指定 gate kind 與必要 case ID。AUTH 必須恰好涵蓋唯一集合；數量、findings 與逐案例結果須一致。schema 2 拒絕 schema 1 舊證據及不同 run ID 的混用。
- 掃描／subject 共用 `security_harness/inputs.py`。只在 repo 根目錄排除生成目錄；Python／pytest 快取為明列例外，已追蹤的保留生成路徑會拒絕。候選容器使用相同清冊的 fixture Python 子集，未納入來源不會掛載。
- Gitleaks 使用重新命名的快照，映射回原始檔名；原始 `.git` 等名字不能觸發工具的隱含略過，候選 inline allow 與 ignore file 不能自行抑制可信掃描。
- Audit envelope 在設定解析之前寫出，subject／policy 尚不可得時保留 null。錯誤只記錄階段與例外型別。報告採原子替換，初始 RUNNING 報告一律 BLOCK；沒有成功完成的證據不得放行。
- `artifacts/latest.txt` 僅索引 security run；其他入口各有 `<operation>-latest.txt`。目前 artifact 未簽章，CI 保存 7 天，不是長期不可竄改證據庫。

## 合法基準更新

一般 app Python 與 Markdown 文件變更可走既有基準；其他路徑預設受保護，包括新增 `conftest.py`、Python import 入口、ignore/config、workflow、工具與測試。

受保護變更使用以下流程：

1. 開立 PR，完成差異審閱及候選版本驗證。此時舊基準可以拒絕變更，屬預期行為。
2. `security/trust-policy.json` 中的基準 reviewer 對目前 head SHA 核准；reviewer 必須不同於 PR 作者。核准權限來自 base 版本的政策，不能由 PR 自增 reviewer。
3. 重新執行可信工作流程。guard 即時查詢 GitHub PR 與 reviews，確認仍 open、base/head 相符、最後有效決定為 APPROVED 且 commit_id 相同。查詢失敗、撤回、CHANGES_REQUESTED 或 head 變動均不授權。
4. 此輪依然由舊 evaluator／policy 執行。核准變更不代表新 evaluator 已自動證明正確；維護者需評估新增政策與測試的驗收證據。合併後的新 commit 才成為下一輪基準。

`pull_request_target` 不會因 review submitted 自動重跑；審核後由有權人員 rerun 對應的 head run。禁止用 PR label、候選檔案或任意 CLI approval 字串取代 GitHub 的即時審核查驗。單人作者不能自行核准自己的 PR；需有合格的獨立 reviewer。

## 首次遷移與 GitHub 管理設定

舊 main 的 guard 不支援此更新流程，且新 workflow 尚未成為預設分支內容。因此第一次採納此版本屬明確的基準遷移：維護者先審查 PR 與手動 workflow 驗證，再採納新基準；不能把舊 guard 的拒絕偽裝成成功。手動 workflow 的 evaluator 由執行者選定 ref，只能當選定版本的測試證據。

`docs/github-main-ruleset.json` 提供最低合併保護候選設定：禁止刪除／強推、獨立 CODEOWNERS 核准、變更後重審、嚴格 required check `trusted-security-pilot`、無 bypass。管理者完成基準遷移後才套用，避免要求尚不存在的檢查而卡住所有更新。

**GitHub Actions app ID + check 名稱仍不唯一綁定 evaluator workflow。** 若要把檢查視為不可偽造的自動閘門，需額外採平台支援的 required workflow，或獨立 GitHub App：App 必須查核 repository、workflow 身分／可信 evaluator SHA、事件、候選 SHA、run attempt、完整報告與結論後，才對候選 SHA 發佈必要檢查。其他 workflow 的 GITHUB_TOKEN 不應能以該 App 身分發佈檢查。此獨立來源機制目前未部署，不能聲稱一般開發者無法偽造同名檢查。

管理驗收至少包含：普通開發者直接 push 失敗、未核准政策修改阻擋、同名假檢查不放行、核准後換 SHA 失效、合法更新成功、規則讀回顯示 active。需使用普通開發者角色，不以 owner/admin 的測試代替。若 ruleset API 回覆 403，程式與 CI 驗證仍可完成，但遠端保護必須維持未完成狀態。

## 本地驗收

```bash
python scripts/bootstrap.py
python scripts/build_runtime.py
python scripts/dev_db.py start
.venv/bin/python -m pytest --junitxml=artifacts/pytest.xml
.venv/bin/python scripts/expect_block.py
.venv/bin/python scripts/run_security.py
python scripts/dev_db.py stop
```

隔離回歸會執行缺陷版、修正版，以及在候選匯入時嘗試寫入唯讀來源／入口、讀取 evaluator／Docker socket／token、建立 IP 出向連線的探測。必要結果為：完整 14 案例、缺陷版 5 findings／BLOCK、修正版 0 findings／ALLOW，以及邊界探測符合限制。
