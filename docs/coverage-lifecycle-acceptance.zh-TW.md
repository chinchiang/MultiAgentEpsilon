# 掃描覆蓋、資源限制與取消驗收

## 掃描契約

工作樹與 subject manifest 共用檔案清冊。G2 額外掃描**候選 HEAD 可達的全部 Git blobs**，包括從工作樹移除的舊內容；不將其他本地分支、遠端不可得物件算入本次覆蓋。報告保存 history_head、history_blobs 與 finding 的 object_id，結束前再次核對 HEAD。

支援 UTF-8 文字及以 magic 辨識的 gzip、zip、ustar。壓縮成員只讀入平坦掃描快照，絕不依 archive 路徑解壓至檔案系統。未知二進位、加密 ZIP、link／特殊成員、不安全路徑、壞檔與超限皆產生 G2 ERROR／INCOMPLETE，不能當成零 findings 通過。這不代表支援任意編碼、加密或所有封裝格式。

報告區分 selected_files／selected_bytes、scanned_leaves／scanned_bytes、expanded_bytes、archives 與 history_blobs。政策要求 COMPLETE、unsupported_files=0 及與 gate 相符的檔案數；單獨填入正數 coverage_count 不足以放行。

## 硬上限

| 項目 | 上限 |
|---|---|
| 工作樹檔案數／單檔／總輸入 | 20,000／20 MiB／64 MiB |
| Git 歷史 blobs／原始 blob 總量 | 20,000／128 MiB |
| 工作樹＋歷史＋展開內容累計讀取 | 64 MiB（壓縮前後皆計費） |
| Archive 巢狀深度／成員 | 3／2,000 |
| 外層管線執行期限 | 600 秒；AUTH 另有 120 秒期限 |
| Worker 與其子程序 | 每程序資料記憶體 512 MiB、虛擬位址 8 GiB、CPU soft/hard 120/125 秒、單一輸出檔 64 MiB、256 descriptors、禁用 core dump |
| 候選／資料庫容器 | 各 1 CPU、512 MiB、128 PIDs；既有唯讀 root 與無網路限制 |
| HTTP 通道 | 16 KiB request、64 KiB body、128 KiB envelope、5 秒 host bridge deadline；候選 tmpfs 16 MiB |

較大的虛擬位址上限供 Gitleaks 的 WebAssembly 引擎保留位址；不等於允許每程序寫入 8 GiB 資料。過小的 RLIMIT_AS 會讓掃描器無法啟動，因此另以 RLIMIT_DATA 約束資料記憶體。來源清冊、展開量及 scanner report 另有獨立上限。

執行期限到達或收到取消後，另有有界終止／清理寬限（最多約 36 秒）。Docker 清理逾時或任何清理失敗皆 BLOCK，保留 owner 標記供重試，不宣稱已清除。

## 取消與孤兒回收

`run_security.py` 的 CLI 啟動外層 supervisor，整個 G1／G2／AUTH worker 使用獨立 process group。supervisor 擁有 `.state/runs/<run-id>` 標記與短路徑暫存目錄；短路徑避免 PostgreSQL Unix socket 超過 Linux 限制。

- SIGTERM／SIGINT／deadline：終止整個程序群組，依 run label 刪除容器，再刪除本輪暫存目錄。
- Supervisor 被 SIGKILL：沒有任何程式能在 SIGKILL 中執行 finally；須由 `scripts/cleanup_runs.py` 回收。它比對 PID、start time、boot ID 與 UID，只回收已死亡 owner，不觸碰其他仍在執行的 run。
- CI 的 always 清理步驟與後續任務可執行 janitor；若 runner 本身也被立即摧毀，需 runner／環境生命週期負責容器銷毀，不能以本機 finally 保證。
- Worker 的 ALLOW 在清理前只是 pending_decision；對外 decision 維持 BLOCK。supervisor 清理成功後才正式放行，避免先發布綠燈再發現殘留資源。

```bash
.venv/bin/python -I scripts/cleanup_runs.py
.venv/bin/python -m pytest --junitxml=artifacts/coverage-lifecycle-pytest.xml
.venv/bin/python -I scripts/run_security.py
.venv/bin/python -I scripts/expect_block.py
```

本輪本地回歸：125 passed，0 failures/errors/skips，1 項既有 Starlette 棄用警告。包含壓縮機密、已刪除的壓縮歷史機密、壓縮炸彈／巢狀／路徑穿越、完整狀態 AUTH 變體、真實程序群組 timeout，以及帶真實無網路容器的 SIGTERM／SIGINT／SIGKILL 回收。

## 遠端合併保護：尚未完成

`scripts/audit_merge_protection.py` 是唯讀設定稽核，**不是行為驗收通過證明**。它保留六種尚未執行的 probe，回傳 BLOCK，不用管理員讀取結果代替普通開發者實測。

2026-10-04 再次觀測：main 未受保護、rulesets 為空、作者為唯一 collaborator／baseline reviewer。嘗試建立 disabled 規則草稿也得到 `403 Resource not accessible by integration`；沒有啟用或改動 main 保護。

完成前提：

1. 目前 GitHub 連線需要可寫 repository Administration 的 integration 權限；repo 回傳使用者 admin=true 並不等於 integration 具有此 API 權限。
2. 提供並授權一位非作者的 reviewer，以及普通 Write 身分（可由同一人兼任），更新 reviewer／CODEOWNERS 並完成獨立核准。
3. 部署可信必要檢查來源：平台可用的 required workflow，或外部獨立 GitHub App 驗證 evaluator、candidate SHA、事件、run attempt 與完整證據。Actions app ID 15368 + 同名 check 不足以達成。
4. 先完成可信基準導入與 check/head 綁定，再啟用保護；不得將尚未審查的 PR 自行合併來繞過此步。
5. 以非管理員驗證直接 push 拒絕、未核准政策修改拒絕、偽造同名 check 無效、換 head 舊核准失效、撤回核准重新阻擋，以及合法獨立核准成功。

本輪管理權限拒絕屬 GitHub API 授權問題，並非自動核准審查拒絕。遠端 CI 成功也不代表上述保護已生效。
