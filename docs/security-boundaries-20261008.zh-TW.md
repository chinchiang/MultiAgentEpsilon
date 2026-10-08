# 2026-10-08 安全邊界修正與驗收

本輪依 `main` 的 `ba05e1c` 確認結果修正，公開分支只繼承既有公開歷史。私人附件及舊 `work` 歷史不納入 PR。此文件區分程式修正、測試結果與仍需外部資源的部署驗收。

## 修正對照

| 問題 | 修正後行為 | 回歸或驗收 |
|---|---|---|
| PR 改 base 後沿用舊 run | 比對完整 timeline；同一 SHA／head repository／分支曾改 base 即拒絕；`edited` 會觸發檢查 | 缺失、畸形、改走再改回的歷程皆拒絕；發布前再次讀回 |
| 報告或檢查名稱冒充來源 | 獨立工作簽署 ZIP 摘要；固定 CLI 驗證簽章、workflow SHA／main ref／GitHub runner／run／attempt／digest | 官方公開樣本的合法簽章通過，五種竄改或缺失拒絕；此儲存庫仍待遠端驗收 |
| fixture／文件排除可信審查 | 所有變更路徑均須可信、具寫入權限的精確 head 核准 | fixture 改名、README 與文件均納入保護 |
| 混合核准／要求修改、重跑者核准 | guard 與 publisher 共用審查契約；寫入者要求修改會阻擋；排除 run actor／triggering actor 及所有 PR commit 身分 | 寫入／維護／管理／唯讀角色與完整 API 查詢回歸 |
| 相同 SHA 的其他 fork 或分支造成誤擋 | 相關 PR、最新 run 依 repository ID 與分支分開判定 | 不同 fork／分支不取代此 run，同範圍仍嚴格拒絕 |
| 核心 janitor 跨開機訊號與登記空窗 | 先查 boot ID；子程序收到持久化登記後的握手才執行 | 跨開機 PID、登記失敗、真實取消與 SIGKILL 回收 |
| 清理證據不足 | 檢查非殭屍程序群組已消失，目錄是否實際移除，失敗保留回收清冊 | 真實 Docker／程序／取消與孤兒回收測試 |
| 強制終止遺失呼叫預留 | 呼叫前同步寫入 call ID、請求摘要及預留；完成後再更新 | 實際送出模擬請求後 SIGKILL，仍有 IN_FLIGHT／預留／未知用量 |
| 報告 budget／limits 可竄改 | 重新計算精確規劃、總期限及逐筆預留；成功呼叫不能刪除預留 | 個別欄位及整批預留竄改皆拒絕，重複輪次共享預算 |
| 基底 pin 與執行權限摘要 | 啟動前核對工具鎖定的映像；manifest 使用 Git 的擁有者執行分類 | stale pin 在候選或容器啟動前拒絕；不同 umask 的分類一致 |
| 歷史機密範圍缺漏 | 掃描提交訊息／作者／提交者及標籤名稱／附註 | 五種中繼資料 canary 均被偵測且不寫入報告 |
| 分頁與 403 分類 | 完整頁另查下一頁；上限 10,000；一般權限 403 與限流區分 | 1,000／10,000 正常、10,001 拒絕；首個查詢限流也退避 |
| CODEOWNERS 審核粗略 | 規則集與協作者分頁；所有有效 owner 規則採保守交集 | 分路徑 owner 不會被誤報為全檔案 owner；原生每路徑審查仍必要 |
| 模型逐案類別提示及 RoE 綁定 | 目錄升為 v2、移除逐案 CWE 提示、綁定模型 RoE 摘要 | 舊版指標不與新版混算；兩家收到相同內容 |
| 結構化輸出與不可見字元 | 按供應商支援 schema 設定，保留嚴格本機引用／行號／文字驗證 | Bedrock 不傳不支援關鍵字；格式合法但引用偽造仍拒絕 |
| 未知供應商及缺少 AWS CLI | 呼叫前判為 CONFIGURATION | 不會默認送往 Bedrock 或消耗呼叫預留 |
| 未使用的 helper／清單／文件 | 註記增加實際讀取驗證；移除未使用模型清單與 imports；合併重複狀態說明 | 註記與修改後報告不能混用；文件明列揭盲後裁決 |
| 重複 seed 契約 | 維持可信 oracle 與 app 分開實作，以契約回歸防止漂移 | 比對兩者的 schema、資料列及認證設定；不從候選匯入可信 seed |
| GLM 缺少完整離線路徑 | 模擬 HTTP 走實際 adapter、盲審 worker、評分與清理 | 完整離線驗收；依使用者指示不連線內網 |
| 固定 Actions／工具版本 | checkout 7.0.1、setup-python 7.0.0、upload-artifact 7.0.2、attest 4.2.2 固定 SHA；CLI 固定雜湊 | AWS CLI 2.37.10 官方 PGP 驗證後鎖定；簽章驗證 CLI 2.102.0 |

`base_ref_changed` 採保守拒絕，包含主分支來回切換後的重跑。若要重新評估，使用新的 head 分支建立 PR；不以時間戳推測已排隊事件的 workflow 來源。共用 Actions 同名必要檢查的人工驗證仍採保守阻擋；專用 App 來源正式綁定後，才可消除共用來源的限制。

## 本機驗收

- 完整回歸：703 項通過、0 失敗／錯誤／跳過，包含資料庫、無網路容器與真實取消清理；保留一項既有 Starlette 棄用警告。結果由 JUnit 記錄，遠端 CI 另行核對。
- 第一輪完整回歸：686 項通過；後續增加註記消費、seed 契約、GLM 全路徑、缺少 CLI、映像 pin、owner、重跑者、預留竄改及安裝封存變體。
- 修正版安全測試：18 個授權案例、0 findings、ALLOW；缺陷版恰好政策指定 6 個 findings、BLOCK，G1／G2 無 findings，兩者清理完成。
- HTTP smoke：資料庫健康、登入、合法讀取與跨 owner 拒絕通過。
- 官方 CLI 簽章樣本：合法、竄改 artifact、錯誤 signer digest、錯誤 ref、無效簽章及缺少驗證材料，六種結果符合預期。此為驗證工具驗收，不是專用 App 已部署的證明。
- 模型新版目錄一輪八次呼叫（報告 `a7b33efc-9e72-44bf-944e-eb2a1d132690`）：Gemini 三個回答通過，一個 DEADLINE；Claude 受重建後缺少 CLI／profile 影響，未取得有效推論。該報告 INCOMPLETE、預留八次／8192 輸出權杖、用量不完整、清理完成。不能作為配對成功或偏誤降低證據。
- 新的單案 Gemini B09 驗收（報告 `ca84cbef-0829-4fe3-8f00-74f4bfdeb112`）成功且清理完成；為另一次有界驗收，不把不同批次拼接成完整配對。
- AWS CLI 已安裝並補回非機密 profile；STS 後續確認 ExpiredToken。需安全環境更新臨時憑證後才能完成 Claude 新 schema 真實驗收。沒有自動重試或模型切換。

## 部署與外部待辦

1. 專用 GitHub App、Installation、私鑰與受控 Linux 主機仍缺。程式及安裝步驟已備妥，依[部署文件](trusted-check-publisher.zh-TW.md)安裝固定工具與設定後，才能驗證 App 發布及 Ruleset 綁定。
2. `main` 規則集 24512048 仍 active、無 bypass，必要來源仍為共用 Actions App 15368。未核准、檢查失敗、偽造或過期證據的實際合併阻擋，需在隔離驗收 PR 由普通開發者身分確認；本輪不對 main 做可能成功的合併探測。
3. Actions 管理 API 回應 403，無法設定 fork 核准政策與全域 SHA pinning。私人弱點回報讀取為 disabled，啟用操作也回應 403。由儲存庫擁有者的管理連線處理；不是沙箱或使用者身分被拒絕。Secret scanning／Push Protection／Dependabot 的設定未取得完整驗收，保留未知狀態。
4. 授權條款尚待擁有者決定；本輪不自行授予公開原始碼授權。歷史 AWS 帳號 ID 是識別資訊，沒有以停用 main 規則集或強推改寫歷史。
5. G3、完整 G5、SBOM／SCA／CVE、產品 ASVS 適用性、較大模型樣本與 W15–W25 保留原路線圖。這些擴充功能不屬於本輪缺陷已修復的聲明。

Starlette 的 httpx 棄用警告仍須在後續相依套件遷移時處理；本輪沒有修改套件鎖定或降低隔離限制。
