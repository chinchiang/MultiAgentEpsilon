# 專用 GitHub App 必要檢查：部署準備

已提供發布程式、CI 來源紀錄、設定及獨立 Linux 主機的 systemd 範本。**尚未建立 App、部署服務或發布真實的 `epsilon/trusted-merge` 檢查。** main 已啟用規則集 24512048，目前必要檢查仍是 GitHub Actions App（15368）的 `trusted-security-pilot`。

專用 App 讀取 GitHub 資料並發布檢查，不執行候選程式或取得模型憑證。一般工作流程的 GITHUB_TOKEN 不能以此 App 身分發布檢查。程式與政策須從獨立審查的版本部署到受控、唯讀位置；候選 PR 內的設定不會自行成為可信政策。

## 建立並安裝 App

由儲存庫擁有者開啟 [建立 GitHub App](https://github.com/settings/apps/new)：

1. 設定名稱，例如 `epsilon-trusted-check-chinchiang`；Homepage URL 使用儲存庫網址。
2. 此版採輪詢，取消 Webhook 的 Active。
3. Repository permissions：Actions、Contents、Pull requests 讀取，Checks 讀寫；Metadata 為必要讀取。不要加入其他寫入權限。
4. 建立 App，記錄 **App ID**，產生私鑰並經安全管道保存於部署主機。不要貼到聊天、issue、儲存庫或本儲存庫的 Actions secrets。
5. Install App → Only select repositories → `chinchiang/MultiAgentEpsilon`；記錄安裝網址尾端的 **Installation ID**。

權限對照見 `deploy/trusted-publisher/github-app-permissions.json`；它不是 App 建立 manifest。此 App 不需 Administration；改 Ruleset 仍由擁有者介面或有管理權限的另一連線執行。

## 完成可信基準與主機設定

選用管理者控制的 Linux 主機，具備 Python 3.12、OpenSSL、systemd，能驗證 TLS 並連線至 `api.github.com` 與 artifact 儲存服務 `*.blob.core.windows.net`。保留既有代理伺服器與 CA 設定，不得停用 TLS 驗證。此服務不需要 Docker、Gemini、Bedrock 或 GLM 憑證。

先完成可信基準的獨立審查、首次遷移與完整驗證。不能直接採用 PR 分支或手動 CI 成功當成核准。main 的舊 CODEOWNERS 只有作者 chinchiang、CatGrocery 尚無寫入權限，舊基準也不會自動授權評分器更新；首次遷移需另外安排。涉及規則例外的遷移須經擁有者明確授權，本程式不會移除既有規則。

| 位置 | 用途與權限 |
|---|---|
| `/opt/epsilon-publisher/app` | 已審查版本的程式；管理者持有，服務帳號唯讀 |
| `/etc/epsilon-publisher/publisher.json` | 從 `security/trusted-publisher.example.json` 製作；管理者持有，0644 或 0444 |
| `/etc/epsilon-publisher/gate-policy.json` | 從已核准 evaluator commit 複製 `security/policy.json`；唯讀 |
| `/etc/epsilon-publisher/github-app.pem` | App 私鑰；服務帳號讀取，0600，放在程式 checkout 之外 |
| `/var/lib/epsilon-publisher` | 執行鎖與固定格式結果；服務帳號持有，0700 |

範本 repository ID 是 1403706385、workflow ID 是 374309318；部署前讀回確認。填入真正 App ID、Installation ID、已核准 `evaluator_sha`、該 evaluator 的 worktree manifest digest，以及 gate policy 原檔 SHA-256。reviewers 僅列獲基準授權且有寫入審查權限的獨立審查者；minimum_regression_tests 設為核准基準的完整測試數，範本 360 是既有下限。

範本缺值會回傳 SETTINGS_INCOMPLETE，不產生權杖或檢查。main 基準 SHA 改變後服務會阻擋；新基準需審查及驗證，再由部署管理者更新設定，不能自動追蹤 main。

## 驗證設定與首次執行

先執行不連線的設定驗證：

```bash
python3.12 -I /opt/epsilon-publisher/app/scripts/publish_trusted_check.py \
  --settings /etc/epsilon-publisher/publisher.json \
  --gate-policy /etc/epsilon-publisher/gate-policy.json --validate-config
```

成功只代表設定與 policy digest 有效。使用真實非草稿、經獨立審查的驗收 PR，以服務帳號執行：

```bash
python3.12 -I /opt/epsilon-publisher/app/scripts/publish_trusted_check.py \
  --settings /etc/epsilon-publisher/publisher.json \
  --gate-policy /etc/epsilon-publisher/gate-policy.json \
  --private-key /etc/epsilon-publisher/github-app.pem \
  --lock-file /var/lib/epsilon-publisher/publisher.lock \
  --pr 5 --output /var/lib/epsilon-publisher/pr-5.json
```

PR #5 目前是草稿，不能用它宣稱正向發布成功。預設查找與 PR 關聯的最新 pull_request_target run；可指定 --run-id，但同樣核對最新執行與 attempt。手動 workflow_dispatch 不授權。GitHub 若缺少 PR 關聯、artifact digest 或來源契約欄位，保持失敗；真實平台相容性仍須驗證。

每次先建立 in_progress 檢查，再核對來源、獨立核准與完整證據，拒絕後發布 failure。JWT 核對 App、Installation 身分，安裝權杖限此儲存庫與最低所需權限；下載 artifact 時不把權杖轉送到儲存服務。不記錄私鑰、權杖、原始 API 錯誤或 artifact 內容。

## 持續執行與限制

範本為 `deploy/trusted-publisher/epsilon-publisher@.service`、`.timer`。由主機管理者建立 epsilon-publisher 服務帳號、安裝程式與設定，再複製 unit 至 `/etc/systemd/system`。範本使用 `/usr/bin/python3`；該路徑必須是 Python 3.12，其他版本會回傳 PYTHON_VERSION。核對 Python 路徑、檔案權限與代理設定後執行：

```bash
systemd-analyze verify /etc/systemd/system/epsilon-publisher@.service /etc/systemd/system/epsilon-publisher@.timer
systemctl daemon-reload
systemctl enable --now epsilon-publisher@5.timer
```

同一儲存庫的所有實例共用執行鎖。每次完成後等待 30 秒；每個 PR 需啟用對應 timer。程式限制 300 次 API 請求與 API 階段 240 秒；unit 限制總執行 300 秒、256 MiB 記憶體及 64 個工作項目。來源核對限 200 個檔案、單檔 1 MiB、總計 20 MiB；超限保持失敗，不能縮減清冊後放行。

此版是**一次性發布程式與輪詢範本**，沒有 webhook 接收器、所有 PR 自動發現或高可用監控。Checks 成功狀態沒有原生期限，輪詢有延遲；GitHub 或服務中斷也可能無法撤銷既有綠燈。必須保留原生審查與既有必要檢查，驗證撤銷行為並監控服務及過期結果；不得把範本或本地回歸當成即時、不可繞過的正式驗收。

## 綁定規則與遠端驗收

第一次真實發布後，讀回 check_run.app.id 等於專用 App ID。在現有 main Ruleset **新增** epsilon/trusted-merge，Expected source 選專用 App；保留 trusted-security-pilot、嚴格必要檢查及所有審查／禁止強推規則。不能選共用 App 15368 或虛構 ID。

先在隔離驗收分支／PR，以普通開發者身分驗證：錯誤 App 同名成功、其他 workflow／repository、錯誤 SHA／attempt、報告過期／不完整、未核准／核准撤回、換版、檢查失敗及直接推送均不得放行；合法條件才通過。保留真實身分、規則與 API 回應，不以作者自行審查或草稿 PR 的阻擋代替。不可對 main 做可能真的合併成功的探測。

本地測試驗證程式拒絕與再次查核邏輯。App 註冊、主機部署、實際 API 相容性、專用來源規則綁定與遠端行為驗收仍待完成。
