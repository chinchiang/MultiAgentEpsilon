[正體中文](#zh-tw) | [English](#en)

<a id="zh-tw"></a>

# 專用 GitHub App 必要檢查：部署準備

已提供發布程式、CI 來源紀錄、設定及獨立 Linux 主機的 systemd 範本。**尚未建立 App、部署服務或發布真實的 `epsilon/trusted-merge` 檢查。** main 已啟用規則集 24512048，目前必要檢查仍是 GitHub Actions App（15368）的 `trusted-security-pilot`。

專用 App 讀取 GitHub 資料並發布檢查，不執行候選程式或取得模型憑證。一般工作流程的 GITHUB_TOKEN 不能以此 App 身分發布檢查。程式與政策須從獨立審查的版本部署到受控、唯讀位置；候選 PR 內的設定不會自行成為可信政策。

## 建立並安裝 App

由儲存庫擁有者開啟 [建立 GitHub App](https://github.com/settings/apps/new)：

1. 設定名稱，例如 `epsilon-trusted-check-chinchiang`；Homepage URL 使用儲存庫網址。
2. 此版採輪詢，取消 Webhook 的 Active。
3. Repository permissions：Actions、Contents、Pull requests、Attestations 讀取，Checks 讀寫；Metadata 為必要讀取。不要加入其他寫入權限。
4. 建立 App，記錄 **App ID**，產生私鑰並經安全管道保存於部署主機。不要貼到聊天、issue、儲存庫或本儲存庫的 Actions secrets。
5. Install App → Only select repositories → `chinchiang/MultiAgentEpsilon`；記錄安裝網址尾端的 **Installation ID**。

權限對照見 `deploy/trusted-publisher/github-app-permissions.json`；它不是 App 建立 manifest。此 App 不需 Administration；改 Ruleset 仍由擁有者介面或有管理權限的另一連線執行。

## 完成可信基準與主機設定

選用管理者控制的 Linux 主機，具備 Python 3.12、OpenSSL、systemd，能驗證 TLS 並連線至 `api.github.com` 與 artifact 儲存服務 `*.blob.core.windows.net`。保留既有代理伺服器與 CA 設定，不得停用 TLS 驗證。此服務不需要 Docker、Gemini、Bedrock 或 GLM 憑證。

先完成可信基準的獨立審查、首次遷移與完整驗證。不能直接採用 PR 分支或手動 CI 成功當成核准。首次基準遷移已於 2026-10-06 完成，CatGrocery 也已於 2026-10-07 成為具寫入權限的審查者；部署前仍須確認設定中的 `evaluator_sha` 是已經審查合併的 main commit，基準不會自動授權評分器更新。涉及規則例外的遷移須經擁有者明確授權，本程式不會移除既有規則。

選定已審查合併、測試完成的乾淨 checkout 後，可先產生不含憑證的部署資料：

```bash
python3.12 -I scripts/prepare_publisher_deployment.py \
  --evaluator-sha <已核准的完整-main-SHA> \
  --app-id <真正-App-ID> --installation-id <真正-Installation-ID> \
  --output-dir /受控目錄/epsilon-deployment
```

輸出包含 `app.tar`、`publisher.json`、原樣複製的 `gate-policy.json`、`preparation.json` 與 `SHA256SUMS`。工作樹有修改、未追蹤檔案、HEAD 與指定 SHA 不一致、輸出位於 checkout 內，或輸出目錄已存在時均拒絕；不會覆寫正式設定。也會核對封存的實際逐檔內容、執行權限與評估器清冊一致，`export-ignore` 或 `export-subst` 造成的刪減或替換均拒絕。還沒有 App 時可省略兩個 ID，先準備其餘資料，缺值仍保持 `null`，live 模式不能使用。

本工具只固定本地輸入，不查證獨立核准、不部署服務、不授權基準更新。部署管理者仍須確認此 SHA 的 GitHub 審查與正式驗收。傳送至受控主機後先執行 `sha256sum -c SHA256SUMS`，再由 root 將程式封存解至 `/opt/epsilon-publisher/app`、設定裝至 `/etc/epsilon-publisher`；程式及設定的上層目錄也須由 root 持有且不可供服務帳號寫入，不能經由中途 symlink。live 模式以逐層目錄 descriptor 核對後開啟設定，避免只保護檔案卻可從上層替換。root 持有的 sticky 目錄可作祖先，但其下仍必須是受保護目錄。

| 位置 | 用途與權限 |
|---|---|
| `/opt/epsilon-publisher/app` | 已審查版本的程式；管理者持有，服務帳號唯讀 |
| `/etc/epsilon-publisher/publisher.json` | 從 `security/trusted-publisher.example.json` 製作；**root 持有**，0644 或 0444（live 模式會拒絕非 root 持有或群組／其他人可寫的設定） |
| `/etc/epsilon-publisher/gate-policy.json` | 從已核准 evaluator commit 複製 `security/policy.json`；root 持有、唯讀 |
| `/etc/epsilon-publisher/github-app.pem` | App 私鑰；**root 持有、0600**，放在程式 checkout 之外。unit 以 systemd `LoadCredential` 提供服務一份私有唯讀副本，服務帳號無法讀取或替換原檔 |
| `/var/lib/epsilon-publisher` | 執行鎖、固定格式結果與每個 PR 的狀態檔（已驗證 blob 摘要快取、上次發布結果、節流退避期限）；服務帳號持有，0700 |

範本 repository ID 是 1403706385、workflow ID 是 374309318；部署前讀回確認。填入真正 App ID、Installation ID、已核准 `evaluator_sha`、該 evaluator 的 worktree manifest digest，以及 gate policy 原檔 SHA-256。reviewers 須與 `security/trust-policy.json` 的 `baseline_reviewers` 一致（範本為 chinchiang、CatGrocery、d98922036ntu）；PR 作者、該 run 的觸發者及 PR 中任一 commit 的作者／提交者一律不計（rerun 請由非核准者執行），且只採計具寫入權限者；minimum_regression_tests 設為核准基準的完整測試數；範本值即為本版基準的完整測試數，CI 的證據自我檢查也以它為下限，測試被刪減會直接失敗。

新增可信審查者須同步 `.github/CODEOWNERS`、`security/trust-policy.json` 與發布器範本，並由原主分支的既有可信審查者核准這項清單變更。候選 PR 內新增的名字不能核准自己的加入；清單合併後才適用於後續基準變更。部署管理者也須採用已核准版本重新準備外部 `publisher.json` 與基準 pins，候選或已合併的設定都不會自動覆寫正式主機的政策。

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
  --private-key <可讀取的-systemd-credential-副本> \
  --lock-file /var/lib/epsilon-publisher/publisher.lock \
  --state-file /var/lib/epsilon-publisher/pr-<編號>-state.json \
  --pr <編號> --output /var/lib/epsilon-publisher/pr-<編號>.json
```

服務帳號無法直接讀取 root 專用的原始私鑰；正式執行請透過下方 unit 的 `LoadCredential` 副本。請使用非草稿的驗收 PR；草稿 PR 不能用來宣稱正向發布成功。手動 workflow_dispatch 不授權。PR 清單依 head 擁有者與分支查詢，再依 SHA、repository ID 與分支過濾；分頁上限為 10,000 筆，剛好完整頁時會查下一頁證明完整，超限拒絕。

**執行與簽章身分：** `pull_request_target` 使用 PR **base 分支**的 workflow；目前 PR 的 base 不能證明舊 run 的來源。發布程式以提交 SHA、head repository ID 與分支綁定 PR／run，讀取包含已關閉 PR 的完整 timeline；同一範圍曾發生 `base_ref_changed` 時，一律拒絕，改用新 head 分支建立 PR。不同 fork 或分支上的相同 SHA 不互相取代。

評估工作顯示名稱為 `trusted-security-evaluation`；獨立的 `attest-evidence` 工作在評估成功後，以 OIDC 簽署上傳 ZIP 的 SHA-256；它使用新 runner，不取出候選來源、不執行 evaluator 匯入，也不接收模型憑證。發布器使用固定版本、root 持有且雜湊相符的 GitHub CLI 驗證 Sigstore 簽章，要求此儲存庫的 `security.yml`、核准的 evaluator commit、`refs/heads/main` 與 GitHub 託管 runner；另外核對已驗證 SLSA 陳述中的 run／attempt URL 及 artifact digest。未簽署的 JSON、其他版本或其他批次的簽章都不能放行。最終必要工作 `trusted-security-pilot` 必須在評估及簽章成功後才成功，發布器另核對三項工作與指定步驟；手動執行最終名稱為 `manual-security-completion`。GitHub 個人私人儲存庫若不支援 artifact attestation，不能移除簽章驗證或以評估成功替代，需先處理儲存庫／平台支援條件。CLI 從離線 bundle 驗證，不接收 App 權杖或模型金鑰；更新可信根仍需連線至 `tuf-repo.github.com` 與 Sigstore 的可信根服務。

**負例證據：** `expect_block.py` 執行的是 evaluator 自己的缺陷版，因此負例報告綁定 evaluator 的 worktree manifest 與 evaluator SHA，不綁定候選；失敗案例必須恰好是政策 `seeded_defect_case_ids`。同一套證據契約（`validate_evidence`）也在 CI 上傳前由 `scripts/check_publishable_evidence.py` 自我檢查，契約不一致會讓產生證據的 run 直接失敗。

每次核對來源、獨立核准與完整證據後，只在結果（head、結論、診斷碼、run、attempt、核准）與上次發布不同時，才建立一個 completed 檢查；不再先發 in_progress，避免必要檢查每個週期閃爍。證據超過 1 小時會使驗證失敗，結果改變而發布 failure。GitHub 回應 429、帶速率限制標頭的 403，或超出 API 預算時不發布任何結果，並在狀態檔記錄 15 分鐘退避；這段期間既有結果不會被更新，需監控。一般 403 會以權限錯誤失敗，不當成速率限制。首個 PR 查詢遭限流也會記錄退避。API 無法寫入時不能保證撤銷既有綠燈，監控須告警。每次執行結束都會撤銷該次安裝權杖。JWT 核對 App、Installation 身分，安裝權杖限此儲存庫與最低所需權限；下載 artifact 時不把權杖轉送到儲存服務。不記錄私鑰、權杖、原始 API 錯誤或 artifact 內容。

## 持續執行與限制

範本為 `deploy/trusted-publisher/epsilon-publisher@.service`、`.timer`。由主機管理者建立 epsilon-publisher 服務帳號、安裝程式與設定，再複製 unit 至 `/etc/systemd/system`。範本使用 `/usr/bin/python3`；該路徑必須是 Python 3.12，其他版本會回傳 PYTHON_VERSION。核對 Python 路徑、檔案權限與代理設定後執行：

```bash
systemd-analyze verify /etc/systemd/system/epsilon-publisher@.service /etc/systemd/system/epsilon-publisher@.timer
systemctl daemon-reload
systemctl enable --now epsilon-publisher@<驗收-PR-編號>.timer
```

同一儲存庫的所有實例共用執行鎖。每次完成後等待 120 秒；每個 PR 需啟用對應 timer。已驗證的 blob 摘要以內容位址快取在狀態檔，每個週期約 20 次 API 請求，遠低於安裝權杖的速率上限。程式限制 300 次 API 請求與 API 階段 240 秒；unit 限制總執行 300 秒、256 MiB 記憶體及 64 個工作項目。來源核對限 200 個檔案、單檔 1 MiB、總計 20 MiB；超限保持失敗，不能縮減清冊後放行。

此版是**一次性發布程式與輪詢範本**，沒有 webhook 接收器、所有 PR 自動發現或高可用監控。Checks 成功狀態沒有原生期限，輪詢有延遲；GitHub 或服務中斷也可能無法撤銷既有綠燈。必須保留原生審查與既有必要檢查，驗證撤銷行為並監控服務及過期結果；不得把範本或本地回歸當成即時、不可繞過的正式驗收。

## 綁定規則與遠端驗收

第一次真實發布後，讀回 check_run.app.id 等於專用 App ID。在現有 main Ruleset **新增** epsilon/trusted-merge，Expected source 選專用 App；保留 trusted-security-pilot、嚴格必要檢查及所有審查／禁止強推規則。不能選共用 App 15368 或虛構 ID。

先在隔離驗收分支／PR，以普通開發者身分驗證：錯誤 App 同名成功、其他 workflow／repository、錯誤 SHA／attempt、報告過期／不完整、未核准／核准撤回、換版、檢查失敗及直接推送均不得放行；合法條件才通過。保留真實身分、規則與 API 回應，不以作者自行審查或草稿 PR 的阻擋代替。不可對 main 做可能真的合併成功的探測。

本地測試驗證程式拒絕與再次查核邏輯。App 註冊、主機部署、實際 API 相容性、專用來源規則綁定與遠端行為驗收仍待完成。

## 安裝簽章驗證工具

使用已獨立核准的程式版本，在 Linux x86_64 下載並核對封存與執行檔兩層雜湊：

```bash
python3 -I scripts/install_attestation_verifier.py --output /tmp/epsilon-gh-verified
sudo install -d -o root -g root -m 0755 /opt/epsilon-publisher/tools
sudo install -o root -g root -m 0755 /tmp/epsilon-gh-verified /opt/epsilon-publisher/tools/gh
```

`publisher.json` 的 `attestation_verifier` 與 `attestation_verifier_sha256` 必須與核准的工具鎖定檔相符。所有上層目錄須由 root 持有且不能被服務帳號替換。驗證器的設定與可信根快取使用每次獨立的暫存目錄，避免依賴服務帳號的家目錄。更新工具或來源版本須重新審查、更新 pin 並驗收。首次部署需確認 App 已授予 Attestations 讀取；既有 Connector 的權限不等同專用 App 權限。

<a id="en"></a>

# Dedicated GitHub App required check: deployment preparation

Publisher, provenance, configuration, and Linux systemd templates exist. No App/service/live epsilon/trusted-merge check has been deployed. Active main ruleset 24512048 still requires shared Actions App 15368's trusted-security-pilot. The dedicated App reads GitHub and publishes checks; it never executes candidate code or receives model credentials. Deploy independently reviewed code/policy to controlled read-only locations; candidate settings are not authority.

## Create and install the App

The owner opens [New GitHub App](https://github.com/settings/apps/new), chooses a name such as epsilon-trusted-check-chinchiang and repository homepage, and disables Webhook Active because this implementation polls. Grant repository Actions, Contents, Pull requests, Attestations read; Checks read/write; required Metadata read. No additional writes. Record App ID, generate a private key, and transfer it securely to the host—not chat/issues/source or this repository's Actions secrets. Install only on chinchiang/MultiAgentEpsilon and record the Installation ID from the installation URL. github-app-permissions.json documents permissions, not an App-creation manifest. This App needs no Administration; the owner or separate administrative connection updates rules.

## Trusted baseline and host

Use administrator-controlled Linux with Python 3.12, OpenSSL, systemd, verified TLS access to api.github.com and *.blob.core.windows.net, preserving proxy/CA settings. No Docker/model credentials are needed. Initial migration and CatGrocery write access are historical prerequisites already completed; still verify evaluator_sha is independently reviewed, merged main with completed testing. Baseline updates never automatically authorize deployment or rule exceptions.

From a clean, reviewed checkout:

```bash
python3.12 -I scripts/prepare_publisher_deployment.py --evaluator-sha <approved-full-main-SHA> --app-id <real-App-ID> --installation-id <real-Installation-ID> --output-dir /controlled/epsilon-deployment
```

Outputs: app.tar, publisher.json, unchanged gate-policy.json, preparation.json, SHA256SUMS. Dirty/untracked worktree, mismatched HEAD, output inside checkout, or existing output directory rejects; production configuration is never overwritten. Archive content/executable inventory must match evaluator; export-ignore/export-subst changes reject. IDs may be omitted for preparation, remaining null and unusable live. This tool pins local inputs; it neither verifies GitHub approval nor deploys/authorizes updates.

After secure transfer, run sha256sum -c SHA256SUMS. Root installs code under /opt/epsilon-publisher/app and configuration under /etc/epsilon-publisher. Every ancestor must be root-owned and unreplaceable by the service account, without intermediate symlinks; descriptor-by-descriptor opening enforces this. Root-owned sticky ancestors are permitted only with protected descendants.

| Path | Ownership/use |
|---|---|
| /opt/epsilon-publisher/app | Reviewed code, administrator-owned, service read-only |
| /etc/epsilon-publisher/publisher.json | Root-owned 0644/0444; live rejects non-root or group/other-writable configuration |
| /etc/epsilon-publisher/gate-policy.json | Unchanged approved security/policy.json, root-owned/read-only |
| /etc/epsilon-publisher/github-app.pem | Root-owned 0600 outside checkout; systemd LoadCredential supplies a private read-only copy, original inaccessible to service |
| /var/lib/epsilon-publisher | Service-owned 0700 lock/results/per-PR state, verified blob cache, last result, backoff deadline |

Read back repository ID 1403706385/workflow ID 374309318 before deployment. Set real App/installation IDs, approved evaluator SHA/worktree manifest digest, and exact gate-policy SHA-256. Reviewers match baseline_reviewers (chinchiang, CatGrocery, d98922036ntu); exclude PR author, original/rerun actors, every PR commit author/committer, and non-writers. Rerun as a non-approver. minimum_regression_tests must equal the approved complete baseline; CI self-check uses it to reject deleted coverage. JUnit identities must also be nonempty/unique; duplicate records cannot inflate this minimum.

Reviewer additions must synchronize CODEOWNERS, trust-policy, and publisher template and be approved by an existing base reviewer. New candidate names cannot approve their own admission. Deployment administrators explicitly regenerate external policy/pins from approved code; merged files never overwrite host configuration automatically. Missing settings return SETTINGS_INCOMPLETE before token/check creation. A changed main SHA blocks until an explicitly reviewed/accepted pin update.

## Validation and first execution

```bash
python3.12 -I /opt/epsilon-publisher/app/scripts/publish_trusted_check.py --settings /etc/epsilon-publisher/publisher.json --gate-policy /etc/epsilon-publisher/gate-policy.json --validate-config
```

This proves only configuration/policy digest validity. For an independently reviewed, non-draft acceptance PR, use the service account and a key accessible through the intended credential mechanism:

```bash
python3.12 -I /opt/epsilon-publisher/app/scripts/publish_trusted_check.py --settings /etc/epsilon-publisher/publisher.json --gate-policy /etc/epsilon-publisher/gate-policy.json --private-key <readable-systemd-credential-copy> --lock-file /var/lib/epsilon-publisher/publisher.lock --state-file /var/lib/epsilon-publisher/pr-<number>-state.json --pr <number> --output /var/lib/epsilon-publisher/pr-<number>.json
```

The service cannot directly read the root-only original key. Use the supplied unit/LoadCredential for live execution. Draft PRs/manual dispatch never authorize successful publication. Related-PR lookup binds owner/branch/SHA/repository ID, paginates to 10,000, and fetches an additional page after full pages to prove completeness; excess rejects.

**Run/signature identity:** pull_request_target executes base-branch YAML; current base cannot prove old provenance. Complete timelines including closed PRs bind SHA/head repository/branch and reject any base_ref_changed in that scope; use a new branch/PR. Same SHA in unrelated forks/branches does not supersede runs.

trusted-security-evaluation precedes independent attest-evidence. The fresh signing runner signs the uploaded ZIP digest without candidate checkout, evaluator imports, or model credentials. A pinned, root-owned, hash-matching GitHub CLI verifies offline Sigstore bundles against this repository's security.yml, approved evaluator commit, refs/heads/main, hosted runner, and verified SLSA run/attempt/digest. Unsigned JSON, other revisions/batches, and missing signatures cannot pass. Final trusted-security-pilot requires both evaluation/signing success, with publisher checking all three jobs/required steps; manual completion is named manual-security-completion. Unsupported private-repository attestation requires fixing platform/repository eligibility, never removing signatures. CLI receives no App/model secrets; trusted-root refresh still requires tuf-repo.github.com and Sigstore root services.

**Negative evidence:** expect_block.py runs the evaluator's seeded variant, binding evaluator manifest/SHA rather than candidate. Findings must exactly match policy seeded IDs. CI check_publishable_evidence.py uses the same validate_evidence contract before upload.

After full source/review/evidence checks, publish a completed check only when head/conclusion/code/run/attempt/approval changes. No periodic in_progress flicker. Evidence expires after one hour, causing failure publication on change. 429, rate-limited 403, or API-budget exhaustion produces no publication and a 15-minute stateful backoff—even on first PR lookup. Existing checks remain unchanged during backoff/outage and require monitoring; ordinary 403 is a permission failure. A failed write cannot guarantee revocation of a previous green check. Installation tokens are revoked at completion; JWT verifies App/installation, token scope is minimum permissions/this repository only, artifact downloads do not forward tokens to storage. Keys/tokens/raw API errors/artifact content are not logged.

## Continuous operation and limits

Administrator installs epsilon-publisher account, code/settings, and epsilon-publisher@.service/.timer into /etc/systemd/system. /usr/bin/python3 must be Python 3.12 or PYTHON_VERSION rejects. Verify paths/ownership/proxy configuration:

```bash
systemd-analyze verify /etc/systemd/system/epsilon-publisher@.service /etc/systemd/system/epsilon-publisher@.timer
systemctl daemon-reload
systemctl enable --now epsilon-publisher@<acceptance-PR-number>.timer
```

All instances share a repository lock. Each PR needs its own timer, waiting 120 seconds after completion. Content-addressed verified blob caching reduces ordinary cycles to roughly 20 requests. Hard bounds: 300 API calls, 240-second API phase; unit 300 seconds/256 MiB/64 tasks; source inventory 200 files, 1 MiB/file, 20 MiB total. Exceeding limits fails; never shrink the inventory to pass.

This is a one-shot publisher plus polling template, without webhook reception, PR auto-discovery, or high availability. Successful Checks have no native expiry; polling/outages delay revocation. Retain native reviews/existing required checks, monitor stale status/service health, and test revocation. Local regressions/templates do not prove instantaneous non-bypassable enforcement.

## Source binding and remote acceptance

After real publication, read back check_run.app.id equals the dedicated App ID. Add epsilon/trusted-merge to main Ruleset with that Expected source; retain trusted-security-pilot, strict checks, all review/no-force-push rules. Do not select shared 15368 or invent IDs.

First use isolated acceptance branches/PRs and a non-admin developer to reject wrong-App same-name success, other workflows/repositories, wrong SHA/attempt, stale/incomplete reports, absent/dismissed approval, changed versions, failed checks, and direct pushes; valid conditions alone pass. Preserve actual identity/rules/responses. Self-review or draft blocking is insufficient; do not risk successful unsafe main merges. App registration, host deployment, real API compatibility, binding, and behavior remain pending.

## Install the signature verifier

From independently approved Linux x86_64 code, verify archive and executable hashes:

```bash
python3 -I scripts/install_attestation_verifier.py --output /tmp/epsilon-gh-verified
sudo install -d -o root -g root -m 0755 /opt/epsilon-publisher/tools
sudo install -o root -g root -m 0755 /tmp/epsilon-gh-verified /opt/epsilon-publisher/tools/gh
```

Set attestation_verifier and attestation_verifier_sha256 from approved tool locks. Ancestors remain root-owned/unreplaceable. Each verification uses isolated temporary config/root caches rather than service home state. Tool/source updates require reviewed new pins and acceptance. Ensure the dedicated App has Attestations read; connector permissions are separate.
