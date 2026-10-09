[正體中文](#zh-tw) | [English](#en)

<a id="zh-tw"></a>

# 合成資料模型 gateway

gateway 提供共用 `Request`／`Reply`、離線 mock、Gemini `generateContent`、GLM 的 OpenAI-compatible chat，Bedrock `Converse`，以及 LM Studio 文字 adapter。不新增 Python 依賴；HTTP 使用既有 httpx，Bedrock 使用已安裝的 AWS CLI v2 與受管理的 AWS credential chain。

## 執行

```bash
# 預設只跑固定合成回應，無模型網路請求。 / Default: fixed mock replies; no model network requests.
.venv/bin/python -I scripts/model_smoke.py
.venv/bin/python -m pytest tests/test_model_gateway.py tests/test_model_hardening.py tests/test_lmstudio.py

# 明確選擇真實 API；可能產生供應商費用。 / Explicit live APIs may incur provider charges.
.venv/bin/python -I scripts/model_smoke.py --live --provider gemini
.venv/bin/python -I scripts/model_smoke.py --live --provider bedrock
.venv/bin/python -I scripts/model_smoke.py --live --provider lmstudio
```

`--live` 之外，live 呼叫還必須通過受保護的 `security/model-roe.json`：只限合成資料、`security_gate_effect` 為 NONE、每 run 規劃的 live 呼叫數（供應商 × 案例 × 輪數）不得超過 `max_calls_per_run`（上限 16），且所選供應商都在 `allowed_live_providers` 內；不符合時在建立任何報告或預留預算前就拒絕。安全閘門使用的 `security/roe.json` 維持 `llm_calls: false`，兩者互不取代。

Bedrock 透過 AWS CLI 子程序呼叫時，只傳入 `AWS_*`（不含 endpoint 覆寫）與基本程序、代理及 CA 環境變數；`GH_TOKEN` 或其他供應商金鑰等無關權杖不會進入 CLI 或其 `credential_process`。Gemini 若回報推理詞元卻缺少可見輸出計數，視為用量格式錯誤，不能略過輸出預算檢查。

每個供應商只收到同一個固定 ACK fixture，不接受 repository 路徑、附件或任意 prompt 參數。每個供應商最多 1 次呼叫、要求最多 256 output tokens、單次期限 30 秒；不重試、不自動切換付費供應商。一般 HTTP 操作另有 10 秒 I/O timeout，LM Studio 使用涵蓋模型清單與推論的 30 秒呼叫期限。supervisor 的工作期限為 min(130, 供應商數 × 30＋10) 秒，期限後進行程序清理。退出碼 0 必須同時滿足全部固定回應驗證及清理完成；任一失敗、缺設定或取消為 1。

從報告 schema 2 起，正式證據位於 `artifacts/<run-id>/report.json`，開始執行前即建立 INCOMPLETE，逐供應商原子更新進度。`--output` 保留為額外匯出，必須使用新路徑；若 supervisor 被 SIGKILL，匯出檔可能停留在初始 INCOMPLETE，應依其 `canonical_report` 回查正式報告。janitor 不依任意匯出路徑寫檔。

環境設定：

| Adapter | 必要設定 | 驗證界線 |
|---|---|---|
| mock | 無 | 固定回應，不證明任何真實端點可用 |
| Gemini | `GEMINI_MODEL_ID`、安全注入的 `GEMINI_API_KEY` | host 固定為 Google API；支援先前經 metadata 確認的 display-name alias |
| GLM | `GLM_MODEL_ID`、`GLM_CHAT_URL`；需要認證時另設 `GLM_API_KEY` | URL 必須是 HTTPS 443、`/v1/chat/completions`，禁止 userinfo／query／fragment；實際相容性須驗證 |
| LM Studio | `LMSTUDIO_BASE_URL`、`LMSTUDIO_MODEL_ID`；選用 `LMSTUDIO_API_KEY` | 精確 `/v1` 路徑；HTTP 僅限本機回送位址，其他使用 HTTPS／443；每次查核模型清單與回應的精確 ID |
| Bedrock | `BEDROCK_MODEL_ID`、`BEDROCK_REGION`、已設定的 AWS 身分；選用 `AWS_CLI_PATH` | model ID／inference profile ID 或 ARN 與 SSO 角色分開；profile 未解析時 family 為 unverified |

只從可信執行環境讀取設定；不將端點、金鑰、SSO 或帳號值放進原始碼。使用 managed outbound identity 時，先依 runtime manifest 選擇對應 alias 與 AWS config selector，保留平台注入的認證設定。缺 profile 或模型時，先完成環境設定，不在 runner 裡發動互動式登入。GLM 的地端 TLS CA 必須透過受信任 CA 設定提供，保留 TLS 驗證。

## 已實作的安全邊界

- `Gateway` 只接受可信呼叫者標示的 synthetic 類別，限制 system＋user 共 16 KiB、單次 output 上限與整個 gateway 的呼叫／token 預留額度。預留在 I/O 前完成，失敗不退還，不會以多次平行請求繞過預算。
- HTTP 禁止 redirects，保留 proxy 與 CA trust；回應 envelope 最多 128 KiB、文字最多 64 KiB。拒絕壓縮回應、非 JSON、重複 key、非有限數值、截斷與不支援的結束原因。
- tool／function 呼叫、code-execution payload 與 content-filter 拒答均產生失敗證據。任何文字輸出都只當資料，沒有 shell、工具分派或網路委派入口。system 與 user 在供應商協定中分開傳送。
- AWS CLI 使用封存的 Linux 匿名記憶體檔案傳送 JSON，子程序只繼承指定的檔案描述元；不將內容放入命令列參數或具名暫存檔。stdin 只傳遞登記後的放行字元。禁止 shell、互動提示、重試及 configured endpoint overrides；stdout 有上限，stderr 不寫入證據。取消／逾時時終止 process group 並回收 CLI。
- 證據保存 call ID、模型／輸入／輸出 digest、可讀的模型標籤（`model_label`；ARN 及任何 12 位數帳號樣式一律遮蔽）、耗時、固定錯誤碼與供應商回報 token 數。缺 usage 為 null，不記作免費或零消耗。ACK smoke 的原始 prompt、回答，以及所有呼叫的 HTTP body、憑證、端點及例外文字都不進報告；盲測則另外保存模型原始回答文字（`response_text`），以便由原文重新導出 review。

synthetic 標籤是可信呼叫者的分類聲明，並不是 DLP 或機密偵測。模型輸出仍是不可信資料；分離角色不保證模型本身不受 prompt injection 影響。token 限制不是精確的金額預算，供應商計價、hidden reasoning 與取消後的遠端運算可能另有費用。回應超限時只能拒絕本次結果，無法追回供應商已收取的費用。

## 本輪驗證與後續

2026-10-04 的實際 Gemini 固定 ACK 推論成功，API 回報 input 35／output 9 tokens。GLM 於 proxy CONNECT 收到 403，尚未到達應用協定驗收；Bedrock 的本地 AWS CLI 回報 profile 尚未設定，且尚缺實際模型識別值。離線 adapter 成功不能取代這兩項真實串接驗收。

56 項離線測試涵蓋協定 payload、資料路由拒絕、平行預算、redirect／429／5xx、不可信 JSON、usage、截斷／拒答／工具請求、輸出指令不執行、HTTP streaming 取消、真實 CLI 子程序逾時／取消／回收及 mock CLI。這些測試由既有 pytest CI 執行，不使用模型金鑰。

結果皆為 `advisory_only`，不輸出安全閘門 ALLOW，也不改變 `security/roe.json` 中既有試點的 `llm_calls:false`。多 provider smoke 只證明各協定能完成固定 fixture，尚不構成獨立安全審查或降低 bias 的實驗證據。

## 2026-10-05 模型 runner 生命週期

smoke runner 現在由獨立 supervisor 管理，使用既有 `.state/runs/<run-id>` 登記及同一支 janitor。模型回收不需要 Docker。worker 及每個 AWS CLI process group 都先以 PID、start ticks、boot ID、UID 持久化登記，再透過 stdin 放行執行；登記前 owner 消失會使 pipe EOF，子程序不會執行模型請求。AWS JSON 透過封存記憶體檔案提供，放行包裝程式不讀取或記錄其內容。登記前收到 EOF 仍不會執行 AWS 命令。

worker 最多只能寫 AWAITING_CLEANUP，最後的 COMPLETE 由 parent 在驗證所有供應商結果、退出碼及清理成功後寫入。worker／CLI 受到 2 GiB address-space、512 MiB data、30／35 秒 CPU、1 MiB 檔案、128 FD 及禁用 core dump 的限制。SIGTERM／SIGINT、總期限、worker 異常退出均終止登記的程序群組並清理專屬 TMPDIR。

supervisor 遭 SIGKILL 或主機重啟後，執行：

```bash
.venv/bin/python -I scripts/cleanup_runs.py
```

janitor 只處理已死亡的 owner；先停止 worker，再重新盤點 AWS 子程序，避免清理時仍新增程序。以 flock 避免同一 run 被並行回收；PID start ticks 不同或不同 boot 的程序不會被發送訊號。清理失敗保留登記、標記 ERROR，後續可重試。孤兒報告一律為 CANCELLED，即使 worker 曾回報成功也不補升 COMPLETE。缺失／損壞報告會重建不成功的最小證據，不複製原始錯誤文字。

新增 29 項離線生命週期回歸涵蓋 parent SIGTERM／SIGINT／SIGKILL、worker SIGKILL、忽略 SIGTERM 的 CLI 子程序、登記前中斷、成功待清理時中斷、清理途中取消、缺失／損壞／重複 key 證據、清理重試、PID／boot 身分保護及並行 janitor。既有 CI 的 always 清理步驟會執行相同 janitor；主機中斷需在恢復後、保留原 workspace 的環境執行。若整個 workspace／登記遺失，就無法由本地 janitor 重建證據；已送到供應商的遠端推論也不能保證停止或不計費。直接呼叫未綁定 run directory 的 adapter 不具有此 runner 的孤兒回收契約。

已加入 [固定合成案例的盲測與裁決框架](blind-review.zh-TW.md)，保存獨立意見、分歧及帶分母的品質指標。ACK smoke 預設不保留回答文字；盲測會保存經 schema 驗證的結構化 finding／reason，供人工判讀。後續仍需 GLM 真實推論驗收、Claude 失敗回應的後續觀測、兩個真實家族的重複實驗與裁決身分驗證，再擴充 SCA／SBOM／G3、完整 G5 與 G6。不得用多數模型同意替代確定性 oracle 或獨立合併核准。


## 2026-10-05 Bedrock 真實串接修正

真實 AWS CLI v2.37.9 無法解析透過管線 `/dev/stdin` 傳入的 JSON。原有模擬命令直接讀取標準輸入，未涵蓋這個差異。現在使用 Linux `memfd_create` 建立可定位讀取的匿名記憶體檔案，寫入後封存寫入、增長及縮短能力，只讓指定子程序繼承。父程序啟動子程序後關閉自己的描述元；啟動或封存失敗也會關閉。這項實作依賴 Linux 與 `/proc`；能力不足時不改用明文暫存檔。

測試命令現在按照真正的 `--cli-input-json` 檔案參數讀取，驗證可重新定位及禁止寫入；另加入啟動失敗、封存失敗的描述元清理回歸。取消、期限及孤兒回收仍沿用既有監督程序。

目前設定的 Claude 模型拒絕固定溫度參數。Bedrock 介面因此只傳送輸出詞元上限，取樣採模型預設值；Gemini 與 GLM 的既有設定不變。不同供應商的取樣設定並不相同，不能將一次配對測試視為控制所有變因的偏誤實驗。

若使用者已透過安全環境設定提供 AWS 暫時憑證，而繼承的 `AWS_PROFILE` 指向不存在的設定檔，可只在單次命令移除 `AWS_PROFILE`／`AWS_DEFAULT_PROFILE`。必須先使用相同選擇方式執行 `sts get-caller-identity`，核對目標帳號及角色；單一登入角色可能是權限集名稱加上 AWS 保留前綴與識別後綴。不得因此切換至未核對的其他身分，也不改寫原有設定檔。若有受管理的 AWS 身分，仍優先按照執行環境的身分清單選擇，不套用此方式。

本輪已核對 AWS 帳號及單一登入權限集，固定合成回覆成功，API 回報輸入 63、輸出 19 個詞元，清理完成。模型資料查詢仍遭權限拒絕，不能把它誤判為推論權限也不可用；反過來，推論成功也不代表具備模型資料查詢權限。模型設定保留在環境，不寫入儲存庫。

## 結構化審查輸出

盲測的 Gemini／Bedrock 現在使用原生 JSON schema；Gemini 3 Flash 審查使用 LOW 思考程度，思考詞元納入回報輸出用量。固定 ACK 仍為純文字。本機嚴格驗證、截斷阻擋與既有預算不變，詳見[設定、限制與真實驗收](structured-output.zh-TW.md)。

目前可執行的介接器為 mock、Gemini、Bedrock、GLM 與 LM Studio；設定入口為 `.env.example` 與對應環境變數，不讀取模型清單 JSON。GLM 真實連線依使用者指示暫停，離線協定測試持續保留。每次送出呼叫前會將預留次數與詞元上限同步寫入磁碟；程序遭 SIGKILL 時可保留 IN_FLIGHT 紀錄，但無法據此推算遠端實際費用或保證遠端推論已取消。

環境重建後可執行 `python -I scripts/install_aws_cli.py`，安裝官方 PGP 簽章已驗證並固定封存雜湊的 AWS CLI 2.37.10。模型指令使用 `AWS_CLI_PATH="$PWD/.tools/aws-bin/aws"`；SSO profile 與非機密設定另存於忽略的 `.state/bedrock/config`，以 `AWS_CONFIG_FILE` 指定。臨時憑證到期仍須經安全環境更新，不會從聊天或測試報告載入。

## LM Studio 地端文字模型

新增 `--provider lmstudio`，設定 `LMSTUDIO_BASE_URL`、`LMSTUDIO_MODEL_ID` 及選用的 `LMSTUDIO_API_KEY`。只對字面 loopback 位址開放 HTTP，其餘維持 HTTPS／443；先查核 `/v1/models` 的精確 ID，再傳送文字與 JSON schema。完整設定、網路界線及待完成真實驗收見 [LM Studio 文件](lmstudio.zh-TW.md)。固定 ACK 的整輪期限為 `min(130, 30 × 供應商數 + 10)` 秒；新增供應商不會提高 130 秒上限。

<a id="en"></a>

# Bounded multi-model gateway pilot

The shared gateway supports offline mocks, Gemini generateContent, Bedrock Converse via AWS CLI, GLM OpenAI-compatible chat, and LM Studio OpenAI-compatible text chat. Existing httpx and verified AWS CLI are used; no similarly named SDK is installed. Model opinions remain advisory and do not alter deterministic gates/container authority.

```bash
.venv/bin/python -I scripts/model_smoke.py
.venv/bin/python -m pytest tests/test_model_gateway.py tests/test_model_hardening.py tests/test_lmstudio.py
.venv/bin/python -I scripts/model_smoke.py --live --provider gemini
.venv/bin/python -I scripts/model_smoke.py --live --provider bedrock
.venv/bin/python -I scripts/model_smoke.py --live --provider lmstudio
```

Actual cloud/local providers require --live, valid settings, and separate security/model-roe.json authorization. Unknown/duplicate/malformed providers and more than the approved 16 planned live calls reject before I/O; security/roe.json's deterministic scope still forbids automatic LLM calls. GLM live remains paused. AWS subprocess environments use only the AWS allowlist (excluding endpoint overrides), basic paths/proxy/CA settings, not other providers' secrets.

ACK probes use fixed synthetic text only: one request/provider, 256 output tokens, 30-second call deadline; normal HTTP I/O defaults to ten seconds (LM Studio discovery/chat uses the encompassing call deadline). Supervisor deadline is min(130, 30 × providers + 10) seconds. No arbitrary prompt/repository input, retries, provider switch, or cap increases. Exit code 0 requires every fixed reply to validate and cleanup to finish; any failure, missing setting, or cancellation returns 1. Schema-2 canonical reports begin as INCOMPLETE before execution and use atomic replacement and per-run paths. Exports require a new path and may remain INCOMPLETE after supervisor SIGKILL; follow their canonical_report pointer to the authoritative report. The janitor never writes arbitrary export destinations.

| Provider | Nonsecret configuration and credentials |
|---|---|
| mock | None; a fixed reply does not prove that any real endpoint is available |
| Gemini | GEMINI_MODEL_ID, secure GEMINI_API_KEY; fixed Google endpoint |
| Bedrock | BEDROCK_MODEL_ID, BEDROCK_REGION, valid AWS identity; optional AWS_CLI_PATH; SSO role/profile names do not establish a model inference ID |
| GLM | GLM_MODEL_ID, GLM_CHAT_URL exact HTTPS:443 /v1/chat/completions, optional secure key; internal route/TLS must be accepted separately |
| LM Studio | LMSTUDIO_BASE_URL exact /v1, LMSTUDIO_MODEL_ID from /v1/models, optional secure key; loopback-only HTTP exception, otherwise HTTPS:443 |

Use secure environment settings, never committed keys. Managed outbound credentials and existing proxy/CA settings take precedence over unnecessary interactive login. Do not disable TLS for internal services. See [LM Studio setup](lmstudio.zh-TW.md#en).

Gateway accepts only trusted caller-labeled synthetic inputs. Input is limited to 16 KiB, HTTP response to 128 KiB, text to 64 KiB. Call and output-token reservations occur before I/O and are not refunded after failure; concurrent calls cannot bypass the shared budget. No redirects, compressed/non-JSON responses, duplicate keys, nonfinite numbers, invalid endings, tools, code execution, or refusals accepted as answers. System/user roles remain separate. Gemini candidate plus thinking usage counts toward bounds; missing visible-output usage is invalid/unknown, never fabricated. Strict output formatting is further described in [structured output](structured-output.zh-TW.md#en).

Bedrock request JSON goes through sealed anonymous Linux memfd, not named plaintext files, shell commands, prompt arguments, or retries/endpoint overrides. Registered AWS children await stdin handshake; stdout is bounded and stderr text is not retained. Cancellation kills the owned group. Sealing/proc support is required with no plaintext fallback. Parent descriptors close on failure; CLI parsing/sealing are regression-tested.

Evidence retains call/request/response digests, bounded status/usage/time, redacted readable model labels, and unknown/null usage/cost where absent. ARNs/account-bearing labels are redacted. ACK raw prompts/replies, endpoint URLs, and keys are excluded. Valid blind-review response_text is retained for scoring rederivation; invalid bodies are not. Synthetic labeling is not a DLP system and role separation does not prove prompt-injection immunity. Tokens are not exact money; canceled remote work may still bill.

## Lifecycle and historical observations

Initial October 4 offline acceptance had 56 tests. Gemini ACK succeeded (35 input/9 output tokens). GLM proxy CONNECT returned 403 before the application, so no inference/auth/model claim was possible. Bedrock then lacked usable profile/model settings; later results supersede this.

October 5 added registered supervisor/worker/AWS processes with PID/start ticks/boot ID/UID persisted before handshake, AWAITING_CLEANUP until parent completion, and 29 lifecycle regressions. Worker bounds: 2 GiB address space, 512 MiB data, CPU soft/hard 30/35 seconds, 1 MiB file, 128 descriptors, no core dumps. SIGTERM/SIGINT/deadline clean resources; SIGKILL is recovered by janitor.

Janitor stops worker then rescans AWS groups, takes flock, verifies process identity, retries cleanup failures, and marks orphaned runs CANCELLED without upgrading old success. Corrupt reports become minimal failures without raw errors. Losing the whole workspace requires platform recovery; remote billing and unregistered direct-adapter processes are outside these guarantees.

AWS CLI 2.37.9 did not accept piped /dev/stdin JSON as expected; seekable sealed memfd corrected the actual CLI path. Some Claude models rejected temperature, so Bedrock retains model-default sampling while Gemini/GLM/LM Studio use zero. This difference is recorded, not hidden. If explicitly supplied temporary credentials are shadowed by an invalid inherited AWS_PROFILE, remove the profile only for a validated command after STS confirms the intended account/role through that same chain; managed identity remains preferable. Historical Bedrock ACK reported 63 input/19 output with cleanup. Metadata-query denial neither proves nor disproves inference permission.

Blind reviews, repeated observations, human identity, and model-family comparisons have separate acceptance requirements. New LM Studio code has offline/loopback-fixture coverage; real Nemotron weights/server/schema behavior are still pending. GLM live remains paused; no arbitrary model registry or automatic model download was added.


## Recovery and AWS CLI setup

After supervisor SIGKILL or a host restart, recover registered orphan processes with:

```bash
.venv/bin/python -I scripts/cleanup_runs.py
```

After rebuilding the environment, install the pinned AWS CLI 2.37.10 using the official PGP-verified archive and fixed archive digest:

```bash
python3 -I scripts/install_aws_cli.py
```

Set `AWS_CLI_PATH="$PWD/.tools/aws-bin/aws"` for model commands. Nonsecret SSO profile settings may live in the ignored `.state/bedrock/config`, selected through `AWS_CONFIG_FILE`. Renew expired temporary credentials through secure environment settings; never load credentials from chat or test reports. The scripts do not automatically load `.env`.
