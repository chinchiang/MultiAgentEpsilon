# 合成資料模型 gateway

gateway 提供共用 `Request`／`Reply`、離線 mock、Gemini `generateContent`、GLM 的 OpenAI-compatible chat，以及 Bedrock `Converse` adapter。不新增 Python 依賴；HTTP 使用既有 httpx，Bedrock 使用已安裝的 AWS CLI v2 與受管理的 AWS credential chain。

## 執行

```bash
# 預設只跑固定合成回應，無模型網路請求。
.venv/bin/python -I scripts/model_smoke.py
.venv/bin/python -m pytest tests/test_model_gateway.py

# 明確選擇真實 API；可能產生供應商費用。
.venv/bin/python -I scripts/model_smoke.py --live --provider gemini
.venv/bin/python -I scripts/model_smoke.py --live --provider bedrock --provider glm
```

每個供應商只收到同一個固定 ACK fixture，不接受 repository 路徑、附件或任意 prompt 參數。每個供應商最多 1 次呼叫、要求最多 256 output tokens、總期限 30 秒；不重試、不自動切換付費供應商。每個 HTTP 操作另有 10 秒 I/O timeout。預設結果寫入新的 `artifacts/model-smoke-<uuid>.json`，已有的結果檔不能覆寫。退出碼 0 代表選定的所有供應商都完成固定回應驗證；任一失敗、缺設定或取消為 1。

環境設定：

| Adapter | 必要設定 | 驗證界線 |
|---|---|---|
| mock | 無 | 固定回應，不證明任何真實端點可用 |
| Gemini | `GEMINI_MODEL_ID`、安全注入的 `GEMINI_API_KEY` | host 固定為 Google API；支援先前經 metadata 確認的 display-name alias |
| GLM | `GLM_MODEL_ID`、`GLM_CHAT_URL`；需要認證時另設 `GLM_API_KEY` | URL 必須是 HTTPS 443、`/v1/chat/completions`，禁止 userinfo／query／fragment；實際相容性須驗證 |
| Bedrock | `BEDROCK_MODEL_ID`、`BEDROCK_REGION`、已配置的 AWS 身分；選用 `AWS_CLI_PATH` | model ID／inference profile ID 或 ARN 與 SSO 角色分開；profile 未解析時 family 為 unverified |

只從可信執行環境讀取設定；不將端點、金鑰、SSO 或帳號值放進原碼。使用 managed outbound identity 時，先依 runtime manifest 選擇對應 alias 與 AWS config selector，保留平台注入的認證設定。缺 profile 或模型時，先完成環境設定，不在 runner 裡發動互動式登入。GLM 的地端 TLS CA 必須透過受信任 CA 設定提供，保留 TLS 驗證。

## 已實作的安全邊界

- `Gateway` 只接受可信呼叫者標示的 synthetic 類別，限制 system＋user 共 16 KiB、單次 output 上限與整個 gateway 的呼叫／token 預留額度。預留在 I/O 前完成，失敗不退還，不會以多次平行請求繞過預算。
- HTTP 禁止 redirects，保留 proxy 與 CA trust；回應 envelope 最多 128 KiB、文字最多 64 KiB。拒絕壓縮回應、非 JSON、重複 key、非有限數值、截斷與不支援的結束原因。
- tool／function 呼叫、code-execution payload 與 content-filter 拒答均產生失敗證據。任何文字輸出都只當資料，沒有 shell、工具分派或網路委派入口。system 與 user 在供應商協定中分開傳送。
- AWS CLI 使用 stdin 傳送 JSON，禁止 shell、互動提示、重試及 configured endpoint overrides；stdout 有上限，stderr 不寫入證據。取消／逾時時終止 process group 並回收 CLI。
- 證據保存 call ID、模型／輸入／輸出 digest、耗時、固定錯誤碼與供應商回報 token 數。缺 usage 為 null，不記作免費或零消耗。原始 prompt、回答、HTTP body、憑證、端點及例外文字都不進報告。

synthetic 標籤是可信呼叫者的分類聲明，並不是 DLP 或機密偵測。模型輸出仍是不可信資料；分離角色不保證模型本身不受 prompt injection 影響。token 限制不是精確的金額預算，供應商計價、hidden reasoning 與取消後的遠端運算可能另有費用。回應超限時只能拒絕本次結果，無法追回供應商已收取的費用。

## 本輪驗證與後續

2026-10-04 的實際 Gemini 固定 ACK 推論成功，API 回報 input 35／output 9 tokens。GLM 於 proxy CONNECT 收到 403，尚未到達應用協定驗收；Bedrock 的本地 AWS CLI 回報 profile 尚未配置，且尚缺實際模型識別值。離線 adapter 成功不能取代這兩項真實串接驗收。

56 項離線測試涵蓋協定 payload、資料路由拒絕、平行預算、redirect／429／5xx、不可信 JSON、usage、截斷／拒答／工具請求、輸出指令不執行、HTTP streaming 取消、真實 CLI 子程序逾時／取消／回收及 mock CLI。這些測試由既有 pytest CI 執行，不使用模型金鑰。

結果皆為 `advisory_only`，不輸出安全閘門 ALLOW，也不改變 `security/roe.json` 中既有試點的 `llm_calls:false`。多 provider smoke 只證明各協定能完成固定 fixture，尚不構成獨立安全審查或降低 bias 的實驗證據。

這個獨立 smoke runner 支援 SIGTERM／SIGINT 取消；SIGKILL 或主機中斷無法保證寫出最終報告或回收 AWS 子程序，尚未接入 security supervisor 的孤兒回收清冊。缺報告不能視為成功。正式長時間執行前仍需補足這段生命週期整合。

下一批依序完成：Bedrock／GLM 真實推論驗收；使用已知缺陷及乾淨案例做盲測，分開保存不同模型家族的意見與分歧；建立可重現的人工裁決及誤報／漏報指標。其後再擴充 SCA／SBOM／G3、完整 G5 與 G6 的安全案例。不得用多數模型同意替代確定性 oracle 或獨立合併核准。
