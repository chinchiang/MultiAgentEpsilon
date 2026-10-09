[正體中文](#zh-tw) | [English](#en)

<a id="zh-tw"></a>

# LM Studio 地端 Nemotron 文字模型

已提供 `lmstudio` adapter，目標模型為 `nvidia/nemotron-3-nano-omni`。目前完成合成 HTTP、實際 loopback 測試伺服器、嚴格回應驗證與生命週期回歸；**尚未連到使用者的 LM Studio 或驗證真實模型權重、版本與推論結果**。GLM 真實連線維持暫停。

## 準備服務與設定

1. 在地端 LM Studio 安裝／載入所選 Nemotron 模型，確認本機硬體與該模型格式相容，再啟動 OpenAI 相容 API 伺服器。此程式不下載模型、不安裝 LM Studio、不自動啟動服務。
2. 從**執行 harness 的同一台主機**確認 `/v1/models` 回傳模型清單，將其中實際 `id` 填入 `LMSTUDIO_MODEL_ID`。下載頁名稱不一定等於 API ID；不自動猜測、改別名或換模型。
3. 透過安全環境設定提供下列值；`.env.example` 僅供參考，程式不會自動載入 `.env`。金鑰不可提交或貼到聊天。

```dotenv
LMSTUDIO_BASE_URL=http://127.0.0.1:1234/v1
LMSTUDIO_MODEL_ID=nvidia/nemotron-3-nano-omni
LMSTUDIO_API_KEY=
```

ID 範例須以實際 `/v1/models` 為準。未設定驗證的同主機服務可留空金鑰；受控遠端入口應設定適當的存取控制與 TLS。使用名稱分類的 `family=nemotron` 不是權重或供應商身分的密碼學證明。

## 雲端如何連到地端

雲端工作環境的 `127.0.0.1` 指向雲端主機，**不會自動連到個人電腦**。可在 LM Studio 同一主機執行 harness，或先建立受控 HTTPS／443 入口及核准的內網路由／VPN。實際路由、TLS 信任、身分與存取控制須分別驗收；目前沒有因新增 adapter 而部署任何網路。

HTTP 只允許字面 `127.0.0.1` 或 `[::1]`、明確的 1024–65535 連接埠與精確 `/v1` 路徑；僅這種同主機連線不使用環境代理。`localhost`、縮寫／整數 IP、其他回環位址、私有網段 HTTP、公開 HTTP、userinfo、query、fragment、反斜線與編碼路徑均拒絕。遠端維持 HTTPS／443、原有代理及 CA 驗證；不允許關閉 TLS 驗證。請勿直接將無驗證的模型伺服器暴露到公網。

## 執行與預算

```bash
# 固定合成 ACK，不傳送專案原始碼。 / Fixed synthetic ACK, no project source.
.venv/bin/python -I scripts/model_smoke.py --live --provider lmstudio

# 先做兩案單模型；再做三模型同批比較。 / Two local cases, then a three-model batch.
.venv/bin/python -I scripts/model_review.py --live --provider lmstudio --case B13 --case B14 --output-tokens 1024
.venv/bin/python -I scripts/model_review.py --live --provider gemini --provider bedrock --provider lmstudio --case B13 --case B14 --output-tokens 1024

# 離線比較不同批次，不會呼叫 API。 / Offline comparison without API calls.
.venv/bin/python -I scripts/model_compare.py --report artifacts/<run-a>/report.json --report artifacts/<run-b>/report.json
```

三模型、兩案、一輪共六次推論、預留 6,144 個輸出詞元；增加至兩輪會超過 8,192，必須拒絕。可另開相同設定且保存完整結果的批次，不能挑選成功回答拼湊。整批上限仍為 16 次／8,192 詞元／130 秒，每次 30 秒且不自動重試。模型清單 GET 與 chat POST 共用該次呼叫期限；每次推論都先查清單。GET 不另算推論次數，最壞情況每次推論有兩個 HTTP 請求。

## 輸出契約與驗收

介面只傳送文字、獨立 system／user 訊息與 JSON schema；不傳影像、音訊、影片，不啟用工具。`omni` 名稱不代表此試點已支援多模態。使用 `temperature=0`、`stream=false`、`n=1` 與既有輸出詞元限額。回應模型必須與設定 ID 完全相同；不支援 schema、模型缺失／變更、截斷、工具要求、拒答、非法用量或偽造引用一律保留失敗，不降級為成功。

真實驗收順序：確認路由／TLS或loopback、查清單及精確 ID、ACK、單模型正反例、Gemini／Claude／Nemotron 同批、相同設定多批比較、取消與資源清理。記錄伺服器／模型版本、實際回報用量、錯誤與清理；三模型全同意仍不代表無漏洞、獨立性或偏誤降低。跨批報告未簽章、身分未驗證，服務版本跨批一致性仍標為未知。所需端點與設定由使用者於真實驗收時提供。

<a id="en"></a>

# Local Nemotron text models through LM Studio

The lmstudio adapter targets nvidia/nemotron-3-nano-omni. Synthetic HTTP, a real loopback fixture server, strict response checks, and lifecycle regressions exist. **The user's actual LM Studio, model weights/version, and inference remain unverified.** Live GLM stays paused.

## Server and configuration

Install/load the chosen model in LM Studio on compatible hardware and start its OpenAI-compatible API. This harness does not download models, install LM Studio, or start the server. From the same host that runs the harness, inspect /v1/models and set its exact returned ID; download-page names may differ. No guessing, alias substitution, or model switching occurs. Supply settings through the secure environment; .env.example is reference only, not automatically loaded:

```dotenv
LMSTUDIO_BASE_URL=http://127.0.0.1:1234/v1
LMSTUDIO_MODEL_ID=nvidia/nemotron-3-nano-omni
LMSTUDIO_API_KEY=
```

Replace the example ID with the actual catalog ID. A same-host unauthenticated service may omit a key; controlled remote ingress needs appropriate access control/TLS. Never commit or paste keys. The name-derived nemotron family label is not cryptographic model-weight/provider attestation.

## Cloud-to-local connectivity

Cloud 127.0.0.1 refers to the cloud host, not the user's computer. Run the harness alongside LM Studio, or provide controlled HTTPS:443 ingress and an approved internal route/VPN. Routing, TLS trust, identity, and access controls require separate acceptance; adding an adapter deploys no network.

HTTP permits only literal127.0.0.1 or [::1], explicit port1024–65535, exact /v1. Only this same-host path bypasses environmental proxies. localhost, shortened/integer IPs, other loopback addresses, private/public HTTP, userinfo/query/fragment/backslash/encoded paths reject. Remote HTTPS preserves port443/proxy/CA verification, with no TLS-disable option. Do not expose an unauthenticated server publicly.

## Commands and budget

The shared commands above perform a fixed synthetic ACK, two local cases, a Gemini/Bedrock/LM Studio batch, and offline comparison. Three providers × two cases × one round reserves six calls/6,144 output tokens; two rounds exceeds8,192 and rejects. Additional batches must preserve identical settings and complete results, never cherry-pick successful answers. Caps remain16 calls/8,192 tokens/130 seconds per batch,30 seconds per call, no retry. Each call's model-list GET and chat POST share that deadline; discovery repeats before every inference. GET is not a separate inference reservation; at most two HTTP requests accompany each inference.

## Contract and live acceptance

Only text, separate system/user roles, and JSON schema are supported—no images/audio/video/tools. Omni naming does not establish multimodal support. Requests use temperature0, stream=false, n=1 and bounded max_tokens. Response model must exactly match configured ID. Unsupported schema, missing/changed models, truncation, tools/refusal, invalid usage, or fabricated evidence remain failures without fallback.

Live sequence: route/TLS or loopback, catalog/exact ID, ACK, single-model positive/negative cases, matched three-provider batch, compatible repeated batches, cancellation/cleanup. Record server/model version, reported usage, errors, and cleanup. Unanimity does not prove safety, independence, or bias reduction. Cross-batch reports remain unsigned/unverified and serving-version consistency unknown. The user will provide actual endpoint/settings at that acceptance stage.
