# 固定預算的多輪盲測與錯誤分類

`--rounds` 可預先指定一至四輪，預設一輪。所有輪次共用同一份計畫、同一個監督程序及同一個閘道額度，沒有逐輪加額、失敗退款或自動重試。單批仍最多十六次請求、預留 8,192 個輸出詞元；整批期限仍為 `min(130, 20 × 請求數 + 10)` 秒。計算額度時先乘上供應商數、案例數與輪數，超限便在連線前拒絕。

```bash
# 兩個模擬審查者、兩案、兩輪：八次離線請求，共預留 4,096 個輸出詞元。
.venv/bin/python -I scripts/model_review.py \
  --case B07 --case B08 --rounds 2

# 真實配對：需要兩家都具有可用的身分、模型及連線。
# 同樣八次請求，但每次 1,024 個輸出詞元，總預留額度 8,192。
.venv/bin/python -I scripts/model_review.py --live \
  --provider gemini --provider bedrock --case B07 --case B08 \
  --rounds 2 --output-tokens 1024

.venv/bin/python -m pytest tests/test_model_rounds.py
```

以上真實指令不會自動替換失效身分；AWS 暫時環境憑證的選取與帳號核對方式見 [模型介面文件](model-gateway.zh-TW.md)。憑證到期時應先更新安全環境設定，不能以換身分、略過驗證或反覆重試解決。

每輪在內部隨機排列請求，輪次按順序執行。同輪同案的各供應商取得相同不透明識別碼；下一輪使用新識別碼。提示詞不提供輪次、案例編號、標準答案或先前回答，各次請求沒有對話歷史。報告保留 `round_index`、計畫及請求綁定；跨輪替換、重複輪次、識別碼重用與模型識別摘要改變均拒絕評分；若供應商在回應中回報實際服務的模型版本（例如 Gemini 的 `modelVersion`），同一 run 內版本改變也會拒絕，可偵測 `*-latest` 之類浮動別名在輪次間被改指。模型識別摘要以每個 run 的隨機金鑰計算，只能在同一份報告內比較，避免由摘要回推含帳號 ID 的 inference profile ARN。取消後未執行的輪次仍留在計畫及分母內。

## 診斷資料

既有 `code` 保留相容性；新增 `diagnostic` 只允許程式定義的固定分類，不保存解析器訊息、欄位名稱、供應商原始錯誤或失敗回答。合法的結構化意見仍依既有規則保存，供人工審查。

| 分類 | 可確認的失敗階段 |
|---|---|
| `JSON_SYNTAX`、`JSON_ENCODING` | JSON 語法或字元編碼錯誤；不能僅憑語法錯誤推斷截斷 |
| `JSON_DUPLICATE_KEY`、`JSON_NONFINITE` | 重複欄位或不允許的非有限數值 |
| `MISSING_FIELD`、`ENVELOPE_SCHEMA` | 必要的供應商封裝欄位缺漏或結構不符 |
| `UNEXPECTED_CONTENT`、`EMPTY_TEXT` | 不支援的內容區塊或沒有可用文字 |
| `USAGE_SCHEMA`、`STOP_REASON` | 用量型別或完成原因不符合契約 |
| `REVIEW_SCHEMA`、`EVIDENCE_MISMATCH` | 盲測回答格式不符，或引用與指定原碼行不一致 |
| `HTTP_CONTENT_TYPE` | HTTP 內容類型或編碼不符既有傳輸契約 |

拒答、截斷、工具要求、逾時等繼續使用 `REFUSED`、`TRUNCATED`、`TOOL_REQUEST`、`DEADLINE`。只有供應商明確回報截斷時才使用截斷分類。無法確認原因時保留一般失敗，不猜測或補造診斷。這些分類不放寬任何接受條件，也不會重新讀取已丟棄的歷史失敗原文。

## 統計與判讀

報告同時保留逐輪與合併結果。合併統計先加總計數再計算比例，不直接平均各輪百分比。

- `planned` 的單位為「案例 × 輪次」，不是不同案例數。
- `valid_response_rate` 包含符合格式的棄答；`coverage` 只包含明確分類。棄答不視為安全。
- 誤報、漏報及定位指標沿用獨立標準答案；失敗與未執行仍保留在整體漏判與覆蓋率分母。
- `error_categories` 統計固定診斷／錯誤分類；棄答另外標為 `ABSTAIN`。
- 配對分歧同時顯示可比較數與全部預定數，兩家都失敗不算一致。
- `stability` 逐供應商、逐案例呈現有效輪次與不同回答數；任何一輪未完成或棄答，`all_rounds_agree` 就是未知。全部一致也可能全部錯誤，仍須看標準答案比對。
- 用量是已回報的小計，缺值維持未知；金額成本仍為未知。取消無法保證遠端推論或計費同步停止。

報告記錄取樣政策：Gemini／GLM 使用固定溫度，Bedrock 使用模型預設值。重複觀測不是獨立樣本，也無法證明模型訓練資料彼此獨立。小樣本不提供偏誤降低結論，仍標示 `NOT_ESTABLISHED`。人工案例註記綁定整份報告，涵蓋所有預定輪次，不得挑選最有利的一輪充作整批核准。

## 2026-10-05 有限真實驗證

AWS 身分重驗回傳 `ExpiredToken`，本輪沒有送出 Bedrock 推論請求。使用既有 Gemini 設定，對 B07／B08 各執行兩輪，共四次請求，預留上限 4,096 個輸出詞元。四次均取得符合格式的結果，兩個真陽性、兩個真陰性，兩個弱點根因行號均命中；每案兩輪判斷一致。API 回報輸入 1,819、輸出 466 個詞元，資源清理完成。

這是單一模型、兩個案例的流程驗證，不是雙模型穩定性或偏誤改善的證據。所有案例仍因單一審查者而保持待審。待安全環境設定中的 AWS 暫時憑證更新，且重新核對帳號及角色後，才能執行雙模型重複驗收；不要將憑證貼在聊天或儲存庫。

## 2026-10-06 雙模型多輪驗收

使用者重新以 AWS IAM Identity Center 登入後，先以相同的憑證選取方式執行 `sts get-caller-identity`，核對為帳號 576607007707、Inventec-IT-Bedrock01 權限集；暫時憑證只經由程序標準輸入傳給執行環境，不寫入命令列、儲存庫或對話。評估程式為可信閘門 #6 之上的多模型分支 `30c959b`，指令與上方「真實配對」相同：Gemini／Bedrock、B07／B08、兩輪、每次 1,024 個輸出詞元，共八次請求。

**第一次（報告 `792ef595-81f1-484b-8d8f-818b921b1036`，INCOMPLETE）：** Bedrock 使用 `global.anthropic.claude-opus-5-5`，四次皆為 `PROVIDER_FAILURE`；Gemini 四次有效且正確。以兩次最小合成請求個別診斷：同一模型的純文字 Converse 成功，加入 `outputConfig.textFormat` 後回報 `ValidationException`（`output_config.format: Extra inputs are not permitted`）。也就是此模型不接受 Bedrock 的原生 JSON schema 輸出，不是權限或憑證問題。報告保留，未被下一批覆蓋。之後 Bedrock CLI 的失敗會依固定分類記錄（結構化輸出被拒為 `OUTPUT_CONFIGURATION`，權限／權杖為 `AUTHENTICATION`，節流為 `RATE_LIMIT`），不保存 CLI 或供應商原文。

**第二次（報告 `4d847d59-daf0-4502-874b-50fefe4eceb6`，COMPLETE）：** 先以一次最小請求確認 `global.anthropic.claude-sonnet-4-5-20250929-v1:0` 支援結構化輸出，再完整重跑。八個回應全部有效，清理完成；兩輪各自使用新的不透明識別碼。

| 供應商 | B07（有漏洞） | B08（無漏洞） | 統計 | 跨輪一致 |
|---|---|---|---|---|
| Gemini 3.8 Flash | 兩輪皆 VULNERABLE、CWE-639 第 2 行 | 兩輪皆 CLEAN | tp=2／tn=2／fp=0／fn=0 | 2／2 案 |
| Claude Sonnet 4.5 | 兩輪皆 VULNERABLE、CWE-639 第 2 行 | 第 1 輪 CLEAN、**第 2 輪 VULNERABLE（第 2 行）** | tp=2／tn=1／fp=1／fn=0 | 1／2 案 |

四組配對均可比較，其中 1 組分歧（25%）。第 2 輪 B08 標示 `PENDING_HUMAN_REVIEW`（DISAGREEMENT、REFERENCE_MISMATCH），其餘三組為 `REFERENCE_MATCH`。Claude 第 2 輪的理由是「先取資料再檢查授權，KeyError 與 PermissionError 可區分文件是否存在」——這屬於存在性資訊洩漏（CWE-203 類），不在案例限定的 CWE-639 範圍；B08 並未允許越權讀取，因此標準答案 CLEAN 維持不變。是否接受此判讀，仍須由人工審查者以 `review_adjudicate.py` 註記；本文不代為裁決。

用量：Gemini 輸入 1,819、輸出 552（含回報的思考詞元）；Claude 輸入 3,804、輸出 482；金額成本未知。

判讀：這是兩個案例、兩輪的小樣本，第一次觀測到同一模型對同一案例跨輪答案不同，且屬於範圍外的誤報；它說明多輪與跨家族比對確實能凸顯待人工審查的案例，但樣本太小，不能據此估計穩定性、比較模型優劣或宣稱偏誤降低（`bias_reduction` 仍為 NOT_ESTABLISHED）。兩家取樣設定不同（Gemini temperature=0，Bedrock 為模型預設），也不是受控的偏誤實驗。

後續已完成 B09～B12 的 Gemini／Claude 一輪真實配對，詳見[結構化輸出驗收](structured-output.zh-TW.md)。該批成功沒有覆蓋上述歷史失敗，也尚未完成雙模型多輪驗收。
