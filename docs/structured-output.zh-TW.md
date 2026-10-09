[正體中文](#zh-tw) | [English](#en)

<a id="zh-tw"></a>

# 受限的結構化審查輸出

盲測請求使用 `security-review-json-v1` 輸出模式。Gemini 透過 `responseMimeType=application/json` 與 `responseJsonSchema`，Bedrock Converse 透過 `outputConfig.textFormat`，要求模型原生輸出 JSON。共用 schema 只描述審查資料形狀，不含案例 ID、標準答案或其他模型的回答，亦不使用工具呼叫傳遞審查結果。固定 ACK 測試維持純文字；GLM 維持既有提示詞與嚴格本機驗證，尚未宣稱有原生 schema 約束。

Gemini 3 Flash 系列的審查請求指定 `thinkingLevel=LOW`、`includeThoughts=false`。本次實際端點拒絕 `MINIMAL`，改成 `LOW` 後才通過；此設定不是自動降級或重試。舊世代、Pro 與不明模型名稱不套用該模型專屬參數。模型能力仍須實際驗證，不保證所有別名或日後版本均相容。

單次輸出與整批預留上限不變。Gemini 的 `candidatesTokenCount` 與 `thoughtsTokenCount`（若有回報）合計作為輸出用量，超額仍拒絕；不保存或要求回傳思考內容。失敗回應缺少的用量維持未知，金額成本也維持未知。

schema 依供應商支援範圍設定；它不取代本機驗證。Gemini 使用 `maxItems=3` 與行號上下限；Bedrock 使用行號列舉，不傳送不支援的 `maxItems`、數值上下限或字串長度。兩者仍由本機拒絕超過三項 findings。重複 JSON key、非有限數字、Markdown 圍欄、額外欄位、錯誤案例識別碼、偽造引用、不符的弱點行號及判定／finding 不一致均拒絕。供應商回報截斷、拒答或工具呼叫也維持失敗；不修補模型輸出、不把失敗轉為 CLEAN、不自動重試或切換供應商。`response_format` 納入請求摘要，schema 與 adapter 實作納入實作摘要。

HTTP 400 可讀取最多 8 KiB、未壓縮的 JSON 錯誤本文，只將提及思考設定或輸出設定的訊息分類為 `THINKING_CONFIGURATION`／`OUTPUT_CONFIGURATION`。不保留原文、欄位路徑或憑證；無法分類、過大或不合法的錯誤維持一般 `HTTP_ERROR`。這是診斷線索，不能憑此推斷完整原因。

## 2026-10-05 真實配對驗收

以同一組 B09～B12 案例執行 Gemini／Claude 各四次，共八次請求，每次最多 1,024 個輸出詞元、總預留 8,192、整批期限 130 秒。最終報告 `f4f05433-4c03-40c7-b618-7351a012030e` 的八個回應全部有效；每家均為兩個真陽性、兩個真陰性，兩個弱點行號全部命中。四組配對均可比較且無分歧，程序與暫存清理完成。

Gemini 回報輸入 1,896、輸出 1,151（包含回報的思考詞元）；Claude 回報輸入 3,879、輸出 484。此為最後一批的用量，不包括前面的失敗與診斷批次。先前拒答、截斷、JSON 語法錯誤與不支援設定的報告皆保留，未以本批成功覆蓋。

這是一輪、四個合成案例的有效性驗收，不是多輪穩定性、完整 ASVS 覆蓋、偏誤降低或獨立人工核准。`REFERENCE_MATCH` 只代表與既有標準答案一致，不代表真人已審查。

## 2026-10-06 模型相容性

`global.anthropic.claude-opus-5-5` 的純文字 Converse 可用，但加入 `outputConfig.textFormat` 時回報 `ValidationException`（`output_config.format: Extra inputs are not permitted`），因此不能用於盲測審查請求；`global.anthropic.claude-sonnet-4-5-20250929-v1:0` 已確認支援並完成多輪驗收（見 [多輪盲測](repeated-review.zh-TW.md)）。選用 Bedrock 模型前，先以一次最小合成請求確認結構化輸出可用。不支援時，報告的診斷為 `OUTPUT_CONFIGURATION`，不會自動改用其他模型或移除 schema。

## 2026-10-08 新版目錄驗收

更新 AWS 臨時憑證後，STS 確認指定帳號與角色有效。新版 `synthetic-review-v2` 已移除逐案 CWE 提示；第一批 `66d86091-639e-4b25-b74f-94c2d6c0358f` 的 Gemini 四次有效，Claude 四次遭 `OUTPUT_CONFIGURATION` 拒絕，報告維持 INCOMPLETE 且清理完成。Bedrock 官方支援清單只列陣列 `minItems=0/1`；移除 `maxItems` 後，Claude 單案 B10（`2fcffea2-53a1-4c02-8697-04009d240950`）成功。本機三項 finding 上限與嚴格證據驗證維持不變。

修正後重新執行同一批 B09～B12，報告 `edf879a8-390d-4bc0-bcfb-0234325871c3` 為 COMPLETE，八個回應全部有效。Gemini 與 Claude Sonnet 各有兩個真陽性、兩個真陰性，零誤報／漏報，兩個弱點行號全部命中；四組配對均可比較且無分歧，程序群組與暫存目錄清理完成。每次預留 1,024 個輸出詞元，整批八次／8,192 個，期限 130 秒。

本批 Gemini 回報輸入 1,842、輸出 576（包含回報的思考詞元）；Claude 回報輸入 4,157、輸出 537。用量只屬於本批，不含前述失敗或單案診斷；金額成本維持未知。歷史失敗不改寫，也不與不同批次拼接。此為四個合成案例的一輪驗收；偏誤降低、多輪穩定性、產品安全性與獨立人工核准仍未由此建立。

## API 依據

- [AWS Bedrock structured outputs](https://docs.aws.amazon.com/bedrock/latest/userguide/structured-output.html)
- [Gemini thinking](https://ai.google.dev/gemini-api/docs/thinking)
- [Gemini v1beta REST discovery](https://generativelanguage.googleapis.com/$discovery/rest?version=v1beta)

本輪 LM Studio 文字審查使用 OpenAI 相容的 `response_format.json_schema`，固定 ACK 仍為純文字。模型清單與推論回報識別值須一致；本機語意驗證不變，地端真實模型的 schema 相容性尚待實測。

<a id="en"></a>

# Bounded structured review output

Review requests use `security-review-json-v1`. Gemini requests JSON through `responseMimeType`/`responseJsonSchema`; Bedrock Converse uses `outputConfig.textFormat`. LM Studio adds OpenAI-compatible `response_format.json_schema` with local semantic validation; its real-model capability remains pending. The common schema describes shape without case IDs, reference answers, or peer answers, and does not use tool calls. ACK probes remain text. GLM retains prompt-based output plus strict local parsing, without a claim of native schema enforcement.

Gemini 3 Flash uses `thinkingLevel=LOW`, `includeThoughts=false`. The tested endpoint rejected MINIMAL and accepted LOW; this was an explicit correction, not automatic fallback/retry. Older generations, Pro, and unknown aliases do not receive that model-specific parameter. Future versions still require validation. Reported candidate plus thinking tokens count toward the existing output cap; thoughts are neither requested nor saved. Missing usage and monetary cost remain unknown.

Gemini/LM Studio schemas use line bounds and `maxItems=3`; Bedrock uses line enums and omits unsupported array/numeric/string constraints. Local validation always enforces at most three findings, exact quoted source lines, valid locations/IDs, verdict consistency, lengths, and safe Unicode. Duplicate keys, nonfinite numbers, Markdown fences, extra fields, fabricated evidence, truncation, refusal, and tool requests fail. Outputs are not repaired into passes, failures are not CLEAN, and there is no automatic retry/provider switch. Output format enters the request digest; schema and adapter code enter the implementation digest.

HTTP 400 diagnostics read at most 8 KiB of uncompressed JSON and classify recognized thinking/output configuration references into fixed codes. Raw provider errors, field paths, and credentials are not retained. Oversized/invalid/unrecognized bodies remain generic HTTP_ERROR; the code is a clue, not a complete diagnosis.

## Historical live acceptance

- **2026-10-05:** B09–B12, Gemini and Claude, eight calls, 1,024 output tokens each, 8,192 reserved total, 130-second deadline. Report `f4f05433-4c03-40c7-b618-7351a012030e` completed with eight valid responses; each provider had two TP/two TN and both vulnerable locations correct. All four pairs were comparable with no disagreement; cleanup completed. Gemini reported 1,896 input/1,151 output including reported thinking; Claude 3,879/484. These totals exclude earlier failed/diagnostic batches, which remain preserved.
- **2026-10-06:** `global.anthropic.claude-opus-5-5` accepted plain Converse but rejected `outputConfig.textFormat` with ValidationException (`output_config.format: Extra inputs are not permitted`). It is not accepted for schema-based reviews. Sonnet `global.anthropic.claude-sonnet-4-5-20250929-v1:0` supported the tested schema and completed the [repeated run](repeated-review.zh-TW.md#en). Probe compatibility with a minimal synthetic request before selecting a model; never silently remove schema or switch models.
- **2026-10-08, v2 without per-case CWE hints:** after secure AWS credential refresh and expected account/role validation, report `66d86091-639e-4b25-b74f-94c2d6c0358f` had four valid Gemini responses and four Claude OUTPUT_CONFIGURATION failures, remaining INCOMPLETE with cleanup. Bedrock supported only array minItems=0/1; removing unsupported maxItems allowed B10 diagnostic `2fcffea2-53a1-4c02-8697-04009d240950`. The local three-finding cap stayed unchanged.
- A complete B09–B12 rerun, `edf879a8-390d-4bc0-bcfb-0234325871c3`, returned eight valid answers: each provider two TP/two TN, zero FP/FN, both locations correct, four comparable agreeing pairs, and full cleanup. The same 8-call/8,192-token/130-second bounds applied. Gemini reported 1,842 input/576 output including thinking; Claude 4,157/537. Earlier failures and diagnostic usage are not overwritten or spliced into this batch.

These are one-round, four-case acceptance observations, not proof of multi-round stability, complete ASVS, bias reduction, product safety, or independent human approval. REFERENCE_MATCH is a reference comparison, not a human review. Current catalog v3 does not inherit v2 model-performance claims.

References: [Bedrock structured outputs](https://docs.aws.amazon.com/bedrock/latest/userguide/structured-output.html), [Gemini thinking](https://ai.google.dev/gemini-api/docs/thinking), [Gemini REST discovery](https://generativelanguage.googleapis.com/$discovery/rest?version=v1beta).
