# 受限的結構化審查輸出

盲測請求使用 `security-review-json-v1` 輸出模式。Gemini 透過 `responseMimeType=application/json` 與 `responseJsonSchema`，Bedrock Converse 透過 `outputConfig.textFormat`，要求模型原生輸出 JSON。共用 schema 只描述審查資料形狀，不含案例 ID、標準答案或其他模型的回答，亦不使用工具呼叫傳遞審查結果。固定 ACK 測試維持純文字；GLM 維持既有提示詞與嚴格本機驗證，尚未宣稱有原生 schema 約束。

Gemini 3 Flash 系列的審查請求指定 `thinkingLevel=LOW`、`includeThoughts=false`。本次實際端點拒絕 `MINIMAL`，改成 `LOW` 後才通過；此設定不是自動降級或重試。舊世代、Pro 與不明模型名稱不套用該模型專屬參數。模型能力仍須實際驗證，不保證所有別名或日後版本均相容。

單次輸出與整批預留上限不變。Gemini 的 `candidatesTokenCount` 與 `thoughtsTokenCount`（若有回報）合計作為輸出用量，超額仍拒絕；不保存或要求回傳思考內容。失敗回應缺少的用量維持未知，金額成本也維持未知。

schema 使用兩家共同支援的子集；它不取代本機驗證。重複 JSON key、非有限數字、Markdown 圍欄、額外欄位、錯誤案例識別碼、偽造引用、不符的弱點行號及判定／finding 不一致均拒絕。供應商回報截斷、拒答或工具呼叫也維持失敗；不修補模型輸出、不把失敗轉為 CLEAN、不自動重試或切換供應商。`response_format` 納入請求摘要，schema 與 adapter 實作納入實作摘要。

HTTP 400 可讀取最多 8 KiB、未壓縮的 JSON 錯誤本文，只將提及思考設定或輸出設定的訊息分類為 `THINKING_CONFIGURATION`／`OUTPUT_CONFIGURATION`。不保留原文、欄位路徑或憑證；無法分類、過大或不合法的錯誤維持一般 `HTTP_ERROR`。這是診斷線索，不能憑此推斷完整原因。

## 2026-10-05 真實配對驗收

以同一組 B09～B12 案例執行 Gemini／Claude 各四次，共八次請求，每次最多 1,024 個輸出詞元、總預留 8,192、整批期限 130 秒。最終報告 `f4f05433-4c03-40c7-b618-7351a012030e` 的八個回應全部有效；每家均為兩個真陽性、兩個真陰性，兩個弱點行號全部命中。四組配對均可比較且無分歧，程序與暫存清理完成。

Gemini 回報輸入 1,896、輸出 1,151（包含回報的思考詞元）；Claude 回報輸入 3,879、輸出 484。此為最後一批的用量，不包括前面的失敗與診斷批次。先前拒答、截斷、JSON 語法錯誤與不支援設定的報告皆保留，未以本批成功覆蓋。

這是一輪、四個合成案例的有效性驗收，不是多輪穩定性、完整 ASVS 覆蓋、偏誤降低或獨立人工核准。`REFERENCE_MATCH` 只代表與既有標準答案一致，不代表真人已審查。

## API 依據

- [AWS Bedrock structured outputs](https://docs.aws.amazon.com/bedrock/latest/userguide/structured-output.html)
- [Gemini thinking](https://ai.google.dev/gemini-api/docs/thinking)
- [Gemini v1beta REST discovery](https://generativelanguage.googleapis.com/$discovery/rest?version=v1beta)
