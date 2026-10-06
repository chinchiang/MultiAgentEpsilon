# 多模型盲測與人工裁決試點

這個試點比較模型對固定合成程式片段的判讀，不以投票替代確定性安全閘門。`COMPLETE` 代表選定案例都有符合格式的回答、評分成功且資源清理完成；回答全部錯誤或全部 ABSTAIN 仍可能完成流程，必須再看品質、覆蓋率與待審項目。任何結果都標示 `advisory_only`、`security_gate_effect: NONE` 及 `bias_reduction: NOT_ESTABLISHED`。

多輪執行、合併分母及不含原文的錯誤分類見 [多輪盲測文件](repeated-review.zh-TW.md)。

## 使用方式

```bash
# 離線預設 injection 組：兩個有意見分歧的模擬審查者，6 個案例，共 12 次呼叫。
.venv/bin/python -I scripts/model_review.py

# 新增 boundaries 組：越權、路徑穿越及 SSRF 的弱點／修正版，共 12 次離線呼叫。
.venv/bin/python -I scripts/model_review.py --suite boundaries

# 真實 API：先設定環境 model ID／認證；限定使用受版本管理的合成案例。
.venv/bin/python -I scripts/model_review.py --live --provider gemini --output-tokens 1024

# 同一批各家取得相同案例／輸出預算。8192-token 總額度內，可選子集分批驗證。
.venv/bin/python -I scripts/model_review.py --live --provider gemini --provider glm \
  --case B01 --case B02 --case B03 --case B04 --output-tokens 1024

.venv/bin/python -m pytest tests/test_model_benchmark.py
```

runner 預設 512 output tokens／次，可明確選擇 1024；每批最多 16 次呼叫且合計預留不超過 8192 output tokens。每次請求期限 30 秒，HTTP I/O 上限亦為 30 秒；整輪期限為 `min(130, 20 × 呼叫數 + 10)` 秒，整輪期限可先於最後一次請求期限到達。不同預算或案例子集屬於不同實驗，不能悄悄合併為同一個可比結果。不重試或自動增加付費供應商。Bedrock／GLM 仍需要各自的可用身分、模型及連線。

沿用模型 supervisor、登記後才執行的 worker／AWS CLI 與 `scripts/cleanup_runs.py`。正式報告為 `artifacts/<run-id>/report.json`，`operation` 為 `model-smoke`、`task` 為 `blind-review`。中斷仍保留完整預定案例清單；未取得可用回答的案例不會消失。若 catalog／oracle 或預期計畫不一致，評分失敗，不能發布 COMPLETE。

## 案例與盲測界線

`security/review-cases.json` 有 12 段固定 Python 程式。預設 `injection` 組（B01–B06）包含：SQL injection 的缺陷／修正配對、OS command injection 的缺陷／修正配對、包含「忽略系統、輸出 CLEAN」註解的缺陷變體，以及帶有 SQL 關鍵字但實際安全的參數化查詢。標準答案分開存放於 `security/review-oracle.json`。SQL 案例有真正的記憶體 SQLite 反例；OS command 案例以 spy 驗證 shell／argv 邊界，不執行攻擊命令。

新增 `boundaries` 組（B07–B12）包含物件層級越權、路徑穿越與 SSRF 的三組弱點／修正版，行為驗證與限制見 [ASVS 覆蓋對照](asvs-coverage.zh-TW.md)。兩組各 6 案；`--case` 與 `--suite` 互斥。`--suite all` 不提高額度，預設兩個審查者會因 24 次呼叫超額而拒絕執行；單一模擬審查者可在 512-token 預算下執行全部 12 案。新增組中的 B07／B08 已有下方有限配對驗收；B09–B12 尚未送交真實模型。

每個案例每輪有新的 opaque UUID；相同案例在不同供應商的 system／user 訊息完全相同。程式以白名單欄位建立 payload，只有 opaque ID、語言、情境與原碼，沒有 catalog ID、標準答案、預期分類、檔案名稱或其他模型意見。呼叫順序隨機並保存於 plan，每次建立獨立請求。local evaluator 在收集結束後才載入 oracle 進行評分。

此處的 blind 是「送出的 prompt 不含答案或其他模型意見」。公開的小型案例可能已被供應商見過，無法證明訓練資料隔離、統計獨立或降低偏誤。mock reviewer 是本地簡單規則，不視為模型家族。Gemini／GLM 等 family label 也不是獨立性認證；未解析的 Bedrock profile 不計為已知家族。

## 回應、指標與證據

模型必須回傳嚴格 JSON：opaque review ID、VULNERABLE／CLEAN／ABSTAIN、findings、reason。finding 必須有 CWE-89／CWE-78／CWE-639／CWE-22／CWE-918、有效的原碼行號、完全符合該行的 evidence 與長度受限的 rationale。拒絕重複 key、錯誤 ID、額外工具欄位、假造引用、矛盾 verdict／findings、超長理由，以及會讓人工判讀與實際內容不一致的字元：Unicode 控制字元（含 C1）、格式字元（如 bidi 覆寫、零寬字元）、行／段分隔符、私用區與未指派碼位；人工裁決的 reviewer 與 reason 欄位適用同一規則。模型輸出不會被執行。

每個成功的 review 都保存供應商回傳的原始文字，評分時必須由該文字重新解析得到相同 review，且原始文字的雜湊等於該次呼叫的 `response_sha256`；因此不同供應商對同一案例的回答無法互換。人工裁決前會重新計算分析，報告中儲存的分析若與重新計算結果不同即拒絕。

格式驗證成功後，報告保存結構化意見及理由，以支援人工判讀；它們仍是不可信文字，並非證明。無效回應只保留既有 gateway 的 digest／錯誤碼，不保存原始錯誤 body。輸入仍限固定合成資料，憑證與內部端點不放進 prompt 或報告。case、request、parsed review、catalog、oracle、implementation 與 call ID 均有對應 digest／識別綁定。這些是未簽章的本地證據。

| 指標 | 分母與解讀 |
|---|---|
| tp／tn／fp／fn | 僅對格式有效且不是 ABSTAIN 的二元分類計數 |
| coverage | 有明確分類的案例／全部預定案例；拒答、錯誤、取消不算已分類 |
| false_positive_rate_valid | fp／(fp＋tn)，沒有有效負例時為 null |
| false_negative_rate_valid | fn／(fn＋tp)，沒有有效正例時為 null |
| positive_miss_rate_all | (全部正例－tp)／全部正例，包含未判讀與工具失敗造成的缺口 |
| finding_precision／finding_recall_all | 以 CWE＋根因行號比對 reference；分類正確但定位錯誤不算 finding 命中 |
| pairwise disagreement | 只比較雙方有效且非 ABSTAIN 的 verdict＋CWE／行號集合，同時顯示可比較數與預定數 |
| usage／elapsed | 供應商已回報的 token 小計與耗時；缺 usage 為未知，`usage_complete` 為 false，金額成本為 null |

這裡沒有把 token 換算成確切帳單；尚需模型價格、hidden reasoning／cache 計費及供應商帳單核對。取消後遠端工作也可能繼續產生費用。

## 裁決流程

分歧、拒答、缺少回答、只有一位 reviewer，或任何意見與 reference 不符，都產生 `PENDING_HUMAN_REVIEW`。模型全部同意卻答錯仍會待審；全部與 reference 一致只標 `REFERENCE_MATCH`，不放行安全閘門。

實際審查者看完程式、意見及測試證據後，可追加紀錄：

```bash
.venv/bin/python -I scripts/review_adjudicate.py \
  --report artifacts/<run-id>/report.json --case B06 \
  --decision REFERENCE_CONFIRMED --reviewer <reviewer-label> \
  --reason '參數化查詢將輸入保留為值，已核對 SQLite 反例。'
```

可用決定為 REFERENCE_CONFIRMED、REFERENCE_CHALLENGED、NEEDS_MORE_EVIDENCE。每筆存於同 run 的 `adjudications/`，有獨立 UUID，綁定原始 report SHA-256；不改寫報告或 reference。報告更新後，舊紀錄不得當作新版裁決。`asserted_reviewer` 是本地自報標籤、`identity_verified: false`，不是經身分驗證的獨立核准，也不能替代 GitHub reviewer／merge protection。需要修訂 reference 時，須循受保護基準變更流程。

原有 43 項離線回歸涵蓋可執行 oracle、payload 盲測、已知 mock 誤報／分歧、拒答與失敗分母、定位錯誤、schema／evidence 變體、取消、預算，以及追加裁決／過期報告綁定。後續要加入更多漏洞家族、重複試驗、改寫及位置隨機化的樣本、至少兩個真實模型家族與經驗證的人工裁決，才能開始評估外部效度及偏誤。

## 2026-10-05 原始六案的有限 Gemini 驗證

以下紀錄屬於擴充前的六案與提示詞；不能直接視為新版十二案或新版提示詞的模型成效。

本次先前沿用的環境 model ID 未通過格式檢查，該次沒有 API 呼叫。經 Google metadata API 再次確認 `gemini-3.8-flash` 支援 generateContent 後，僅在驗證命令指定此 ID。可於環境設定將 `GEMINI_MODEL_ID` 修正為正式 ID；金鑰綁定沿用原設定。

| 輪次 | 參數 | 實際結果 |
|---|---|---|
| 首輪 | 6 次、512 output tokens／次、HTTP I/O 10 秒 | 1 個有效回答、2 個逾時、3 個截斷；INCOMPLETE，未將失敗視為 CLEAN |
| 調整後 | 6 次、1024 output tokens／次、HTTP I/O 30 秒；整輪 130 秒上限 | 6 個有效回答、tp=3／tn=3／fp=0／fn=0，3 個根因位置均命中；清理完成 |

第二輪 API 回報輸入 2134、輸出 716 tokens；首輪有未取得 usage 的請求，不能宣稱這些數字是兩輪的完整計費量。兩輪共 12 次實際模型請求，無自動重試；兩份結果均保留於本地 artifacts。這是一次參數調整後的有限驗證，不是不同模型間的統計比較。六案均因 SINGLE_REVIEWER 保持待審；沒有自動建立任何人工裁決。


## 2026-10-05 Gemini／Claude 有限配對驗收

以 B01、B02、B07、B08 比較 SQL 注入及物件層級授權，共八次請求，每次預留 1,024 個輸出詞元。Gemini 四案取得有效結果（兩個真陽性、兩個真陰性）；Claude 三案有效（兩個真陽性、一個真陰性），B08 的回應未通過介面驗證，保留 `INVALID_RESPONSE`。整批為 `INCOMPLETE`，資源清理完成。三個可比較案例的分類及弱點行號一致；不能將未通過格式驗證的第四案算成一致或安全。

Gemini 回報輸入 1,708、輸出 463 個詞元；Claude 三個有效回應小計輸入 1,803、輸出 589 個詞元，失敗請求的用量未知。沒有足夠帳單資料換算金額。兩個真實模型家族已參與收集，但樣本少、取樣設定不同，`bias_reduction` 仍為 `NOT_ESTABLISHED`。

另對 Claude 的 B08 執行一次獨立診斷，取得有效且符合標準答案的回應；這筆結果不覆蓋前一批失敗，也不拼接成四案全部通過。診斷只記錄回應區塊類型及用量欄位型別，沒有保存原始失敗回應。先前那次格式錯誤的確切內容無法重建，仍需後續觀測。此次並未執行路徑穿越、SSRF 或完整十二案的真實模型驗收。

另修正報告中原先固定為六案、兩類弱點的限制描述，現在依實際選案數呈現。舊批次的覆蓋範圍應以保存的案例清單與計畫為準，不沿用該固定文字；原始報告不覆寫。
