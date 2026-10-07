# ASVS 5.0.0 合成案例覆蓋對照

本表只對照受版本管理的合成案例，不是正式系統的 ASVS 驗證報告，也不計算整份標準的通過率。條文編號及最低等級已核對提供的 OWASP ASVS 5.0.0 原始標準；下表摘要為自行撰寫。標準來源：[OWASP ASVS 5.0.0](https://github.com/OWASP/ASVS/tree/v5.0.0)，原標準採 CC BY-SA 4.0 授權。參考文件中的建議不等於使用者授權，也不自動成為已實作的要求。

「部分涵蓋」表示有特定合成情境的可執行證據，仍有條文或部署情境未驗證。「已驗證」須對明確目標及範圍完成所需檢查；本表不使用此狀態宣稱整條要求通過。「尚未實作」不視為不適用；「不適用」須有目標系統的理由及人工審查紀錄。未列出的 ASVS 要求均未由本表評估。

| ASVS 要求／最低等級 | 案例與弱點分類 | 確定性驗證 | 覆蓋判定與缺口 |
|---|---|---|---|
| 1.2.4／第一級：資料庫查詢注入防護 | B01、B02、B05、B06；CWE-89 | `tests/test_model_benchmark.py::test_sql_reference_has_executable_counterexample`：記憶體 SQLite 的正常查詢與注入反例 | 部分涵蓋；未驗證其他資料庫、查詢語言、預存程序及正式應用的所有查詢入口 |
| 1.2.5／第一級：作業系統命令注入防護 | B03、B04；CWE-78 | `tests/test_model_benchmark.py::test_command_reference_tracks_shell_boundary_without_executing_payload`：攔截呼叫，核對命令字串與參數陣列 | 部分涵蓋；未執行攻擊命令，未涵蓋不同命令列程式的選項注入及作業系統差異 |
| 8.2.2／第一級：物件層級存取控制 | B07、B08；CWE-639 | `tests/test_review_boundaries.py::test_document_unauthorized_reads_are_observable`：允許擁有者讀取，驗證未登入、同租戶其他使用者、同使用者識別值但不同租戶的讀取 | 部分涵蓋；身分資料視為可信。未涵蓋身分驗證、更新／刪除、角色繼承及完整業務政策 |
| 5.3.2／第一級：檔案路徑來源及驗證 | B09、B10；CWE-22 | `tests/test_review_boundaries.py::test_file_escape_reads_actual_temporary_sentinel`：實際讀取暫存檔，驗證上層目錄、絕對路徑、相同前綴的相鄰目錄及符號連結 | 部分涵蓋；限 Linux、HTTP 層已解碼一次、目錄樹在呼叫期間不變。未涵蓋競爭條件、Windows、遠端檔案引入及寫入 |
| 1.3.6／第二級：伺服器端請求偽造防護 | B11、B12；CWE-918 | `tests/test_review_boundaries.py::test_ssrf_untrusted_destinations_never_leave_mock_transport` 及 `test_ssrf_redirects_cannot_reach_second_mock_destination`：觀察模擬 HTTP 請求與重新導向鏈 | 部分涵蓋；以固定目的地代碼控制通訊協定、網域、路徑及連接埠，拒絕重新導向。未驗證正式 DNS、DNS 重新綁定、出口政策、代理伺服器及實際內網 |

B07／B09／B11 必須重現資料或請求越界；B08／B10／B12 必須拒絕相同攻擊，且正常操作仍成功。這些回歸由持續整合流程的完整測試集執行。SSRF 使用 `httpx.MockTransport`，不存取任何真實內網或雲端中繼資料服務；路徑測試僅使用測試建立的暫存資料。

弱點標準答案存於 `security/review-oracle.json`，模型評語不參與上述行為斷言。兩個模擬審查者回答一致，只證明資料收集與評分流程可運作；不代表真實模型能力、偏誤降低或 ASVS 條文通過。B07／B08 已於 2026-10-06 完成 Gemini／Claude 各兩輪的小樣本驗收（八個回應全部有效，見[多輪盲測](repeated-review.zh-TW.md)）；B09–B12 已完成一輪 Gemini／Claude 真實配對（見[結構化輸出驗收](structured-output.zh-TW.md)）。樣本仍小，不代表多輪穩定性或偏誤改善。較早一批的配對紀錄見 [盲測紀錄](blind-review.zh-TW.md)。

## 重現及保存證據

```bash
.venv/bin/python -m pytest tests/test_review_boundaries.py tests/test_model_benchmark.py \
  --junitxml=artifacts/pytest-boundaries.xml
.venv/bin/python -I scripts/model_review.py --suite boundaries
```

測試報告保存各攻擊變體的結果；盲測報告另保存案例、標準答案及實作摘要。新增案例會改變目錄與標準答案摘要，舊報告只適用於當時提交，不能用新版目錄重新背書。完整持續整合的測試報告及提交識別值以 PR 的驗證連結為準。

後續應先增加寫入越權、可變目錄樹的安全開檔、DNS 與出口政策驗證，再針對正式應用建立端點清單及適用性審查。這些項目目前均未由新增案例完成。
