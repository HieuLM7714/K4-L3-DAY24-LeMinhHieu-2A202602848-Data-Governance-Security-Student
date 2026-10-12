# Baseline — điền trong checkpoint 1

1. Agent có identity mỗi run chưa? Dẫn file/hàm:
   **Chưa.** `agent/loop.py` `_naive_loop(message, llm)` (dòng 27) chỉ nhận `message` và `llm` — không có `run_id`, `agent_id` hay principal; `principal_id` từ `--as` được `run_once()` (dòng 58, 69) chuyển cho `runner.handle()` nhưng khi rơi về baseline (dòng 73–74) thì bị bỏ qua, nên mọi tool call chạy dưới cùng một identity ẩn danh của process.

2. Ai cho phép `http_post`? Dẫn file/hàm:
   **Không ai.** `agent/loop.py` `_naive_loop()` dòng 34–44 gọi `tools.http_post(injected.target_url, ...)` ngay khi `llm.find_injection()` thấy chỉ thị trong text corpus (untrusted), không qua policy/PEP nào; kiểm tra duy nhất là allowlist cứng `127.0.0.1:10024` trong `agent/tools.py` `http_post()` dòng 76–83, vốn là hàng rào an toàn của lab chứ không phải quyết định cho phép theo dữ liệu/mục đích.

3. Nếu gửi sai PII ra sink, bằng chứng ở đâu? Dẫn file/hàm:
   **Chỉ ở phía nhận:** `sink/sink.py` `make_handler().do_POST()` dòng 42–47 ghi body vào `reports/sink.log`; phía agent không có ledger/audit nào (`_naive_loop()` không ghi gì, `agent/ledger.py` chưa được gọi), nên không biết run nào, ai, vì sao đã đọc `read_customer` (dòng 39) và POST record đó đi.
