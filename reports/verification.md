# Verification — điền trước khi nộp

- **OS / Python / Gitleaks version:** Windows 10 (10.0.19044, chạy **native Windows**, không qua WSL2) /
  Python 3.12.3 trong `.venv` / Gitleaks **8.30.1** (`gitleaks version`, binary release chính thức, đã kiểm SHA-256).

- **`python -m pytest tests/ -q`:** `33 passed`.
  - `tests/test_pii.py -s`: `gold=118 pred=118 tp=118`, `precision=1.000 recall=1.000`.
  - `tests/test_injection.py`: 8/8 (4 biến thể × `support_l1`, `dpo`); `tests/test_split.py`, `tests/test_obo.py`,
    `tests/test_policy.py`, `tests/test_ledger.py`, `tests/test_supply_chain.py` đều pass.

- **`pre-commit run --all-files`:** `Detect hardcoded secrets....Passed` (hook `gitleaks-system`, `rev: v8.30.1`).
  Thêm: `gitleaks dir --config .gitleaks.toml .` → no leaks found (exit 0);
  `gitleaks git --config .gitleaks.toml --redact --verbose .` → **1 finding dự kiến** ở commit `1bdd849`,
  rule `lab24-synthetic-token`, exit 1 (token giả, xem `reports/secrets-incident.md`).

- **Ledger verify:** `verify(Path('reports/ledger.jsonl'))` → `True` (46 dòng, mọi dòng có `reason`).
  Chứng minh tamper: trên **bản copy** của ledger, đổi `decision` dòng 2 từ `allow` sang `deny` mà không tính lại hash →
  `verify()` = `False` (cùng tính chất được `tests/test_ledger.py::test_verify_detects_tampering` kiểm).

- **Before / after:**
  - `reports/attack-before.log`: 1 dòng, POST `/reconcile` chứa record synthetic của `KH-000999` (chạy baseline ở checkpoint 2).
  - `reports/attack-after.log`: **0 byte**. Quy trình: `sink --reset` → `pytest tests/ -q` → `sink --reset` →
    `python -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"` → thêm một lần `--as support_l1` →
    copy `reports/sink.log`.

- **Các lỗi còn lại / ghi chú môi trường:**
  - README khuyến nghị WSL2/macOS/Linux; bài này chạy **native Windows** và mọi lệnh kiểm ở trên đều chạy được.
  - Trong Git Bash, output tiếng Việt của `agent.check_lure` lỗi `UnicodeEncodeError` (console cp1252).
    Tái hiện: chạy `python -m agent.check_lure corpus/ticket-90*.md` trong Git Bash không đặt biến môi trường.
    Cách xử lý: `PYTHONIOENCODING=utf-8` hoặc chạy trong PowerShell. Không ảnh hưởng logic hay test.
  - `requirements.lock` được sinh trên Windows nên có `colorama` (phụ thuộc của pytest trên Windows).
  - Không còn test FAIL/SKIP. Không làm phần bonus.
