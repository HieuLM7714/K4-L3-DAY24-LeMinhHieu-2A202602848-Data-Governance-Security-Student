# Secret giả trong lịch sử Git — điền trong checkpoint 4

> Token trong bài là **token giả, vô hiệu** (`LAB24-DEMO-...`) do đề bài cài sẵn để luyện tập.
> Finding dưới đây là bằng chứng checkpoint 4, **không phải** sự cố lộ credential thật.

- **Scanner và phiên bản:** Gitleaks `8.30.1` (`gitleaks version`), binary tải từ release chính thức
  v8.30.1, đã đối chiếu SHA-256 với `gitleaks_8.30.1_checksums.txt` trước khi cài. Cấu hình
  `.gitleaks.toml` = rule mặc định (`useDefault = true`) + rule `lab24-synthetic-token`.

- **Commit chứa token giả:** `1bdd849` (`1bdd849922156c868a5ee9293d68f5b72e242d2c`,
  "chore: seed student lab with synthetic secret exercise", 2026-10-09).
  File bị xoá ở commit kế tiếp `ece6ca4` ("feat: publish two-hour L3 student lab ...").

- **File, rule và kết quả quét lịch sử:**
  `gitleaks git --config .gitleaks.toml --redact --verbose .` → **exit 1, `leaks found: 1`**, 8 commit được quét.

  ```
  RuleID:      lab24-synthetic-token
  File:        lab-fake-secret.txt
  Line:        1
  Commit:      1bdd849922156c868a5ee9293d68f5b72e242d2c
  Fingerprint: 1bdd849922156c868a5ee9293d68f5b72e242d2c:lab-fake-secret.txt:lab24-synthetic-token:1
  Secret:      REDACTED
  ```

  Exit 1 là kết quả **dự kiến** (CHECKPOINTS §4), không phải lỗi công cụ.

- **Kết quả quét file hiện tại:** `gitleaks dir --config .gitleaks.toml --redact .` → **exit 0,
  `no leaks found`**. Hook `.pre-commit-config.yaml` (repo `https://github.com/gitleaks/gitleaks`,
  `rev: v8.30.1`, `id: gitleaks-system`, `pass_filenames: false`): `pre-commit run --all-files` → **Passed**;
  đã `pre-commit install` nên mỗi commit mới đều được quét phần staged.
  Dependency: `requirements.lock` sinh bằng `pip-compile --generate-hashes`, 11 package đều pin `==`
  và có `--hash=sha256:`; `pip install --require-hashes -r requirements.lock` chạy thành công.

- **Nếu đây là credential thật, cần xử lý thế nào:**
  1. **Thu hồi / rotate ngay** token tại hệ thống phát hành (revoke key cũ, cấp key mới, cập nhật nơi dùng
     qua secret manager/biến môi trường — không commit lại).
  2. Coi token là **đã bị lộ** từ thời điểm push `1bdd849`: kiểm tra audit log của hệ thống đích trong
     khoảng thời gian đó để tìm truy cập bất thường.
  3. Sau khi đã rotate, mới cân nhắc làm sạch lịch sử (`git filter-repo`/BFG + force-push, yêu cầu mọi
     clone/fork đồng bộ lại) — đây chỉ là dọn dẹp, không phải biện pháp khắc phục.
  4. Ghi nhận sự cố, xác định nguyên nhân (vì sao secret vào được repo) và bật chặn trước commit (hook ở trên).

- **Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:**
  - Xoá file ở `ece6ca4` chỉ làm HEAD sạch; blob vẫn nằm trong lịch sử Git và trong **mọi clone/fork/cache**
    đã tải về — chính `gitleaks git` vẫn tìm thấy. Ngay cả viết lại lịch sử cũng không thu hồi được bản
    sao người khác đã có. Chỉ **rotate/thu hồi** mới làm credential đã lộ mất giá trị.
  - Pin dependency bằng hash (`requirements.lock`) chống **package bị tráo/sửa** trong supply chain; nó
    không liên quan tới secret đã nằm trong repo.
  - Hook pre-commit là biện pháp **phòng ngừa cho commit tương lai** (và có thể bị bỏ qua bằng
    `--no-verify` hoặc máy không cài hook); nó không xử lý secret đã được commit/push trước đó.
