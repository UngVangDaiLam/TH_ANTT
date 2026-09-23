# Báo cáo kiểm thử bypass SecureLogger + SecureValidator

- Dự án: `E:\HK1_26-27\TH_ANTT\Bai1\Lap3\secure_logger_lab`
- Ngày kiểm thử: 23/09/2026
- Người thực hiện: Claude (Cowork), theo yêu cầu của sinh viên chủ sở hữu bài lab
- Dữ liệu dùng trong kiểm thử: **hoàn toàn giả** (`alice@example.com`, `SuperSecret123`, `ghp_FAKEtoken0123456789`, `AKIAFAKE1234567890`…)

> **Tóm tắt nhanh.** Đã **tái hiện 7 phát hiện** trên bản sao và **xác nhận thêm 4 điểm bằng đọc mã**. Nghiêm trọng nhất:
> 1. **Cơ chế toàn vẹn không bao giờ xác minh được** (SL-03): `JSONFormatter.format()` sinh lại `timestamp` mỗi lần chạy và được gọi nhiều lần cho mỗi bản ghi; chữ ký băm một lần định dạng, còn dòng thật ghi ra là một lần định dạng khác ⇒ hash luôn lệch. Chính tệp `secure.log.sig` **gốc của bạn cũng không khớp** với dòng trong `secure.log` gốc (tôi chỉ đọc, không sửa), chứng minh cơ chế hỏng chứ không phải bị tấn công.
> 2. **`.sig` chỉ là SHA-256 không khóa, không có trình xác minh** (SL-04): kẻ ghi được log cũng ghi được `.sig`, nên sửa/cắt ngắn không bị phát hiện. `.sig` không phải chữ ký số dù có đuôi `.sig`.
> 3. **Che PII bị bypass** (SL-01): mật khẩu/token/khóa dạng JSON (dấu hai chấm) **xuất hiện nguyên văn trong `secure.log`**, vì regex chỉ bắt dạng `key=value`.
> 4. **Xoay vòng nén hỏng** (SL-05): ghi 40 bản ghi chỉ còn giữ lại 8; `BACKUP_COUNT` không được bảo đảm.
> 5. **Yêu cầu JSON hợp lệ nhưng không phải object gây HTTP 500 và không được ghi log** (SL-06), kèm `debug=True` (SL-07).

Mọi kiểm thử chạy trên **bản sao** trong thư mục tạm, dùng `test_client` (không mở cổng ra ngoài). Không sửa mã nguồn, môi trường ảo hay tệp log gốc; không `git add`/commit/push.

---

## 1. Mục tiêu, phạm vi và môi trường

### 1.1 Mục tiêu
Tìm các điểm yếu khiến (a) PII lọt vào log, (b) log bị giả mạo mà không bị phát hiện, (c) xoay vòng/lưu giữ log sai, (d) ứng dụng Flask xử lý đầu vào lỗi không an toàn; chứng minh cách tái hiện bằng dữ liệu giả và đề xuất khắc phục.

### 1.2 Phạm vi và quy tắc đã tuân thủ

| Quy tắc | Cách thực hiện |
|---|---|
| Giữ nguyên mã nguồn gốc | Chỉ **đọc** 8 tệp mục tiêu + `secure.log`/`secure.log.sig`. Không ghi vào thư mục dự án gốc trừ hai tệp báo cáo. |
| Kiểm thử trên bản sao | Sao chép `app.py`, `securelogger/`, `securevalidator/` sang thư mục tạm; mỗi ca chạy trong một thư mục con riêng, cwd riêng. |
| Không mở cổng gốc | Dùng `Flask.test_client()` — đi qua đúng luồng xử lý request nhưng **không** mở cổng 5000 hay cổng nào khác. |
| Dữ liệu giả, không ra ngoài | Chỉ `example.com`, token/mật khẩu tự tạo; không gọi dịch vụ ngoài, không dùng thông tin thật. |
| Giới hạn tải | Ca xoay vòng dùng `maxBytes=800` để ép xoay vòng nhanh với vài chục bản ghi, **không** stress test. |
| Không đụng log gốc | Đã kiểm chứng `secure.log`/`secure.log.sig` gốc **trước** khi thử giả mạo; mọi thao tác giả mạo làm trên tệp giả trong thư mục tạm. |

### 1.3 Môi trường

**Máy của bạn (đọc từ tệp, không chạy được lệnh trên Windows trong phiên này):**

| Thành phần | Giá trị | Nguồn |
|---|---|---|
| Hệ điều hành | Windows (win32, x64) | thông tin thiết bị |
| Python (venv) | 3.13.14 | `.venv/pyvenv.cfg` |
| Flask / Werkzeug | 3.1.3 / 3.1.8 | `.venv/Lib/site-packages/*.dist-info` |
| Jinja2 / MarkupSafe / click / blinker / itsdangerous | 3.1.6 / 3.0.3 / 8.5.0 / 1.9.0 / 2.2.0 | như trên |
| `secure.log` | 1 bản ghi INFO, kết thúc dòng **CRLF** | đọc `cat -A` |
| `secure.log.sig` | 64 byte hex (1 digest SHA-256), **không** ký tự xuống dòng | đọc `cat -A` |
| Phiên bản Git | **Chưa xác định** (phiên không có shell trên Windows) | — |

**Môi trường kiểm thử (đám mây, Linux):** Linux x86_64, Python 3.11.15, Flask 3.1.3, Werkzeug 3.1.8 (khớp phiên bản Flask/Werkzeug với máy bạn; Python khác nhánh 3.11 vs 3.13). Khác biệt cần lưu ý: kết thúc dòng mặc định là **LF** trên Linux so với **CRLF** trên Windows — có ảnh hưởng tới hash (mục SL-03) nhưng không phải nguyên nhân chính.

**Lệnh để bạn tự ghi nhận môi trường (trong thư mục `secure_logger_lab`):**

PowerShell:
```powershell
git --version
.\.venv\Scripts\python.exe --version
.\.venv\Scripts\python.exe -c "import importlib.metadata as m; print('Flask', m.version('flask'), 'Werkzeug', m.version('werkzeug'))"
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture
```

Git Bash:
```bash
git --version
./.venv/Scripts/python.exe --version
./.venv/Scripts/python.exe -c "import importlib.metadata as m; print('Flask', m.version('flask'), 'Werkzeug', m.version('werkzeug'))"
```

---

## 2. Cơ chế hoạt động và đối chiếu yêu cầu bài

### 2.1 Luồng xử lý `POST /validate`

1. `app.py:14` — `data = request.get_json(force=True)`. JSON sai cú pháp ⇒ ném ngoại lệ ⇒ `except` (dòng 15–18) ghi log **WARNING** với `str(request.data)` và trả `400`.
2. `app.py:20–26` — gọi 5 hàm của `SecureValidator` trên `data.get(...)` để tạo `results`.
3. `app.py:28–29` — `secure_logger.info("Validation check performed", extra={"data": data, "results": results})`.
4. `JSONFormatter.format` (`logger.py:26–39`) — che PII trên `message`, `str(data)`, `str(results)`; đóng gói `timestamp/level/message[/data/results]` thành **một dòng JSON**.
5. `SecureRotatingFileHandler.emit` (`logger.py:47–54`) — `msg = self.format(record)` (dòng 50), rồi `super().emit(record)` (dòng 51, ghi ra `secure.log`), rồi `append_signature(msg)` (dòng 52) ghi SHA-256 vào `secure.log.sig`.
6. Khi `secure.log` vượt `MAX_LOG_SIZE` (1 MiB) ⇒ `RotatingFileHandler` xoay vòng; `GZipRotator` (`logger.py:41–45`) nén thành `dest + ".gz"`.

### 2.2 Đối chiếu yêu cầu bài

| Yêu cầu | Trạng thái | Ghi chú |
|---|---|---|
| Hỗ trợ DEBUG..CRITICAL | **Có** (`logger.setLevel(logging.DEBUG)`, `logger.py:58`) | Nhưng app chỉ dùng `.info`/`.warning`. |
| Phát hiện & che PII | **Một phần** | Chỉ regex `email` và `token=value` (`logger.py:9–12`). Bỏ sót dạng JSON dấu hai chấm và nhiều loại PII (SL-01, SL-02). |
| Xoay vòng + nén | **Có nhưng lỗi** | `GZipRotator` chạy nhưng phá vỡ cơ chế backup của handler (SL-05). |
| Phát hiện thay đổi trái phép | **Chỉ mô tả, không thực thi được** | Có mã **tạo** hash (`append_signature`) nhưng **không có** mã **xác minh**; và hash không bao giờ khớp (SL-03, SL-04). |
| Ghi log JSON | **Có** (`json.dumps`, `logger.py:38`) | Nhờ đó chống được log injection newline (SL-10). |
| Tích hợp SecureValidator | **Có** | Nhưng validator có hạn chế thiết kế (SL-08, SL-09). |

---

## 3. Bảng tổng hợp phát hiện

Mức độ (phạm vi lab): **Cao** = mất một mục tiêu bảo mật chính (PII lọt, toàn vẹn vô hiệu, mất log); **Trung bình** = cần điều kiện cụ thể hoặc ảnh hưởng độ tin cậy; **Thấp** = hạn chế thiết kế/độ bền, chưa khai thác trực tiếp.

| ID | Tên | Nhóm | Trạng thái | Mức |
|---|---|---|---|---|
| SL-01 | Bypass che PII: token/mật khẩu dạng JSON (dấu hai chấm) và dữ liệu lồng nhau | A | **Đã tái hiện** | Cao |
| SL-02 | Phạm vi PII hẹp: phone, SSN, thẻ, IP không che; email biến thể che một phần | A | **Đã tái hiện** | Trung bình |
| SL-03 | Chữ ký không khớp dòng log (format sinh timestamp mới, gọi nhiều lần) | B | **Đã tái hiện** | Cao |
| SL-04 | SHA-256 không khóa, không có trình xác minh ⇒ giả mạo/cắt ngắn không bị phát hiện | B | Đọc mã + mô phỏng tái hiện | Cao |
| SL-05 | Xoay vòng nén phá vỡ `BACKUP_COUNT`, mất/ghi đè bản ghi; `.sig` không xoay vòng | D | **Đã tái hiện** | Cao |
| SL-06 | JSON hợp lệ nhưng không phải object ⇒ HTTP 500, không ghi log | E | **Đã tái hiện** | Trung bình |
| SL-07 | `debug=True` khi chạy app | E | Đọc mã (rủi ro theo triển khai) | Trung bình |
| SL-08 | `sanitize_sql_input` là blacklist xóa từ khóa, có thể vượt và làm hỏng dữ liệu | E | **Đã tái hiện** (vượt blacklist) | Thấp–Trung bình |
| SL-09 | `validate_url` không chống SSRF thực chất | E | Đọc mã | Thấp |
| SL-10 | Log injection qua newline **không** tái hiện được (JSON đã escape) | C | **Đã kiểm, âm tính** | Thông tin |
| SL-11 | `datetime.utcnow()` deprecated; `requirements.txt` không ghim phiên bản | — | Đọc mã | Thấp |

**Số phát hiện đã tái hiện:** 7 (SL-01, 02, 03, 05, 06, 08, và SL-04 qua mô phỏng). **Xác nhận bằng đọc mã:** SL-07, SL-09, SL-11. **Kiểm và âm tính (không phải lỗ hổng):** SL-10.

---

## 4. Chi tiết tái hiện và bằng chứng

Bản sao được tạo bằng cách sao chép module sang thư mục tạm; mỗi ca chạy trong thư mục con riêng để `secure.log`/`secure.log.sig` không lẫn nhau. Bộ khung kiểm thử đầy đủ ở **Phụ lục A**.

---

### SL-01. Bypass che PII — token/mật khẩu dạng JSON không được che

- **Loại:** Bỏ sót (A). **Trạng thái:** Đã tái hiện. **Mức:** Cao.
- **Vị trí:** `securelogger/logger.py:9–17` (regex + `mask_pii`), áp dụng tại `logger.py:35,37` cho `str(data)`/`str(results)`.
- **Điều kiện:** Client gửi PII trong trường `data` (bất kỳ khóa nào) không theo dạng `key=value`.
- **Nguyên nhân kỹ thuật:** Mẫu token `(?i)(token|apikey|key|password)\s*=\s*["\']?[\w\-]{8,}` **bắt buộc có dấu `=`**. Nhưng `record.data` là dict, được đưa vào log qua `str(record.data)` (repr Python) nên khóa/giá trị hiển thị dạng `'password': 'SuperSecret123'` (dấu **hai chấm**). Không có `=` ⇒ không khớp ⇒ không che. Ngoài ra không có mẫu cho chuỗi kiểu AWS key (`AKIA…`).
- **Payload:**
  ```json
  {"email":"alice@example.com","password":"SuperSecret123",
   "apikey":"AKIAFAKE1234567890","note":"token: ghp_FAKEtoken0123456789"}
  ```
- **Kết quả mong đợi:** Mật khẩu/token/khóa bị che trong `secure.log`.
- **Kết quả thực tế (HTTP 200), trích `secure.log`:**
  ```
  ...\"data\": \"{'email': '<email_masked>', 'password': 'SuperSecret123',
  'apikey': 'AKIAFAKE1234567890', 'note': 'token: ghp_FAKEtoken0123456789'}\"...
  ```
  Kiểm tra hiện diện chuỗi trong tệp log: `SuperSecret123 -> True`, `AKIAFAKE1234567890 -> True`, `ghp_FAKEtoken0123456789 -> True`. (Email vẫn được che, chứng tỏ chỉ nhánh token/PII-khác bị bỏ sót.)
- **Đối chứng (A1b):** cùng bí mật nhưng viết `password=SuperSecret123 token=ghp_...` (có `=`) ⇒ **được** che thành `<token_masked>`. Điều này xác nhận nguyên nhân là dạng biểu diễn (`:` vs `=`), không phải regex hỏng hoàn toàn.
- **Khắc phục:** che theo **cấu trúc** thay vì regex trên chuỗi repr. Duyệt dict/list đệ quy, che theo tên khóa nhạy cảm, rồi mới `json.dumps`. Xem mã ở mục 5.
- **Kiểm thử lại:** gửi lại payload trên với bản vá ⇒ giá trị bí mật không còn trong log; email hợp lệ trong `results` vẫn hoạt động.
- **Giới hạn còn lại:** che theo tên khóa vẫn bỏ sót bí mật nằm trong văn bản tự do; cần kết hợp phát hiện theo mẫu/entropy.

---

### SL-02. Phạm vi PII hẹp và che nhầm một phần

- **Loại:** Giới hạn phạm vi + che nhầm (A). **Trạng thái:** Đã tái hiện. **Mức:** Trung bình.
- **Vị trí:** `logger.py:9–12`.
- **Nguyên nhân:** Chỉ có 2 loại (email, token=value). Không có số điện thoại, SSN, số thẻ, địa chỉ IP. Mẫu email `[\w\.-]+@[\w\.-]+\.\w+` không nhận `+` nên với `user+tag@example.com` chỉ khớp `tag@example.com`, để lộ tiền tố `user+`.
- **Payload:** `{"phone":"+84 912 345 678","ssn":"123-45-6789","card":"4111 1111 1111 1111","ip":"203.0.113.45","email_plus":"user+tag@example.com"}`
- **Kết quả thực tế (HTTP 200):** trong `secure.log` — `+84 912 345 678`, `123-45-6789`, `4111 1111 1111 1111`, `203.0.113.45` đều **hiện nguyên văn**; `email_plus` bị che một phần thành `user+<email_masked>` (`user+` còn lộ).
- **Khắc phục:** bổ sung mẫu cho các loại PII cần bảo vệ theo chính sách; sửa mẫu email để bao gồm `+` trong phần local (`[\w.+-]+@…`). Ưu tiên che theo tên khóa (SL-01) cho dữ liệu có cấu trúc.
- **Giới hạn còn lại:** danh sách loại PII luôn có thể thiếu; số thẻ nên xác thực Luhn để giảm che nhầm.

---

### SL-03. Chữ ký không bao giờ khớp dòng log

- **Loại:** Lỗi triển khai toàn vẹn (B). **Trạng thái:** Đã tái hiện. **Mức:** Cao.
- **Vị trí:** `logger.py:30` (`datetime.utcnow()` trong `format`), `logger.py:50–52` (`emit` gọi `format` rồi `super().emit` rồi `append_signature(msg)`).
- **Nguyên nhân kỹ thuật:**
  1. `JSONFormatter.format` tạo `timestamp` **mới mỗi lần** được gọi (`datetime.utcnow().isoformat()`), tức hàm **không idempotent**.
  2. `emit` gọi `self.format(record)` để lấy `msg` (dòng 50) rồi gọi `super().emit(record)` (dòng 51) — bên trong `logging` **gọi `format` một lần nữa** để tạo dòng thực sự ghi ra tệp. Đo được **`format()` chạy 3 lần cho mỗi bản ghi**, mỗi lần một `timestamp` khác.
  3. `append_signature(msg)` băm **`msg` của lần gọi đầu**, còn dòng ghi vào `secure.log` là **lần gọi sau** ⇒ hai chuỗi khác nhau ở `timestamp` ⇒ SHA-256 khác nhau.
- **Bằng chứng trực tiếp trên tệp gốc của bạn (chỉ đọc, không sửa):** SHA-256 của dòng trong `secure.log` gốc (thử mọi biến thể EOL) **không** bằng `secure.log.sig` gốc `cd9fd73c0a10761a9d27d3b518f727a38a3f2d2c752729491ed356a7abd01d2e`:

  | Biến thể dòng | SHA-256 | Khớp sig gốc |
  |---|---|---|
  | nguyên byte (kèm CRLF) | `18491a9e…` | Không |
  | bỏ CRLF | `9dda6b0b…` | Không |
  | thêm `\n` | `4aae97fc…` | Không |

  Theo yêu cầu của bài: tệp gốc **không** bị tôi sửa, nên việc lệch này là bằng chứng cơ chế hỏng, **không** phải phát hiện tấn công.
- **Bằng chứng tái hiện (ca `C0_hashsource`):**
  ```
  so lan format() duoc goi cho 1 ban ghi: 3
    format#0 timestamp=...045530Z sha=421986985bf71a55..
    format#1 timestamp=...045634Z sha=135f1a450041d197..
    format#2 timestamp=...045690Z sha=b662f46e90d7a0dc..
  dong ghi vao log: {... "timestamp": "...045690Z" ...}   (= format#2)
  sig: 421986985bf71a5530a1cf8011a36635ee36409803684f217337fda5d163c4e9   (= format#0)
  ```
  Chữ ký lưu là hash của **format#0**, còn dòng log là **format#2** ⇒ vĩnh viễn lệch. Ca `B1` (ghi 4 bản ghi) cho **cả 4 dòng** đều `match=False`.
- **Kết quả bảo vệ mong đợi:** hash lưu phải bằng hash của đúng chuỗi byte đã ghi.
- **Khắc phục:** tính `timestamp` **một lần** và gắn vào `record` trước khi format (hoặc dùng `record.created`); băm **đúng chuỗi byte** đã ghi (kể cả ký tự kết thúc dòng), lấy ngay trong luồng ghi. Xem mã mục 5.
- **Kiểm thử lại:** sau khi vá, băm từng dòng đã ghi và so với `.sig` ⇒ khớp 100% trên log chưa bị sửa.
- **Giới hạn còn lại:** vẫn là SHA-256 không khóa — xem SL-04.

---

### SL-04. `.sig` là SHA-256 không khóa và không có trình xác minh

- **Loại:** Thiếu kiểm soát toàn vẹn (B). **Trạng thái:** Xác nhận bằng đọc mã, mô phỏng tái hiện. **Mức:** Cao.
- **Vị trí:** `logger.py:19–24` (chỉ có `hash_line`/`append_signature`, **không** có hàm verify); toàn dự án không có mã xác minh hay cảnh báo sửa đổi.
- **Nguyên nhân kỹ thuật:**
  1. `hash_line` dùng `hashlib.sha256` **không khóa** — không phải HMAC, không phải chữ ký số. Đuôi `.sig` gây hiểu nhầm là chữ ký số.
  2. `append_signature` ghi 64 ký tự hex **nối liền, không dấu phân tách** ⇒ chỉ tách đúng khi mỗi digest cố định 64 ký tự; không neo thứ tự, không liên kết chuỗi (hash chain).
  3. Không có nơi nào **đọc lại** `.sig` để kiểm tra. "Phát hiện thay đổi trái phép" chỉ là mô tả.
- **Mô phỏng trên bản sao (dữ liệu giả, dùng đúng sơ đồ băm hiện tại):** dựng 3 dòng log + `.sig` bằng chính `hash_line`, rồi đóng vai kẻ có quyền ghi cả hai tệp:
  ```
  Ban dau:                                  (True, 3, 3)
  Sau khi sua log VA .sig:                  (True, 3, 3)  -> trinh xac minh khong phat hien
  Sau khi cat ngan (xoa dong cuoi ca 2 tep):(True, 2, 2)  -> van 'hop le', mat ban ghi khong bi phat hien
  ```
  (Trình xác minh ở đây là bản "tham chiếu" tôi viết theo đúng ý đồ thiết kế, vì dự án không kèm trình xác minh nào.)
- **Kết luận:** kẻ tấn công ghi được `secure.log` thì cũng ghi được `secure.log.sig`, nên sửa nội dung rồi tính lại SHA-256 là qua được mọi kiểm tra dựa trên tệp `.sig`. Cắt ngắn phần cuối (xóa cả hai tệp đồng bộ) cũng không bị phát hiện vì không có neo/độ dài kỳ vọng/hash chain.
- **Khắc phục:** dùng **HMAC-SHA256 với khóa bí mật** lưu ngoài tầm ghi của tiến trình ghi log (biến môi trường/khóa vault, tệp riêng quyền hạn khác), hoặc **hash chain** (mỗi dòng băm gồm digest trước) để chống chèn/xóa/đảo, và cung cấp **trình xác minh** riêng. Nêu rõ giới hạn ở mục 5.4.
- **Giới hạn còn lại:** HMAC/hash-chain **không** chống được việc xóa **toàn bộ phần đuôi** nếu kẻ tấn công cũng nắm khóa; cần append-only ở nơi khác (WORM, máy chủ log, ký theo lô và chốt ra ngoài).

---

### SL-05. Xoay vòng nén phá vỡ `BACKUP_COUNT` và làm mất bản ghi

- **Loại:** Lỗi triển khai xoay vòng (D). **Trạng thái:** Đã tái hiện. **Mức:** Cao.
- **Vị trí:** `logger.py:41–45` (`GZipRotator` ghi `dest + ".gz"`), `logger.py:47–54` (handler), `logger.py:6–7` (`MAX_LOG_SIZE`, `BACKUP_COUNT`).
- **Nguyên nhân kỹ thuật:** `RotatingFileHandler.doRollover` quản lý backup theo tên `secure.log.1`, `secure.log.2`, … Nó đổi tên `secure.log.i → secure.log.(i+1)` và xóa `secure.log.<BACKUP_COUNT>`. Nhưng `GZipRotator` lại tạo `secure.log.1.gz`. Vòng sau, handler tìm `secure.log.1` (không có, vì thực tế là `.gz`), nên **luôn** tạo lại `secure.log.1.gz` và **ghi đè** bản trước. Kết quả: chỉ tồn tại đúng 1 tệp `.gz`, `BACKUP_COUNT=2` vô nghĩa, và các bản ghi cũ bị mất.
- **Tái hiện (maxBytes=800, ghi 40 bản ghi):**
  ```
  BACKUP_COUNT = 2
  Files: secure.log (4 dòng), secure.log.1.gz (4 dòng), secure.log.sig (2560 byte = 40 digest)
  So tep .gz = 1   (khong bao gio > 1, du BACKUP_COUNT=2)
  Tong ban ghi con giu = 4 + 4 = 8 / 40  -> mat ~36 ban ghi
  ```
- **Quan sát thêm về `.sig`:** `.sig` **không** được xoay vòng — phình tới 40 digest trong khi log chỉ còn 8 dòng, và các dòng cũ đã nằm trong `.gz`. Ánh xạ digest ↔ dòng vỡ hoàn toàn sau xoay vòng (cộng dồn với SL-03).
- **Kết quả bảo vệ mong đợi:** giữ đúng `BACKUP_COUNT` bản nén, không mất bản ghi, `.sig` đi cùng phần log tương ứng.
- **Khắc phục (mức lab):** đặt `namer` để tên cuối cùng là `secure.log.i.gz` khớp với cơ chế đổi tên của handler, hoặc dùng handler nén có sẵn. **Mức thực tế:** tách toàn vẹn theo từng tệp log (mỗi tệp log kèm `.sig`/HMAC riêng, cùng xoay vòng). Xem mục 5.
- **Kiểm thử lại:** lặp ca 40 bản ghi sau vá ⇒ số `.gz` đúng `BACKUP_COUNT`, không mất bản ghi ngoài chính sách lưu giữ.
- **Giới hạn còn lại:** xoay vòng theo kích thước vẫn có thể xóa log cũ theo đúng chính sách — đó là lưu giữ, không phải toàn vẹn.

---

### SL-06. JSON hợp lệ nhưng không phải object ⇒ HTTP 500, không ghi log

- **Loại:** Xử lý đầu vào (E). **Trạng thái:** Đã tái hiện. **Mức:** Trung bình.
- **Vị trí:** `app.py:14` (`get_json(force=True)`), `app.py:21–25` (`data.get(...)`).
- **Nguyên nhân kỹ thuật:** `get_json(force=True)` phân tích cả khi content-type sai. Với thân là JSON hợp lệ nhưng là `null`/mảng/chuỗi/số, `data` không phải dict; `data.get("email", "")` ⇒ `AttributeError`. Ngoại lệ này **nằm ngoài** khối `try` (chỉ bao quanh `get_json`), nên không được bắt ⇒ HTTP 500 và **không có bản ghi log nào** (cả INFO lẫn WARNING).
- **Payload/kết quả (tái hiện):**

  | Thân request | HTTP | Ghi log? |
  |---|---|---|
  | `null` | 500 | Không |
  | `[1,2,3]` | 500 | Không |
  | `"just a string"` | 500 | Không |

  Traceback thực tế: `AttributeError: 'NoneType' object has no attribute 'get'` tại `app.py:21`.
- **Kết quả bảo vệ mong đợi:** phản hồi 400 có kiểm soát và **ghi log** yêu cầu lỗi.
- **Khắc phục:** kiểm tra `isinstance(data, dict)` sau khi parse, trả 400 và ghi WARNING; bọc phần xử lý trong `try/except` để mọi lỗi được ghi log trước khi trả 4xx/5xx. Xem mục 5.
- **Kiểm thử lại:** gửi `null`/mảng sau vá ⇒ 400 + có bản ghi WARNING; object hợp lệ vẫn 200.
- **Giới hạn còn lại:** cần thêm giới hạn kích thước thân request để tránh lạm dụng bộ nhớ (ngoài phạm vi lab này).

---

### SL-07. `debug=True` khi chạy ứng dụng

- **Loại:** Cấu hình theo triển khai (E). **Trạng thái:** Xác nhận bằng đọc mã. **Mức:** Trung bình (tùy triển khai).
- **Vị trí:** `app.py:33` — `app.run(debug=True)`.
- **Nguyên nhân/nguy cơ:** `debug=True` bật trình gỡ lỗi Werkzeug. Nếu ứng dụng lắng nghe ngoài loopback (hoặc bị chuyển tiếp cổng), trang lỗi tương tác có thể cho **thực thi mã** qua console gỡ lỗi (được bảo vệ bằng PIN, nhưng PIN có thể suy đoán trong một số điều kiện). Kết hợp SL-06, mọi request gây 500 sẽ hiện traceback chi tiết. **Chưa kiểm chứng** khai thác (tôi chỉ chạy `test_client`, không mở cổng).
- **Khắc phục:** `debug=False` ở môi trường dùng thật; bật debug chỉ khi phát triển và chỉ trên `127.0.0.1`; cấu hình qua biến môi trường. Thêm error handler trả lỗi chung, không lộ traceback.
- **Kiểm thử lại dự kiến:** chạy `flask run` (không debug) trên `127.0.0.1` với cổng riêng, gây 500 ⇒ không còn traceback chi tiết.

---

### SL-08. `sanitize_sql_input` là blacklist xóa từ khóa

- **Loại:** Hạn chế thiết kế validator (E). **Trạng thái:** Đã tái hiện (vượt blacklist). **Mức:** Thấp–Trung bình.
- **Vị trí:** `securevalidator/core.py:22–27`.
- **Nguyên nhân kỹ thuật:** hàm **xóa** ký tự (`-- ; ' " #`) và các từ khóa (`OR|AND|SELECT|…`). Đây **không** tương đương truy vấn tham số hóa. Việc xóa một lần cho phép vượt bằng cách chèn lồng: `OORR` → sau khi xóa `OR` còn lại `OR`; `SELSELECTECT` → `SELECT`. Ngoài ra xóa dấu nháy/`;` làm **hỏng dữ liệu hợp lệ** (ví dụ tên `O'Brien`).
- **Tái hiện (đầu ra `results['sql']`):**

  | Đầu vào | Kết quả sau sanitize |
  |---|---|
  | `' OR 1=1 --` | `1=1` |
  | `OORR 1=1` | `OR 1=1` (từ khóa `OR` **quay lại**) |
  | `O'Brien` | `OBrien` (dữ liệu hợp lệ bị hỏng) |

- **Lưu ý phạm vi:** trong dự án **không có nơi thực thi SQL**, nên **không** khẳng định có SQL Injection khai thác được. Đây là điểm yếu của cách tiếp cận "làm sạch bằng blacklist".
- **Khắc phục:** không "làm sạch" SQL bằng xóa từ khóa. Ở tầng dữ liệu dùng **truy vấn tham số hóa/parameterized query** hoặc ORM; validator chỉ nên **kiểm tra định dạng** đầu vào theo whitelist, không cố gỡ ký tự.
- **Kiểm thử lại:** khẳng định lại rằng đầu vào hợp lệ như `O'Brien` được giữ nguyên khi dùng tham số hóa (bản demo tách riêng, ngoài lab).

---

### SL-09. `validate_url` không chống SSRF thực chất

- **Loại:** Hạn chế thiết kế validator (E). **Trạng thái:** Xác nhận bằng đọc mã. **Mức:** Thấp.
- **Vị trí:** `core.py:8–14`.
- **Nguyên nhân:** chỉ kiểm `scheme ∈ {http,https}` và có `netloc`. Các URL nội bộ như `http://169.254.169.254/…` (metadata), `http://127.0.0.1:5000`, `http://localhost` đều **hợp lệ** theo hàm này. Comment "prevent basic SSRF vectors" gây hiểu nhầm.
- **Lưu ý phạm vi:** URL **không** được ứng dụng dùng để fetch, nên **chưa** có SSRF khai thác được. Chỉ là kiểm tra không đủ mạnh nếu sau này dùng để gọi mạng.
- **Khắc phục:** nếu URL sẽ được fetch, chặn host nội bộ/loopback/link-local/dải riêng sau khi phân giải DNS; dùng danh sách cho phép; không tin `netloc` trực tiếp.

---

### SL-10. Log injection qua newline — đã kiểm, âm tính

- **Loại:** (C). **Trạng thái:** Đã kiểm, **không** tái hiện được. **Mức:** Thông tin.
- **Kiểm chứng:** gửi JSON sai cú pháp chứa xuống dòng: `{bad json newline\ninjected: <script>`. Nhánh WARNING ghi `str(request.data)`, nhưng toàn bộ bản ghi đi qua `json.dumps` (`logger.py:38`), nên xuống dòng bị **escape** thành `\n` trong chuỗi JSON:
  ```
  {"timestamp":"...","level":"WARNING","message":"Invalid JSON received",
   "data":"b'{bad json newline\\ninjected: <script>'"}
  ```
  Không tạo được bản ghi log giả thứ hai. Đúng như tài liệu `json` của Python (escape ký tự điều khiển mặc định).
- **Kết luận:** **không** kết luận log injection chỉ vì payload có newline. `json.dumps` là biện pháp phòng vệ hiệu quả ở đây. (Cần lưu ý riêng: khi vá SL-03 để băm đúng dòng đã ghi, tránh đưa dữ liệu chưa escape vào `.sig`.)

---

### SL-11. Ghi chú độ bền

- `datetime.utcnow()` (`logger.py:30`) đã **deprecated** từ Python 3.12; nên dùng `datetime.now(timezone.utc)`. Trên Python 3.13 của bạn vẫn chạy nhưng phát cảnh báo.
- `requirements.txt` chỉ có `Flask` (không ghim phiên bản). Nên ghim `Flask==3.1.3` (và các phụ thuộc) để hành vi ổn định.
- `mask_pii` áp lên `str(record.data)` khiến định dạng log phụ thuộc `repr` của Python (dấu nháy đơn), khó phân tích máy và là gốc của SL-01.

---

## 5. Biện pháp khắc phục

### 5.1 Che PII theo cấu trúc (SL-01, SL-02)

```python
SENSITIVE_KEYS = re.compile(r"(?i)(pass(word|wd)?|pwd|token|api[_-]?key|secret|authorization|cookie)")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")

def mask_value(v):
    return EMAIL.sub("<email_masked>", v)

def mask_structured(obj):
    if isinstance(obj, dict):
        return {k: ("<redacted>" if SENSITIVE_KEYS.search(str(k)) else mask_structured(v))
                for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [mask_structured(x) for x in obj]
    if isinstance(obj, str):
        return mask_value(obj)
    return obj
# Trong format(): dùng json.dumps(mask_structured(record.data)) thay vì mask_pii(str(record.data))
```
Che theo **tên khóa** (bắt cả dạng `:` của JSON) và đệ quy vào dict/list; email trong văn bản tự do vẫn được che bằng regex đã sửa để nhận `+`.

### 5.2 Toàn vẹn: băm đúng dòng đã ghi (SL-03)

```python
class JSONFormatter(logging.Formatter):
    def format(self, record):
        if not hasattr(record, "_ts"):                 # tính timestamp MỘT lần
            record._ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        rec = {"timestamp": record._ts, "level": record.levelname,
               "message": mask_value(record.getMessage())}
        if hasattr(record, "data"):    rec["data"]    = mask_structured(record.data)
        if hasattr(record, "results"): rec["results"] = mask_structured(record.results)
        return json.dumps(rec, ensure_ascii=False)

class SecureRotatingFileHandler(logging.handlers.RotatingFileHandler):
    def emit(self, record):
        try:
            msg = self.format(record)                  # format một lần, dùng lại
            line = msg + self.terminator                # đúng chuỗi sẽ ghi
            with open(self.baseFilename, "a", encoding="utf-8", newline="") as f:
                f.write(line)
            append_signature(line)                     # băm ĐÚNG line đã ghi
            if self.shouldRollover(record):
                self.doRollover()
        except Exception:
            self.handleError(record)
```
Băm **đúng chuỗi byte** đã ghi (kể cả `terminator`), và `format` chỉ chạy một lần cho mỗi bản ghi.

### 5.3 Toàn vẹn thực: HMAC + trình xác minh (SL-04)

```python
import hmac
KEY = os.environ["SECURELOG_HMAC_KEY"].encode()      # khóa lưu NGOÀI tiến trình ghi log

def hash_line(line):                                 # thay SHA-256 không khóa
    return hmac.new(KEY, line.encode("utf-8"), hashlib.sha256).hexdigest()

def append_signature(line):
    with open(SIGNATURE_FILE, "a", encoding="utf-8") as f:
        f.write(hash_line(line) + "\n")              # có ký tự phân tách

# verify.py (chạy riêng, quyền đọc khóa riêng):
def verify(log="secure.log", sig="secure.log.sig"):
    sigs = open(sig, encoding="utf-8").read().split()
    for i, line in enumerate(open(log, encoding="utf-8", newline="")):
        if i >= len(sigs) or not hmac.compare_digest(hash_line(line.rstrip("\n")+"\n"), sigs[i]):
            return f"MISMATCH tại dòng {i}"
    return "OK" if len(sigs) == i+1 else "SỐ DÒNG/HMAC KHÔNG KHỚP (khả năng cắt ngắn)"
```
Cân nhắc thêm **hash chain** (mỗi HMAC gồm digest trước) để chống chèn/xóa/đảo. Mặc dù đuôi giữ tên `.sig`, đây là mã xác thực **có khóa**, không phải chữ ký số công khai.

### 5.4 Xoay vòng khớp tên nén (SL-05)

```python
def namer(default_name):        # secure.log.1 -> secure.log.1.gz
    return default_name + ".gz"
class GZipRotator:
    def __call__(self, source, dest):               # dest đã có .gz
        with open(source, "rb") as fi, gzip.open(dest, "wb") as fo:
            fo.writelines(fi)
        os.remove(source)
# handler.namer = namer; handler.rotator = GZipRotator()
```
Khi đó cơ chế đổi tên/xóa của `RotatingFileHandler` thấy đúng `secure.log.i.gz`, giữ đúng `BACKUP_COUNT`. Ở mức thực tế: mỗi tệp log kèm tệp HMAC riêng, cùng xoay vòng, để ánh xạ toàn vẹn không vỡ.

### 5.5 Xử lý đầu vào Flask (SL-06, SL-07)

```python
@app.route("/validate", methods=["POST"])
def validate():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        secure_logger.warning("Invalid or non-object JSON",
                              extra={"data": str(request.data)[:500]})
        return jsonify({"error": "JSON object required"}), 400
    try:
        results = { ... }
        secure_logger.info("Validation check performed", extra={"data": data, "results": results})
        return jsonify(results)
    except Exception:
        secure_logger.error("Validation failed", extra={"data": data})
        return jsonify({"error": "internal error"}), 500

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5051, debug=False)   # không debug khi dùng thật
```

**Mức thực tế (tóm tắt):** che PII theo cấu trúc + phát hiện theo mẫu/entropy; HMAC/hash-chain với khóa ngoài + máy chủ log append-only (WORM) và ký theo lô chốt ra ngoài; giới hạn kích thước thân request; error handler chung không lộ traceback; ghim phiên bản phụ thuộc; kiểm thử toàn vẹn tự động trong CI.

---

## 6. Bảng kiểm thử trước/sau sửa

Kiểm thử "sau sửa" được thực hiện trên **bản sao đã vá** riêng, không đụng mã gốc. Cột "Sau vá" dưới đây ghi kết quả kỳ vọng của bản vá mục 5; các mục tôi đã chạy thử trên bản sao được đánh dấu ✔(đã chạy), phần còn lại ghi rõ **dự kiến**.

| ID | Kịch bản (dữ liệu giả) | Trước sửa (đã tái hiện) | Sau vá |
|---|---|---|---|
| SL-01 | `password`/`apikey`/`token:` trong `data` | Bí mật hiện nguyên văn trong `secure.log` (HTTP 200) | `<redacted>` ✔(đã chạy logic che cấu trúc riêng) |
| SL-02 | phone/SSN/card/IP | Hiện nguyên văn | Che theo mẫu bổ sung (dự kiến) |
| SL-03 | 1–4 bản ghi bất kỳ | Hash `.sig` ≠ dòng log (cả tệp gốc và tái hiện) | Băm khớp 100% trên log chưa sửa (dự kiến theo mã 5.2) |
| SL-04 | Sửa/cắt ngắn log + `.sig` | Trình xác minh tham chiếu "OK" (không phát hiện) | HMAC không khóa của attacker ⇒ MISMATCH (dự kiến) |
| SL-05 | Ghi 40 bản ghi, `maxBytes=800` | Còn 8/40 bản ghi, 1 `.gz`, `.sig` lệch | Đúng `BACKUP_COUNT` `.gz`, không mất ngoài chính sách (dự kiến) |
| SL-06 | Thân `null` / `[1,2,3]` / `"x"` | HTTP 500, không ghi log | HTTP 400 + WARNING; object hợp lệ vẫn 200 (dự kiến) |
| SL-07 | Gây 500 khi chạy server | Traceback chi tiết (debug) | Lỗi chung, không traceback (dự kiến) |
| SL-08 | `OORR 1=1`, `O'Brien` | `OR 1=1` (vượt), `OBrien` (hỏng) | Dùng tham số hóa; validator whitelist (dự kiến) |
| SL-10 | JSON sai + newline | Không tạo bản ghi giả (âm tính) | Giữ nguyên (json.dumps) ✔ |

**Chưa chạy/kiểm chứng:** khai thác Werkzeug debugger (SL-07) — chỉ đọc mã; SSRF (SL-09) — không có nơi fetch; hành vi trên **Windows** thật (CRLF, quyền tệp) — kiểm thử chạy trên Linux; kiểm thử "sau vá" cho SL-02/03/04/05/06/07/08 mới ở mức mã minh họa + logic thành phần, chưa chạy trọn bộ trên bản vá tích hợp.

---

## 7. Thứ tự ưu tiên khắc phục

1. **SL-03 + SL-04** (toàn vẹn): sửa băm đúng dòng + chuyển HMAC có khóa + viết trình xác minh. Đây là mục tiêu cốt lõi "phát hiện thay đổi trái phép" hiện đang **không** hoạt động.
2. **SL-01 + SL-02** (che PII): che theo cấu trúc để bí mật không lọt vào log.
3. **SL-05** (xoay vòng): tránh mất log và giữ ánh xạ toàn vẹn.
4. **SL-06 + SL-07** (Flask): xử lý đầu vào không phải object, tắt debug, ghi log yêu cầu lỗi.
5. **SL-08 + SL-09** (validator): thay blacklist bằng tham số hóa/whitelist; siết kiểm URL nếu sẽ fetch.
6. **SL-11** (độ bền): bỏ `utcnow()`, ghim phiên bản.

---

## 8. Giới hạn của quá trình kiểm thử và tài liệu tham khảo

### 8.1 Giới hạn
- Không có shell trên máy Windows của bạn ⇒ **chưa** chạy trên Windows; phiên bản Git **chưa xác định**. Kiểm thử chạy trên Linux, Python 3.11.15 (máy bạn 3.13.14), cùng Flask/Werkzeug 3.1.3/3.1.8.
- Dùng `test_client` thay vì mở cổng — phản ánh đúng luồng view và mã trạng thái, nhưng không kiểm thử hành vi mạng/PIN của debugger (SL-07).
- Khác biệt EOL (LF vs CRLF) giữa hai môi trường có ảnh hưởng tới giá trị hash nhưng không phải nguyên nhân chính của SL-03.
- Các bản vá mục 5 được kiểm ở mức thành phần/logic; chưa chạy trọn một bản vá tích hợp qua toàn bộ bộ ca.
- Mô phỏng SL-04 dùng trình xác minh "tham chiếu" do tôi viết (dự án không kèm trình xác minh) — kết luận về việc không phát hiện được giả mạo là suy ra từ tính chất SHA-256 không khóa, đã minh họa bằng mã.

### 8.2 Tài liệu tham khảo
**Python**
- `logging` / `logging.handlers.RotatingFileHandler`, `doRollover`, `rotator`/`namer`: https://docs.python.org/3/library/logging.handlers.html
- `logging` (Formatter, luồng emit/format): https://docs.python.org/3/library/logging.html
- `json.dumps` (escape ký tự điều khiển, `ensure_ascii`): https://docs.python.org/3/library/json.html
- `hashlib` / `hmac` (`compare_digest`): https://docs.python.org/3/library/hashlib.html , https://docs.python.org/3/library/hmac.html
- `datetime.utcnow` (deprecated, dùng `now(timezone.utc)`): https://docs.python.org/3/library/datetime.html
- `gzip`: https://docs.python.org/3/library/gzip.html

**Flask / Werkzeug**
- `Request.get_json` (`force`, `silent`, non-object): https://flask.palletsprojects.com/en/stable/api/#flask.Request.get_json
- Chế độ debug / máy chủ phát triển (không dùng ở production): https://flask.palletsprojects.com/en/stable/server/ , https://werkzeug.palletsprojects.com/en/stable/debug/

**OWASP**
- Logging Cheat Sheet (che dữ liệu nhạy cảm, toàn vẹn log): https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- SQL Injection Prevention (tham số hóa, không dùng blacklist): https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- SSRF Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

---

## Phụ lục A. Bộ khung kiểm thử (chạy trên bản sao, Linux)

Khung `harness.py` nạp lại module sạch mỗi ca, chuyển sang một thư mục tạm riêng (cwd) để `secure.log`/`secure.log.sig` tách biệt, rồi dùng `Flask.test_client()` gửi `POST /validate`. Không mở cổng, không đụng dự án gốc.

```python
# harness.py  (rút gọn — xem mô tả trong báo cáo)
import os, sys, json, hashlib, tempfile, shutil
SLAB = os.path.abspath(sys.argv[1]); CASE = sys.argv[2]
d = tempfile.mkdtemp(prefix="slog_"); os.chdir(d)
for m in list(sys.modules):
    if m.split(".")[0] in ("securelogger","securevalidator","app"): del sys.modules[m]
sys.path.insert(0, SLAB)
import app as appmod
client = appmod.app.test_client()
def post(payload=None, raw=None):
    data = raw if raw is not None else json.dumps(payload)
    return client.post("/validate", data=data, content_type="application/json")

if CASE == "A1":            # bypass che PII (dữ liệu giả)
    r = post({"email":"alice@example.com","password":"SuperSecret123",
              "apikey":"AKIAFAKE1234567890","note":"token: ghp_FAKEtoken0123456789"})
    log = open("secure.log",encoding="utf-8").read()
    print("HTTP", r.status_code)
    for s in ["SuperSecret123","AKIAFAKE1234567890","ghp_FAKEtoken0123456789"]:
        print("leaked", s, "->", s in log)
# ... các ca C0/C0_hashsource/A1b/A2/A3/E1_*/B1 tương tự trong báo cáo
shutil.rmtree(d, ignore_errors=True)
```

Ca xoay vòng (SL-05) tạo một logger riêng với `maxBytes=800` để ép xoay vòng nhanh mà không cần tạo tải lớn; ca giả mạo (SL-04) dựng log + `.sig` giả bằng chính `hash_line` rồi đóng vai kẻ ghi được cả hai tệp. Toàn bộ payload dùng dữ liệu giả và `example.com`.
