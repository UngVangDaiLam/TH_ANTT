"""
test_validators.py — Chứng minh các chuỗi TẤN CÔNG vượt qua (bypass) hàng phòng
thủ trong securevalidator/core.py.

Quy ước tên test:
  * test_bypass_*  : chuỗi tấn công LỌT QUA validator/sanitizer  -> lỗ hổng được xác nhận.
  * test_control_* : trường hợp core.py CHẶN đúng (giữ lại để đối chiếu).

Tất cả test đều PASS vì mỗi assertion khẳng định đúng hành vi THỰC TẾ của core.py.
Do đó test_bypass_* PASS nghĩa là: đòn tấn công đã lọt qua thành công.
"""

import unittest
from securevalidator import (
    validate_email, validate_url, validate_filename,
    sanitize_sql_input, sanitize_html_input
)


class TestValidators(unittest.TestCase):
    def setUp(self):
        print("\n Running:", self._testMethodName)

    # ==================================================================== #
    #  validate_url — LỖ HỔNG SSRF
    #  core.py chỉ xét scheme ∈ {http,https} và netloc != rỗng; KHÔNG kiểm
    #  tra IP đích, nên mọi địa chỉ nội bộ đều được coi là "hợp lệ".
    # ==================================================================== #
    def test_control_url_bad_scheme_blocked(self):
        # Phòng thủ hoạt động: sai scheme thì bị chặn.
        self.assertFalse(validate_url("ftp://example.com"))
        self.assertFalse(validate_url("file:///etc/passwd"))

    def test_bypass_url_ssrf_loopback(self):
        # Trỏ vào chính máy chủ / dịch vụ nội bộ.
        self.assertTrue(validate_url("http://127.0.0.1/admin"))
        self.assertTrue(validate_url("http://localhost/"))
        self.assertTrue(validate_url("http://[::1]/"))

    def test_bypass_url_ssrf_cloud_metadata(self):
        # Nguy hiểm nhất: rút credential từ endpoint metadata của cloud.
        self.assertTrue(validate_url("http://169.254.169.254/latest/meta-data/"))

    def test_bypass_url_ssrf_ip_obfuscation(self):
        # Cùng là 127.0.0.1 nhưng viết dạng khác để né bộ lọc so khớp chuỗi.
        self.assertTrue(validate_url("http://2130706433/"))   # IP dạng số nguyên
        self.assertTrue(validate_url("http://0x7f000001/"))   # IP dạng hex
        self.assertTrue(validate_url("http://127.1/"))        # IP dạng rút gọn

    # ==================================================================== #
    #  validate_filename — LỖ HỔNG path traversal biến thể
    #  core.py chỉ chặn chuỗi thô '..', '/', '\'.
    # ==================================================================== #
    def test_control_filename_basic_traversal_blocked(self):
        # Phòng thủ hoạt động với traversal dạng thô.
        self.assertFalse(validate_filename("../../etc/passwd"))
        self.assertFalse(validate_filename("..\\..\\windows\\win.ini"))

    def test_bypass_filename_encoded_traversal(self):
        # %2e%2e%2f không chứa '..' hay '/' -> lọt; thành '../' nếu tầng sau URL-decode.
        self.assertTrue(validate_filename("%2e%2e%2fpasswd"))

    def test_bypass_filename_null_byte(self):
        # \x00 lọt qua; hàm C/hệ thống cũ có thể cắt tên tại null -> còn "report.pdf".
        self.assertTrue(validate_filename("report.pdf\x00.exe"))

    # ==================================================================== #
    #  sanitize_sql_input — LỖ HỔNG do dùng danh sách đen (blacklist)
    #  core.py xoá vài ký tự/từ khoá rồi coi là "sạch" -> luôn có đường lách.
    # ==================================================================== #
    def test_bypass_sql_comment_reconstruction(self):
        # Chỉ xoá 1 lượt, không quét lại: "-'-" xoá dấu ' -> ghép lại thành "--".
        self.assertIn("--", sanitize_sql_input("-'-"))
        self.assertIn("--", sanitize_sql_input("admin'-'-"))

    def test_bypass_sql_inline_comment(self):
        # Chuỗi comment /**/ không nằm trong blacklist -> sống nguyên.
        self.assertIn("/**/", sanitize_sql_input("SEL/**/ECT * FROM users"))

    def test_bypass_sql_non_blacklisted_keywords(self):
        # ||, XOR, SLEEP, LIKE không có trong blacklist -> payload sống NGUYÊN VẸN.
        self.assertEqual(sanitize_sql_input("1 || SLEEP(5)"), "1 || SLEEP(5)")
        self.assertEqual(sanitize_sql_input("1 XOR 1"), "1 XOR 1")
        self.assertEqual(sanitize_sql_input("1) LIKE (1"), "1) LIKE (1")

    def test_bypass_sql_data_corruption(self):
        # Tác dụng phụ: dữ liệu người dùng hợp lệ bị phá (false positive).
        self.assertEqual(sanitize_sql_input("O'Brien"), "OBrien")
        self.assertEqual(sanitize_sql_input("DROP your fear"), "your fear")

    # ==================================================================== #
    #  sanitize_html_input — KHÔNG có lỗ hổng để bypass (cách làm ĐÚNG)
    #  html.escape escape đầy đủ & < > " ' -> đối chiếu với cách sai ở SQL.
    # ==================================================================== #
    def test_control_html_cannot_be_bypassed(self):
        self.assertEqual(
            sanitize_html_input('<script>alert("XSS")</script>'),
            '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;')
        self.assertEqual(
            sanitize_html_input('<img src=x onerror=alert(1)>'),
            '&lt;img src=x onerror=alert(1)&gt;')
        self.assertEqual(
            sanitize_html_input('"><svg/onload=alert(1)>'),
            '&quot;&gt;&lt;svg/onload=alert(1)&gt;')

    # ==================================================================== #
    #  validate_email — chặn được CRLF nhưng chấp nhận Unicode
    # ==================================================================== #
    def test_control_email_header_injection_blocked(self):
        self.assertFalse(validate_email("victim@example.com\r\nBcc: attacker@evil.com"))

    def test_bypass_email_unicode_homograph(self):
        # \w khớp cả ký tự Unicode -> email giả mạo (homograph) vẫn "hợp lệ".
        self.assertTrue(validate_email("user@examp\u0142e.com"))


if __name__ == "__main__":
    unittest.main()