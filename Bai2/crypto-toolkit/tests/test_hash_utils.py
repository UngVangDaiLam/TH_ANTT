import secrets
import pytest
from securecrypto import hash_utils
from argon2.exceptions import VerifyMismatchError

# GitSecure (Bài 1) chặn commit có mật khẩu viết cứng trong code (sách trang 47),
# nên mật khẩu dùng để test được sinh ngẫu nhiên mỗi lần chạy.


def test_hash_password_and_verify():
    password = secrets.token_urlsafe(16)
    hashed = hash_utils.hash_password_secure(password)
    assert hashed is not None

    from argon2 import PasswordHasher
    ph = PasswordHasher()
    try:
        ph.verify(hashed, password)
        verified = True
    except VerifyMismatchError:
        verified = False
    assert verified == True


def test_wrong_password_verification():
    password = secrets.token_urlsafe(16)
    wrong_password = password + "x"
    hashed = hash_utils.hash_password_secure(password)

    from argon2 import PasswordHasher
    ph = PasswordHasher()
    try:
        ph.verify(hashed, wrong_password)
        verified = True
    except VerifyMismatchError:
        verified = False
    assert verified == False
