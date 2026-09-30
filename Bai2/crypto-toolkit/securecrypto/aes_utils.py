from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import os, base64, binascii

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32  # AES-256


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_file_aes(filepath, password):
    salt = os.urandom(SALT_SIZE)
    key = derive_key_from_password(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    with open(filepath, 'rb') as f:
        data = f.read()
    ct = aesgcm.encrypt(nonce, data, None)
    # Định dạng file .enc: salt (16) | nonce (12) | ciphertext + GCM tag
    with open(filepath + '.enc', 'wb') as f:
        f.write(salt + nonce + ct)
    return base64.b64encode(key).decode()


def _candidate_keys(key_or_password, salt):
    # Cách của sách: truyền lại Key base64 mà encrypt_file_aes trả về.
    try:
        key = base64.b64decode(key_or_password, validate=True)
        if len(key) == KEY_SIZE:
            yield key
    except (binascii.Error, ValueError):
        pass
    # Yêu cầu 2.2.1 decrypt_file_aes(encrypted_file, password): dẫn xuất lại key
    # từ password và salt lưu ở đầu file.
    yield derive_key_from_password(key_or_password, salt)


def decrypt_file_aes(encrypted_file, key_or_password):
    with open(encrypted_file, 'rb') as f:
        raw = f.read()
    salt = raw[:SALT_SIZE]
    nonce = raw[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ct = raw[SALT_SIZE + NONCE_SIZE:]
    # GCM xác thực tag nên chỉ đúng key mới giải mã được -> thử lần lượt không bị nhầm.
    for key in _candidate_keys(key_or_password, salt):
        try:
            pt = AESGCM(key).decrypt(nonce, ct, None)
            break
        except InvalidTag:
            continue
    else:
        raise InvalidTag("Wrong key/password or the file was modified")
    # Sách dùng replace('.enc', '.dec'): file không có đuôi .enc sẽ bị ghi đè
    # chính nó bằng bản rõ, và '.enc' ở giữa đường dẫn cũng bị thay.
    base = encrypted_file[:-len('.enc')] if encrypted_file.endswith('.enc') else encrypted_file
    out_path = base + '.dec'
    with open(out_path, 'wb') as f:
        f.write(pt)
    return out_path
