import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

# Sách dùng "certs" tương đối theo thư mục đang đứng khi chạy lệnh; neo vào thư mục
# chứa file này để chạy từ đâu cũng ghi vào mini-ca/certs.
CERTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
os.makedirs(CERTS_DIR, exist_ok=True)


def utcnow():
    # datetime.datetime.utcnow() (bị gạch trong sách) đã deprecated từ Python 3.12
    return datetime.datetime.now(datetime.timezone.utc)


def generate_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def save_key(key, filename):
    with open(os.path.join(CERTS_DIR, filename), "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))


def save_cert(cert, filename):
    with open(os.path.join(CERTS_DIR, filename), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def load_key(filename):
    with open(os.path.join(CERTS_DIR, filename), "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_cert(filepath):
    with open(filepath, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def create_root_ca():
    key = generate_key()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mini Root CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Mini Root CA Root"),
    ])
    now = utcnow()
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(
        issuer).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now
    ).not_valid_after(
        now + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=1), critical=True,
    ).sign(key, hashes.SHA256())

    save_key(key, "root_ca_key.pem")
    save_cert(cert, "root_ca_cert.pem")
    return key, cert


def create_intermediate_ca(root_key, root_cert):
    key = generate_key()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mini Intermediate CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Mini Intermediate CA"),
    ])
    now = utcnow()
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(
        root_cert.subject
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now
    ).not_valid_after(
        now + datetime.timedelta(days=1825)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=0), critical=True
    ).sign(root_key, hashes.SHA256())

    save_key(key, "intermediate_key.pem")
    save_cert(cert, "intermediate_cert.pem")
    return key, cert


def issue_certificate(ca_key, ca_cert, subject_info: dict):
    key = generate_key()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, subject_info.get(
            "country", "VN")),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_info.get(
            "org", "End Entity")),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_info.get(
            "common_name", "user.example.com")),
    ])
    now = utcnow()
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(
        ca_cert.subject
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now
    ).not_valid_after(
        now + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).sign(ca_key, hashes.SHA256())

    filename_prefix = subject_info.get("common_name", "entity").replace(" ", "_")
    save_key(key, f"{filename_prefix}_key.pem")
    save_cert(cert, f"{filename_prefix}_cert.pem")

    return key, cert


def _check_validity(cert, now):
    if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        raise ValueError(f"{cert.subject.rfc4514_string()} đã hết hạn hoặc chưa có hiệu lực")


def verify_certificate_chain(cert_to_verify, chain):
    # chain: [CA cấp cert_to_verify, CA cấp trên nữa, ..., Root CA]
    # Sách chỉ kiểm chữ ký; phần giải thích (trang 55) nói hết hạn hay sai chuỗi cũng
    # phải trả về False, nên kiểm thêm hạn dùng, tên issuer và quyền CA của cấp trên.
    try:
        if not chain:
            raise ValueError("chuỗi rỗng, không có CA nào để xác thực")
        now = utcnow()
        for depth, issuer_cert in enumerate(chain):
            _check_validity(cert_to_verify, now)
            if cert_to_verify.issuer != issuer_cert.subject:
                raise ValueError(
                    f"issuer của {cert_to_verify.subject.rfc4514_string()} "
                    f"không phải {issuer_cert.subject.rfc4514_string()}")
            bc = issuer_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            if not bc.ca:
                raise ValueError(f"{issuer_cert.subject.rfc4514_string()} không phải CA")
            # depth = số CA trung gian đứng dưới issuer_cert trong chuỗi
            if bc.path_length is not None and depth > bc.path_length:
                raise ValueError(
                    f"{issuer_cert.subject.rfc4514_string()} vượt path_length={bc.path_length}")
            issuer_public_key = issuer_cert.public_key()
            issuer_public_key.verify(
                cert_to_verify.signature,
                cert_to_verify.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert_to_verify.signature_hash_algorithm,
            )
            cert_to_verify = issuer_cert
        _check_validity(cert_to_verify, now)  # Root CA ở cuối chuỗi
        return True
    except Exception as e:
        print("Verification failed:", e)
        return False
