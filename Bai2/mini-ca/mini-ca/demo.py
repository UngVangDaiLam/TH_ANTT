import os
from cryptography import x509
from ca_utils import (
    CERTS_DIR,
    create_root_ca,
    create_intermediate_ca,
    issue_certificate,
    verify_certificate_chain,
    load_cert
)
from revoke_utils import (
    revoke_certificate,
    check_revocation_status
)

ROOT_NAME = "Mini Root CA"
INTERMEDIATE_NAME = "Mini Intermediate CA"

# Chứng chỉ người dùng cuối như trong sách; đổi thông tin ở đây là đủ cho cả file
USER_INFO = {
    "common_name": "Phuoc_Nguyen",
    "org": "PHUOCNTMH Company",
    "country": "VN"
}
USER_PREFIX = USER_INFO["common_name"].replace(" ", "_")  # giống issue_certificate
USER_CERT = os.path.join(CERTS_DIR, f"{USER_PREFIX}_cert.pem")
USER_KEY = os.path.join(CERTS_DIR, f"{USER_PREFIX}_key.pem")
INTER_CERT = os.path.join(CERTS_DIR, "intermediate_cert.pem")
INTER_KEY = os.path.join(CERTS_DIR, "intermediate_key.pem")
ROOT_CERT = os.path.join(CERTS_DIR, "root_ca_cert.pem")

root_key = None
root_cert = None
inter_key = None
inter_cert = None


def setup_ca():
    global root_key, root_cert, inter_key, inter_cert

    print("Tạo Root CA...")
    root_key, root_cert = create_root_ca()
    print(f"Root CA: {root_key}, {root_cert}")

    print("Tạo Intermediate CA...")
    inter_key, inter_cert = create_intermediate_ca(root_key, root_cert)
    print(f"Intermediate CA: {inter_key}, {inter_cert}")

    return root_key, root_cert, inter_key, inter_cert


def issue_cert_demo():
    print("Phát hành chứng chỉ người dùng cuối...")
    cert_key, cert = issue_certificate(inter_key, inter_cert, USER_INFO)
    print(f"Đã phát hành: {USER_CERT}, {USER_KEY}")
    return USER_CERT


def verify_chain_demo(user_cert_path):
    print("Kiểm tra chuỗi chứng chỉ...")
    chain_paths = [INTER_CERT, ROOT_CERT]
    chain_certs = [load_cert(p) for p in chain_paths]
    user_cert = load_cert(user_cert_path)

    valid = verify_certificate_chain(user_cert, chain_certs)
    print(f"Chuỗi hợp lệ: {valid}")
    return valid


def revoke_demo():
    print("Thu hồi chứng chỉ user1...")
    revoke_certificate(
        USER_CERT,
        INTER_CERT,
        INTER_KEY,
        reason=x509.ReasonFlags.key_compromise
    )
    print("Đã thu hồi")


def ocsp_check_demo():
    print(f"Kiểm tra trạng thái OCSP của {os.path.basename(USER_CERT)}...")
    status = check_revocation_status(USER_CERT)
    print(f"Trạng thái: {'Revoked' if status else 'Valid'}")


def run_all():
    setup_ca()
    user_cert = issue_cert_demo()
    verify_chain_demo(user_cert)
    revoke_demo()
    ocsp_check_demo()


if __name__ == "__main__":
    run_all()
