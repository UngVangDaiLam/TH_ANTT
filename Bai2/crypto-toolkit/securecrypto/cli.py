import argparse
import sys
from cryptography.exceptions import InvalidTag
from securecrypto import aes_utils


def main():
    parser = argparse.ArgumentParser(description="SecureCrypto CLI")
    parser.add_argument('--encrypt', help='Encrypt file')
    parser.add_argument('--decrypt', help='Decrypt file')
    parser.add_argument('--password', required=True,
                        help='Password for AES encryption/decryption '
                             '(--decrypt also accepts the Key printed by --encrypt)')

    args = parser.parse_args()

    try:
        if args.encrypt:
            res = aes_utils.encrypt_file_aes(args.encrypt, args.password)
            print(res)
        elif args.decrypt:
            out = aes_utils.decrypt_file_aes(args.decrypt, args.password)
            print(f"Decrypted. Output: {out}")
        else:
            parser.error("one of --encrypt / --decrypt is required")
    except FileNotFoundError as e:
        sys.exit(f"File not found: {e.filename}")
    except InvalidTag:
        sys.exit("Decryption failed: wrong key/password or the file was modified.")


# Cho phép chạy "python -m securecrypto.cli" khi thư mục Scripts không nằm trong PATH
if __name__ == "__main__":
    main()
