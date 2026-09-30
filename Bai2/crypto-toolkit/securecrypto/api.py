from flask import Flask, request, jsonify, abort
from werkzeug.utils import secure_filename
from cryptography.exceptions import InvalidTag
from securecrypto import aes_utils
import os

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FILES_DIR = os.path.join(BASE_DIR, 'upload')
os.makedirs(FILES_DIR, exist_ok=True)


@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": e.description}), 400


def save_upload():
    f = request.files.get('file')
    password = request.form.get('password')
    if f is None or not password:
        abort(400, "form-data must contain 'file' and 'password'")
    # Sách ghép thẳng f.filename vào đường dẫn: tên như "../../api.py" sẽ ghi
    # ra ngoài thư mục upload (path traversal). secure_filename bỏ các phần đó.
    filename = secure_filename(f.filename or "")
    if not filename:
        abort(400, "invalid file name")
    save_path = os.path.join(FILES_DIR, filename)
    f.save(save_path)
    return save_path, password


@app.route('/encrypt', methods=['POST'])
def encrypt():
    save_path, password = save_upload()
    key = aes_utils.encrypt_file_aes(save_path, password)
    return jsonify({"key": key})


@app.route('/decrypt', methods=['POST'])
def decrypt():
    save_path, password = save_upload()
    try:
        out_path = aes_utils.decrypt_file_aes(save_path, password)
    except InvalidTag:
        abort(400, "wrong key/password or the file was modified")
    # Chỉ trả tên file (nằm trong upload/), không lộ đường dẫn tuyệt đối trên server
    return jsonify({"output": os.path.basename(out_path)})


if __name__ == '__main__':
    app.run()
