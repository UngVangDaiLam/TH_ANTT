import socket
import ssl
import threading
from connection_manager import ConnectionManager
from room_manager import RoomManager
from message_encryption import MessageEncryption

HOST = '127.0.0.1'
PORT = 8443

SERVER_CERT = 'certs/server/server.crt'
SERVER_KEY = 'certs/server/server.key'
CA_CERT = 'certs/ca/ca.crt'

connection_manager = ConnectionManager()
room_manager = RoomManager()

def handle_client(connstream, addr):
    print(f"[+] Client connected: {addr}")
    try:
        # Bước 1: nhận username và AES key
        # Đơn giản giả định client gửi: "username:key"
        data = connstream.recv(1024).decode()
        if ':' not in data:
            connstream.close()
            return
        username, key_hex = data.split(':')
        encryption_key = bytes.fromhex(key_hex)

        connection_manager.add_client(connstream, username, encryption_key)

        # Mặc định join phòng "general"
        room_manager.create_room('general')
        room_manager.join_room('general', connstream)

        me = MessageEncryption(encryption_key)

        while True:
            enc_message = connstream.recv(4096)
            if not enc_message:
                break
            try:
                message = me.decrypt(enc_message)
            except Exception:
                print("[!] Decryption failed")
                continue

            print(f"[{username}]: {message}")

            # Mã hóa lại message gửi cho phòng, kèm tên user
            out_msg = f"[{username}]: {message}"
            # Mã hóa từng client khác theo key của họ
            with connection_manager.lock:
                for client_sock, info in connection_manager.clients.items():
                    if client_sock != connstream:
                        try:
                            me_other = MessageEncryption(info['encryption_key'])
                            enc_out = me_other.encrypt(out_msg)
                            client_sock.send(enc_out)
                        except Exception:
                            pass

    except Exception as e:
        print(f"Exception {e}")
    finally:
        print(f"[-] Client disconnected: {addr}")
        connection_manager.remove_client(connstream)
        room_manager.leave_room('general', connstream)
        try:
            connstream.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        connstream.close()

def main():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
    context.load_verify_locations(cafile=CA_CERT)
    context.verify_mode = ssl.CERT_REQUIRED  # Yêu cầu client chứng chỉ
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # TLS1.2 trở lên

    bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsocket.bind((HOST, PORT))
    bindsocket.listen(5)
    print(f"Server listening on {HOST}:{PORT}")

    while True:
        newsocket, fromaddr = bindsocket.accept()
        try:
            connstream = context.wrap_socket(newsocket, server_side=True)
            threading.Thread(target=handle_client,
                             args=(connstream, fromaddr), daemon=True).start()
        except ssl.SSLError as e:
            print(f"SSL Error: {e}")

if __name__ == '__main__':
    main()
