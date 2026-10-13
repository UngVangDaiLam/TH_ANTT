import threading

class ConnectionManager:
    def __init__(self):
        self.clients = {}  # socket -> dict {username, encryption_key}
        self.lock = threading.Lock()

    def add_client(self, client_sock, username, encryption_key):
        with self.lock:
            self.clients[client_sock] = {'username': username,
                                         'encryption_key': encryption_key}

    def remove_client(self, client_sock):
        with self.lock:
            if client_sock in self.clients:
                del self.clients[client_sock]

    def get_client(self, client_sock):
        with self.lock:
            return self.clients.get(client_sock)

    def broadcast(self, message, sender_sock):
        with self.lock:
            for client in self.clients:
                if client != sender_sock:
                    try:
                        client.send(message)
                    except Exception:
                        pass
