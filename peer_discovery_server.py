# discovery_server.py

import socket
import threading

PEERS = []
DISCOVERY_PORT = 5000

def handle_client(conn, addr):
    global PEERS
    try:
        while True:
            data = conn.recv(1024).decode()
            if not data:
                break
            if data == "GET_PEERS":
                conn.send(str(PEERS).encode())
            elif data.startswith("REGISTER"):
                peer_address = data.split(" ")[1]
                if peer_address not in PEERS:
                    PEERS.append(peer_address)
                conn.send(b"Registered")
    except:
        pass
    conn.close()

def discovery_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", DISCOVERY_PORT))
    server.listen(5)
    print(f"[DISCOVERY SERVER] Running on port {DISCOVERY_PORT}")
    
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    discovery_server()
