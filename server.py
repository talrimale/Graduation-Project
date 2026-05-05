import socket, threading
HOST = '0.0.0.0'
PORT = 65432
clients = []

def broadcast(message, sender_socket):
    for client in clients:
        if client != sender_socket:
            try:
                client.send(message)
            except:
                clients.remove(client)

def handle_client(client_socket):
    while True:
        try:
            data = client_socket.recv(1024 * 1024 * 15) 
            if not data:
                break
            print(f"[*] Recevied Encrypted Data: {data}")
            broadcast(data, client_socket)
        except:
            break

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('0.0.0.0', 65432))
server.listen()
print(" Server is Running...")

while True:
    conn, addr = server.accept()
    print("Connected:",addr)
    clients.append(conn)
    threading.Thread(target=handle_client, args=(conn,)).start()