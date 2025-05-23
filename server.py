import socket
import threading
import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib

# Generate RSA keys for the server
(public_key, private_key) = rsa.newkeys(2048)

# Server configuration
HOST = '127.0.0.1'
PORT = 12345

# Dictionary to store client sockets and their public keys
clients = {}
public_keys = {}

# Function to broadcast messages to all clients
def broadcast(message, sender_socket=None):
    for client_socket in clients:
        if client_socket != sender_socket:
            try:
                client_socket.send(message.encode('utf-8'))
            except Exception as e:
                print(f"Error broadcasting message: {e}")
                remove_client(client_socket)

# Function to remove a client from the server
def remove_client(client_socket):
    if client_socket in clients:
        username = clients[client_socket]
        del clients[client_socket]
        client_socket.close()

        # Broadcast the updated list of active users 
        active_users = ",".join(clients.values())
        broadcast(f"ACTIVE_USERS:{active_users}")

        # Notify all clients that the user has left
        broadcast(f"{username} has left the chat.", client_socket)
        print(f"{username} disconnected.")

# Function to handle client connections
def handle_client(client_socket):
    try:
        # Receive the client's username
        username = client_socket.recv(1024).decode('utf-8')
        if not username:
            raise Exception("Invalid username")

        # Receive the client's public key
        public_key_data = client_socket.recv(1024).decode('utf-8')
        if not public_key_data.startswith("PUBLIC_KEY:"):
            raise Exception("Invalid public key format")

        # Store the client's public key
        _, _, key_data = public_key_data.split(":")
        public_keys[username] = rsa.PublicKey.load_pkcs1(key_data.encode('utf-8'))

        # Add the client to the dictionary
        clients[client_socket] = username

        # Notify all clients about the new user
        broadcast(f"{username} has joined the chat.", client_socket)

        # Send the list of active users to the new client
        active_users = ",".join(clients.values())
        client_socket.send(f"ACTIVE_USERS:{active_users}".encode('utf-8'))

        # Send the new user's public key to all existing clients
        for sock in clients:
            if sock != client_socket:
                sock.send(f"PUBLIC_KEY:{username}:{key_data}".encode('utf-8'))

        # Send all existing clients' public keys to the new user
        for user, key in public_keys.items():
            if user != username:
                client_socket.send(f"PUBLIC_KEY:{user}:{key.save_pkcs1().decode('utf-8')}".encode('utf-8'))

        # Broadcast the updated list of active users 
        broadcast(f"ACTIVE_USERS:{active_users}")

        # Send the server's public key to the client
        client_socket.send(f"PUBLIC_KEY:Server:{public_key.save_pkcs1().decode('utf-8')}".encode('utf-8'))

        # Handle incoming messages
        while True:
            message = client_socket.recv(1024).decode('utf-8')
            if not message:
                break

            if message.startswith("MSG:"):
                # Handle encrypted messages
                _, recipient, encrypted_message, encrypted_aes_key, message_hash = message.split(":", 4)
                recipient_socket = next((sock for sock, user in clients.items() if user == recipient), None)
                if recipient_socket:
                    recipient_socket.send(f"{username}:{encrypted_message}:{encrypted_aes_key}:{message_hash}".encode('utf-8'))
            elif message.startswith("FILE:"):
                # Handle file transfers
                parts = message.split(":")
                if len(parts) == 4: 
                    _, recipient, file_name, file_size = parts
                    file_size = int(file_size)  
                    recipient_socket = next((sock for sock, user in clients.items() if user == recipient), None)
                    if recipient_socket:
                        recipient_socket.send(f"FILE:{username}:{file_name}:{file_size}".encode('utf-8'))

                        # Forward the file data 
                        bytes_sent = 0
                        while bytes_sent < file_size:
                            file_data = client_socket.recv(1024)
                            if not file_data:
                                break
                            recipient_socket.send(file_data)
                            bytes_sent += len(file_data)
            elif message.startswith("REQUEST_KEY:"):
                # Handle requests for missing public keys
                _, requested_user = message.split(":", 1)
                if requested_user in public_keys:
                    client_socket.send(f"PUBLIC_KEY:{requested_user}:{public_keys[requested_user].save_pkcs1().decode('utf-8')}".encode('utf-8'))
    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        remove_client(client_socket)

# Main server function
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"Server started on {HOST}:{PORT}")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"New connection from {client_address}")
        threading.Thread(target=handle_client, args=(client_socket,)).start()

if __name__ == "__main__":
    start_server()
