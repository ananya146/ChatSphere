import socket
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, scrolledtext, font, colorchooser
import rsa  # For RSA encryption
import os

# Generate RSA keys for the client
(public_key, private_key) = rsa.newkeys(2048)  # 2048-bit key for better security

# Server configuration
HOST = '127.0.0.1'
PORT = 12345

# Create a socket and connect to the server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

# Dictionary to store chat history for each user
chat_history = {}

# Dictionary to store public keys of other users
public_keys = {}

# Threading lock for thread-safe access to shared resources
chat_lock = threading.Lock()

# Function to encrypt a message using RSA
def encrypt_message(message, public_key):
    try:
        return rsa.encrypt(message.encode('utf-8'), public_key)
    except Exception as e:
        print(f"Encryption failed: {e}")
        return None

# Function to decrypt a message using RSA
def decrypt_message(encrypted_message):
    try:
        return rsa.decrypt(encrypted_message, private_key).decode('utf-8')
    except rsa.DecryptionError:
        print("Decryption failed: Incorrect key or corrupted data.")
        return None
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

# Function to update the chat box with the selected user's chat history
def update_chat_box(selected_user):
    chat_box.config(state='normal')
    chat_box.delete(1.0, tk.END)  # Clear the chat box
    if selected_user in chat_history:
        for message in chat_history[selected_user]:
            if message.startswith("FILE:"):
                # Handle file messages
                parts = message.split(":")
                if len(parts) >= 3:
                    file_name = parts[2]
                    chat_box.insert(tk.END, f"File received: {file_name}\n", 'file')
                    chat_box.insert(tk.END, "[Download]\n\n", 'download')
                    chat_box.tag_bind('download', '<Button-1>', lambda event, fn=file_name: download_file(fn))
            else:
                # Handle text messages
                chat_box.insert(tk.END, f"{message}\n", 'received')
    chat_box.config(state='disabled')
    chat_box.yview(tk.END)  # Auto-scroll to the bottom

def request_missing_keys():
    with chat_lock:
        active_users = user_listbox.get(0, tk.END)
        for user in active_users:
            if user != username and user not in public_keys:
                client_socket.send(f"REQUEST_KEY:{user}".encode('utf-8'))
                print(f"DEBUG: Requested public key for {user}")

# Function to send messages
def send_message(event=None):
    selected_user = user_listbox.get(tk.ACTIVE)
    message = entry_field.get()
    if message and selected_user:
        try:
            # Check if the recipient's public key is available
            recipient_public_key = public_keys.get(selected_user)
            if recipient_public_key:
                # Encrypt the message using the recipient's public key
                encrypted_message = encrypt_message(message, recipient_public_key)
                if encrypted_message:
                    client_socket.send(f"MSG:{selected_user}:{encrypted_message.hex()}".encode('utf-8'))
                    entry_field.delete(0, tk.END)

                    # Add the message to the chat history
                    with chat_lock:
                        if selected_user not in chat_history:
                            chat_history[selected_user] = []
                        chat_history[selected_user].append(f"You: {message}")

                    # Update the chat box
                    update_chat_box(selected_user)
            else:
                print(f"Public key for {selected_user} not found. Requesting key...")
                request_missing_keys()  # Request the missing key
        except Exception as e:
            print(f"Error sending message: {e}")

# Function to send files
def send_file():
    selected_user = user_listbox.get(tk.ACTIVE)
    if selected_user:
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                with open(file_path, 'rb') as file:
                    file_data = file.read()
                file_name = file_path.split("/")[-1]  # Extract file name

                # Send the file metadata to the server
                client_socket.send(f"FILE:{selected_user}:{file_name}".encode('utf-8'))

                # Send the file data
                client_socket.send(file_data)

                # Add the file sent message to the chat history
                with chat_lock:
                    if selected_user not in chat_history:
                        chat_history[selected_user] = []
                    chat_history[selected_user].append(f"FILE:You:{file_name}")

                # Update the chat box
                update_chat_box(selected_user)
            except Exception as e:
                print(f"Error sending file: {e}")

# Function to handle file download
def download_file(file_name):
    if not os.path.exists(file_name):
        messagebox.showerror("Error", f"File '{file_name}' not found.")
        return

    file_path = filedialog.asksaveasfilename(defaultextension=".*", initialfile=file_name)
    if file_path:
        try:
            with open(file_name, 'rb') as file:
                file_data = file.read()
            with open(file_path, 'wb') as new_file:
                new_file.write(file_data)
            messagebox.showinfo("Download Complete", f"File saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to download file: {e}")

# Function to change background color
def change_bg_color():
    color = colorchooser.askcolor()[1]
    if color:
        chat_box.config(bg=color)
        user_listbox.config(bg=color)

# Function to change text color
def change_text_color():
    color = colorchooser.askcolor()[1]
    if color:
        chat_box.config(fg=color)
        user_listbox.config(fg=color)
        chat_box.tag_configure('received', foreground=color)

# Function to receive messages
def receive_messages():
    global public_keys

    while True:
        try:
            # Receive the message
            message = client_socket.recv(1024).decode('utf-8')
            if not message:
                break  # Exit if the connection is closed

            if message.startswith("PUBLIC_KEY:"):
                # Handle public key exchange
                parts = message.split(":")
                if len(parts) >= 3:
                    user = parts[1]
                    key_data = parts[2]
                    with chat_lock:
                        public_keys[user] = rsa.PublicKey.load_pkcs1(key_data.encode('utf-8'))
                        print(f"DEBUG: Received public key for {user}")
            elif message.startswith("ACTIVE_USERS:"):
                try:
                    # Extract the list of active users
                    active_users = message.split(":")[1].strip()  # Remove any leading/trailing whitespace
                    print(f"DEBUG: Received ACTIVE_USERS: {active_users}")  # Debug print

                    # Split the active users into a list
                    user_list = active_users.split(",") if active_users else []

                    # Update the user listbox in a thread-safe manner
                    with chat_lock:
                        user_listbox.delete(0, tk.END)
                        for user in user_list:
                            if user != username:  # Exclude the current user
                                user_listbox.insert(tk.END, user)
                except Exception as e:
                    print(f"Error processing ACTIVE_USERS message: {e}")
            elif message.startswith("FILE:"):
                # Handle file transfer
                parts = message.split(":")
                if len(parts) >= 3:
                    sender = parts[1]
                    file_name = parts[2]

                    # Notify the server that the client is ready to receive the file
                    client_socket.send("READY".encode('utf-8'))

                    # Receive the file data in chunks
                    file_data = b""
                    while True:
                        chunk = client_socket.recv(1024)
                        if not chunk:
                            break
                        file_data += chunk
                        if len(chunk) < 1024:
                            break

                    # Save the file
                    with open(file_name, 'wb') as file:
                        file.write(file_data)

                    # Add the file received message to the chat history
                    with chat_lock:
                        if sender not in chat_history:
                            chat_history[sender] = []
                        chat_history[sender].append(f"FILE:{sender}:{file_name}")

                    # Update the chat box if the sender is the selected user
                    selected_user = user_listbox.get(tk.ACTIVE)
                    if selected_user == sender:
                        update_chat_box(sender)
            else:
                # Handle regular messages
                parts = message.split(":")
                if len(parts) >= 2:
                    sender = parts[0]
                    encrypted_message = bytes.fromhex(parts[1])  # Convert hex to bytes

                    # Decrypt the message
                    decrypted_message = decrypt_message(encrypted_message)
                    if decrypted_message:
                        # Add the message to the chat history
                        with chat_lock:
                            if sender not in chat_history:
                                chat_history[sender] = []
                            chat_history[sender].append(f"{sender}: {decrypted_message}")

                        # Update the chat box if the sender is the selected user
                        selected_user = user_listbox.get(tk.ACTIVE)
                        if selected_user == sender:
                            update_chat_box(sender)
        except Exception as e:
            print(f"Connection closed: {e}")
            break

    # Close the socket if the loop exits
    client_socket.close()

# GUI setup
root = tk.Tk()
root.title("ChatSphere")  # Fashionable name
root.geometry("600x500")  # Slightly larger window size
root.configure(bg="#f0f0f0")

# Custom font for the title
title_font = font.Font(family="Helvetica", size=16, weight="bold")
title_label = tk.Label(root, text="ChatSphere", font=title_font, bg="#f0f0f0", fg="#333333")
title_label.pack(pady=10)

# Frame for user list and chat box
main_frame = tk.Frame(root, bg="#f0f0f0")
main_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

# Listbox to display logged-in users
user_listbox = tk.Listbox(main_frame, bg="#ffffff", fg="#000000")
user_listbox.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.Y)

# Bind the listbox selection event to update the chat box
def on_user_select(event):
    selected_user = user_listbox.get(tk.ACTIVE)
    update_chat_box(selected_user)

user_listbox.bind('<<ListboxSelect>>', on_user_select)

# Chat box to display messages
chat_box = scrolledtext.ScrolledText(main_frame, state='disabled', bg="#ffffff", fg="#000000", wrap=tk.WORD)
chat_box.pack(side=tk.LEFT, padx=10, pady=10, fill=tk.BOTH, expand=True)

# Configure tags for message styling
chat_box.tag_configure('sent', foreground='blue', justify='right')
chat_box.tag_configure('received', foreground='green', justify='left')
chat_box.tag_configure('file', foreground='purple')
chat_box.tag_configure('download', foreground='blue', underline=True)

# Frame for input field and buttons
input_frame = tk.Frame(root, bg="#f0f0f0")
input_frame.pack(padx=10, pady=10, fill=tk.X)

# Entry field for typing messages
entry_field = tk.Entry(input_frame, width=50)
entry_field.pack(side=tk.LEFT, padx=5, pady=5)

# Bind Enter key to send message
entry_field.bind("<Return>", send_message)

# Button to send messages
send_button = tk.Button(input_frame, text="Send", bg="#4CAF50", fg="white", command=send_message)
send_button.pack(side=tk.LEFT, padx=5, pady=5)

# Button to send files
file_button = tk.Button(input_frame, text="Send File", bg="#008CBA", fg="white", command=send_file)
file_button.pack(side=tk.LEFT, padx=5, pady=5)

# Menu for customization options
menu_bar = tk.Menu(root)
root.config(menu=menu_bar)

# Appearance menu
appearance_menu = tk.Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="Appearance", menu=appearance_menu)

# Background color option
appearance_menu.add_command(label="Change Background Color", command=change_bg_color)

# Text color option
appearance_menu.add_command(label="Change Text Color", command=change_text_color)

# Login system
username = simpledialog.askstring("Login", "Enter your username:", parent=root)
if not username:
    messagebox.showerror("Error", "Username cannot be empty.")
    root.destroy()
else:
    client_socket.send(username.encode('utf-8'))

    # Send the client's public key to the server
    client_socket.send(f"PUBLIC_KEY:{username}:{public_key.save_pkcs1().decode('utf-8')}".encode('utf-8'))

    # Start a thread to receive messages
    receive_thread = threading.Thread(target=receive_messages)
    receive_thread.start()

    # Run the GUI
    root.mainloop()