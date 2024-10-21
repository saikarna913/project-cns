import socket
import ssl
import threading
import hashlib
import csv
import os
import random
import time

active_sessions = {}  # Active sessions dictionary
user_database = {}    # User database
user_balances = {}    # User balances

def load_user_database(filename):
    if os.path.exists(filename):
        with open(filename, 'r') as file:
            reader = csv.reader(file)
            for row in reader:
                username, password, balance = row
                user_database[username] = password
                user_balances[username] = float(balance)

def save_user_to_database(username, password, balance, filename):
    with open(filename, 'a') as file:
        writer = csv.writer(file)
        writer.writerow([username, password, balance])

def update_user_database(filename):
    with open(filename, 'w') as file:
        writer = csv.writer(file)
        for username, password in user_database.items():
            writer.writerow([username, password, user_balances[username]])

def generate_session_id():
    return ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=16))

def create_session(account_id):
    session_id = generate_session_id()
    active_sessions[session_id] = account_id
    print(f"Session created: {session_id}")
    return session_id

def validate_session(session_id):
    return session_id in active_sessions

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def handle_client_request(conn):
    while True:
        command = conn.recv(1024).decode()
        if not command:
            break
        
        response = ""
        if command == "REGISTER":
            data = conn.recv(1024).decode().split()
            username, hashed_password = data[0], data[1]
            if username in user_database:
                response = "Username already exists!"
            else:
                initial_balance = 0.0
                user_database[username] = hashed_password
                user_balances[username] = initial_balance
                save_user_to_database(username, hashed_password, initial_balance, "user_database.csv")
                response = "Registration successful!"
        elif command == "LOGIN":
            data = conn.recv(1024).decode().split()
            username, hashed_password = data[0], data[1]
            if username in user_database and user_database[username] == hashed_password:
                session_id = create_session(username)
                response = f"Login successful! SessionID: {session_id}"
            else:
                response = "Invalid username or password!"
        elif command == "CHECK_BALANCE":
            session_id = conn.recv(1024).decode()
            if validate_session(session_id):
                username = active_sessions[session_id]
                balance = user_balances[username]
                response = f"Current balance: ${balance}"
            else:
                response = "Invalid session!"
        elif command == "DEPOSIT":
            data = conn.recv(1024).decode().split()
            session_id, amount = data[0], float(data[1])
            if validate_session(session_id):
                username = active_sessions[session_id]
                user_balances[username] += amount
                response = f"Deposited ${amount}. New balance: ${user_balances[username]}"
                update_user_database("user_database.csv")
            else:
                response = "Invalid session!"
        elif command == "WITHDRAW":
            data = conn.recv(1024).decode().split()
            session_id, amount = data[0], float(data[1])
            if validate_session(session_id):
                username = active_sessions[session_id]
                if user_balances[username] >= amount:
                    user_balances[username] -= amount
                    response = f"Withdrew ${amount}. New balance: ${user_balances[username]}"
                    update_user_database("user_database.csv")
                else:
                    response = "Insufficient funds!"
            else:
                response = "Invalid session!"
        elif command == "LOGOUT":
            session_id = conn.recv(1024).decode()
            if validate_session(session_id):
                del active_sessions[session_id]
                response = "Logged out successfully!"
            else:
                response = "Invalid session!"

        conn.send(response.encode())
    
    conn.close()

def main():
    load_user_database("user_database.csv")

    # Create SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="bank_cert.pem", keyfile="bank_key.pem")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 8080))
    server_socket.listen(5)
    print("Bank server is running on port 8080...")

    while True:
        conn, addr = server_socket.accept()
        print(f"Connection from {addr}")
        secure_conn = context.wrap_socket(conn, server_side=True)
        threading.Thread(target=handle_client_request, args=(secure_conn,)).start()

if __name__ == "__main__":
    main()