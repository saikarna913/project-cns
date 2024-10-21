import socket
import ssl
import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def main():
    # Create SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations('certificate.crt')  # Load the bank's certificate

    # Create a socket and connect to the bank server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    secure_sock = context.wrap_socket(sock, server_hostname='localhost')

    try:
        secure_sock.connect(('10.7.59.153', 8080))  # Replace with server IP

        while True:
            print("ATM Menu:")
            print("1. Register")
            print("2. Login")
            print("3. Exit")
            choice = input("Enter your choice: ")

            if choice == '1':
                username = input("Enter username: ")
                password = input("Enter password: ")
                hashed_password = hash_password(password)

                secure_sock.send(b"REGISTER")
                secure_sock.send(f"{username} {hashed_password}".encode())
                response = secure_sock.recv(1024).decode()
                print(f"Server: {response}")

            elif choice == '2':
                username = input("Enter username: ")
                password = input("Enter password: ")
                hashed_password = hash_password(password)

                secure_sock.send(b"LOGIN")
                secure_sock.send(f"{username} {hashed_password}".encode())
                response = secure_sock.recv(1024).decode()
                print(f"Server: {response}")

                # Extract session ID from response
                if "SessionID: " in response:
                    session_id = response.split("SessionID: ")[1]
                    print(f"Your session ID: {session_id}")

                    while True:
                        print("\nLogged in. What would you like to do?")
                        print("1. Check Balance")
                        print("2. Deposit Money")
                        print("3. Withdraw Money")
                        print("4. Logout")
                        sub_choice = input("Enter your choice: ")

                        if sub_choice == '1':
                            secure_sock.send(b"CHECK_BALANCE")
                            secure_sock.send(session_id.encode())
                            response = secure_sock.recv(1024).decode()
                            print(f"Server: {response}")

                        elif sub_choice == '2':
                            amount = input("Enter amount to deposit: ")
                            secure_sock.send(b"DEPOSIT")
                            secure_sock.send(f"{session_id} {amount}".encode())
                            response = secure_sock.recv(1024).decode()
                            print(f"Server: {response}")

                        elif sub_choice == '3':
                            amount = input("Enter amount to withdraw: ")
                            secure_sock.send(b"WITHDRAW")
                            secure_sock.send(f"{session_id} {amount}".encode())
                            response = secure_sock.recv(1024).decode()
                            print(f"Server: {response}")

                        elif sub_choice == '4':
                            secure_sock.send(b"LOGOUT")
                            secure_sock.send(session_id.encode())
                            response = secure_sock.recv(1024).decode()
                            print(f"Server: {response}")
                            break
                        else:
                            print("Invalid option. Please try again.")
            elif choice == '3':
                print("Exiting ATM.")
                break
            else:
                print("Invalid option. Please enter 1, 2, or 3.")
    finally:
        secure_sock.close()

if __name__ == "__main__":
    main()







