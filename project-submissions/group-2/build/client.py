import socket

def main():
    host = '127.0.0.1'  # Server address
    port = 12345        # Port to connect to

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        while True:
            command = input("Enter command (or 'exit' to quit): ")
            if command.lower() == 'exit':
                break
            
            client_socket.sendall(command.encode())
            response = client_socket.recv(4096).decode()
            print("Response from server:")
            print(response)

if __name__ == "__main__":
    main()
