#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

using namespace std;

void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX* create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_client_method(); // Use TLSv1.3 or appropriate method
    ctx = SSL_CTX_new(method);

    if (!ctx) {
        std::cerr << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
}

int create_socket(const std::string &ip, int port) {
    int sock;
    struct sockaddr_in addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) <= 0) {
        perror("Invalid IP address");
        exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to connect");
        exit(EXIT_FAILURE);
    }

    return sock;
}

void handle_communication(SSL *ssl) {
    char buffer[4096] = {};
    std::string input;
    std::cout << "Enter message (type 'exit' to quit): ";
    bool b = false;
    while (true) {
        // std::cout << "Enter message (type 'exit' to quit): ";
        std::getline(std::cin, input);

        if (input == "exit") {
            break;
        }

        // Send the input to the server
        SSL_write(ssl, input.c_str(), input.length());

        // Read the server response
        while(true){
            int bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
            if (bytes_received > 0) {
                buffer[bytes_received] = '\0';  // Null-terminate the response
                std::cout <<  buffer; //"Server response: "
                string str(buffer);
                if(str.find("Enter another command now") == 0 || b == false){
                    break;
                }
            } else {
                std::cerr << "SSL read error: ";
                ERR_print_errors_fp(stderr);
                break;
            }
        }
        b = true;
    }
}

int main() {
    std::string server_ip;
    int server_port = 6969;  // Assuming port 6969 for the server

    std::cout << "Enter server IP: ";
    std::cin >> server_ip;
    
    if (server_ip=="localhost") {
        server_ip = "127.0.0.1";
    }
    
    // Initialize OpenSSL
    initialize_openssl();
    SSL_CTX *ctx = create_context();
    configure_context(ctx);

    // Create TCP connection
    int server_socket = create_socket(server_ip, server_port);

    // Create SSL object and attach the socket
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server_socket);

    // Perform TLS/SSL handshakeSSL_read
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        std::cout << "Connected with " << SSL_get_cipher(ssl) << " encryption" << std::endl;

        // Handle communication
        handle_communication(ssl);

        // Initiate a proper SSL/TLS shutdown handshake
        SSL_shutdown(ssl);
    }

    // Clean up
    SSL_free(ssl);
    close(server_socket);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}
