#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <string>
#include <unistd.h>
#include <arpa/inet.h>
#include <fstream>

// Function to hash password using SHA-256
std::string hash_password(const std::string& password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)password.c_str(), password.size(), hash);

    char hash_string[2*SHA256_DIGEST_LENGTH+1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        snprintf(hash_string + (i * 2), 3, "%02x", hash[i]);

    }
    return std::string(hash_string);
}


// Function to read server IP from a file
std::string read_server_ip(const std::string& file_path) {
    std::ifstream file(file_path);
    std::string ip_address;
    if (file.is_open()) {
        std::getline(file, ip_address); // the first line contains the ip
        file.close();
    } else {
        std::cerr << "Unable to open IP address file." << std::endl;
        exit(1);
    }
    return ip_address;
}



int main() {
    // Initialize OpenSSL library
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = SSLv23_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    if (!ctx) {
        std::cerr << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // Load client's certificate and key
    if (SSL_CTX_use_certificate_file(ctx, "atm_cert.pem", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "atm_key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // Load CA certificate
    if (!SSL_CTX_load_verify_locations(ctx, "ca_cert.pem", NULL)) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // Read server IP address from file
    std::string server_ip = read_server_ip("server_ip.txt");

    // Create TCP socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        std::cerr << "Socket creation failed" << std::endl;
        return 1;
    }

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(8088); // Server's port
    inet_pton(AF_INET, server_ip.c_str(), &serv_addr.sin_addr); // Bank server's IP

    // Connect to server
    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection failed" << std::endl;
        return 1;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) <= 0) {
        std::cerr << "SSL connection failed" << std::endl;
        ERR_print_errors_fp(stderr);
        return 1;
    }

    while (true) {
        std::cout << "ATM Menu:\n1. Register\n2. Login\n3. Exit\nEnter your choice: ";
        std::string choice;
        std::cin >> choice;

        if (choice == "1") {
            std::string username, password;
            std::cout << "Enter username: ";
            std::cin >> username;
            std::cout << "Enter password: ";
            std::cin >> password;

            std::string hashed_password = hash_password(password);

            SSL_write(ssl, "REGISTER", 8);
            std::string data = username + " " + hashed_password;
            SSL_write(ssl, data.c_str(), data.size());

            char response[1024];
            SSL_read(ssl, response, sizeof(response));
            std::cout << "Server: " << response << std::endl;

        } else if (choice == "2") {
            std::string username, password;
            std::cout << "Enter username: ";
            std::cin >> username;
            std::cout << "Enter password: ";
            std::cin >> password;

            std::string hashed_password = hash_password(password);

            SSL_write(ssl, "LOGIN", 5);
            std::string data = username + " " + hashed_password;
            SSL_write(ssl, data.c_str(), data.size());

            char response[1024];
            SSL_read(ssl, response, sizeof(response));
            std::string server_response = response;
            std::cout << "Server: " << server_response << std::endl;

            if (server_response.find("SessionID: ") != std::string::npos) {
                std::string session_id = server_response.substr(server_response.find("SessionID: ") + 11);

                while (true) {
                    std::cout << "\nLogged in. What would you like to do?\n1. Check Balance\n2. Deposit Money\n3. Withdraw Money\n4. Logout\nEnter your choice: ";
                    std::string sub_choice;
                    std::cin >> sub_choice;

                    if (sub_choice == "1") {
                        SSL_write(ssl, "CHECK_BALANCE", 13);
                        SSL_write(ssl, session_id.c_str(), session_id.size());

                        char balance_response[1024];
                        SSL_read(ssl, balance_response, sizeof(balance_response));
                        std::cout << "Server: " << balance_response << std::endl;

                    } else if (sub_choice == "2") {
                        std::string amount;
                        std::cout << "Enter amount to deposit: ";
                        std::cin >> amount;

                        SSL_write(ssl, "DEPOSIT", 7);
                        std::string deposit_data = session_id + " " + amount;
                        SSL_write(ssl, deposit_data.c_str(), deposit_data.size());

                        char deposit_response[1024];
                        SSL_read(ssl, deposit_response, sizeof(deposit_response));
                        std::cout << "Server: " << deposit_response << std::endl;

                    } else if (sub_choice == "3") {
                        std::string amount;
                        std::cout << "Enter amount to withdraw: ";
                        std::cin >> amount;

                        SSL_write(ssl, "WITHDRAW", 8);
                        std::string withdraw_data = session_id + " " + amount;
                        SSL_write(ssl, withdraw_data.c_str(), withdraw_data.size());

                        char withdraw_response[1024];
                        SSL_read(ssl, withdraw_response, sizeof(withdraw_response));
                        std::cout << "Server: " << withdraw_response << std::endl;

                    } else if (sub_choice == "4") {
                        SSL_write(ssl, "LOGOUT", 6);
                        SSL_write(ssl, session_id.c_str(), session_id.size());

                        char logout_response[1024];
                        SSL_read(ssl, logout_response, sizeof(logout_response));
                        std::cout << "Server: " << logout_response << std::endl;
                        break;

                    } else {
                        std::cout << "Invalid choice." << std::endl;
                    }
                }
            }

        } else if (choice == "3") {
            break;

        } else {
            std::cout << "Invalid choice." << std::endl;
        }
    }

    // Close SSL connection
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);

    return 0;
}
