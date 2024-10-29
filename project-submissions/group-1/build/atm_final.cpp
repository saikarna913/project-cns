#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <string>
#include <unistd.h>
#include <fstream>
#include <arpa/inet.h>
#include <sstream>
#include <regex>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <limits>
#include <iomanip>


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

// Function to hash password using SHA-256
std::string hash_password(const std::string &password)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)password.c_str(), password.size(), hash);

    char hash_string[2 * SHA256_DIGEST_LENGTH + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
    {
        sprintf(hash_string + (i * 2), "%02x", hash[i]);
    }
    return std::string(hash_string);
}

// Function to read from SSL with a timeout
bool SSL_read_with_timeout(SSL* ssl, char* buffer, int buffer_size, int timeout_seconds) {
    fd_set read_fds;
    struct timeval timeout;

    // Clear the set and add the socket file descriptor
    int sockfd = SSL_get_fd(ssl);
    FD_ZERO(&read_fds);
    FD_SET(sockfd, &read_fds);

    // Set the timeout value
    timeout.tv_sec = timeout_seconds;
    timeout.tv_usec = 0;

    // Wait for the socket to be ready for reading
    int select_result = select(sockfd + 1, &read_fds, nullptr, nullptr, &timeout);
    if (select_result == -1) {
        perror("select error");
        return false; // Handle select error
    } else if (select_result == 0) {
        std::cout << "Timeout: No response from server." << std::endl;
        return false; // Timeout occurred
    }

    // Read from SSL
    int bytes_read = SSL_read(ssl, buffer, buffer_size);
    if (bytes_read <= 0) {
        ERR_print_errors_fp(stderr);
        return false; // Handle read error
    }

    buffer[bytes_read] = '\0'; // Null-terminate the response
    return true; // Successful read
}

// Function to validate the username
bool validate_username(const std::string &username)
{
    // Check the length of the username
    if (username.length() < 1 || username.length() > 122)
    {
        return false;
    }

    // Check if the username matches the allowed character pattern
    std::regex pattern(R"(^([a-z0-9._-]+)$)");
    if (std::regex_match(username, pattern))
    {
        return true;
    }

    return false;
}
const double MAX_AMOUNT = 4294967295.99; // Maximum allowed amount
// Function to validate currency input as whole and fractional parts
bool isValidAmount(const std::string &input)
{
    std::regex pattern("^(0|[1-9][0-9]*)\\.([0-9]{2})$");
    if (!std::regex_match(input, pattern))
    {
        return false;
    }

    // Check if the amount is within the valid range [0.00, 4294967295.99]
    double amount = std::stod(input);
    return amount > 0.00 && amount <=MAX_AMOUNT;
}

// std::string read_auth_file(const std::string &filename) {
//     std::ifstream auth_file(filename);
//     std::string key;

//     if (auth_file.is_open()) {
//         std::getline(auth_file, key);
//         auth_file.close();
//     } else {
//         std::cerr << "255- Failed to read auth file." << std::endl;
//         exit(255);
//     }

//     return key;
// }

std::string read_auth_file(const std::string &filename) {
    std::ifstream auth_file(filename);
    std::string key;

    if (auth_file.is_open()) {
        // Attempt to read the first line from the file
        std::getline(auth_file, key);
        
        // Check if the file was empty (key remains empty after getline)
        if (key.empty()) {
            key="empty";
            std::cerr << "255- Auth file is empty." << std::endl;
            auth_file.close();
            return key;
            exit(255); // Exit with code 255
        }
        
        //
    } else {
        std::cerr << "255- Failed to read auth file." << std::endl;
                exit(255); // Exit with code 255
    }

    return key;
}

// std::string read_auth_file(const std::string &filename, SSL *ssl, SSL_CTX *ctx, int sockfd) {
//     std::ifstream auth_file(filename);
//     std::string key;

//     if (auth_file.is_open()) {
//         // Attempt to read the first line from the file
//         std::getline(auth_file, key);
        
//         // Check if the file was empty (key remains empty after getline)
//         if (key.empty()) {
//             std::cerr << "255- Auth file is empty." << std::endl;
//             //SSL_shutdown(ssl);
//             //SSL_free(ssl);
//             //close(sockfd);
//             //SSL_CTX_free(ctx);
//             //EVP_cleanup();
//             exit(255); // Exit with code 255
//         }
        
//         auth_file.close();
//     } else {
//         std::cerr << "255- Failed to read auth file." << std::endl;
//         //SSL_shutdown(ssl);
//         //SSL_free(ssl);
//         //close(sockfd);
//         //SSL_CTX_free(ctx);
//         //EVP_cleanup();
//         exit(255); // Exit with code 255
//     }

//     return key;
// }



int main()
{
    // Initialize OpenSSL library
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = SSLv23_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5:!RC4:!DES:!3DES");

    if (!ctx)
    {
        std::cerr << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(63);
        return 1;
    }

    // Load client's certificate and key
    if (SSL_CTX_use_certificate_file(ctx, "atm_cert.pem", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "atm_key.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // Load CA certificate
    if (!SSL_CTX_load_verify_locations(ctx, "ca_cert.pem", NULL))
    {
        ERR_print_errors_fp(stderr);
        return 1;
    }
// Read server IP address from file
    std::string server_ip = read_server_ip("server_ip.txt");
    // Create TCP socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        std::cerr << "Socket creation failed" << std::endl;
        exit(63);
        return 1;
    }

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(8080);                       // Server's port
    inet_pton(AF_INET, server_ip.c_str(), &serv_addr.sin_addr); // Bank server's IP

    // Connect to server
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        std::cerr << "Connection failed" << std::endl;
        exit(63);
        return 1;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) <= 0)
    {
        std::cerr << "SSL connection failed" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(63);
        return 1;
    }
// std::string client_auth_key = read_auth_file("atm_auth_file.txt");

// new function for reading auth file - kills atm application if not authenticated:
std::string client_auth_key = read_auth_file("atm_auth_file.txt");

    // Send the auth key to the bank
    SSL_write(ssl, client_auth_key.c_str(), client_auth_key.size());
      // Wait for server response to auth key verification
    char auth_response[1024] = {0};
    SSL_read(ssl, auth_response, sizeof(auth_response));
    std::string server_response = auth_response;
    std::cout << "Server: " << server_response << std::endl;

    // Proceed only if the server verifies the key successfully
    if (server_response == "VERIFIED")
    {
    while (true)
    {
        std::cout << "ATM Menu:\n1. Register\n2. Login\n3. Exit\nEnter your choice: ";
        std::string choice;
        std::cin >> choice;

        if (choice == "1") // Register
        {
            std::string username, password;
            double initial_balance;

            // Input and validate username
            do
            {
                std::cout << "Enter username (allowed: [_-., digits, lowercase letters], 1-122 chars): ";
                std::cin >> username;

                if (!validate_username(username))
                {
                    std::cout << "255- Invalid username. Please try again." << std::endl;
                }
            } while (!validate_username(username));

            // Input password
            std::cout << "Enter password: ";
            std::cin >> password;

            // Input and validate initial balance
            
            // std::cout << "Enter initial deposit amount (must be greater than $10): ";
            // std::cin >> initial_balance;
            std::string initial_balance_str; // Temporary string for validation
            do {
                std::cout << "Enter initial deposit amount (must be formatted as 0.00): ";
                std::cin >> initial_balance_str;

                if (!isValidAmount(initial_balance_str)) {
                    std::cout << "255- Invalid initial balance format. Please enter a valid amount." << std::endl;
                    continue; // Prompt again for input
                }

                // Convert string to double
                initial_balance = std::stod(initial_balance_str);

                // Note: We are not validating if initial_balance > 10, assuming the bank does this
            } while (!isValidAmount(initial_balance_str)); // Only check if the format is valid

            std::string hashed_password = hash_password(password);
            
            if (SSL_write(ssl, "REGISTER", 8) <= 0 ||
                SSL_write(ssl, (username + " " + hashed_password + " " + std::to_string(initial_balance)).c_str(),
                        (username + " " + hashed_password + " " + std::to_string(initial_balance)).size()) <= 0)
            {
                std::cerr << "Server disconnected. Exiting..." << std::endl;
                exit(63);
                break; // Exit the outer loop
            }

            char response[1024] = {0};

            if (!SSL_read_with_timeout(ssl, response, sizeof(response), 10)) {
                std::cout << "Terminating application due to timeout." << std::endl;
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(sockfd);
                SSL_CTX_free(ctx);
                EVP_cleanup();
                exit(63); // Exit with code 63 on timeout
            }

            std::cout << "Server: " << response << std::endl;
        }

        else if (choice == "2")
        {
            std::string username, password;

            // Input and validate username
            do
            {
                std::cout << "Enter username (allowed: [_-., digits, lowercase letters], 1-127 chars): ";
                std::cin >> username;

                if (!validate_username(username))
                {
                    std::cout << "255- Invalid username. Please try again." << std::endl;
                }
            } while (!validate_username(username));

            // Input password
            std::cout << "Enter password: ";
            std::cin >> password;

            std::string hashed_password = hash_password(password);

            if (SSL_write(ssl, "LOGIN", 5) <= 0 ||
                SSL_write(ssl, (username + " " + hashed_password).c_str(), (username + " " + hashed_password).size()) <= 0)
            {
                std::cerr << "Server disconnected. Exiting..." << std::endl;
                exit(63);
                break; // Exit the outer loop
            }

            char response[1024] = {0};
            if (!SSL_read_with_timeout(ssl, response, sizeof(response), 10)) {
                        std::cout << "Terminating application due to timeout." << std::endl;
                        SSL_shutdown(ssl);
                        SSL_free(ssl);
                        close(sockfd);
                        SSL_CTX_free(ctx);
                        EVP_cleanup();
                        exit(63); // Exit with code 63 on timeout
            }
            std::string server_response = response;
            std::cout << "Server: " << server_response << std::endl;

            // Further logic for successful login

            if (server_response.find("SessionID: ") != std::string::npos)
            {
                std::string session_id = server_response.substr(server_response.find("SessionID: ") + 11);
                int command_counter = 0; // Initialize command counter
                const int MAX_COMMANDS = 10; // Set maximum number of commands allowed

                while (true)
                {
                    command_counter++;
                    if (command_counter > MAX_COMMANDS)
                    {
                        std::cout << "Maximum command limit reached. Logging out..." << std::endl;
                        if (SSL_write(ssl, "LOGOUT", 6) <= 0 ||
                            SSL_write(ssl, session_id.c_str(), session_id.size()) <= 0)
                        {
                            std::cerr << "Server disconnected. Exiting..." << std::endl;
                            exit(63);
                            break; // Exit the inner loop
                        }
                    char logout_response[1024] = {0};
                        if (SSL_read(ssl, logout_response, sizeof(logout_response)) <= 0)
                        {
                            std::cerr << "Server disconnected. Exiting..." << std::endl;
                            exit(63);
                            break; // Exit the inner loop
                        }
                        std::cout << "Server: " << logout_response << std::endl;
                        break; // Exit the inner loop (user is logged out)
                    }
                    std::cout << "\nLogged in. What would you like to do?\n1. Check Balance\n2. Deposit Money\n3. Withdraw Money\n4. View past transactions\n5. Logout\nEnter your choice: ";
                    std::string sub_choice;
                    std::cin >> sub_choice;


                    if (sub_choice == "1")
                    {
                        if (SSL_write(ssl, "CHECK_BALANCE", 13) <= 0 || 
                            SSL_write(ssl, session_id.c_str(), session_id.size()) <= 0)
                        {
                            std::cerr << "Server disconnected. Exiting..." << std::endl;
                            exit(63);
                            break; // Exit the inner loop
                        }

                        char balance_response[1024] = {0};

                        if (!SSL_read_with_timeout(ssl, balance_response, sizeof(balance_response), 10)) {
                            std::cout << "Terminating application due to timeout." << std::endl;
                            SSL_shutdown(ssl);
                            SSL_free(ssl);
                            close(sockfd);
                            SSL_CTX_free(ctx);
                            EVP_cleanup();
                            exit(63); // Exit with code 63 on timeout
                        }
                        std::cout << "Server: " << balance_response << std::endl;
                    }
                    else if (sub_choice == "2")
                    {
                        std::string amount;
                        std::cout << "Enter amount to deposit: ";
                        std::cin >> amount;
                        if (!isValidAmount(amount))
                        {
                            std::cout << "255- Invalid amount! Please enter a valid amount in the format: whole.fractional (e.g., 123.45) and within bounds (0.00, 4294967295.99]." << std::endl;
                            continue;
                        }
                        if (SSL_write(ssl, "DEPOSIT", 7) <= 0 ||
                            SSL_write(ssl, (session_id + " " + amount).c_str(), (session_id + " " + amount).size()) <= 0)
                        {
                            std::cerr << "Server disconnected. Exiting..." << std::endl;
                            exit(63);
                            break; // Exit the inner loop
                        }

                        char deposit_response[1024] = {0};

                        if (!SSL_read_with_timeout(ssl, deposit_response, sizeof(deposit_response), 10)) {
                        std::cout << "Terminating application due to timeout." << std::endl;
                        SSL_shutdown(ssl);
                        SSL_free(ssl);
                        close(sockfd);
                        SSL_CTX_free(ctx);
                        EVP_cleanup();
                        exit(63); // Exit with code 63 on timeout
                    }
                        std::cout << "Server: " << deposit_response << std::endl;
                    }
                    else if (sub_choice == "3")
                    {
                        std::string amount;
                        std::cout << "Enter amount to withdraw: ";
                        std::cin >> amount;
                        if (!isValidAmount(amount))
                        {
                            std::cout << "Invalid amount! Please enter a valid amount in the format: whole.fractional (e.g., 123.45) and within bounds (0.00, 4294967295.99]." << std::endl;
                            continue;
                        }
                        if (SSL_write(ssl, "WITHDRAW", 8) <= 0 ||
                            SSL_write(ssl, (session_id + " " + amount).c_str(), (session_id + " " + amount).size()) <= 0)
                        {
                            std::cerr << "Server disconnected. Exiting..." << std::endl;
                            exit(63);
                            break; // Exit the inner loop
                        }

                        char withdraw_response[1024] = {0};
                        if (!SSL_read_with_timeout(ssl, withdraw_response, sizeof(withdraw_response), 10)) {
                        std::cout << "Terminating application due to timeout." << std::endl;
                        SSL_shutdown(ssl);
                        SSL_free(ssl);
                        close(sockfd);
                        SSL_CTX_free(ctx);
                        EVP_cleanup();
                        exit(63); // Exit with code 63 on timeout
                    }
                        std::cout << "Server: " << withdraw_response << std::endl;
                    }
                    else if (sub_choice == "4")
                    {
                        if (SSL_write(ssl, "VIEW_TRANSACTIONS", 17) <= 0 || 
                            SSL_write(ssl, session_id.c_str(), session_id.size()) <= 0)
                        {
                            std::cerr << "Server disconnected. Exiting..." << std::endl;
                            exit(63);
                            break; // Exit the inner loop
                        }

                        char transaction_response[4096] = {0}; // Larger buffer for potential larger response
                        if (!SSL_read_with_timeout(ssl, transaction_response, sizeof(transaction_response), 10)) {
                        std::cout << "Terminating application due to timeout." << std::endl;
                        SSL_shutdown(ssl);
                        SSL_free(ssl);
                        close(sockfd);
                        SSL_CTX_free(ctx);
                        EVP_cleanup();
                        exit(63); // Exit with code 63 on timeout
                    }
                        std::cout << "Transaction History:\n"
                                << transaction_response << std::endl;
                    }

                    else if (sub_choice == "5")
                    {
                        if (SSL_write(ssl, "LOGOUT", 6) <= 0 || 
                            SSL_write(ssl, session_id.c_str(), session_id.size()) <= 0)
                        {
                            std::cerr << "Server disconnected. Exiting..." << std::endl;
                            exit(63);
                            break; // Exit the inner loop
                        }

                        char logout_response[1024] = {0};

                        if (!SSL_read_with_timeout(ssl, logout_response, sizeof(logout_response), 10)) {
                        std::cout << "Terminating application due to timeout." << std::endl;
                        SSL_shutdown(ssl);
                        SSL_free(ssl);
                        close(sockfd);
                        SSL_CTX_free(ctx);
                        EVP_cleanup();
                        exit(63); // Exit with code 63 on timeout
                    }
                        std::cout << "Server: " << logout_response << std::endl;
                        break; // Logout and exit inner loop
                    }
                    else
                    {
                        std::cout << "Invalid choice." << std::endl;
                    }
                }
            }
        }
        else if (choice == "3")
        {
            break;
        }
        else
        {
            std::cout << "Invalid choice." << std::endl;
        }
    }
    }
 else
    {
        std::cout << "Authentication failed. Exiting..." << std::endl;
        exit(255);
    }

    // Close SSL connection
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);

    return 0;
}
