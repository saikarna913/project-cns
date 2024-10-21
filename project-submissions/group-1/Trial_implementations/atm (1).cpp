#include <iostream>
#include <string>
#include <sstream>
#include <cstring>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <limits>
#include <iomanip>

using namespace std;

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

// SSL_CTX *create_context() {
//     const SSL_METHOD *method;
//     SSL_CTX *ctx;

//     method = SSLv23_client_method(); // Client method
//     ctx = SSL_CTX_new(method);

//     if (!ctx) {
//         perror("Unable to create SSL context");
//         ERR_print_errors_fp(stderr);
//         exit(EXIT_FAILURE);
//     }
//     return ctx;
// }

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();  // Client-side SSL/TLS method
    ctx = SSL_CTX_new(method);

    if (!ctx) {
        std::cerr << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// void configure_context(SSL_CTX *ctx) {
//     // Load the bank's certificate to establish a trusted connection
//     if (SSL_CTX_load_verify_locations(ctx, "bank_cert.pem", NULL) != 1) {
//         perror("Failed to load bank certificate");
//         ERR_print_errors_fp(stderr);
//         exit(EXIT_FAILURE);
//     }
// }

void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_load_verify_locations(ctx, "ca.pem", nullptr) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
}

string hashPassword(const string &password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(password.c_str()), password.size(), hash);
    
    // Convert the hash to a hexadecimal string
    ostringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

const int BUFFER_SIZE = 1024;

int main() {
    init_openssl();
    SSL_CTX *ctx = create_context();
    configure_context(ctx);

    // Create a socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8080); // Replace with your server's port
    inet_pton(AF_INET, "172.17.0.1", &server_addr.sin_addr); // Replace with your server's IP

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        cerr << "Connection failed!" << endl;
        return -1;
    }

    // // Create an SSL object
    // SSL *ssl = SSL_new(ctx);
    // SSL_set_fd(ssl, sock);
    
    // // Establish SSL connection
    // if (SSL_connect(ssl) <= 0) {
    //     ERR_print_errors_fp(stderr);
    //     close(sock);
    //     SSL_free(ssl);
    //     SSL_CTX_free(ctx);
    //     cleanup_openssl();
    //     return -1;
    // }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);  // server_socket_fd is the connected socket

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        std::cout << "SSL connection established!" << std::endl;
        // Use SSL_write and SSL_read instead of send/recv
        // SSL_write(ssl, message, strlen(message));
    }

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    char buffer[BUFFER_SIZE];

    while (true) {
        cout << "ATM Menu:" << endl;
        cout << "1. Register" << endl;
        cout << "2. Login" << endl;
        cout << "3. Exit" << endl;
        cout << "Enter your choice: ";
        int choice;

        if (!(cin >> choice)) {
            // Handle invalid input (non-integer)
            cout << "Invalid input! Please enter a valid number (1, 2, or 3)." << endl;
            cin.clear(); // Clear the error state of cin
            cin.ignore(numeric_limits<streamsize>::max(), '\n'); // Ignore the rest of the line
            continue; // Re-prompt the user
        }

        cin.ignore(); // Clear the newline from input buffer after reading choice

        if (choice == 1) {
            // Register
            string username, password;
            cout << "Enter username: ";
            getline(cin, username);
            cout << "Enter password: ";
            getline(cin, password);

            // Hash the password
            string hashedPassword = hashPassword(password);

            // Send the command to the bank server
            SSL_write(ssl, "REGISTER", strlen("REGISTER"));

            // Prepare the input to send (username and hashed password)
            string regData = username + " " + hashedPassword;
            SSL_write(ssl, regData.c_str(), regData.length());

            int valread = SSL_read(ssl, buffer, sizeof(buffer));
            cout << "Server: " << string(buffer, valread) << endl;

        } else if (choice == 2) {
            // Login
            string username, password;
            cout << "Enter username: ";
            getline(cin, username);
            cout << "Enter password: ";
            getline(cin, password);

            // Hash the password
            string hashedPassword = hashPassword(password);

            SSL_write(ssl, "LOGIN", strlen("LOGIN"));
            string loginData = username + " " + hashedPassword;
            SSL_write(ssl, loginData.c_str(), loginData.length());

            int valread = SSL_read(ssl, buffer, sizeof(buffer));
            cout << "Server: " << buffer << endl;

            // Extract session ID from response
            string sessionID(buffer);
            size_t pos = sessionID.find("SessionID: ");
            if (pos != string::npos) {
                sessionID = sessionID.substr(pos + 11); // Extract session ID
                cout << "Your session ID: " << sessionID << endl;

                // Menu after login
                while (true) {
                    cout << "\nLogged in. What would you like to do?" << endl;
                    cout << "1. Check Balance" << endl;
                    cout << "2. Deposit Money" << endl;
                    cout << "3. Withdraw Money" << endl;
                    cout << "4. Logout" << endl;
                    cout << "Enter your choice: ";
                    int subChoice;

                    if (!(cin >> subChoice)) {
                        // Handle invalid input (non-integer)
                        cout << "Invalid input! Please enter a valid number (1-4)." << endl;
                        cin.clear(); // Clear the error state of cin
                        cin.ignore(numeric_limits<streamsize>::max(), '\n'); // Ignore the rest of the line
                        continue; // Re-prompt the user
                    }

                    cin.ignore(); // Clear newline

                    if (subChoice == 1) {
                        // Check Balance
                        SSL_write(ssl, "CHECK_BALANCE", strlen("CHECK_BALANCE"));
                        SSL_write(ssl, sessionID.c_str(), sessionID.length());

                        int valread = SSL_read(ssl, buffer, sizeof(buffer));
                        cout << "Server: " << buffer << endl;

                    } else if (subChoice == 2) {
                        // Deposit Money
                        double amount;
                        cout << "Enter amount to deposit: ";
                        cin >> amount;
                        SSL_write(ssl, "DEPOSIT", strlen("DEPOSIT"));
                        string depositRequest = sessionID + " " + to_string(amount);
                        SSL_write(ssl, depositRequest.c_str(), depositRequest.length());

                        int valread = SSL_read(ssl, buffer, sizeof(buffer));
                        cout << "Server: " << buffer << endl;

                    } else if (subChoice == 3) {
                        // Withdraw Money
                        double amount;
                        cout << "Enter amount to withdraw: ";
                        cin >> amount;
                        SSL_write(ssl, "WITHDRAW", strlen("WITHDRAW"));
                        string withdrawRequest = sessionID + " " + to_string(amount);
                        SSL_write(ssl, withdrawRequest.c_str(), withdrawRequest.length());

                        int valread = SSL_read(ssl, buffer, sizeof(buffer));
                        cout << "Server: " << buffer << endl;

                    } else if (subChoice == 4) {
                        // Logout
                        SSL_write(ssl, "LOGOUT", strlen("LOGOUT"));
                        SSL_write(ssl, sessionID.c_str(), sessionID.length());

                        int valread = SSL_read(ssl, buffer, sizeof(buffer));
                        cout << "Server: " << buffer << endl;
                        break; // Exit the login submenu
                    } else {
                        cout << "Invalid option. Please try again." << endl;
                    }
                    memset(buffer, 0, BUFFER_SIZE); // Clear buffer for next command
                }
            } else {
                cout << "Login failed. Please try again." << endl;
            }
        } else if (choice == 3) {
            cout << "Exiting ATM." << endl;
            break;
        } else {
            cout << "Invalid option. Please enter 1, 2, or 3." << endl;
        }
        memset(buffer, 0, BUFFER_SIZE); // Clear buffer for next command
    }

    // Clean up
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}
