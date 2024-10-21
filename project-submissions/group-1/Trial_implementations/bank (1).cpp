#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <unordered_map>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <ctime>
#include <cstdlib>
#include <openssl/sha.h>
#include <iomanip>

using namespace std;

unordered_map<string, string> activeSessions;   // To store active sessions (sessionID -> username)
unordered_map<string, string> userDatabase;     // To store user data (username -> hashed password)
unordered_map<string, double> userBalances;      // To store user balances (username -> balance)

// Function to load user database from a file
void loadUserDatabase(const string &filename) {
    ifstream file(filename);
    string line, username, password;
    double balance;
    
    while (getline(file, line)) {
        stringstream ss(line);
        getline(ss, username, ',');
        getline(ss, password, ',');
        ss >> balance;
        userDatabase[username] = password;
        userBalances[username] = balance; // Load balance from file
    }
    file.close();
}

// Function to save a new user to the database
void saveUserToDatabase(const string &username, const string &password, double balance, const string &filename) {
    ofstream file;
    file.open(filename, ios::app);
    file << username << "," << password << "," << balance << "\n"; // Save balance in CSV
    file.close();
}

// Function to update the user database file
void updateUserDatabase(const string &filename) {
    ofstream file(filename);
    for (const auto &pair : userDatabase) {
        string username = pair.first;
        string password = pair.second;
        double balance = userBalances[username];
        file << username << "," << password << "," << balance << "\n"; // Update balance
    }
    file.close();
}

// Function to generate a random session ID
string generateSessionID() {
    string sessionID;
    srand(time(0));
    for (int i = 0; i < 16; ++i) {
        sessionID += 'A' + rand() % 26; // Random session ID
    }
    return sessionID;
}

// Function to create a session and store it
string createSession(const string &accountID) {
    string sessionID = generateSessionID();
    activeSessions[sessionID] = accountID; // Store session ID and account mapping
    cout << "Session created: " << sessionID << endl;
    return sessionID;
}

// Function to validate a session ID
bool validateSession(const string &sessionID) {
    return activeSessions.find(sessionID) != activeSessions.end(); // Check if session ID is valid
}

// Function to initialize OpenSSL
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Function to clean up OpenSSL
void cleanup_openssl() {
    EVP_cleanup();
}

// Function to create an SSL context
// SSL_CTX *create_context() {
//     const SSL_METHOD *method;
//     SSL_CTX *ctx;

//     method = SSLv23_server_method(); // Server method
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

    method = TLS_server_method();  // Server-side SSL/TLS method
    ctx = SSL_CTX_new(method);

    if (!ctx) {
        std::cerr << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// Function to configure SSL context
// void configure_context(SSL_CTX *ctx) {
//     // Set the key and cert for SSL
//     if (SSL_CTX_use_certificate_file(ctx, "bank_cert.pem", SSL_FILETYPE_PEM) <= 0) {
//         ERR_print_errors_fp(stderr);
//         exit(EXIT_FAILURE);
//     }
//     if (SSL_CTX_use_PrivateKey_file(ctx, "bank_key.pem", SSL_FILETYPE_PEM) <= 0) {
//         ERR_print_errors_fp(stderr);
//         exit(EXIT_FAILURE);
//     }
// }

void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "bank_server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "bank_server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

// Function to hash passwords using SHA-256
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

// Function to handle client requests
void handleClientRequest(SSL *ssl) {
    char buffer[1024] = {0};
    int valread;

    while ((valread = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
        string command(buffer);
        memset(buffer, 0, sizeof(buffer));
        string response;

        // Handle REGISTER command
        if (command == "REGISTER") {
            // Read username and password
            valread = SSL_read(ssl, buffer, sizeof(buffer)); // Read user data
            stringstream ss(buffer);
            string username, hashedPassword;
            ss >> username >> hashedPassword;

            // Check if username already exists
            if (userDatabase.find(username) != userDatabase.end()) {
                response = "Username already exists!";
            } else {
                double initialBalance = 0.0; // Set initial balance to 0
                userDatabase[username] = hashedPassword; // Store hashed password
                userBalances[username] = initialBalance; // Store balance
                saveUserToDatabase(username, hashedPassword, initialBalance, "user_database.csv");
                response = "Registration successful!";
            }
        }
        // Handle LOGIN command
        else if (command == "LOGIN") {
            // Read username and password
            valread = SSL_read(ssl, buffer, sizeof(buffer)); // Read user data
            stringstream ss(buffer);
            string username, hashedPassword;
            ss >> username >> hashedPassword;

            // Check if username exists and password matches
            if (userDatabase.find(username) != userDatabase.end() &&
                userDatabase[username] == hashedPassword) {
                string sessionID = createSession(username);
                response = "Login successful! SessionID: " + sessionID;
            } else {
                response = "Invalid username or password!";
            }
        }
        // Handle CHECK_BALANCE command
        else if (command == "CHECK_BALANCE") {
            // Read session ID
            valread = SSL_read(ssl, buffer, sizeof(buffer));
            string sessionID(buffer);

            // Validate session ID
            if (validateSession(sessionID)) {
                string username = activeSessions[sessionID];
                double balance = userBalances[username];
                response = "Current balance: $" + to_string(balance);
            } else {
                response = "Invalid session!";
            }
        }
        // Handle DEPOSIT command
        else if (command == "DEPOSIT") {
            // Read session ID and amount
            valread = SSL_read(ssl, buffer, sizeof(buffer));
            stringstream ss(buffer);
            string sessionID;
            double amount;
            ss >> sessionID >> amount;

            // Validate session ID
            if (validateSession(sessionID)) {
                string username = activeSessions[sessionID];
                userBalances[username] += amount; // Update balance
                response = "Deposited $" + to_string(amount) + ". New balance: $" + to_string(userBalances[username]);
                updateUserDatabase("user_database.csv"); // Update the user database file
            } else {
                response = "Invalid session!";
            }
        }
        // Handle WITHDRAW command
        else if (command == "WITHDRAW") {
            // Read session ID and amount
            valread = SSL_read(ssl, buffer, sizeof(buffer));
            stringstream ss(buffer);
            string sessionID;
            double amount;
            ss >> sessionID >> amount;

            // Validate session ID
            if (validateSession(sessionID)) {
                string username = activeSessions[sessionID];
                if (userBalances[username] >= amount) {
                    userBalances[username] -= amount; // Update balance
                    response = "Withdrew $" + to_string(amount) + ". New balance: $" + to_string(userBalances[username]);
                    updateUserDatabase("user_database.csv"); // Update the user database file
                } else {
                    response = "Insufficient funds!";
                }
            } else {
                response = "Invalid session!";
            }
        }
        // Handle LOGOUT command
        else if (command == "LOGOUT") {
            // Read session ID
            valread = SSL_read(ssl, buffer, sizeof(buffer));
            string sessionID(buffer);

            // Validate session ID
            if (validateSession(sessionID)) {
                activeSessions.erase(sessionID); // Remove the session
                response = "Logged out successfully!";
            } else {
                response = "Invalid session!";
            }
        }
        // Send the response back to the client
        SSL_write(ssl, response.c_str(), response.length());
        memset(buffer, 0, sizeof(buffer)); // Clear buffer for next command
    }
}

// Main function for the bank server
int main() {
    init_openssl();
    SSL_CTX *ctx = create_context();
    configure_context(ctx);

    // Load user data
    loadUserDatabase("user_database.csv");

    // Create a socket and listen for connections
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    // Set socket options
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080); // Use port 443 for SSL

    // Bind and listen
    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 3);

    cout << "Bank server is running on port 8080..." << endl;

    // Main server loop to accept and handle connections
    while (true) {
        int client_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        // SSL *ssl = SSL_new(ctx);
        // SSL_set_fd(ssl, client_fd);

        // if (SSL_accept(ssl) <= 0) {
        //     ERR_print_errors_fp(stderr);
        // } else {
        //     handleClientRequest(ssl); // Handle requests
        // }

        // SSL_shutdown(ssl);
        // SSL_free(ssl);
        // close(client_fd);
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);  // client_socket_fd is the accepted socket

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            // std::cout << "SSL connection established!" << std::endl;
            // // Use SSL_write and SSL_read instead of send/recv
            // SSL_write(ssl, message, strlen(message));
            handleClientRequest(ssl);
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }

    // Cleanup
    close(server_fd);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}
