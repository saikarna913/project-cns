// bank_combined.cpp
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <json/json.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <map>
#include <mutex>
#include <csignal>
#include "secret_key.h"  // Include the header file with the secret key

const char* CERT_FILE = "server.crt";
const char* KEY_FILE = "server.key";
const char* CA_FILE = "ca.crt";

std::mutex authFileMutex; // Mutex to protect access to the auth file
std::map<std::string, double> accountBalances; // Map to hold account balances
std::map<std::string, std::string> accountPins; // Map to hold account PINs

int PORT = 3000; // Default port
std::string authFileName = "bank.auth"; // Default auth file name

// Function to generate HMAC for message integrity
std::string generateHMAC(const std::string& message) {
    unsigned char* hmacResult;
    unsigned int len = EVP_MAX_MD_SIZE;

    hmacResult = HMAC(EVP_sha256(), SECRET_KEY.c_str(), SECRET_KEY.size(), 
                      (unsigned char*)message.c_str(), message.size(), nullptr, &len);

    std::stringstream hmacHex;
    for (unsigned int i = 0; i < len; i++) {
        hmacHex << std::hex << std::setw(2) << std::setfill('0') << (int)hmacResult[i];
    }

    return hmacHex.str();
}

// Function to verify HMAC
bool verifyHMAC(const std::string& message, const std::string& receivedHmac) {
    std::string computedHmac = generateHMAC(message);
    return computedHmac == receivedHmac;
}

// Function to read authentication file
void readAuthFile(const std::string& authFile) {
    std::lock_guard<std::mutex> lock(authFileMutex); // Lock the mutex
    std::ifstream infile(authFile);
    std::string line;

    while (std::getline(infile, line)) {
        // Initialize accounts with PINs and balances from the auth file if needed
        std::string accountNumber = line.substr(0, line.find(','));
        std::string pin = line.substr(line.find(',') + 1);
        accountPins[accountNumber] = pin; // Store the PIN
        accountBalances[accountNumber] = 0.0; // Initialize balance to zero
    }
}

// Function to create a new account and store it in the auth file
void createAccount(const std::string& accountNumber, double initialBalance, const std::string& pin) {
    std::lock_guard<std::mutex> lock(authFileMutex);
    
    // Check if account already exists
    if (accountBalances.find(accountNumber) != accountBalances.end()) {
        std::cerr << "Card file already exists. Account creation not allowed." << std::endl;
        exit(EXIT_FAILURE); // Exit if account already exists
    }

    accountBalances[accountNumber] = initialBalance;
    accountPins[accountNumber] = pin; // Store the PIN

    // Append the new account to the auth file
    std::ofstream authFile(authFileName, std::ios::app);
    if (authFile.is_open()) {
        authFile << accountNumber << "," << pin << std::endl; // Save account and PIN
        authFile.close();
    } else {
        std::cerr << "Failed to open auth file for writing." << std::endl;
    }

    std::cout << "Account " << accountNumber << " created successfully with initial balance: " << initialBalance << std::endl;
}

// Function to verify PIN for transactions
bool verifyPin(const std::string& accountNumber, const std::string& inputPin) {
    auto it = accountPins.find(accountNumber);
    if (it != accountPins.end()) {
        return it->second == inputPin;
    }
    return false; // Account not found
}

// SSL initialization
SSL_CTX* InitServerCTX() {
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();      /* Bring in and register error messages */
    method = TLS_server_method();  /* Create new server-method instance */
    ctx = SSL_CTX_new(method);     /* Create new context */

    if (ctx == nullptr) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    /* Load server certificate */
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    /* Load server private key */
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    /* Load CA certificate file for client validation */
    if (!SSL_CTX_load_verify_locations(ctx, CA_FILE, nullptr)) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);  /* Enable peer verification */
    SSL_CTX_set_verify_depth(ctx, 1);  /* Set the verification depth */

    return ctx;
}

void handleClient(SSL* ssl) {
    char buffer[1024] = {0};
    int bytes = SSL_read(ssl, buffer, sizeof(buffer));

    if (bytes > 0) {
        std::string requestMessage(buffer, bytes);

        // Parse JSON request
        Json::Value requestJson;
        Json::Reader reader;
        if (reader.parse(requestMessage, requestJson)) {
            // Extract HMAC and validate
            std::string receivedHmac = requestJson["hmac"].asString();
            requestJson.removeMember("hmac"); // Remove HMAC for verification

            std::string messageForHMAC = Json::writeString(Json::StreamWriterBuilder(), requestJson);
            if (verifyHMAC(messageForHMAC, receivedHmac)) {
                std::cout << "HMAC verification successful." << std::endl; // Print success
                std::string operation = requestJson["operation"].asString();
                std::string account = requestJson["account"].asString();
                std::string pin = requestJson["pin"].asString(); // Receive PIN from ATM
                double amount = requestJson.isMember("amount") ? requestJson["amount"].asDouble() : 0.0;

                Json::Value responseJson;

                if (operation == "create") {
                    createAccount(account, amount, pin);
                    responseJson["status"] = "success";
                    responseJson["message"] = "Account created successfully.";
                } else if (operation == "deposit" || operation == "withdraw" || operation == "get_balance") {
                    if (verifyPin(account, pin)) {
                        if (operation == "deposit") {
                            accountBalances[account] += amount;
                            responseJson["message"] = "Deposit successful.";
                        } else if (operation == "withdraw") {
                            if (accountBalances[account] >= amount) {
                                accountBalances[account] -= amount;
                                responseJson["message"] = "Withdrawal successful.";
                            } else {
                                responseJson["status"] = "failed";
                                responseJson["message"] = "Insufficient funds.";
                            }
                        } else if (operation == "get_balance") {
                            responseJson["balance"] = accountBalances[account];
                        }
                        responseJson["status"] = "success";
                    } else {
                        std::cerr << "Invalid PIN." << std::endl; // Print error
                        responseJson["status"] = "failed";
                        responseJson["message"] = "Invalid PIN.";
                        exit(EXIT_FAILURE); // Exit on invalid PIN
                    }
                } else {
                    responseJson["status"] = "failed";
                    responseJson["message"] = "Unknown operation.";
                }

                // Add HMAC for the response
                responseJson["hmac"] = generateHMAC(Json::writeString(Json::StreamWriterBuilder(), responseJson));

                // Send response to ATM
                Json::StreamWriterBuilder writer;
                std::string responseString = Json::writeString(writer, responseJson);
                SSL_write(ssl, responseString.c_str(), responseString.size());
            } else {
                std::cerr << "HMAC verification failed." << std::endl; // Print failure
                // Send error response
                Json::Value errorResponse;
                errorResponse["status"] = "failed";
                errorResponse["message"] = "Invalid HMAC.";
                SSL_write(ssl, Json::writeString(Json::StreamWriterBuilder(), errorResponse).c_str(),
                          Json::writeString(Json::StreamWriterBuilder(), errorResponse).size());
            }
        } else {
            std::cerr << "Failed to parse request JSON." << std::endl;
            // Handle JSON parsing error
            Json::Value errorResponse;
            errorResponse["status"] = "failed";
            errorResponse["message"] = "Invalid JSON format.";
            SSL_write(ssl, Json::writeString(Json::StreamWriterBuilder(), errorResponse).c_str(),
                      Json::writeString(Json::StreamWriterBuilder(), errorResponse).size());
        }
    }
}

// Signal handler to exit cleanly
void signalHandler(int signum) {
    std::cout << "Exiting bank server." << std::endl;
    exit(0);
}

// Function to handle command-line arguments
void parseCommandLineArguments(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-p" && (i + 1) < argc) {
            PORT = std::stoi(argv[++i]); // Set the port
        } else if (arg == "-a" && (i + 1) < argc) {
            authFileName = argv[++i]; // Set the auth file
        }
    }
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler); // Register signal handler for clean exit
    parseCommandLineArguments(argc, argv); // Parse command-line arguments

    SSL_CTX* ctx = InitServerCTX(); // Initialize SSL context

    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attach socket to the port
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; // Bind to all interfaces
    address.sin_port = htons(PORT);

    // Bind the socket to the specified port
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Start listening for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    readAuthFile(authFileName); // Read the authentication file

    while (true) {
        std::cout << "Waiting for connections..." << std::endl;
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        SSL* ssl = SSL_new(ctx); // Create a new SSL structure for a connection
        SSL_set_fd(ssl, new_socket); // Bind the socket to the SSL structure

        if (SSL_accept(ssl) <= 0) { // Perform SSL handshake
            ERR_print_errors_fp(stderr);
        } else {
            handleClient(ssl); // Handle the client connection
        }

        SSL_shutdown(ssl); // Shut down the connection
        SSL_free(ssl); // Free the SSL structure
        close(new_socket); // Close the socket
    }

    close(server_fd); // Close server socket
    SSL_CTX_free(ctx); // Free the SSL context
    return 0;
}