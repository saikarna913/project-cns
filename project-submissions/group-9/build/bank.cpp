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
#include <filesystem> // For checking file existence
#include "secret_key.h" // Include the header file with the secret key
#include "encryption.h"

const char* CERT_FILE = "server.crt";
const char* KEY_FILE = "server.key";
const char* CA_FILE = "ca.crt";

std::mutex authFileMutex;
std::map<std::string, double> accountBalances;
std::map<std::string, std::string> accountPins;

int PORT = 3000; // Default port
std::string authFileName = "bank.auth"; // Default auth file name

// Function declarations
std::string generateHMAC(const std::string& message);
bool verifyHMAC(const std::string& message, const std::string& receivedHmac);
void readAuthFile(const std::string& authFile);
void createAccount(const std::string& accountNumber, double initialBalance, const std::string& pin);
bool verifyPin(const std::string& accountNumber, const std::string& inputPin);
SSL_CTX* InitServerCTX();
void handleClient(SSL* ssl);
void signalHandler(int signum);
int parseCommandLineArguments(int argc, char* argv[]);

// Main function
int main(int argc, char* argv[]) {
    // Parse command line arguments
    if (parseCommandLineArguments(argc, argv) != 0) {
        return 255; // Exit on argument parse failure
    }

    // Check if auth file exists
    if (std::filesystem::exists(authFileName)) {
        std::cerr << "Error: Auth file already exists." << std::endl;
        return 255; // Exit if the auth file already exists
    }

    // Create the auth file
    std::ofstream authFile(authFileName);
    if (!authFile) {
        std::cerr << "Error: Unable to create auth file." << std::endl;
        return 255; // Exit on failure to create file
    }
    encryptFile(authFileName);
    authFile.close();
    std::cout << "created" << std::endl; // Print confirmation

    // SSL setup
    SSL_CTX* ctx = InitServerCTX();
    
    // Signal handling for graceful exit
    signal(SIGTERM, signalHandler);

    // Socket setup and listening...
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Attaching socket to the port
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Binding the socket to the specified port
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Start listening for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    // Accept clients in a loop
    while (true) {
        std::cout << "Waiting for connections..." << std::endl;
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        // SSL connection handling
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, new_socket);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            handleClient(ssl);
        }

        // Clean up
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(new_socket);
    }

    // Clean up
    close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}

// Function implementations

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

bool verifyHMAC(const std::string& message, const std::string& receivedHmac) {
    std::string computedHmac = generateHMAC(message);
    return computedHmac == receivedHmac;
}

void readAuthFile(const std::string& authFile) {
    std::lock_guard<std::mutex> lock(authFileMutex);
    std::ifstream infile(authFile);
    std::string line;

    decryptFile(authFile);

    while (std::getline(infile, line)) {
        std::string accountNumber = line.substr(0, line.find(','));
        std::string pin = line.substr(line.find(',') + 1);
        accountPins[accountNumber] = pin; // Store the PIN
        accountBalances[accountNumber] = 0.0; // Initialize balance to zero
    }

    encryptFile(authFile);
}

void createAccount(const std::string& accountNumber, double initialBalance, const std::string& pin) {
    std::lock_guard<std::mutex> lock(authFileMutex);

    if (accountBalances.find(accountNumber) != accountBalances.end()) {
        std::cerr << "Account already exists." << std::endl;
        return; // Do not exit, just return
    }

    decryptFile(authFileName);

    accountBalances[accountNumber] = initialBalance;
    accountPins[accountNumber] = pin;

    std::ofstream authFile(authFileName, std::ios::app);
    if (authFile.is_open()) {
        authFile << accountNumber << "," << pin << std::endl; // Save account and PIN
        authFile.close();
    } else {
        std::cerr << "Failed to open auth file for writing." << std::endl;
    }

    encryptFile(authFileName);

    std::cout << "Account " << accountNumber << " created successfully with initial balance: " << initialBalance << std::endl;
}

bool verifyPin(const std::string& accountNumber, const std::string& inputPin) {
    auto it = accountPins.find(accountNumber);
    if (it != accountPins.end()) {
        return it->second == inputPin;
    }
    return false;
}

SSL_CTX* InitServerCTX() {
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = TLS_server_method();
    ctx = SSL_CTX_new(method);

    if (ctx == nullptr) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    if (!SSL_CTX_load_verify_locations(ctx, CA_FILE, nullptr)) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_verify_depth(ctx, 1);

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
            std::string receivedHmac = requestJson["hmac"].asString();
            requestJson.removeMember("hmac");

            std::string messageForHMAC = Json::writeString(Json::StreamWriterBuilder(), requestJson);
            if (verifyHMAC(messageForHMAC, receivedHmac)) {
                std::cout << "HMAC verification successful." << std::endl;
                std::string operation = requestJson["operation"].asString();
                std::string account = requestJson["account"].asString();
                std::string pin = requestJson["pin"].asString();
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
                            responseJson["status"] = "success";
                            responseJson["message"] = "Deposit successful.";
                        } else if (operation == "withdraw") {
                            if (accountBalances[account] >= amount) {
                                accountBalances[account] -= amount;
                                responseJson["status"] = "success";
                                responseJson["message"] = "Withdrawal successful.";
                            } else {
                                responseJson["status"] = "failed";
                                responseJson["message"] = "Insufficient balance.";
                            }
                        } else if (operation == "get_balance") {
                            responseJson["status"] = "success";
                            responseJson["balance"] = accountBalances[account];
                        }
                    } else {
                        responseJson["status"] = "failed";
                        responseJson["message"] = "Invalid PIN.";
                    }
                } else {
                    responseJson["status"] = "failed";
                    responseJson["message"] = "Invalid operation.";
                }

                // Send JSON response
                Json::StreamWriterBuilder writer;
                std::string responseMessage = Json::writeString(writer, responseJson);
                SSL_write(ssl, responseMessage.c_str(), responseMessage.size());
            } else {
                std::cerr << "HMAC verification failed." << std::endl;
            }
        } else {
            std::cerr << "Failed to parse JSON request." << std::endl;
        }
    }
}

void signalHandler(int signum) {
    std::cout << "Caught signal " << signum << ", exiting gracefully." << std::endl;
    // Perform cleanup if necessary
    exit(signum);
}

int parseCommandLineArguments(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-p" && i + 1 < argc) { // Change from "-port" to "-p"
            PORT = std::stoi(argv[++i]);
        } else if (arg == "-s" && i + 1 < argc) { // Change from "-auth" to "-s"
            authFileName = argv[++i];
        } else {
            std::cerr << "Invalid argument: " << arg << std::endl;
            return -1; // Indicate parsing error
        }
    }
    return 0; // Indicate success
}
