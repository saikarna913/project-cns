// bank.cpp
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <cstring>
#include <json/json.h>  // Requires the JsonCpp library
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <csignal>

const int DEFAULT_PORT = 3000;
std::string authFile = "bank.auth";
bool running = true;

struct Account {
    std::string accountName;
    double balance;
};

// Accounts database
std::unordered_map<std::string, Account> accounts;

void handleClient(int clientSocket);
void createAuthFile();
void sigtermHandler(int signum);

int main(int argc, char* argv[]) {
    // Parse command-line arguments
    int port = DEFAULT_PORT;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            authFile = argv[++i];
        }
    }

    // Create auth file
    createAuthFile();

    // Setup SIGTERM handler
    signal(SIGTERM, sigtermHandler);

    // Setup TCP server
    int serverSocket, clientSocket;
    struct sockaddr_in serverAddr, clientAddr;
    socklen_t addr_size;

    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        std::cerr << "Failed to create socket" << std::endl;
        exit(255);
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Binding failed" << std::endl;
        exit(255);
    }

    if (listen(serverSocket, 10) == 0) {
        std::cout << "Bank server listening on port " << port << std::endl;
    } else {
        std::cerr << "Error in listen" << std::endl;
        exit(255);
    }

    while (running) {
        addr_size = sizeof(clientAddr);
        clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &addr_size);
        if (clientSocket < 0) {
            std::cerr << "Error accepting connection" << std::endl;
            continue;
        }
        handleClient(clientSocket);
    }

    close(serverSocket);
    return 0;
}

void handleClient(int clientSocket) {
    char buffer[1024];
    recv(clientSocket, buffer, 1024, 0);
    
    // Process request (example: create account, deposit, etc.)
    std::string request(buffer);
    // std::cout << "Received Request: " << request << std::endl; // Debug output
    Json::Reader reader;
    Json::Value requestData;
    if (!reader.parse(request, requestData)) {
        std::cerr << "Invalid JSON request" << std::endl;
        close(clientSocket);
        return;
    }

    std::string operation = requestData["operation"].asString();
    std::string accountName = requestData["account"].asString();

    Json::Value response;
    if (operation == "create") {
        double initialBalance = requestData["amount"].asDouble();
        if (accounts.find(accountName) != accounts.end()) {
            response["error"] = "Account already exists";
        } else if (initialBalance < 10) {
            response["error"] = initialBalance;
            response["error"] = "Initial balance must be >= 10";
        } else {
            accounts[accountName] = {accountName, initialBalance};
            response["account"] = accountName;
            response["initial_balance"] = initialBalance;
        }
    } else if (operation == "deposit") {
        double amount = requestData["amount"].asDouble();
        if (accounts.find(accountName) == accounts.end()) {
            response["error"] = "Account does not exist";
        } else if (amount < 0) { // Check for negative deposit
            std::cerr << "Invalid deposit amount" << std::endl;
            response["error"] = "Cannot deposit negative amount";
            close(clientSocket);
            exit(255);  // Exit with status 255
        } else {
            accounts[accountName].balance += amount;
            response["account"] = accountName;
            response["deposit"] = amount;
        }
    } else if (operation == "withdraw") {
        double amount = requestData["amount"].asDouble();
        if (accounts.find(accountName) == accounts.end()) {
            response["error"] = "Account does not exist";
        } else if (amount < 0) {  // Check for negative withdrawal
            std::cerr << "Invalid withdrawal amount" << std::endl;
            response["error"] = "Cannot withdraw negative amount";
            close(clientSocket);
            exit(255);  // Exit with code 255 if negative amount is detected
        } else if (accounts[accountName].balance < amount) {
            response["error"] = "Insufficient funds";
        } else {
            accounts[accountName].balance -= amount;
            response["account"] = accountName;
            response["withdraw"] = amount;
        }
    } else if (operation == "get_balance") {
        if (accounts.find(accountName) == accounts.end()) {
            response["error"] = "Account does not exist";
        } else {
            response["account"] = accountName;
            response["amount"] = accounts[accountName].balance;
        }
    }

    // Send response
    Json::StreamWriterBuilder writer;
    std::string jsonResponse = Json::writeString(writer, response);
    send(clientSocket, jsonResponse.c_str(), jsonResponse.length(), 0);
    close(clientSocket);
}

void createAuthFile() {
    std::ifstream infile(authFile);
    if (infile.good()) {
        std::cerr << "Auth file already exists" << std::endl;
        exit(255);
    }
    std::ofstream outfile(authFile);
    outfile << "auth_token" << std::endl;  // Placeholder for actual authentication logic
    std::cout << "created" << std::endl;
    outfile.close();
}

void sigtermHandler(int signum) {
    std::cout << "Bank shutting down..." << std::endl;
    running = false;
}
