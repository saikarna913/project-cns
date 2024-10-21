// atm.cpp
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <json/json.h>  // Requires the JsonCpp library
#include <cstring>

const char* DEFAULT_IP = "127.0.0.1";
const int DEFAULT_PORT = 3000;

void sendRequest(Json::Value& request, const char* ip, int port);

int main(int argc, char* argv[]) {
    std::string account;
    std::string operation;
    double amount = 0.0;
    int port = DEFAULT_PORT;
    const char* ip = DEFAULT_IP;

    // Parsing command-line options
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            account = argv[++i];
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            operation = "create";
            amount = atof(argv[++i]);
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            operation = "deposit";
            amount = atof(argv[++i]);
        } else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            operation = "withdraw";
            amount = atof(argv[++i]);
        } else if (strcmp(argv[i], "-g") == 0) {
            operation = "get_balance";
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            ip = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        }
    }

    if (account.empty() || operation.empty()) {
        std::cerr << "Missing required parameters" << std::endl;
        return 255;
    }

    // Create JSON request
    Json::Value request;
    request["account"] = account;
    request["operation"] = operation;
    if (operation == "create" || operation == "deposit" || operation == "withdraw") {
        request["amount"] = amount;
    }

    // Send request to the bank server
    sendRequest(request, ip, port);

    return 0;
}

void sendRequest(Json::Value& request, const char* ip, int port) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Socket creation error" << std::endl;
        return;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address/ Address not supported" << std::endl;
        return;
    }

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection failed" << std::endl;
        return;
    }

    // Send JSON request
    Json::StreamWriterBuilder writer;
    std::string jsonRequest = Json::writeString(writer, request);
    // std::cout << "JSON Request: " << jsonRequest << std::endl; // Debug output
    send(sock, jsonRequest.c_str(), jsonRequest.length(), 0);

    // Receive response
    read(sock, buffer, 1024);
    std::cout << "Response from bank: " << buffer << std::endl;

    close(sock);
}
