#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <arpa/inet.h>  // For inet_pton
#include <sys/socket.h> // For socket functions
#include <netinet/in.h> // For sockaddr_in
#include <unistd.h>     // For close

using namespace std;

string sessionID; // Store session ID on the client side

// Function to register a new user
void registerUser(int sock) {
    string username, password;
    cout << "Enter new username: ";
    cin >> username;
    cout << "Enter new password: ";
    cin >> password;

    // Send register command
    send(sock, "REGISTER", strlen("REGISTER"), 0);
    sleep(1); // Short delay to prevent overlap
    send(sock, (username + " " + password).c_str(), username.length() + password.length() + 1, 0);

    char buffer[1024] = {0};
    read(sock, buffer, sizeof(buffer)); // Read server response

    cout << "Server: " << buffer << endl;
}

// Function to log in and receive session ID from server
void loginUser(int sock) {
    string username, password;
    cout << "Enter username: ";
    cin >> username;
    cout << "Enter password: ";
    cin >> password;

    // Send login command
    send(sock, "LOGIN", strlen("LOGIN"), 0);
    sleep(1); // Short delay to prevent overlap
    send(sock, (username + " " + password).c_str(), username.length() + password.length() + 1, 0);

    char buffer[1024] = {0};
    read(sock, buffer, sizeof(buffer)); // Read session ID from server

    string response(buffer);
    if (response.find("SessionID:") != string::npos) {
        sessionID = response.substr(response.find("SessionID:") + 10);
        cout << "Logged in successfully. Session ID: " << sessionID << endl;
    } else {
        cout << "Login failed: " << response << endl;
    }
}

// Function to check balance
void checkBalance(int sock) {
    if (sessionID.empty()) {
        cout << "You are not logged in!" << endl;
        return;
    }

    send(sock, "CHECK_BALANCE", strlen("CHECK_BALANCE"), 0);
    sleep(1);
    send(sock, sessionID.c_str(), sessionID.length(), 0);

    char buffer[1024] = {0};
    read(sock, buffer, sizeof(buffer)); // Read response from server
    cout << "Server response: " << buffer << endl;
}

// Function to deposit money
void deposit(int sock) {
    if (sessionID.empty()) {
        cout << "You are not logged in!" << endl;
        return;
    }

    double amount;
    cout << "Enter amount to deposit: ";
    cin >> amount;

    string command = "DEPOSIT";
    send(sock, command.c_str(), command.length(), 0);
    sleep(1);
    send(sock, (sessionID + " " + to_string(amount)).c_str(), sessionID.length() + to_string(amount).length() + 1, 0);

    char buffer[1024] = {0};
    read(sock, buffer, sizeof(buffer)); // Read response from server
    cout << "Server response: " << buffer << endl;
}

// Function to withdraw money
void withdraw(int sock) {
    if (sessionID.empty()) {
        cout << "You are not logged in!" << endl;
        return;
    }

    double amount;
    cout << "Enter amount to withdraw: ";
    cin >> amount;

    string command = "WITHDRAW";
    send(sock, command.c_str(), command.length(), 0);
    sleep(1);
    send(sock, (sessionID + " " + to_string(amount)).c_str(), sessionID.length() + to_string(amount).length() + 1, 0);

    char buffer[1024] = {0};
    read(sock, buffer, sizeof(buffer)); // Read response from server
    cout << "Server response: " << buffer << endl;
}

// Main function to handle user input
int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        cerr << "Socket creation failed" << endl;
        return 1;
    }

    sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(8080); // Port number

    // Convert IP address from text to binary
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        cerr << "Invalid address/ Address not supported" << endl;
        return 1;
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        cerr << "Connection failed" << endl;
        return 1;
    }

    int choice;
    do {
        cout << "1. Register" << endl;
        cout << "2. Login" << endl;
        cout << "3. Check Balance" << endl;
        cout << "4. Deposit" << endl;
        cout << "5. Withdraw" << endl;
        cout << "6. Exit" << endl;
        cout << "Enter your choice: ";
        cin >> choice;

        switch (choice) {
            case 1:
                registerUser(sock);
                break;
            case 2:
                loginUser(sock);
                break;
            case 3:
                checkBalance(sock);
                break;
            case 4:
                deposit(sock);
                break;
            case 5:
                withdraw(sock);
                break;
            case 6:
                cout << "Exiting..." << endl;
                break;
            default:
                cout << "Invalid choice. Please try again." << endl;
        }
    } while (choice != 6);

    close(sock);
    return 0;
}
