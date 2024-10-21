#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <unordered_map>
#include <arpa/inet.h>  // For inet_pton
#include <sys/socket.h> // For socket functions
#include <netinet/in.h> // For sockaddr_in
#include <unistd.h>     // For close
#include <ctime>
#include <cstdlib>

using namespace std;

unordered_map<string, string> activeSessions; // Store sessionID -> accountID
unordered_map<string, string> userDatabase;   // Store username -> password
unordered_map<string, double> userBalances;    // Store accountID -> balance

// Load user database from CSV file
void loadUserDatabase(const string& filename) {
    ifstream file(filename);
    string line, username, password;

    while (getline(file, line)) {
        stringstream ss(line);
        getline(ss, username, ',');
        getline(ss, password, ',');
        userDatabase[username] = password;
        userBalances[username] = 0.0; // Initialize balance
    }
    file.close();
}

// Save user data to CSV file
void saveUserToDatabase(const string& username, const string& password, const string& filename) {
    ofstream file;
    file.open(filename, ios::app); // Open in append mode
    file << username << "," << password << "\n";
    file.close();
}

// Generate a unique session ID
string generateSessionID() {
    string sessionID;
    srand(time(0)); // Seed for randomness
    for (int i = 0; i < 16; ++i) { // Generate a 16-character session ID
        sessionID += 'A' + rand() % 26;
    }
    return sessionID;
}

// Create a new session for a client
string createSession(const string& accountID) {
    string sessionID = generateSessionID();
    activeSessions[sessionID] = accountID;
    cout << "Session created: " << sessionID << endl;
    return sessionID;
}

// Validate session
bool validateSession(const string& sessionID) {
    return activeSessions.find(sessionID) != activeSessions.end();
}

// Function to handle client requests
void handleClientRequest(int client_sock) {
    char buffer[1024] = {0};
    int valread;

    while ((valread = read(client_sock, buffer, sizeof(buffer))) > 0) {
        string command(buffer);
        memset(buffer, 0, sizeof(buffer)); // Clear buffer for next read
        string response;

        if (command == "REGISTER") {
            string username, password;
            valread = read(client_sock, buffer, sizeof(buffer)); // Read registration credentials
            stringstream ss(buffer);
            ss >> username >> password;

            if (userDatabase.find(username) != userDatabase.end()) {
                response = "Username already exists.";
            } else {
                saveUserToDatabase(username, password, "users.csv");
                userDatabase[username] = password; // Add to in-memory database
                response = "Registration successful";
            }

        } else if (command == "LOGIN") {
            string username, password;
            valread = read(client_sock, buffer, sizeof(buffer)); // Read login credentials
            stringstream ss(buffer);
            ss >> username >> password;

            if (userDatabase.find(username) != userDatabase.end() && userDatabase[username] == password) {
                string sessionID = createSession(username);
                response = "Login successful. SessionID: " + sessionID;
            } else {
                response = "Invalid username or password";
            }

        } else if (command == "REQUEST") {
            valread = read(client_sock, buffer, sizeof(buffer)); // Read session ID
            string sessionID(buffer);

            if (validateSession(sessionID)) {
                response = "Request processed successfully!";
            } else {
                response = "Invalid session. Please log in.";
            }
        } else if (command == "CHECK_BALANCE") {
            valread = read(client_sock, buffer, sizeof(buffer)); // Read session ID
            string sessionID(buffer);

            if (validateSession(sessionID)) {
                string accountID = activeSessions[sessionID];
                response = "Your balance is: $" + to_string(userBalances[accountID]);
            } else {
                response = "Invalid session. Please log in.";
            }
        } else if (command == "DEPOSIT") {
            valread = read(client_sock, buffer, sizeof(buffer)); // Read session ID
            stringstream ss(buffer);
            string sessionID;
            double amount;
            ss >> sessionID >> amount;

            if (validateSession(sessionID)) {
                string accountID = activeSessions[sessionID];
                userBalances[accountID] += amount;
                response = "Deposited $" + to_string(amount) + ". New balance: $" + to_string(userBalances[accountID]);
            } else {
                response = "Invalid session. Please log in.";
            }
        } else if (command == "WITHDRAW") {
            valread = read(client_sock, buffer, sizeof(buffer)); // Read session ID
            stringstream ss(buffer);
            string sessionID;
            double amount;
            ss >> sessionID >> amount;

            if (validateSession(sessionID)) {
                string accountID = activeSessions[sessionID];
                if (userBalances[accountID] >= amount) {
                    userBalances[accountID] -= amount;
                    response = "Withdrew $" + to_string(amount) + ". New balance: $" + to_string(userBalances[accountID]);
                } else {
                    response = "Insufficient funds.";
                }
            } else {
                response = "Invalid session. Please log in.";
            }
        } else {
            response = "Unknown command.";
        }

        send(client_sock, response.c_str(), response.length(), 0);
        cout << "Sent response: " << response << endl;
        memset(buffer, 0, sizeof(buffer)); // Clear buffer for next command
    }

    if (valread == 0) {
        cout << "Client disconnected." << endl;
    } else if (valread < 0) {
        perror("Read failed");
    }
}

// Main function to start the server
int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    
    // Load the user database from CSV file
    loadUserDatabase("users.csv");

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Define the server address
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);

    // Bind the socket to the network
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    cout << "Server is listening on port 8080" << endl;

    // Accept and handle client connections
    while (true) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("Accept failed");
            exit(EXIT_FAILURE);
        }

        // Handle client request in a separate function
        handleClientRequest(new_socket);
        close(new_socket); // Close the connection after handling
    }

    return 0;
}
