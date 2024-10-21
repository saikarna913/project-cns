#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <fstream>
#include <string>
#include <unordered_map>
#include <sstream>
#include <arpa/inet.h>
#include <thread>
#include <mutex> 
#include <random>

using namespace std;

// Globals
unordered_map<string, string> user_database;
unordered_map<string, double> user_balances;
unordered_map<string, string> active_sessions;
mutex session_mutex, db_mutex;

// Function to load user database from a file
void loaduser_database(const string &filename) {
    ifstream file(filename);
    if (!file.is_open()) {
        cerr << "Error opening file: " << filename << endl;
        return;
    }
    
    string line, username, password;
    double balance;
    
    while (getline(file, line)) {
        stringstream ss(line);
        getline(ss, username, ',');
        getline(ss, password, ',');
        ss >> balance;
        user_database[username] = password;
        user_balances[username] = balance; // Load balance from file
    }
    file.close();
}

// Function to save a new user to the database
void saveUserToDatabase(const string &username, const string &password, double balance, const string &filename) {
    ofstream file(filename, ios::app);
    if (!file.is_open()) {
        cerr << "Error opening file: " << filename << endl;
        return;
    }
    file << username << "," << password << "," << balance << "\n"; // Save balance in CSV
    file.close();
}

// Function to update the user database file
void updateuser_database(const string &filename) {
    ofstream file(filename);
    if (!file.is_open()) {
        cerr << "Error opening file: " << filename << endl;
        return;
    }
    
    for (const auto &pair : user_database) {
        string username = pair.first;
        string password = pair.second;
        double balance = user_balances[username];
        file << username << "," << password << "," << balance << "\n"; // Update balance
    }
    file.close();
}

// Helper functions
string hash_password(const string &password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)password.c_str(), password.size(), hash);

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << hex << (int)hash[i];
    }
    return ss.str();
}

string generate_session_id() {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "abcdefghijklmnopqrstuvwxyz"
                           "0123456789"
                           "!@#$%^&*()-_=+[]{};:,.<>?";
    random_device rd; // Seed for random number generator
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, sizeof(charset) - 2); // Last character is null terminator

    string session_id;
    for (int i = 0; i < 32; i++) { // Increased length to 32 characters
        session_id += charset[dis(gen)];
    }
    return session_id;
}

// Function to create a session and store it
string createSession(const string &accountID) {
    string sessionID = generate_session_id();
    active_sessions[sessionID] = accountID; // Store session ID and account mapping
    cout << "Session created: " << sessionID << endl;
    return sessionID;
}

bool validate_session(const string &session_id) {
    lock_guard<mutex> lock(session_mutex);
    return active_sessions.find(session_id) != active_sessions.end();
}

void handle_client_request(SSL *ssl) {
    char buffer[1024] = {0};
    while (SSL_read(ssl, buffer, sizeof(buffer)) > 0) {
        string command = string(buffer);
        string response;

        memset(buffer, 0, sizeof(buffer)); // Clear buffer before reading again

        if (command == "REGISTER") {
            SSL_read(ssl, buffer, sizeof(buffer));
            stringstream ss(buffer);
            string username, hashed_password;
            ss >> username >> hashed_password;

            lock_guard<mutex> lock(db_mutex);
            if (user_database.find(username) != user_database.end()) {
                response = "Username already exists!";
            } else {
                user_database[username] = hashed_password;
                user_balances[username] = 0.0; // Initial balance
                response = "Registration successful!";
                saveUserToDatabase(username, hashed_password, user_balances[username], "user_database.csv");
            }

        } else if (command == "LOGIN") {
            SSL_read(ssl, buffer, sizeof(buffer));
            stringstream ss(buffer);
            string username, hashed_password;
            ss >> username >> hashed_password;

            lock_guard<mutex> lock(db_mutex);
            if (user_database.find(username) != user_database.end() && user_database[username] == hashed_password) {
                string sessionID = createSession(username);
                response = "Login successful! SessionID: " + sessionID;
            } else {
                response = "Invalid username or password!";
            }

        } else if (command == "CHECK_BALANCE") {
            SSL_read(ssl, buffer, sizeof(buffer));
            string session_id(buffer);
            if (validate_session(session_id)) {
                lock_guard<mutex> lock(db_mutex);
                string username = active_sessions[session_id];
                response = "Current balance: $" + to_string(user_balances[username]);
            } else {
                response = "Invalid session!";
            }

        } else if (command == "DEPOSIT") {
            SSL_read(ssl, buffer, sizeof(buffer));
            stringstream ss(buffer);
            string session_id;
            double amount;
            ss >> session_id >> amount;

            if (validate_session(session_id)) {
                lock_guard<mutex> lock(db_mutex);
                string username = active_sessions[session_id];
                user_balances[username] += amount;
                response = "Deposited $" + to_string(amount) + ". New balance: $" + to_string(user_balances[username]);
                updateuser_database("user_database.csv");
            } else {
                response = "Invalid session!";
            }

        } else if (command == "WITHDRAW") {
            SSL_read(ssl, buffer, sizeof(buffer));
            stringstream ss(buffer);
            string session_id;
            double amount;
            ss >> session_id >> amount;

            if (validate_session(session_id)) {
                lock_guard<mutex> lock(db_mutex);
                string username = active_sessions[session_id];
                if (user_balances[username] >= amount) {
                    user_balances[username] -= amount;
                    response = "Withdrew $" + to_string(amount) + ". New balance: $" + to_string(user_balances[username]);
                    updateuser_database("user_database.csv");
                } else {
                    response = "Insufficient funds!";
                }
            } else {
                response = "Invalid session!";
            }

        } else if (command == "LOGOUT") {
            SSL_read(ssl, buffer, sizeof(buffer));
            string session_id(buffer);

            if (validate_session(session_id)) {
                lock_guard<mutex> lock(session_mutex);
                active_sessions.erase(session_id);
                response = "Logged out successfully!";
            } else {
                response = "Invalid session!";
            }
        }

        SSL_write(ssl, response.c_str(), response.size());
        memset(buffer, 0, sizeof(buffer)); // Clear buffer
    }
}

int main() {
    // Initialize SSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());

    // Load server certificate and private key
    if (!SSL_CTX_use_certificate_file(ctx, "bank_cert.pem", SSL_FILETYPE_PEM) ||
        !SSL_CTX_use_PrivateKey_file(ctx, "bank_key.pem", SSL_FILETYPE_PEM)) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // Load CA certificates to verify clients
    if (!SSL_CTX_load_verify_locations(ctx, "ca_cert.pem", NULL)) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    loaduser_database("user_database.csv");
    
    // Setup socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8088);
    if (::bind(server_fd, (sockaddr *)&address, sizeof(address)) < 0) {
    cerr << "Bind failed" << endl;
    return 1;
}

    listen(server_fd, 5);

    cout << "Bank server is running on port 8088..." << endl;

    while (true) {
        int client_fd = accept(server_fd, NULL, NULL);
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            thread(handle_client_request, ssl).detach();
        }
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    // EVP_cleanup();
    return 0;
}
