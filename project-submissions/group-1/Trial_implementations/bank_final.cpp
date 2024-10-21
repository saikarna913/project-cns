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
#include <chrono>  // For timestamps
#include <iomanip> // For formatting the timestamp

using namespace std;

// Globals
unordered_map<string, string> user_database;
unordered_map<string, double> user_balances;
unordered_map<string, string> active_sessions;
mutex session_mutex, db_mutex;

std::string generate_random_key(size_t length) {
    const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string result;
    std::random_device rd;  // Random number generator
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> distribution(0, charset.size() - 1);

    for (size_t i = 0; i < length; ++i) {
        result += charset[distribution(generator)];
    }
    return result;
}
string get_transactions(const string &username)
{
    ifstream file("transaction_log.csv");
    if (!file.is_open())
    {
        return "255 - Error opening transaction log file!";
    }

    string line, response;
    while (getline(file, line))
    {
        stringstream ss(line);
        string user, timestamp, transaction_type;
        double amount;
        getline(ss, user, ',');
        getline(ss, timestamp, ',');
        getline(ss, transaction_type, ',');
        ss >> amount;

        if (user == username)
        {
            // Format the amount with 2 decimal places
            stringstream amount_ss;
            amount_ss << fixed << setprecision(2) << amount;

            response += timestamp + " | " + transaction_type + " | $" + amount_ss.str() + "\n";
        }
    }

    file.close();
    if (response.empty())
    {
        return "No transactions found for user: " + username;
    }

    return response;
}

void create_auth_file() {
    std::string key = generate_random_key(32);  // Generate a 32-character random key
    std::ofstream auth_file("auth_file.txt");   // Create or overwrite the auth file
    if (auth_file.is_open()) {
        auth_file << key;                        // Write the key to the file
        auth_file.close();
        std::cout << "Auth file created: " << key << std::endl;
    } else {
        std::cerr << " 255 - Failed to create auth file." << std::endl;
    }
}

// Function to read auth file
std::string read_auth_file(const std::string &filename) {
    std::ifstream auth_file(filename);
    std::string key;

    if (auth_file.is_open()) {
        std::getline(auth_file, key);
        auth_file.close();
    } else {
        std::cerr << " 255 - Failed to read auth file." << std::endl;
    }

    return key;
}
bool verify_auth_file(const std::string &client_auth_key) {
    // Read bank's auth file
    std::string bank_auth_key = read_auth_file("auth_file.txt");
    return client_auth_key == bank_auth_key;
}


void log_transaction(const string &username, const string &transaction_type, double amount = 0.0)
{
    // Open the transaction log file in append mode
    ofstream file("transaction_log.csv", ios::app);
    if (!file.is_open())
    {
        cerr << " 255 - Error opening transaction log file!" << endl;
        return;
    }

    // Get the current timestamp
    auto now = chrono::system_clock::now();
    time_t now_time = chrono::system_clock::to_time_t(now);
    tm local_tm = *localtime(&now_time);
    if (!(file << username << "," << put_time(&local_tm, "%Y-%m-%d %H:%M:%S")
               << "," << transaction_type << "," << fixed << setprecision(2) << amount << "\n"))
    {
        cerr << " 255 - Error writing to transaction log!" << endl; // Log any write errors
    }
    file.flush();

    file.close();
}

// Function to load user database from a file
void loaduser_database(const string &filename)
{
    ifstream file(filename);
    if (!file.is_open())
    {
        cerr << " 255 - Error opening file: " << filename << endl;
        return;
    }

    string line, username, password;
    double balance;

    while (getline(file, line))
    {
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
void saveUserToDatabase(const string &username, const string &password, double balance, const string &filename)
{
    ofstream file(filename, ios::app);
    if (!file.is_open())
    {
        cerr << " 255 - Error opening file: " << filename << endl;
        return;
    }
    file << username << "," << password << "," << balance << "\n"; // Save balance in CSV
    file.close();
}

// Function to update the user database file
void updateuser_database(const string &filename)
{
    ofstream file(filename);
    if (!file.is_open())
    {
        cerr << " 255 - Error opening file: " << filename << endl;
        return;
    }

    for (const auto &pair : user_database)
    {
        string username = pair.first;
        string password = pair.second;
        double balance = user_balances[username];
        file << username << "," << password << "," << balance << "\n"; // Update balance
    }
    file.close();
}

// Helper functions
string hash_password(const string &password)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)password.c_str(), password.size(), hash);

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << hex << (int)hash[i];
    }
    return ss.str();
}

string generate_session_id()
{
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    random_device rd; // Seed for random number generator
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 25);

    string session_id;
    for (int i = 0; i < 16; i++)
    {
        session_id += charset[dis(gen)];
    }
    return session_id;
}

// Function to create a session and store it
string createSession(const string &accountID)
{
    string sessionID = generate_session_id();
    active_sessions[sessionID] = accountID; // Store session ID and account mapping
    cout << "Session created: " << sessionID << endl;
    return sessionID;
}

bool validate_session(const string &session_id)
{
    lock_guard<mutex> lock(session_mutex);
    return active_sessions.find(session_id) != active_sessions.end();
}

void handle_client_request(SSL *ssl)
{
    char buffer[1024] = {0};
    while (SSL_read(ssl, buffer, sizeof(buffer)) > 0)
    {
        string command = string(buffer);
        string response;

        memset(buffer, 0, sizeof(buffer)); // Clear buffer before reading again

        // Inside handle_client_request function (Bank code)

        if (command == "REGISTER")
        {
            SSL_read(ssl, buffer, sizeof(buffer));
            stringstream ss(buffer);
            string username, hashed_password;
            double initial_balance;
            ss >> username >> hashed_password >> initial_balance; // Read initial balance

            lock_guard<mutex> lock(db_mutex);
            if (user_database.find(username) != user_database.end())
            {
                response = " 255 - Username already exists!";
            }
            else if (initial_balance < 10.0)
            { // Ensure the initial deposit is greater than $10
                response = " 255 - Initial deposit must be greater than/ equal to $10!";
            }
            else
            {
                user_database[username] = hashed_password;
                user_balances[username] = initial_balance; // Set the user's initial balance
                response = "Registration successful!";
                saveUserToDatabase(username, hashed_password, initial_balance, "user_database.csv");
            }
        }
        else if (command == "LOGIN")
        {
            SSL_read(ssl, buffer, sizeof(buffer));
            stringstream ss(buffer);
            string username, hashed_password;
            ss >> username >> hashed_password;

            lock_guard<mutex> lock(db_mutex);
            if (user_database.find(username) != user_database.end() && user_database[username] == hashed_password)
            {
                string sessionID = createSession(username);
                response = "Login successful! SessionID: " + sessionID;
            }
            else
            {
                response = " 255 - Invalid username or password!";
            }
        }
        else if (command == "CHECK_BALANCE")
        {
            SSL_read(ssl, buffer, sizeof(buffer));
            string session_id(buffer);
            if (validate_session(session_id))
            {
                lock_guard<mutex> lock(db_mutex);
                string username = active_sessions[session_id];
                double current_balance = user_balances[username];
                //updated code
                stringstream balance_stream;
                balance_stream << fixed << setprecision(2) << current_balance; // Format balance
                response = "Current balance: $" + balance_stream.str();
                // response = "Current balance: $" + to_string(current_balance);
                log_transaction(username, "CHECK_BALANCE", current_balance); // Include the current balance in the log
            }
            else
            {
                response = " 255 - Invalid session!";
            }
        }
        else if (command == "DEPOSIT")
        {
            SSL_read(ssl, buffer, sizeof(buffer));
            stringstream ss(buffer);
            string session_id;
            double amount;
            ss >> session_id >> amount;

            if (validate_session(session_id))
            {
                lock_guard<mutex> lock(db_mutex);
                string username = active_sessions[session_id];
                user_balances[username] += amount;
                stringstream amount_stream, balance_stream;
                amount_stream << fixed << setprecision(2) << amount; // Format amount
                balance_stream << fixed << setprecision(2) << user_balances[username]; // Format new balance
                response = "Deposited $" + amount_stream.str() + ". New balance: $" + balance_stream.str();
                //response = "Deposited $" + to_string(amount) + ". New balance: $" + to_string(user_balances[username]);
                updateuser_database("user_database.csv");
                log_transaction(username, "DEPOSIT", amount);
            }
            else
            {
                response = " 255 - Invalid session!";
            }
        }
        else if (command == "WITHDRAW")
        {
            SSL_read(ssl, buffer, sizeof(buffer));
            stringstream ss(buffer);
            string session_id;
            double amount;
            ss >> session_id >> amount;

            if (validate_session(session_id))
            {
                lock_guard<mutex> lock(db_mutex);
                string username = active_sessions[session_id];
                if (user_balances[username] >= amount)
                {
                    user_balances[username] -= amount;
                    stringstream amount_stream, balance_stream;
                    amount_stream << fixed << setprecision(2) << amount; // Format amount
                    balance_stream << fixed << setprecision(2) << user_balances[username]; // Format new balance
                    response = "Withdrew $" + amount_stream.str() + ". New balance: $" + balance_stream.str();
                    //response = "Withdrew $" + to_string(amount) + ". New balance: $" + to_string(user_balances[username]);
                    updateuser_database("user_database.csv");
                    log_transaction(username, "WITHDRAW", amount);
                }
                else
                {
                    response = " 255 - Insufficient funds!";
                }
            }
            else
            {
                response = " 255 - Invalid session!";
            }
        }else if (command == "VIEW_TRANSACTIONS")
        {
            SSL_read(ssl, buffer, sizeof(buffer));
            string session_id(buffer);
            if (validate_session(session_id))
            {
                lock_guard<mutex> lock(db_mutex);
                string username = active_sessions[session_id];
                response = get_transactions(username); // Fetch transactions
            }
            else
            {
                response = " 255 - Invalid session!";
            }
        }
        else if (command == "LOGOUT")
        {
            SSL_read(ssl, buffer, sizeof(buffer));
            string session_id(buffer);

            if (validate_session(session_id))
            {
                lock_guard<mutex> lock(session_mutex);
                active_sessions.erase(session_id);
                response = "Logged out successfully!";
            }
            else
            {
                response = " 255 - Invalid session!";
            }
        }

        SSL_write(ssl, response.c_str(), response.size());
        memset(buffer, 0, sizeof(buffer)); // Clear buffer
    }
}

int main()
{
    // Initialize SSL
   create_auth_file();
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());

    // Load server certificate and private key
    if (!SSL_CTX_use_certificate_file(ctx, "bank_cert.pem", SSL_FILETYPE_PEM) ||
        !SSL_CTX_use_PrivateKey_file(ctx, "bank_key.pem", SSL_FILETYPE_PEM))
    {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // Load CA certificates to verify clients
    if (!SSL_CTX_load_verify_locations(ctx, "ca_cert.pem", NULL))
    {
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
    address.sin_port = htons(8080);
    if (::bind(server_fd, (sockaddr *)&address, sizeof(address)) < 0)
    {
        cerr << " Bind failed" << endl;
        exit(255);
        return 1;
    }

    listen(server_fd, 5);

    cout << "Bank server is running on port 8080..." << endl;

    while (true){
    
        int client_fd = accept(server_fd, NULL, NULL);
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0)
        {
            ERR_print_errors_fp(stderr);
        }
       char buffer[256] = {0};
        int bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        buffer[bytes_read] = '\0'; // Null-terminate the buffer

        // Verify the received auth key against the one in auth_file.txt
        std::string atm_auth_key(buffer);
        // cout<<atm_auth_key;
        std::string bank_auth_key = read_auth_file("auth_file.txt"); // Read the bank's auth key
        // cout<<bank_auth_key;
        if (atm_auth_key == bank_auth_key)
        {
            cout << "Auth files verified on bank side." << endl;
            // Optionally, send a success message to the ATM
            SSL_write(ssl, "VERIFIED", strlen("VERIFIED"));
            thread(handle_client_request, ssl).detach(); // Handle client requests
        }
        else
        {
            cout << " Auth files not verified. Connection denied." << endl;
            SSL_write(ssl, " Connection denied", strlen(" Connection denied"));
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_fd); // Close the connection
        }

    }
    close(server_fd);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}













