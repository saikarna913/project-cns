//server
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <map>
#include <sstream>
#include <vector>
#include <cstring>
#include <random>
#include <chrono>
#include <openssl/sha.h>
#include <regex>
#include <mutex>
#include <thread>
#include <fstream>
#include <openssl/aes.h>
#include <iomanip>
using namespace std;

void save_auth_file(const string &filename);
#define SERVER_PORT 8080
#define PRIVATE_KEY_FILE "../../certs/private_key.pem"
#define AUTH_FILE "../auth.txt"
#define BACKUP_FILE "../auth_backup.txt"

map<string, tuple<string, double, string, string>> user_database;
mutex user_database_mutex;

map<string, string> session_tokens;
mutex session_tokens_mutex;

const int SESSION_TIMEOUT_SECONDS = 10;
map<string, chrono::steady_clock::time_point> session_last_activity;
mutex session_last_activity_mutex;

void log_message(const string &msg) {
    cout << "[INFO] " << msg << "\n";
}

void log_error(const string &msg) {
    cerr << "[ERROR] " << msg << "\n";
}

bool is_valid_username(const string &username) {
    if (username == "." || username == "..") {
        return true;
    }

    regex username_regex(R"(^(?!.[-]{2,})(?!.[.]{2,})[a-z0-9_.-]{1,122}$)");
    
    if (!regex_match(username, username_regex)) {
        return false;
    }

    return true;
}

bool is_valid_amount(const string &amount_str) {
    regex amount_regex(R"(^([1-9][0-9]*|0)\.[0-9]{2}$)");
    if (!regex_match(amount_str, amount_regex)) {
        return false;
    }

    try {
        size_t decimal_pos = amount_str.find('.');
        if (decimal_pos == string::npos || 
            amount_str.length() - decimal_pos - 1 != 2) { 
            return false;
        }

        double amount = stod(amount_str);
        return amount >= 0.00 && amount <= 4294967295.99;
    } catch (const exception&) {
        return false;
    }
}


void handle_error(SSL *ssl, const string &error_message) {
    log_error(error_message);
    SSL_write(ssl, "An error occurred.", 42);
}


string base64_decode(const string &input) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new_mem_buf(input.c_str(), input.size());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    vector<unsigned char> output(input.size());
    int len = BIO_read(b64, output.data(), input.size());
    BIO_free_all(b64);
    return string(output.begin(), output.begin() + len);
}


string rsa_decrypt(const string &encrypted_base64) {
    string encrypted = base64_decode(encrypted_base64);

    FILE *privkey_file = fopen(PRIVATE_KEY_FILE, "rb");
    if (!privkey_file) {
        log_error("Failed to open private key file");
        return "";
    }
    EVP_PKEY *privkey = PEM_read_PrivateKey(privkey_file, NULL, NULL, NULL);
    fclose(privkey_file);

    if (!privkey) {
        log_error("Failed to read private key");
        return "";
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
    EVP_PKEY_decrypt_init(ctx);

    size_t outlen = 0;
    EVP_PKEY_decrypt(ctx, NULL, &outlen, (const unsigned char *)encrypted.c_str(), encrypted.size());

    vector<unsigned char> decrypted(outlen);
    if (EVP_PKEY_decrypt(ctx, decrypted.data(), &outlen, (const unsigned char *)encrypted.c_str(), encrypted.size()) <= 0) {
        log_error("Decryption failed");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privkey);
        return "";
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(privkey);

    return string(decrypted.begin(), decrypted.end());
}

string generate_random_number(int length) {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 9);
    string number;
    for (int i = 0; i < length; ++i) {
        number += to_string(dis(gen));
    }
    return number;
}

string hash_password_server(const string &password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)password.c_str(), password.size(), hash);
    return string((char*)hash, SHA256_DIGEST_LENGTH);
}

string generate_session_token() {
    string token = generate_random_number(32); 
    return token;
}

void handle_protocol_error(SSL *ssl) {
    log_error("protocol error");
    SSL_write(ssl, "protocol error", 14);
}

void handle_create_account(SSL *ssl, const string &username, const string &encrypted_password, const string &initial_amount_str) {
    if (!is_valid_username(username)) {
        string error_msg = "ERROR 255 - due to invalid user name";
        SSL_write(ssl, error_msg.c_str(), error_msg.size());
        log_error("Account creation failed: invalid username - " + username);
        return;
    }

    if (!is_valid_amount(initial_amount_str)) {
        string error_msg = "ERROR 255 - due to invalid amount value";
        SSL_write(ssl, error_msg.c_str(), error_msg.size());
        log_error("Account creation failed: invalid amount - " + initial_amount_str + " for username: " + username);
        return;
    }

    double initial_amount = stod(initial_amount_str);

    if (initial_amount < 10.00) {
        string error_msg = "ERROR 255 - due to invalid amount value";
        SSL_write(ssl, error_msg.c_str(), error_msg.size());
        log_error("Account creation failed: initial amount less than 10 for username: " + username);
        return;
    }

    string decrypted_password = rsa_decrypt(encrypted_password);
    if (decrypted_password.empty()) {
        handle_protocol_error(ssl);
        return;
    }

    string hashed_password = hash_password_server(decrypted_password);
    if (hashed_password.empty()) {
        handle_protocol_error(ssl);
        return;
    }

    lock_guard<mutex> lock(user_database_mutex);
    if (user_database.find(username) != user_database.end()) {
        string error_msg = "ERROR 255 - due to account already exists";
        SSL_write(ssl, error_msg.c_str(), error_msg.size());
        log_error("Account creation failed: username already exists");
    } else {
        string card_id = generate_random_number(16);
        string account_number = generate_random_number(10);
        
        user_database[username] = {hashed_password, initial_amount, card_id, account_number};
        
        ostringstream json_response;
        json_response << "{"
                      << "\"account\":\"" << account_number << "\","
                      << "\"card_id\":\"" << card_id << "\","
                      << "\"initial_balance\":" << fixed << setprecision(2) << initial_amount
                      << "}";
        string response = json_response.str();
        
        SSL_write(ssl, response.c_str(), response.size());
        log_message("Account created for username: " + username + 
                   " with initial amount: " + initial_amount_str + 
                   " card_id: " + card_id + 
                   " account_number: " + account_number);

        save_auth_file(AUTH_FILE);
    }
}

bool handle_login(SSL *ssl, const string &username, const string &encrypted_password, const string &card_id, const string &account_number) {
    if (!is_valid_username(username)) {
        handle_protocol_error(ssl);
        return false;
    }

    string decrypted_password = rsa_decrypt(encrypted_password);
    string hashed_password = hash_password_server(decrypted_password);
    
    lock_guard<mutex> lock(user_database_mutex);
    if (user_database.find(username) != user_database.end()) {
        auto &[stored_password, balance, stored_card_id, stored_account_number] = user_database[username];
        if (stored_password == hashed_password && stored_card_id == card_id && stored_account_number == account_number) {
            string session_token = generate_session_token();
            {
                lock_guard<mutex> session_lock(session_tokens_mutex);
                session_tokens[username] = session_token;
            }
            {
                lock_guard<mutex> activity_lock(session_last_activity_mutex);
                session_last_activity[username] = chrono::steady_clock::now();
            }
            string response = "LOGIN_SUCCESS " + session_token;
            SSL_write(ssl, response.c_str(), response.size());
            log_message("Login successful for username: " + username);
            return true;
        } else {
            SSL_write(ssl, "LOGIN_FAILED: Incorrect credentials", 36);
            log_error("Login failed: incorrect credentials for " + username);
        }
    } else {
        SSL_write(ssl, "LOGIN_FAILED: User not found", 28);
        log_error("Login failed: user not found - " + username);
    }
    return false;
}


bool is_session_valid(const string &username) {
    lock_guard<mutex> lock(session_last_activity_mutex);
    auto it = session_last_activity.find(username);
    if (it == session_last_activity.end()) {
        return true;  
    }
    auto now = chrono::steady_clock::now();
    auto duration = chrono::duration_cast<chrono::seconds>(now - it->second).count();
    return duration <= SESSION_TIMEOUT_SECONDS;
}

void update_session_activity(const string &username) {
    lock_guard<mutex> lock(session_last_activity_mutex);
    session_last_activity[username] = chrono::steady_clock::now();
}

void handle_transaction(SSL *ssl, const string &username) {
    char buffer[1024] = {0};
    double previous_balance = 0.0;
    bool transaction_in_progress = false;

    while (true) {
        int bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes_read <= 0) {
            if (transaction_in_progress) {
                lock_guard<mutex> lock(user_database_mutex);
                get<1>(user_database[username]) = previous_balance;
                save_auth_file(AUTH_FILE);
            }
            log_error("Failed to read from SSL connection");
            break;
        }

        if (!is_session_valid(username)) {
            SSL_write(ssl, "ERROR 255 - Session expired", 28);
            log_error("Session expired for username: " + username);
            break;
        }

        string command(buffer, bytes_read);
        log_message("Received command: " + command);

        istringstream iss(command);
        string session_token, action, amount_str;
        iss >> session_token >> action;

        {
            lock_guard<mutex> lock(session_tokens_mutex);
            if (session_tokens[username] != session_token) {
                string error_msg = "ERROR 255 - due to invalid session token";
                SSL_write(ssl, error_msg.c_str(), error_msg.size());
                log_error("Invalid session token for username: " + username);
                break;
            }
        }

        update_session_activity(username);

        if (action == "LOGOUT") {
            {
                lock_guard<mutex> lock(session_tokens_mutex);
                session_tokens.erase(username);
            }
            string response = "Logged out successfully";
            SSL_write(ssl, response.c_str(), response.size());
            log_message("User logged out: " + username);
            break;
        } else if (action == "CHECK_BALANCE") {
            lock_guard<mutex> lock(user_database_mutex);
            double balance = get<1>(user_database[username]);

            ostringstream json_response;
            json_response << "{"
                          << "\"account\":\"" << get<3>(user_database[username]) << "\","
                          << "\"balance\":" << fixed << setprecision(2) << balance
                          << "}";
            string response = json_response.str();

            SSL_write(ssl, response.c_str(), response.size());
            log_message("Balance checked for username: " + username + ", Balance: " + to_string(balance));
        } else if (action == "DEPOSIT" || action == "WITHDRAW") {
            iss >> amount_str;
            if (!is_valid_amount(amount_str)) {
                string error_msg = "ERROR 255 - due to invalid amount value";
                SSL_write(ssl, error_msg.c_str(), error_msg.size());
                log_error("Transaction failed: invalid amount - " + amount_str + " for username: " + username);
                continue;
            }
            double amount = stod(amount_str);

            try {
                lock_guard<mutex> lock(user_database_mutex);
                if (!transaction_in_progress) {
                    previous_balance = get<1>(user_database[username]);
                    transaction_in_progress = true;
                }

                if (action == "DEPOSIT") {
                    get<1>(user_database[username]) += amount;

                    ostringstream json_response;
                    json_response << "{"
                                  << "\"account\":\"" << get<3>(user_database[username]) << "\","
                                  << "\"deposit\":" << fixed << setprecision(2) << amount
                                  << "}";
                    string response = json_response.str();

                    SSL_write(ssl, response.c_str(), response.size());
                    log_message("Deposit made for username: " + username + ", Amount: " + amount_str);
                } else {
                    if (get<1>(user_database[username]) >= amount) {
                        get<1>(user_database[username]) -= amount;

                        
                        ostringstream json_response;
                        json_response << "{"
                                      << "\"account\":\"" << get<3>(user_database[username]) << "\","
                                      << "\"withdraw\":" << fixed << setprecision(2) << amount
                                      << "}";
                        string response = json_response.str();

                        SSL_write(ssl, response.c_str(), response.size());
                        log_message("Withdrawal made for username: " + username + ", Amount: " + amount_str);
                    } else {
                        string error_msg = "ERROR 255 - due to insufficient balance";
                        SSL_write(ssl, error_msg.c_str(), error_msg.size());
                        log_error("Insufficient balance for username: " + username);
                        continue;
                    }
                }

                save_auth_file(AUTH_FILE);
                transaction_in_progress = false;
            } catch (const exception&) {
                string error_msg = "ERROR 255 - due to invalid amount value";
                SSL_write(ssl, error_msg.c_str(), error_msg.size());
                log_error("Exception occurred while processing amount: " + amount_str);
            }
        } else {
            string error_msg = "ERROR 255 - due to invalid command";
            SSL_write(ssl, error_msg.c_str(), error_msg.size());
            log_error("Invalid command received: " + action);
        }

        memset(buffer, 0, sizeof(buffer));
    }

    if (transaction_in_progress) {
        lock_guard<mutex> lock(user_database_mutex);
        get<1>(user_database[username]) = previous_balance;
        save_auth_file(AUTH_FILE);
    }
}

SSL_CTX *create_ssl_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        log_error("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, "../../certs/server_cert.pem", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "../../certs/server_key.pem", SSL_FILETYPE_PEM) <= 0) {
        log_error("Failed to load certificates");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void derive_aes_key_iv(const string &password, unsigned char *aes_key, unsigned char *aes_iv) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)password.c_str(), password.size(), hash);
    memcpy(aes_key, hash, 32);
    memcpy(aes_iv, hash + 16, 16);
}

string aes_decrypt(const string &ciphertext, const unsigned char *aes_key, const unsigned char *aes_iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);

    vector<unsigned char> plaintext(ciphertext.size());
    int len, plaintext_len = 0;
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, (unsigned char*)ciphertext.c_str(), ciphertext.size());
    plaintext_len += len;
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return string(plaintext.begin(), plaintext.begin() + plaintext_len);
}

void save_auth_file(const string &filename) {
    ofstream file(filename);
    if (!file.is_open()) {
        log_error("Failed to open auth file for writing: " + filename);
        return;
    }

    for (const auto &[username, data] : user_database) {
        const auto &[password, balance, card_id, account_number] = data;
        file << username << " " << password << " " << balance << " " << card_id << " " << account_number << "\n";
    }

    file.close();
    log_message("Auth file saved: " + filename);
}

void load_auth_file(const string &filename) {
    ifstream file(filename);
    if (!file.is_open()) {
        log_error("Failed to open auth file for reading: " + filename);
        return;
    }

    user_database.clear();
    string line;
    while (getline(file, line)) {
        istringstream iss(line);
        string username, password, card_id, account_number;
        double balance;
        if (iss >> username >> password >> balance >> card_id >> account_number) {
            user_database[username] = {password, balance, card_id, account_number};
        }
    }

    file.close();
    log_message("Auth file loaded: " + filename);
}

void create_backup() {
    save_auth_file(BACKUP_FILE);
    log_message("Backup created: " + string(BACKUP_FILE));
}



int main() {
    SSL_CTX *ctx = create_ssl_context();

    load_auth_file(AUTH_FILE);

    create_backup();

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(server_fd, SOMAXCONN);

    log_message("Server listening on port 8080...");

    thread session_cleanup_thread([]() {
        while (true) {
            this_thread::sleep_for(chrono::seconds(60)); 
            lock_guard<mutex> lock(session_last_activity_mutex);
            auto now = chrono::steady_clock::now();
            for (auto it = session_last_activity.begin(); it != session_last_activity.end();) {
                if (chrono::duration_cast<chrono::seconds>(now - it->second).count() > SESSION_TIMEOUT_SECONDS) {
                    lock_guard<mutex> token_lock(session_tokens_mutex);
                    session_tokens.erase(it->first);
                    it = session_last_activity.erase(it);
                } else {
                    ++it;
                }
            }
        }
    });

    while (true) {
        int client_fd = accept(server_fd, NULL, NULL);
        thread([client_fd, ctx]() {
            SSL *ssl = SSL_new(ctx);
            SSL_set_fd(ssl, client_fd);

            if (SSL_accept(ssl) <= 0) {
                log_error("SSL accept failed");
                ERR_print_errors_fp(stderr);
                SSL_free(ssl);
                close(client_fd);
                return;
            }

            char buffer[1024] = {0};
            SSL_read(ssl, buffer, sizeof(buffer));
            log_message("Received message: " + string(buffer));

            string command, username, encrypted_password, card_id, account_number, initial_amount_str;

            istringstream iss(buffer);
            iss >> command >> username >> encrypted_password;

            if (command == "CREATE_ACCOUNT") {
                iss >> initial_amount_str;
                handle_create_account(ssl, username, encrypted_password, initial_amount_str);
            } else if (command == "LOGIN") {
                iss >> card_id >> account_number;
                if (handle_login(ssl, username, encrypted_password, card_id, account_number)) {
                    handle_transaction(ssl, username);
                }
            }

            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_fd);
        }).detach();

        create_backup();
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}