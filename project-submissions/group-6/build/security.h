#ifndef SECURE_LOGGER_H
#define SECURE_LOGGER_H

#include <sodium.h>
#include <vector>
#include <iostream>
#include <string>
#include <iomanip>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <nlohmann/json.hpp>
#include <filesystem>
#include <sys/stat.h>

using namespace std;
using json = nlohmann::json;

class SecureLogger
{
private:
    unsigned char *salt;
    unsigned char *nonce;
    const char *token;
    const unsigned char *key;
    string filename;
    string metadata_filename = "logfile_metadata.json";
    unsigned long long plaintext_len;

    void print_hex(const unsigned char *data, unsigned long long len);
    unsigned char *hash_token();
    void store_token(unsigned char *hashpassword, const string &filename, const string &metadata_filename);
    int verify_token();
    json get_logfile_metadata();
    void update_logfile_length(const string &target_logfile, const string &json_file_path, size_t new_length);
    string toHexString(const unsigned char *data, size_t length);
    unsigned char *fromHexString(const string &hexStr, size_t outLength);
    bool isRegularFile(string filePath);

public:
    int init(string token, string filename);
    unsigned long long get_plaintext_len();
    void encrypt_log_plaintext(const unsigned char *plaintext);
    void encrypt_log_file();
    unsigned char *decrypt_log();
};

#endif // SECURE_LOGGER_H
