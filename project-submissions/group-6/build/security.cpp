#include "security.h"

void SecureLogger::print_hex(const unsigned char *data, unsigned long long len)
{
    for (unsigned long long i = 0; i < len; ++i)
    {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(data[i]);
    }
    cout << endl;
}

unsigned char *SecureLogger::hash_token()
{
    // cout << "Inside hash and verify password...." << endl;

    unsigned char *hashed_token = new unsigned char[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];

    // initialize the hashed_token with 0
    memset(hashed_token, 0, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    // cout << "token: " << token << endl;
    // cout << "strlen(token): " << strlen(token) << endl;
    // cout << "salt: " << salt << endl;
    // cout << "strlen(salt): " << strlen(reinterpret_cast<const char *>(salt)) << endl;

    if (crypto_pwhash(hashed_token,
                      crypto_aead_xchacha20poly1305_ietf_KEYBYTES, token, strlen(token),
                      salt, crypto_pwhash_OPSLIMIT_MODERATE,
                      crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_ALG_DEFAULT) != 0)
    {
        /* out of memory */
        // cerr << "Failed to generate key from token!" << endl;
        // throw runtime_error("Failed to generate key from token!");
        exit(255);
    }

    // cout << "Token: " << token << endl;
    // cout << "Hashed token:" << hashed_token << endl;

    // // convert hashed_token to hex
    // cout << "Hashed token in hex: ";
    // for (unsigned long long i = 0; i < crypto_aead_xchacha20poly1305_ietf_KEYBYTES; ++i)
    // {
    //     cout << hex << setw(2) << setfill('0') << static_cast<int>(hashed_token[i]);
    // }
    return hashed_token;
}

void SecureLogger::store_token(unsigned char *hashpassword, const string &filename, const string &metadata_filename)
{
    // Declare the JSON object that will hold the metadata
    json logfile_metadata;

    // Open the JSON file for reading
    ifstream input_file(metadata_filename);
    if (input_file.is_open())
    {
        try
        {
            // Read and parse the existing JSON content
            input_file >> logfile_metadata;
        }
        catch (const json::parse_error &e)
        {
            // std::cerr << "Parse error: " << e.what() << ". Reinitializing the file." << std::endl;
            logfile_metadata = json::array(); // Initialize a new empty array if there's an error
        }
        input_file.close();
    }
    else
    {
        // If file doesn't exist or can't be opened, start with an empty JSON array
        // std::cerr << "Error: Could not open file " << metadata_filename << " for reading. Creating a new one." << std::endl;
        logfile_metadata = json::array();
    }

    // Generate metadata for the current log file and add it to the JSON array
    logfile_metadata.push_back(get_logfile_metadata());

    // Write the updated metadata back to the file
    ofstream output_file(metadata_filename);
    if (output_file.is_open())
    {
        // cout << "Metadata: " << logfile_metadata << endl;
        output_file << std::setw(4) << logfile_metadata << std::endl; // Write formatted JSON
        output_file.close();
        // cout << "Stored token and metadata in " << metadata_filename << endl;
    }
    else
    {
        // cerr << "Error: Could not open file " << metadata_filename << " for writing." << endl;
        exit(255);
    }
}

int SecureLogger::verify_token()
{
    // if metadata file does not exist then create a new medata file
    // check if a file exists in c++
    ifstream f(metadata_filename.c_str());
    if (!f.good())
    {
        // cout << "File does not exist" << endl;
        ofstream myfile;
        myfile.open(metadata_filename);
        myfile.close();
        return -1;
    }

    ifstream input_file(this->metadata_filename);
    if (!input_file.is_open())
    {
        // cerr << "Error: Could not open file " << this->metadata_filename << endl;
        // return -2;
        exit(255);
    }

    string logfile_metadata_str((istreambuf_iterator<char>(input_file)),
                                istreambuf_iterator<char>());
    input_file.close();

    if (logfile_metadata_str.empty())
    {
        // cerr << "Error: Metadata file is empty" << endl;
        return -1; // No entries in the metadata file
    }

    // cout << "File content: " << logfile_metadata_str << endl;

    json logfile_metadata;
    try
    {
        logfile_metadata = json::parse(logfile_metadata_str);
    }
    catch (const json::parse_error &e)
    {
        // cerr << "Parse error: " << e.what() << std::endl;
        return -1;
    }

    if (logfile_metadata.empty())
    {
        // cerr << "Error: Parsed JSON is empty" << std::endl;
        return -1; // No entries in the metadata file
    }

    for (const auto &logfile : logfile_metadata)
    {
        if (logfile["filename"] == this->filename)
        {
            unsigned char *stored_token = fromHexString(logfile["key"].get<string>(), crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
            salt = fromHexString(logfile["salt"].get<string>(), crypto_pwhash_SALTBYTES);
            nonce = fromHexString(logfile["nonce"].get<string>(), crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

            // cout << "salt:" << salt << endl;
            // cout << "nonce:" << nonce << endl;
            // cout << "stored_token:" << stored_token << endl;

            plaintext_len = logfile["length"];
            unsigned char *hashed_token = hash_token();
            string hashed_token_str = toHexString(hashed_token, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
            string stored_token_str = logfile["key"].get<string>();

            if (hashed_token_str == stored_token_str)
            {
                // cout << "Token verified" << endl;
                key = stored_token;
                return 1;
            }
            else
            {
                // cout << "Token does not match" << endl;
                return 0;
            }
        }
    }
    // cout << "Token does not exist" << endl;
    return -1;
}

json SecureLogger::get_logfile_metadata()
{
    string entry_key = toHexString(key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    string entry_salt = toHexString(salt, crypto_pwhash_SALTBYTES);
    string entry_nonce = toHexString(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    json metadata = {
        {"filename", this->filename},
        {"key", entry_key},
        {"salt", entry_salt},
        {"nonce", entry_nonce},
        {"length", plaintext_len}};
    return metadata;
}

void SecureLogger::update_logfile_length(const string &target_logfile, const string &json_file_path, size_t new_length)
{
    // Open the existing JSON file
    ifstream input_file(json_file_path);
    if (!input_file.is_open())
    {
        // cerr << "Could not open the JSON file!" << endl;
        // return;
        exit(255);
    }

    // Parse the existing JSON data
    json logfile_metadata;
    input_file >> logfile_metadata;
    input_file.close();

    // Find the logfile and update its length
    bool found = false;
    for (auto &logfile : logfile_metadata)
    {
        if (logfile["filename"] == target_logfile)
        {
            // Update the length field with the new size of the file
            logfile["length"] = new_length;
            found = true;
            break;
        }
    }

    if (!found)
    {
        // cerr << "Logfile not found in the metadata!" << endl;
        // return;
        exit(255);
    }

    // Write the updated JSON back to the file
    ofstream output_file(json_file_path);
    if (output_file.is_open())
    {
        output_file << setw(4) << logfile_metadata << endl; // Write formatted JSON
        output_file.close();
        // cout << "Updated length for " << target_logfile << " in " << json_file_path << endl;
        return;
    }
    else
    {
        // cerr << "Could not open the JSON file for writing!" << endl;
        // return;
        exit(255);
    }
}

string SecureLogger::toHexString(const unsigned char *data, size_t length)
{
    ostringstream oss;
    for (size_t i = 0; i < length; ++i)
    {
        oss << setw(2) << setfill('0') << hex << (data[i] & 0xff);
    }
    // oss << '\0';  // Null terminator for C-string
    // cout << "Hex String: " << oss.str() << endl; // Logging hex string for debugging
    return oss.str();
}

unsigned char *SecureLogger::fromHexString(const string &hexStr, size_t outLength)
{
    if (hexStr.length() % 2 != 0)
        return nullptr; // Invalid hex string length

    outLength = hexStr.length() / 2;
    unsigned char *a = new unsigned char[outLength];
    for (size_t i = 0; i < hexStr.length(); i += 2)
    {
        string byteString = hexStr.substr(i, 2);
        a[i / 2] = static_cast<unsigned char>(strtoul(byteString.c_str(), nullptr, 16));
    }

    // // Logging byte array for debugging
    // cout << "Byte Array after hex conversion: ";
    // for (size_t i = 0; i < outLength; ++i)
    // {
    //     cout << hex << (a[i] & 0xff) << " ";
    // }
    // cout << endl;

    return a;
}

bool SecureLogger::isRegularFile(string filePath)
{
    struct stat sb;
    if (stat(filePath.c_str(), &sb) == 0)
    {
        return S_ISREG(sb.st_mode);
    }
    return false;
}

/// @brief This function initialises the instance of the class and should be called first after creating the instance.
/// @param token --- string --- token passed in the command.
/// @param filename --- string --- name of the logfile passed in the command.
/// @return --- int --- 0 --> if the logfile exists from before and the token matches or if the file does not exist from before.
///                     -1 --> if the logfile exists from before and the token does not match.
///                      1 --> if in case some other unknown error occured in the verification process.
///                      2 --> if the file does not exist from before.
int SecureLogger::init(string token, string filename)
{
    this->filename = filename;
    this->token = token.c_str();
    plaintext_len = 0;
    // initialise the salt and nonce randomly and generate the key from salt
    // if the file exist from before then overwrite salt and nonce
    // also if file exists from before and the token provided is verified (i.e. the token is correct) then instead of hashing and generating the key again, take it form the meta data file

    salt = new unsigned char[crypto_pwhash_SALTBYTES];
    nonce = new unsigned char[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];

    randombytes_buf(salt, crypto_pwhash_SALTBYTES);
    randombytes_buf(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    // cout << "salt:" << salt << endl;
    // cout << "nonce:" << nonce << endl;

    int verify = verify_token();
    if (verify == 1)
    {
        // cout << "Token verified" << endl;
        return 0;
    }
    else if (verify == -1)
    {
        // cout << "Token does not exist(means file does not exists)" << endl;

        // create a new file given the relative path as filename
        std::filesystem::path pathObj(filename);

        if (isRegularFile(filename))
        {
            cout << "Not a regular file path!" << endl;
            exit(255);
        }

        // Check if path has no parent directory (i.e., it's only a file name)
        if (!pathObj.has_parent_path())
        {
            string correctedPath = "./" + filename; // Prepend "./" to file name
            ofstream file(correctedPath);           // Create or open the file
            if (file.is_open())
            {
                // cout << "File created: " << correctedPath << std::endl;
                file.close();
            }
            else
            {
                // cerr << "Failed to create file: " << correctedPath << std::endl;
                exit(255);
            }
        }
        else
        {
            std::filesystem::path directory = pathObj.parent_path();
            if (!filesystem::exists(directory))
            {
                filesystem::create_directories(directory);
            }
            ofstream file(filename); // Create or open the file at the given path
            if (file.is_open())
            {
                // cout << "File created: " << filename << std::endl;
                file.close();
            }
            else
            {
                // cerr << "Failed to create file: " << filename << std::endl;
                exit(255);
            }
        }

        // Hash the token
        unsigned char *hashed_token1 = hash_token();
        key = hashed_token1;
        store_token(hashed_token1, this->filename, this->metadata_filename);
        return 2;
    }
    else if (verify == 0)
    {
        // cout << "Token does not match" << endl;
        // cerr << "Token does not match" << endl;
        // throw runtime_error("Token does not match");
        return -1;
    }
    else
    {
        // cout << "Error in verifying token" << endl;
        // cerr << "Error in verifying token" << endl;
        // throw runtime_error("Error in verifying token");
        return 1;
    }
}

unsigned long long SecureLogger::get_plaintext_len()
{
    return plaintext_len;
}

/// @brief This function encrypts the plaintext passed in it as a parameter and writes the encrypted data to the file having the name as with which the class instance was initialised.
/// @param plaintext --- const unsigned char* --- This is the plaintext to be encrypted.
void SecureLogger::encrypt_log_plaintext(const unsigned char *plaintext)
{
    unsigned long long newplaintext_size = strlen((const char *)plaintext);
    if (newplaintext_size == 0)
    {
        // cerr << "Cannot encrypt empty plaintext..." << endl;
        // throw runtime_error("Cannot encrypt empty plaintext...");
        exit(255);
    }
    plaintext_len = newplaintext_size;
    update_logfile_length(this->filename, this->metadata_filename, this->plaintext_len);

    unsigned char *ciphertext = new unsigned char[newplaintext_size + crypto_aead_xchacha20poly1305_ietf_ABYTES];
    unsigned long long ciphertext_len;

    // Encrypt the plaintext
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext, &ciphertext_len, plaintext, newplaintext_size,
                                                   NULL, 0, NULL, nonce, key) != 0)
    {
        // cerr << "Encryption of plaintext failed" << endl;
        // throw runtime_error("Encryption of plaintext failed");
        exit(255);
    }

    // cout << "ciphertext len: " << ciphertext_len << endl;
    // cout << "Encrypted Data (Hex): ";
    // print_hex(ciphertext, ciphertext_len);

    // Write encrypted data to file
    ofstream encrypted_file(filename, ios::binary | ios::trunc);
    if (!encrypted_file)
    {
        // cerr << "Unable to open file for writing encrypted data" << endl;
        // throw runtime_error("Unable to open file for writing encrypted data");
        exit(255);
    }

    // Write the ciphertext to the end of the file
    encrypted_file.write(reinterpret_cast<const char *>(ciphertext), ciphertext_len);
    encrypted_file.close();

    // cout << "Encrypted data successfully written to file: " << filename << endl;
}

// ////////////////////////////////////////////////////////////////

//     void SecureLogger::encrypt_log_file()
//     {
//         ifstream myfile(filename, ios::binary);

//         if (!myfile.is_open())
//         {
//             cerr << "Unable to open encrypted log file" << endl;
//             throw runtime_error("Unable to open encrypted log file");
//         }

//         // Get the size of the file
//         myfile.seekg(0, ios::end);
//         streamsize file_size = myfile.tellg();
//         myfile.seekg(0, ios::beg);

//         if (file_size == 0)
//         {
//             cerr << "file to be encrypted is empty" << endl;
//             throw runtime_error("file to be encrypted is empty");
//         }

//         // Read the entire file into a vector
//         vector<unsigned char> buffer((istreambuf_iterator<char>(myfile)), istreambuf_iterator<char>());
//         myfile.close();

//         // Set the size of the data read
//         size_t plaintext_len = buffer.size();

//         const unsigned char *plaintext = buffer.data();

//         unsigned char *ciphertext = new unsigned char[plaintext_len + crypto_aead_xchacha20poly1305_ietf_ABYTES];
//         unsigned long long ciphertext_len;

//         // Encrypt the plaintext
//         if (crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext, &ciphertext_len, plaintext, plaintext_len,
//                                                        NULL, 0, NULL, nonce, key) != 0)
//         {
//             cerr << "Encryption of log file failed" << endl;
//             throw runtime_error("Encryption of log file failed");
//         }

//         // cout << "Encrypted Data (Hex): ";
//         // print_hex(ciphertext, ciphertext_len);

//         // Write encrypted data to file
//         ofstream encrypted_file(filename, ios::binary | ios::trunc);
//         if (!encrypted_file)
//         {
//             cerr << "Unable to open file for writing encrypted data" << endl;
//             throw runtime_error("Unable to open file for writing encrypted data");
//         }

//         // Write the ciphertext to the file
//         encrypted_file.write(reinterpret_cast<const char *>(ciphertext), ciphertext_len);
//         encrypted_file.close();

//         cout << "Encrypted data successfully written to file: " << filename << endl;
//     }

// //////////////////////////////////////////////////////////////

/// @brief This function decrypts the encrypted text form the file (name of the file was passed during initialisation).
/// @return --- unsigned char* --- This function returns the decrypted plaintext value.
unsigned char *SecureLogger::decrypt_log()
{
    // Read the encrypted file
    ifstream myfile(filename, ios::binary);

    if (!myfile.is_open())
    {
        // cerr << "Unable to open encrypted log file" << endl;
        // throw runtime_error("Unable to open encrypted log file");
        exit(255);
    }

    // Get the size of the file
    myfile.seekg(0, ios::end);
    streamsize file_size = myfile.tellg();
    myfile.seekg(0, ios::beg);

    // Read the entire file into a vector
    vector<unsigned char> buffer((istreambuf_iterator<char>(myfile)), istreambuf_iterator<char>());
    myfile.close();

    // Set the size of the data read
    unsigned long long ciphertext_len = buffer.size();
    const unsigned char *ciphertext = buffer.data();

    // unsigned char *decrypted = new unsigned char[ciphertext_len - crypto_aead_xchacha20poly1305_ietf_ABYTES];
    unsigned char decrypted[ciphertext_len - crypto_aead_xchacha20poly1305_ietf_ABYTES];
    unsigned long long decrypted_len;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted, &decrypted_len,
                                                   NULL, ciphertext, ciphertext_len,
                                                   NULL, 0, nonce, key) != 0)
    {
        // cerr << "Decryption failed or integrity check failed" << endl;
        // throw runtime_error("Decryption failed or integrity check failed");
        cout << "integrity violation" << endl;
        exit(255);
    }
    // cout << "decrypted len: " << decrypted_len << endl;

    // Allocate a new array to return only the relevant decrypted data
    unsigned char result[decrypted_len];

    // Copy the decrypted data up to decrypted_len
    for (unsigned long long i = 0; i < decrypted_len; i++)
    {
        result[i] = decrypted[i];
    }
    result[decrypted_len] = '\0';

    unsigned char *ret = result;

    // cout << "result size: " << strlen((char *)result) << endl;
    return ret;
}