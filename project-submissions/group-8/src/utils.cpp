// utils.cpp
#include "utils.h"
#include <nlohmann/json.hpp>
#include <sys/stat.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <unordered_map>
#include <set>
#include <map>
#include <openssl/evp.h> 
#include <openssl/rand.h>
#include <cstdlib>
#include <vector>
#include <stdexcept>
#include <string>

using json = nlohmann::json;
using namespace std;

const int LINEBYLINE_KEY_SIZE = 32; // 256 bits
const string LINEBYLINE_KEY_ENV_VAR = "LINEBYLINE_KEY";

////restore to here


std::string base64_encode(const std::string &in) {
    size_t encoded_length = 4 * ((in.size() + 2) / 3);
    std::string out(encoded_length, '\0');
    int actual_length = EVP_EncodeBlock((unsigned char*)&out[0], 
                                        (const unsigned char*)in.data(), 
                                        in.size());
    out.resize(actual_length);
    return out;
}


std::string base64_decode(const std::string &in) {
    size_t decoded_length = 3 * (in.size() / 4);
    std::string out(decoded_length, '\0');
    int actual_length = EVP_DecodeBlock((unsigned char*)&out[0], 
                                        (const unsigned char*)in.data(), 
                                        in.size());
    if (in.size() > 0 && in[in.size() - 1] == '=') actual_length--;
    if (in.size() > 1 && in[in.size() - 2] == '=') actual_length--;
    out.resize(actual_length);
    return out;
}

std::string LINEBYLINE_encrypt(const std::string &plaintext, const std::string &key) {
    unsigned char ciphertext[plaintext.size()];
    int outlen;
    const std::string null = "000000000000"; 
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create context for encryption");
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, (unsigned char *)key.data(), (unsigned char *)null.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize LINEBYLINE encryption");
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &outlen, (unsigned char *)plaintext.data(), plaintext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to encrypt data");
    }

    int final_outlen;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &final_outlen)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize encryption");
    }

    EVP_CIPHER_CTX_free(ctx);

    
    std::string ciphertext_str(reinterpret_cast<char*>(ciphertext), outlen + final_outlen);

   
    return base64_encode(ciphertext_str);
}

std::string LINEBYLINE_decrypt(const std::string &ciphertext_b64, const std::string &key) {
    std::string ciphertext = base64_decode(ciphertext_b64);

    unsigned char decryptedtext[ciphertext.size()];
    int outlen;
    const std::string null = "000000000000"; 

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create context for decryption");
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, (unsigned char *)key.data(), (unsigned char *)null.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize LINEBYLINE decryption");
    }

    if (1 != EVP_DecryptUpdate(ctx, decryptedtext, &outlen, (unsigned char *)ciphertext.data(), ciphertext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to decrypt data");
    }

    int final_outlen;
    if (1 != EVP_DecryptFinal_ex(ctx, decryptedtext + outlen, &final_outlen)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize decryption");
    }

    EVP_CIPHER_CTX_free(ctx);
    return std::string(reinterpret_cast<char*>(decryptedtext), outlen + final_outlen);
}


const std::string KEY_FILE_PATH = "key.txt"; 

void store_key_in_env() {
    
    std::ifstream keyFile(KEY_FILE_PATH);
    if (keyFile.is_open()) {
        std::string key;
        keyFile >> key; 

      
        if (key.length() == LINEBYLINE_KEY_SIZE * 2) {
            
            if (setenv("LINEBYLINE_KEY", key.c_str(), 1) != 0) {
                perror("Failed to set environment variable");
                throw std::runtime_error("Failed to set environment variable");
            }

            std::cout << "LINEBYLINE key loaded from file and stored in environment variable LINEBYLINE_KEY." << std::endl;
            return; // Exit the function since the key was found and set
        } else {
            std::cerr << "Invalid key length in key file. Generating a new key." << std::endl;
        }
    } else {
        std::cout << "Key file not found. Generating a new key." << std::endl;
    }

    // Generate a new random key
    unsigned char key[LINEBYLINE_KEY_SIZE]; // LINEBYLINE key size is 32 bytes
    if (RAND_bytes(key, sizeof(key)) != 1) {
        throw std::runtime_error("Failed to generate random key");
    }

    // Convert key to hexadecimal string
    std::ofstream outFile(KEY_FILE_PATH); // Open the file for writing
    if (!outFile.is_open()) {
        throw std::runtime_error("Failed to open key file for writing");
    }

    for (size_t i = 0; i < sizeof(key); ++i) {
        outFile << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(key[i]);
    }
    outFile.close(); 

    
    std::string hexKey(key, key + sizeof(key) * 2); 

    if (setenv("LINEBYLINE_KEY", hexKey.c_str(), 1) != 0) {
        perror("Failed to set environment variable");
        throw std::runtime_error("Failed to set environment variable");
    }

    std::cout << "LINEBYLINE key generated and stored in " << KEY_FILE_PATH
              << " and in environment variable LINEBYLINE_KEY." << std::endl;
}



std::string get_key_from_env() {
    std::ifstream keyFile(KEY_FILE_PATH); 

    if (!keyFile.is_open()) {
        throw std::runtime_error("Key file not found or could not be opened");
    }

    std::string key;
    keyFile >> key; 

    
    if (key.length() != LINEBYLINE_KEY_SIZE * 2) { 
        throw std::runtime_error("Invalid key length in key file");
    }

    return key;
}

// // Store log entry function
// void storeLogEntry(const LogAppendArgs &logEntry, const std::string &logFilePath) {
//     ofstream logFile(logFilePath, ios::app); // Correct usage of ofstream
//     if (!logFile.is_open()) {
//         throw runtime_error("Unable to open log file for writing");
//     }
//     logFile << logEntry.dump() << endl;
// }

bool isValidInteger(const string& str) {
    if (str.empty() || (!isdigit(str[0]) && str[0] != '-')) return false;
    char* p;
    strtoll(str.c_str(), &p, 10);
    return (*p == 0);
}

// Validate Timestamp
bool isValidTimestamp(const string& timestamp) {
    if (!isValidInteger(timestamp)) {
        return false;
    }
    long long ts = stoll(timestamp);
    return ts >= 1 && ts <= 1073741823;
}

bool validateTimestamp(const long ts, const string& logFilePath) {
    ifstream logFile(logFilePath);
    if (!logFile.is_open()) {
        return false; // If the log file doesn't exist, return false
    }

    // string line;
    long mostRecentTimestamp = 0;

    // Parse each line as a JSON object

    string encrypted;
    while (getline(logFile, encrypted)) {
        std::string key = get_key_from_env(); 
        std::string line = LINEBYLINE_decrypt((encrypted), key);
        // cout<<line<<endl;
        // cout<<line<<endl;
        json logEntry = json::parse(line);

        // Extract the timestamp from the JSON log entry
        if (logEntry.contains("timestamp")) {
            long timestamp = logEntry["timestamp"];

            // Update the most recent timestamp
            mostRecentTimestamp = max(mostRecentTimestamp, timestamp);
        }
    }

    logFile.close();
    
    // Return true if the provided timestamp is greater than the most recent one
    return ts > mostRecentTimestamp;
}

// Validate Token
bool isValidToken(const string& token) {
    return all_of(token.begin(), token.end(), [](char c) {
        return isalnum(c);
    });
}

bool validateToken(const string& token, const string& logFilePath) {
    ifstream logFile(logFilePath);
    if (!logFile.is_open()) {
        return true; // If the log file doesn't exist, any token is valid
    }

string encrypted;
    while (getline(logFile, encrypted)) {
        std::string key = get_key_from_env(); 
        std::string line = LINEBYLINE_decrypt((encrypted), key);
        // cout<<line<<endl;
        json logEntry = json::parse(line);

        // Extract the token from the JSON log entry
        if (logEntry.contains("token")) {
            string existingToken = logEntry["token"];
            
            // Return false if the token doesn't match
            if (existingToken != token) {
                return false;
            }
        }
    }

    logFile.close();
    return true;
}

// Validate Employee Name
bool isValidEmployeeName(const string& name) {
    return name.length() <= 32 && all_of(name.begin(), name.end(), [](char c) {
        return isalpha(c);
    });
}

// Validate Guest Name
bool isValidGuestName(const string& name) {
    return name.length() <= 32 && all_of(name.begin(), name.end(), [](char c) {
        return isalpha(c);
    });
}

// Validate Arrival
bool validateArrival(const LogAppendArgs& args, const string& logFilePath) {
    ifstream logFile(logFilePath);
    if (!logFile.is_open()) {
        return true; // If the log file doesn't exist, any arrival is valid
    }

    unordered_map<string, string> lastLocation;
   string encrypted;
    while (getline(logFile, encrypted)) {
        std::string key = get_key_from_env(); 
        std::string line = LINEBYLINE_decrypt((encrypted), key);
        // cout<<line<<endl;
        json logEntry = json::parse(line);

        string name = logEntry["name"];
        string location = logEntry["room"];
        string action = logEntry["action"];
        if(logEntry["isEmployee"] == true){
            name = name + "-E";
        }
        else {
            name = name + "-G";
        }
        bool isArrival = (action == "arrival");

        // Update the last known location
        if (isArrival) {
            lastLocation[name] = location.empty() ? "campus" : location;
        }
        else if (!location.empty()) {
            lastLocation[name] = "campus";
        }
        else {
            lastLocation.erase(name);
        }
    }

    logFile.close();

    // Now, validate the current `args` for arrival

    string name_tag  = args.name;
    if(args.isEmployee == true){
        name_tag = name_tag + "-E";
    }
    else {
        name_tag = name_tag + "-G";
    }

    if(lastLocation.find(name_tag) == lastLocation.end() && args.room.empty()){ // Entering the campus
        return true;
    }
    else if (lastLocation.find(name_tag) != lastLocation.end() && !args.room.empty() && lastLocation[name_tag] == "campus") {
        return true; // Cannot enter a room without first entering the campus
    }

    return false;
}

// Validate Departure
bool validateDeparture(const LogAppendArgs& args, const string& logFilePath) {
    ifstream logFile(logFilePath);
    if (!logFile.is_open()) {
        return false; // If the log file doesn't exist, any departure is invalid
    }

    unordered_map<string, string> lastLocation;
    string encrypted;
    while (getline(logFile, encrypted)) {
        std::string key = get_key_from_env(); 
        std::string line = LINEBYLINE_decrypt((encrypted), key);
        // cout<<line<<endl;
        json logEntry = json::parse(line);

        string name = logEntry["name"];
        string location = logEntry["room"];
        string action = logEntry["action"];
        bool isArrival = (action == "arrival");

        if(logEntry["isEmployee"] == true){
            name = name + "-E";
        }
        else {
            name = name + "-G";
        }

        // Update the last known location
        if (isArrival) {
            lastLocation[name] = location.empty() ? "campus" : location;
        }
        else if (!location.empty()) {
            lastLocation[name] = "campus";
        }
        else {
            lastLocation.erase(name);
        }
    }

    logFile.close();

    string name_tag  = args.name;
    if(args.isEmployee == true){
        name_tag = name_tag + "-E";
    }
    else {
        name_tag = name_tag + "-G";
    }

    // Now, validate the current `args` for departure
    if(lastLocation.find(name_tag) == lastLocation.end()){ // name doesn't exist (no entry of that name in logs)
        return false;
    }
    else if(args.room.empty() && lastLocation[name_tag] == "campus"){
        return true;
    }
    else if(!args.room.empty() && lastLocation[name_tag] == args.room){
        return true;
    }

    return false;
}

// Validate Room ID
bool isValidRoomID(const string& roomID) {
    if (roomID.empty() || !all_of(roomID.begin(), roomID.end(), ::isdigit)) {
        return false;
    }
    long room = stol(roomID);
    return room >= 0 && room <= 1073741823;
}

bool validateRoomEvent(const LogAppendArgs& args, const string& logFilePath) {
    ifstream logFile(logFilePath);
    if (!logFile.is_open()) {
        return true; // If the log file doesn't exist, any room event is valid
    }

    unordered_map<string, string> lastLocation;
    string encrypted;
    while (getline(logFile, encrypted)) {
        std::string key = get_key_from_env(); 
        std::string line = LINEBYLINE_decrypt((encrypted), key);
        // cout<<line<<endl;
        json logEntry = json::parse(line);

        string name = logEntry["name"];
        string location = logEntry["room"];
        string action = logEntry["action"];
        bool isArrival = (action == "arrival");

        // Update the last known location
        if (isArrival) {
            lastLocation[name] = location.empty() ? "campus" : location;
        }
        else if (!location.empty()) {
            lastLocation[name] = "campus";
        }
        else {
            lastLocation.erase(name);
        }
    }

    logFile.close();

    // Now, validate the current `args`
    if (args.isArrival) {
        if (!args.room.empty() && lastLocation.find(args.name) == lastLocation.end()) {
            return false; // Cannot enter a room without first entering the campus
        }
    } else {
        if (lastLocation.find(args.name) == lastLocation.end()) {
            return false; // Cannot leave a room without first entering the campus
        }
        if (!args.room.empty() && lastLocation[args.name] != args.room) {
            return false; // Cannot leave a room they are not currently in
        }
    }

    return true;
}

// Validate Log File
bool isValidLogFilePath(const string& logFilePath) {
    if (logFilePath.length() > 32) {
        throw invalid_argument("Log file path should be less than 32 char");
    }
    return all_of(logFilePath.begin(), logFilePath.end(), [](char c) {
        return isalnum(c) || c == '_' || c == '.' || c == '/';
    });
}

bool validateLogFile(const string& logFilePath) {
    struct stat buffer;
    if (stat(logFilePath.c_str(), &buffer) != 0) {
        // Try to create the log file if it does not exist
        ofstream logFile(logFilePath);
        if (!logFile.is_open()) {
            cerr << "invalid" << endl;
            return false;
        }
        logFile.close();
    } else if (!S_ISREG(buffer.st_mode)) {
        cerr << "invalid" << endl;
        return false;
    }
    return true;
}

void storeLogEntry(const LogAppendArgs& args, const string& logFilePath) {
    // Create a JSON object to represent the log entry
    json logEntry = {
        {"timestamp", args.timestamp},
        {"token", args.token},
        {"name", args.name},
        {"isEmployee", args.isEmployee},
        {"action", args.isArrival ? "arrival" : "departure"},
        {"room", args.room},
        {"logFile", args.logFile}
    };
    std::string key = get_key_from_env();
    // LINEBYLINE_encrypt(, key);
    // Check if the log file already exists
    // string logFilePath = "logs/" + args.logFile;


    // if (!fs::exists(logFilePath)) {
    //     // Count the number of files in the folder
    //     size_t fileCount = 0;
    //     for (const auto& entry : fs::directory_iterator("logs")) {
    //         if (fs::is_regular_file(entry.path())) {
    //             fileCount++;
    //         }
    //     }

    //     // If the number of files is 100 or more, throw an error
    //     if (fileCount >= 1) {
    //         throw runtime_error("Maximum number of log files reached. Cannot create new file.");
    //     }
    // }


    // Open the log file and append the JSON entry
    ofstream logFile(logFilePath, ios::app);
    if (!logFile.is_open()) {
        throw runtime_error("Unable to open log file");
    }

    logFile << (LINEBYLINE_encrypt(logEntry.dump() , key)) << endl;
    // cout<< "log entry stored successfully" << endl;
    logFile.close();
}

// Validate Batch File
bool isValidBatchFilePath(const string& batchFilePath) {
    if (batchFilePath.length() > 32) {
        throw invalid_argument("Batch file path should be less than 32 char");
    }
    return all_of(batchFilePath.begin(), batchFilePath.end(), [](char c) {
        return isalnum(c) || c == '_' || c == '.' || c == '/';
    });
}

// Print Log State
string printLogState(const string& logFilePath) {
    // Data structures to store the state
    set<string> employeesInCampus;
    set<string> guestsInCampus;
    map<int, set<string>> roomOccupants;
    string messages;

    // Read the log file
    ifstream logFile(logFilePath);
    if (!logFile.is_open()) {
        throw runtime_error("Unable to open log file");
    }

    string encrypted;
    while (getline(logFile, encrypted)) {
        std::string key = get_key_from_env(); 
        // cout<<"encryption key fetched successfullly for de"<<endl;
        // cout<<"encryption key fetched successfullly for de"<<endl;
        std::string line = LINEBYLINE_decrypt((encrypted), key);
        // cout<<line<<end/
        try {
            // Parse the log line as JSON
            json logEntry = json::parse(line);

            string name = logEntry.value("name", "");
            string action = logEntry.value("action", "");
            string roomStr = logEntry.value("room", "");
            int room = roomStr.empty() ? -1 : stoi(roomStr);

            bool isArrival = (action == "arrival");
            bool isEmployee = logEntry.value("isEmployee", false);

            // Process the data based on arrival or departure
            if (isArrival) {
                if (isEmployee) {
                    employeesInCampus.insert(name);
                } else {
                    guestsInCampus.insert(name);
                }

                // Add to room occupants if a room is specified
                if (room != -1) {
                    roomOccupants[room].insert(name);
                }
            } else if(!isArrival && room == -1){
                if (isEmployee) {
                    employeesInCampus.erase(name);
                } else {
                    guestsInCampus.erase(name);
                }

                // Remove from room occupants if a room is specified
                if (room != -1) {
                    roomOccupants[room].erase(name);
                    if (roomOccupants[room].empty()) {
                        roomOccupants.erase(room);
                    }
                }
            }
            else{
                // Remove from room occupants if a room is specified
                if (room != -1) {
                    roomOccupants[room].erase(name);
                    if (roomOccupants[room].empty()) {
                        roomOccupants.erase(room);
                    }
                }
            }
        } catch (const json::parse_error& e) {
            cerr << "JSON parse error: " << e.what() << endl;
        } catch (const json::type_error& e) {
            cerr << "JSON type error: " << e.what() << endl;
        } catch (const invalid_argument& e) {
            cerr << "Invalid argument: " << e.what() << endl;
        }
    }

    logFile.close();

    // Print employees in campus
    for (const auto& name : employeesInCampus) {
        messages += name + ",";
    }
    if (!employeesInCampus.empty()) {
        messages.pop_back(); // Remove trailing comma
    }
    messages += "\n";

    // Print guests in campus
    for (const auto& name : guestsInCampus) {
        messages += name + ",";
    }
    if (!guestsInCampus.empty()) {
        messages.pop_back(); // Remove trailing comma
    }
    messages += "\n";

    // Print room-by-room information
    for (const auto& room : roomOccupants) {
        messages += to_string(room.first) + ": ";
        for (const auto& name : room.second) {
            messages += name + ",";
        }
        if (!room.second.empty()) {
            messages.pop_back(); // Remove trailing comma
        }
        messages += "\n";
    }

    if (!messages.empty() && messages.back() == '\n') {
        messages.pop_back();
    }

    return messages;
}

string printLogRooms(const string& logFilePath, const string& name, bool isEmployee) {
    // Data structure to store the rooms visited
    vector<int> roomsInOrder;

    // Read the log file
    ifstream logFile(logFilePath);
    if (!logFile.is_open()) {
        throw runtime_error("Unable to open log file");
    }

    string encrypted;
    while (getline(logFile, encrypted)) {
        std::string key = get_key_from_env(); 
        // cout<<"encryption key fetched successfullly for de"<<endl;
        std::string line = LINEBYLINE_decrypt((encrypted), key);
        // cout<<line<<endl;
        // cout<<line<<endl;
        try {
            // Parse the log line as JSON
            json logEntry = json::parse(line);

            string entryName = logEntry.value("name", "");
            string action = logEntry.value("action", "");
            string roomStr = logEntry.value("room", "");
            int room = roomStr.empty() ? -1 : stoi(roomStr);
            bool entryIsEmployee = logEntry.value("isEmployee", false);

            // Check if the entry matches the specified name and type (employee or guest)
            if (entryName == name && entryIsEmployee == isEmployee) {
                // Only consider entries with a valid room number
                if (room != -1 && action == "arrival") {
                    // Add the room to the vector
                    roomsInOrder.push_back(room);
                }
            }
        } catch (const json::parse_error& e) {
            cerr << "JSON parse error: " << e.what() << endl;
        } catch (const json::type_error& e) {
            cerr << "JSON type error: " << e.what() << endl;
        } catch (const invalid_argument& e) {
            cerr << "Invalid argument: " << e.what() << endl;
        }
    }

    logFile.close();

    // Create the comma-separated list of rooms
    string messages;
    for (const auto& room : roomsInOrder) {
        messages += to_string(room) + ",";
    }
    if (!messages.empty()) {
        messages.pop_back(); // Remove trailing comma
    }

    return messages;
}

string printLogTime(const string& logFilePath, const string& name, bool isEmployee) {
    // Data structure to store the total time spent
    int totalTimeSpent = 0;
    int arrivalTime = -1;
    int currentTime = -1;

    // Read the log file
    ifstream logFile(logFilePath);
    if (!logFile.is_open()) {
        throw runtime_error("Unable to open log file");
    }

    string encrypted;
    while (getline(logFile, encrypted)) {
        std::string key = get_key_from_env(); 
        // cout<<"encryption key fetched successfullly for de"<<endl;
        std::string line = LINEBYLINE_decrypt((encrypted), key);
        // cout<<line<<endl;
        // cout<<line<<endl;
        try {
            // Parse the log line as JSON
            json logEntry = json::parse(line);

            string entryName = logEntry.value("name", "");
            string action = logEntry.value("action", "");
            string roomStr = logEntry.value("room", "");
            int room = roomStr.empty() ? -1 : stoi(roomStr);
            int timestamp = logEntry.value("timestamp", -1);
            bool entryIsEmployee = logEntry.value("isEmployee", false);

            // Check if the entry matches the specified name and type (employee or guest)
            if (entryName == name && entryIsEmployee == isEmployee) {
                if (action == "arrival" && room == -1) {
                    arrivalTime = timestamp;
                }
                else if (action == "departure" && room == -1) {
                    totalTimeSpent += (timestamp - arrivalTime);
                    arrivalTime = -1;
                }
            }

            currentTime = timestamp;
        } catch (const json::parse_error& e) {
            cerr << "JSON parse error: " << e.what() << endl;
        } catch (const json::type_error& e) {
            cerr << "JSON type error: " << e.what() << endl;
        } catch (const invalid_argument& e) {
            cerr << "Invalid argument: " << e.what() << endl;
        }
    }

    logFile.close();
    
    if (arrivalTime != -1) {
        totalTimeSpent += (currentTime - arrivalTime);
    }

    return to_string(totalTimeSpent);
}