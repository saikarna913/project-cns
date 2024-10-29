// utils.h
#ifndef UTILS_H
#define UTILS_H

#include <vector>
#include <string>

using namespace std;

struct LogAppendArgs {
    long timestamp = 0;
    string token;
    string name;
    string room;
    string logFile;
    string fileContents;
    bool isEmployee = false;
    bool isGuest = false;
    bool isArrival = false;
    bool isLeave = false;
    bool isFile = false;
    string file;
};

struct LogReadArgs {
    string token;
    string logFile;
    bool isState = false;
    bool isRooms = false;
    bool isTime = false;
    bool isIntersection = false;
    vector<string> employees;
    vector<string> guests;
};

bool isValidInteger(const string& str);
bool isValidTimestamp(const string& timestamp);
bool isValidToken(const string& token);
bool isValidEmployeeName(const string& name);
bool isValidGuestName(const string& name);
bool isValidRoomID(const string& roomID);
bool isValidLogFilePath(const string& logFilePath);
bool isValidBatchFilePath(const string& batchFilePath);

bool validateTimestamp(const long timestamp, const string& logFilePath);
bool validateToken(const string& token, const string& logFilePath);
bool validateArrival(const LogAppendArgs& args, const string& logFilePath);
bool validateDeparture(const LogAppendArgs& args, const string& logFilePath);
bool validateRoomEvent(const LogAppendArgs& args, const string& logFilePath);
bool validateLogFile(const string& logFilePath);

void storeLogEntry(const LogAppendArgs& args, const string& logFilePath);
string printLogState(const string& logFilePath);
string printLogRooms(const string& logFilePath, const string& name, const bool isEmployee);
string printLogTime(const string& logFilePath, const string& name, bool isEmployee);
std::string base64_encode(const std::string &in);
std::string base64_decode(const std::string &in);
std::string LINEBYLINE_encrypt(const std::string &plaintext, const std::string &key);
std::string LINEBYLINE_decrypt(const std::string &ciphertext, const std::string &key);
void store_key_in_env();
std::string get_key_from_env();
#endif // UTILS_H