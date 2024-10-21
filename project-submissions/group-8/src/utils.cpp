// utils.cpp
#include "utils.h"
#include <nlohmann/json.hpp>
#include <sys/stat.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
// #include <experimental/filesystem>
#include <unordered_map>
#include <set>
#include <map>

using json = nlohmann::json;
using namespace std;
// namespace fs = std::experimental::filesystem; // Aliasing for simplicity

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

    string line;
    long mostRecentTimestamp = 0;

    // Parse each line as a JSON object
    while (getline(logFile, line)) {
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

    string line;

    // Parse each line as a JSON object
    while (getline(logFile, line)) {
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
    string line;

    // Parse each line as a JSON object
    while (getline(logFile, line)) {
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
    string line;

    // Parse each line as a JSON object
    while (getline(logFile, line)) {
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
    string line;

    // Parse each line as a JSON object
    while (getline(logFile, line)) {
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

    logFile << logEntry.dump() << endl;
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

    string line;
    while (getline(logFile, line)) {
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

    string line;
    while (getline(logFile, line)) {
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

    string line;
    while (getline(logFile, line)) {
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