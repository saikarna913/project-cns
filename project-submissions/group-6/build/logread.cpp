#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <vector>
#include <sstream>
#include <algorithm>
#include "parseRead.h"
#include "security.h"

using namespace std;

// Structure to hold information of each person (employee/guest)
struct PersonInfo
{
    string name;
    bool isEmployee;                          // true if employee, false if guest
    vector<pair<string, string>> roomHistory; // room visits: <roomId, timestamp>
    vector<string> roomEntries;               // List to store all rooms entered over the history
};

struct TimeInfo
{
    string entryTimestamp;
    string exitTimestamp;
    int totalTime = 0; // Total time spent
};

// Function to read the log file and construct the data structure
void readLogFile(const string &token, const string &logFile, map<string, PersonInfo> &campusState, set<string> &employees, set<string> &guests, map<string, TimeInfo> &timeTracking, string &latestTimestamp)
{
    ifstream log(logFile);

    if (!log.is_open())
    {
        cerr << "Unable to open log file." << endl;
        exit(255);
    }
    // cout << "inside" << endl;
    SecureLogger logger;

    // uncomment the following line and pass the token and fileppath as strings
    logger.init(token, logFile);
    // cout << "inside1" << endl;
    // logger.encrypt_log_file();

    unsigned char *decrypted_data = logger.decrypt_log();
    // cout << "inside2" << endl;

    unsigned long long leng = logger.get_plaintext_len();
        char newarray[leng];
        for (unsigned long long i = 0; i < leng; i++)
                {
                    newarray[i] = decrypted_data[i];
                }


    
    // cout << "Decrypted: " << reinterpret_cast<const char *>(newarray) << endl;

    // Convert decrypted_data to a string for easier line-by-line processing
    string decryptedString(reinterpret_cast<const char *>(newarray));
    // cout << decryptedString << endl;
    // Now we'll process the decrypted string line by line using a stringstream
    stringstream logStream(decryptedString);
    string line;

    while (getline(logStream, line))
    {
        stringstream ss(line);
        // T: 1 K: token1 E: Fred G: null R: -1 A_flag: true L_flag: false
        string T, timestamp, K, token, E, employee, G, guest, R, roomId, A, a_flag_str, L, l_flag_str;
        bool A_flag, L_flag;

        // Extract the fields from the log line
        ss >> T >> timestamp >> K >> token >> E >> employee >> G >> guest >> R >> roomId >> A >> a_flag_str >> L >> l_flag_str;

        // cout << timestamp << " " << token << " " << employee << " " << guest << " " << roomId << " " << a_flag_str << " " << l_flag_str << endl;
        // Parsing the values
        // timestamp = timestamp.substr(2);  // Remove "T:"
        // token = token.substr(2);          // Remove "K:"
        // employee = employee.substr(2);    // Remove "E:"
        // guest = guest.substr(2);          // Remove "G:"
        // roomId = roomId.substr(2);        // Remove "R:"
        // a_flag_str = a_flag_str.substr(8); // Remove "A_flag:"
        // l_flag_str = l_flag_str.substr(8); // Remove "L_flag:"

        // Convert A_flag and L_flag from string to boolean
        A_flag = (a_flag_str == "true");
        L_flag = !A_flag;

        latestTimestamp = timestamp; // Update the latest timestamp

        // Determine whether it's an employee or guest
        bool isEmployee = (employee != "null");
        string name = isEmployee ? employee : guest;

        // Track entry and exit timestamps in the timeTracking map
        if (roomId == "-1")
        { // Entering or leaving the campus
            if (A_flag)
            {
                // If a person enters, store the entry timestamp
                timeTracking[name].entryTimestamp = timestamp;
            }
            else if (L_flag)
            {
                // If a person exits, calculate the time spent and update the total
                if (!timeTracking[name].entryTimestamp.empty())
                {
                    timeTracking[name].exitTimestamp = timestamp;

                    // Calculate time difference and update total time
                    int duration = stoi(timeTracking[name].exitTimestamp) - stoi(timeTracking[name].entryTimestamp);
                    timeTracking[name].totalTime += duration;

                    // Clear the entry timestamp for future entries
                    timeTracking[name].entryTimestamp.clear();
                    timeTracking[name].exitTimestamp.clear();
                }
            }
        }

        // Update campus state
        if (isEmployee)
        {
            if (A_flag && roomId == "-1")
                employees.insert(name);
            else if (L_flag && roomId == "-1")
                employees.erase(name);
        }
        else
        {
            if (A_flag && roomId == "-1")
                guests.insert(name);
            else if (L_flag && roomId == "-1")
                guests.erase(name);
        }
        
        // Track room history if it's not the campus entry (-1)
        if (roomId != "-1")
        {
            campusState[name].name = name;
            campusState[name].isEmployee = isEmployee;

            // If it's an arrival, log the room and update the history
            if (A_flag)
            {
                campusState[name].roomHistory.push_back({roomId, timestamp});
                campusState[name].roomEntries.push_back(roomId); // Track all rooms entered
            }
            else if (L_flag)
            {
                // If leaving, remove the last room entry
                if (!campusState[name].roomHistory.empty())
                {
                    campusState[name].roomHistory.pop_back();
                }
            }
        }
    }

    // log.close();
}

// Function to print the current state of the log (for -S option)
void printState(const set<string> &employees, const set<string> &guests, const map<string, PersonInfo> &campusState)
{
    // Print employees currently in the campus
    for (auto it = employees.begin(); it != employees.end(); ++it)
    {
        cout << *it;
        if (next(it) != employees.end())
            cout << ", ";
    }
    cout << endl;

    // Print guests currently in the campus
    for (auto it = guests.begin(); it != guests.end(); ++it)
    {
        cout << *it;
        if (next(it) != guests.end())
            cout << ", ";
    }
    cout << endl;

    // Prepare a map to store people present in each room
    map<string, vector<string>> rooms;

    // Iterate over each person in campusState and record room visits
    for (const auto &entry : campusState)
    {
        const string &name = entry.first;
        const auto &roomHistory = entry.second.roomHistory;

        // If the room history is not empty, get the last visited room
        if (!roomHistory.empty())
        {
            const auto &lastVisit = roomHistory.back(); // Get last room visited
            rooms[lastVisit.first].push_back(name);     // Add person to the respective room
        }
    }

    // Print the room-wise occupancy in ascending order
    for (const auto &room : rooms)
    {
        if (stoi(room.first) >= 0)
        {
            cout << room.first << ": "; // Print room ID
            for (auto it = room.second.begin(); it != room.second.end(); ++it)
            {
                cout << *it;
                if (next(it) != room.second.end())
                    cout << ", "; // Print comma between people but not after the last one
            }
            cout << endl;
        }
    }
}

// Function to print the history of rooms visited by a person (employee/guest)
void printRoomHistory(const string &name, const map<string, PersonInfo> &campusState, const set<string> &employees, const set<string> &guests, bool checkEmployee)
{

    // Check if the person is an employee or a guest based on the flag
    if (checkEmployee && employees.find(name) == employees.end())
    {
        cout << name << " not an employee." << endl; // Output invalid if the person is not an employee
        return;
    }
    else if (!checkEmployee && guests.find(name) == guests.end())
    {
        cout << name << " not a guest." << endl; // Output invalid if the person is not a guest
        return;
    }

    // Check if the person exists in campusState
    if (campusState.find(name) == campusState.end())
    {
        // cout << "not in any room" << endl; // Output invalid if the person is not found
        return;
    }
    // Get the person's room entries
    const auto &personInfo = campusState.at(name);
    const auto &roomsVisited = personInfo.roomEntries;

    // Print room history as comma-separated values
    if (roomsVisited.empty())
    {
        cout << "" << endl; // If no rooms visited, return "invalid"
    }
    else
    {
        for (size_t i = 0; i < roomsVisited.size(); ++i)
        {
            if (stoi(roomsVisited[i]) >= 0)
            {
                cout << roomsVisited[i];
                if (i != roomsVisited.size() - 1)
                    cout << ",";
            }
        }
        cout << endl;
    }
}

void printTotalTime(const string &name, const map<string, TimeInfo> &timeTracking, const string &latestTimestamp, const set<string> &employees, const set<string> &guests, bool checkEmployee)
{
    // Check if the person is an employee or a guest based on the flag
    if (checkEmployee && employees.find(name) == employees.end())
    {
        cout << name << " is not an employee." << endl; // Output invalid if the person is not an employee
        return;
    }
    else if (!checkEmployee && guests.find(name) == guests.end())
    {
        cout << name << " is not a guest." << endl; // Output invalid if the person is not a guest
        return;
    }

    // Check if the person exists in timeTracking
    if (timeTracking.find(name) == timeTracking.end())
    {
        cout << "" << endl; // Output invalid if the person is not found
        return;
    }

    const auto &timeInfo = timeTracking.at(name);
    int totalTime = timeInfo.totalTime;
    // If the person is currently inside (no exit timestamp), calculate time till now
    if (!timeInfo.entryTimestamp.empty())
    {
        totalTime += stoi(latestTimestamp) - stoi(timeInfo.entryTimestamp);
    }

    cout << totalTime << endl;
}
void printCommonRooms(const vector<pair<string, bool>> &names, const map<string, PersonInfo> &campusState, const set<string> &employees, const set<string> &guests)
{
    // Map of roomId -> vector of (entry, exit) intervals for each person
    map<string, vector<pair<int, int>>> roomOccupancy;
    // cout<<"check1"<<endl;
    for (const auto &namePair : names)
    {
        const string &name = namePair.first;
        bool isEmployee = namePair.second;

        // Check if the person is in campusState
        if (campusState.find(name) == campusState.end())
        {
            continue; // If the person is not found, ignore
        }

        // Check if the person is an employee or guest based on the flag
        if (isEmployee && employees.find(name) == employees.end())
        {
            cout << name << " is not an employee." << endl;
            return;
        }
        else if (!isEmployee && guests.find(name) == guests.end())
        {
            cout << name << " is not a guest." << endl;
            return;
        }

        const auto &personInfo = campusState.at(name);
        const auto &roomHistory = personInfo.roomHistory; // roomHistory contains {roomId -> timestamp}
        // cout<<"check2"<<endl;
        // Iterate through room history
        for (size_t i = 0; i < roomHistory.size(); ++i)
        {
            const string &roomId = roomHistory[i].first;
            int entryTime = stoi(roomHistory[i].second); // Get entry time

            int exitTime = (i + 1 < roomHistory.size()) ? stoi(roomHistory[i + 1].second) : INT_MAX; // Get exit time, or INT_MAX if no exit timestamp is found

            // Add the entry-exit interval to the roomOccupancy map
            roomOccupancy[roomId].push_back({entryTime, exitTime});
            // cout<<namePair.first<<" "<<entryTime<<" "<<exitTime<<endl;
        }
    }

    // Find common rooms where the time intervals overlap for all persons
    vector<string> commonRooms;

    for (const auto &entry : roomOccupancy)
    {
        const string &roomId = entry.first;
        const auto &intervals = entry.second;

        // If not all persons were in this room, skip
        if (intervals.size() != names.size())
        {
            continue;
        }

        // Find the overlapping interval of all persons in this room
        int commonEntryTime = -1, commonExitTime = INT_MAX;

        for (const auto &interval : intervals)
        {
            commonEntryTime = max(commonEntryTime, interval.first); // Get the latest entry time
            commonExitTime = min(commonExitTime, interval.second);  // Get the earliest exit time
        }

        // If there's a valid overlap, add the room to the commonRooms
        if (commonEntryTime < commonExitTime)
        {
            commonRooms.push_back(roomId);
        }
    }

    // Print the common rooms in ascending order
    if (!commonRooms.empty())
    {
        sort(commonRooms.begin(), commonRooms.end());
        for (size_t i = 0; i < commonRooms.size(); ++i)
        {
            cout << commonRooms[i];
            if (i != commonRooms.size() - 1)
                cout << ",";
        }
        cout << endl;
    }
    else
    {
        cout << endl; // No common rooms found
    }
}


int main(int argc, char *argv[])
{
    if (sodium_init() < 0)
    {
        cerr << "Failed to initialize sodium" << endl;
        return 1;
    }

    if (argc < 4)
    {
        cout << "invalid" << endl;
        return 255;
    }

    // string token = argv[2];
    string logFile = argv[argc - 1];
    logFile = logFile.append(".txt");
    ParsedData data;

    data = parse_input(argc, argv);
    string token = data.K;
    // string token = "Break the system ";
    map<string, PersonInfo> campusState;
    set<string> employees;
    set<string> guests;
    map<string, TimeInfo> timeTracking;
    string latestTimestamp = "10"; // Variable to hold the latest timestamp
    // cout << "Started" << endl;
    readLogFile(token, logFile, campusState, employees, guests, timeTracking, latestTimestamp);
    // cout << "Ended" << endl;
    string option;
    if (data.S_flag)
    {
        option = "-S";
    }
    else if (data.R_flag)
    {
        option = "-R";
    }
    else if (data.T_flag)
    {
        option = "-T";
    }
    else if (data.I_flag)
    {
        option = "-I";
    }
    else
    {
        cout << "invalid" << endl;
        return 255;
    }

    if (option == "-S")
    {
        // cout<<"Started"<<endl;
        printState(employees, guests, campusState);
    }
    else if (option == "-R")
    {
        bool checkEmployee = data.E_flag;
        string name;
        if (checkEmployee)
        {
            name = data.E_names[data.E_names.size() - 1];
        }
        else
        {
            name = data.G_names[data.G_names.size() - 1];
        }
        printRoomHistory(name, campusState, employees, guests, checkEmployee);
    }
    else if (option == "-T")
    {
        bool checkEmployee = data.E_flag;
        string name;
        if (checkEmployee)
        {
            name = data.E_names[data.E_names.size() - 1];
        }
        else
        {
            name = data.G_names[data.G_names.size() - 1];
        }
        printTotalTime(name, timeTracking, latestTimestamp, employees, guests, checkEmployee);
    }
    else if (option == "-I")
    {
        vector<pair<string, bool>> names; // To hold (name, isEmployee)
        for (int i = 0; i < data.E_names.size();i++)
        {
            names.push_back({data.E_names[i], true});
        }
        for (int i = 0; i < data.G_names.size(); i++)
        {
            names.push_back({data.G_names[i], false});
        }
        // cout<<"Started"<<endl;   
        // Call the function to print common rooms
        printCommonRooms(names, campusState, employees, guests);
    }
    else
    {
        cout << "invalid" << endl;
        return 255;
    }

    return 0;
}