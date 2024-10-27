#include <bits/stdc++.h>
#include "utils.h"
#include <unistd.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <filesystem>

using namespace std;

std::string removeLeadingZeros(const std::string& str) {
    int s = str.size(), i=0;
    while(i<s && str[i] == '0') {
        i++;
    }
    if(i==s) return "0";
    else return str.substr(i);

}

// Log append and log read parsing functions (unchanged)
LogAppendArgs parseLogAppend(const string &message)
{
    LogAppendArgs parsedArgs = {};
    istringstream iss(message);
    string arg;
    vector<string> args;
    bool isarrival = false, isdept = false, isemp = false, isguest = false;

    while (iss >> arg)
    {
        args.push_back(arg);
    }


    bool b1=false,b2=false,b3=false,b4=false,b5=false,b6=false,b7=false;

    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "-T" && i + 1 < args.size()) {
            parsedArgs.timestamp = stol(args[++i]);
            b1=true;
        } else if (args[i] == "-K" && i + 1 < args.size()) {
            parsedArgs.token = args[++i];
            b2=true;
        } else if (args[i] == "-E" && i + 1 < args.size()) {
            parsedArgs.name = args[++i];
            parsedArgs.isEmployee = true;
            isemp = true;
            b3=true;
        } else if (args[i] == "-G" && i + 1 < args.size()) {
            parsedArgs.name = args[++i];
            parsedArgs.isGuest = true;
            isguest = true;
            b3=true;
        } else if (args[i] == "-A") {
            parsedArgs.isArrival = true;
            isarrival = true;
            b4=true;
        } else if (args[i] == "-L") {
            parsedArgs.isLeave = true;
            isdept = true;
            b4=true;
        } else if (args[i] == "-R" && i + 1 < args.size()) {
            string ss = args[++i];
            parsedArgs.room = removeLeadingZeros(ss);
        }
        else
        {
            parsedArgs.logFile = args[i];
        }
    }

    if(isemp && isguest){
        throw invalid_argument("Cannot be both employee and guest\n");
    }

    if(isarrival && isdept){
        throw invalid_argument("Cannot be both arrival and departure\n");
    }

    if(!(b1&&b2&&b3&&b4)){
        throw invalid_argument("invalid format\n");
    }

    // if(parsedArgs.isEmployee == false && parsedArgs.isGuest == false){
    //     throw invalid_argument("invalid, enter either employee or guest\n");
    // }
    // if(parsedArgs.isArrival == false && parsedArgs.isLeave == false){
    //     throw invalid_argument("invalid, enter either arrival or deparutre\n");
    // }

    return parsedArgs;
}


LogReadArgs parseLogRead(const string &message)
{
    LogReadArgs parsedArgs = {};
    istringstream iss(message);
    string arg;
    vector<string> args;

    while (iss >> arg)
    {
        args.push_back(arg);
    }

    bool isemp = false, isguest = false;

    for (size_t i = 0; i < args.size(); ++i)
    {
        if (args[i] == "-K" && i + 1 < args.size())
        {
            parsedArgs.token = args[++i];
        }
        else if (args[i] == "-S" && i + 1 < args.size())
        {
            parsedArgs.isState = true;
            parsedArgs.logFile = args[++i];
        }
        else if (args[i] == "-R")
        {
            parsedArgs.isRooms = true;
        }
        else if (args[i] == "-T")
        {
            parsedArgs.isTime = true;
        }
        else if (args[i] == "-I")
        {
            parsedArgs.isIntersection = true;
        }
        else if (args[i] == "-E" && i + 2 < args.size())
        {
            isemp = true;
            parsedArgs.employees.push_back(args[++i]);
            parsedArgs.logFile = args[++i];
        }
        else if (args[i] == "-G" && i + 2 < args.size())
        {
            isguest = true;
            parsedArgs.guests.push_back(args[++i]);
            parsedArgs.logFile = args[++i];
        }
        else{
            throw invalid_argument("invalid command or not implemented\n");
        }
    }

    if(isemp && isguest){
        throw invalid_argument("Cannot be both employee and guest\n");
    }

    return parsedArgs;
}

void appendLog(const LogAppendArgs &args)
{
    // Ensure the logs directory exists
    const string logDir = "logs";
    mkdir(logDir.c_str(), 0777);
    string logFilePath = logDir + "/" + args.logFile;

    // Validate log file
    if (!isValidLogFilePath(logFilePath))
    {
        throw invalid_argument("invalid log file\n");
    }

    if (!filesystem::exists(logFilePath))
    {
        std::ofstream logFile(logFilePath); // Creates the file if it doesn't exist
        if (!logFile) // Check if file creation was successful
        {
            throw std::runtime_error("Failed to create log file\n");
        }
        logFile.close();
    }

    // Validate timestamp
    if (!(validateTimestamp(args.timestamp, logFilePath) && isValidTimestamp(to_string(args.timestamp))))
    {
        throw invalid_argument("invalid timestamp\n");
    }

    // Validate token
    if (!(isValidToken(args.token)))
    {
        throw invalid_argument("invalid token\n");
    }

    // Validate token
    if (!validateToken(args.token, logFilePath))
    {
        throw invalid_argument("integrity violation\n");
    }

    // Validate employee name if applicable
    if (args.isEmployee && !isValidEmployeeName(args.name))
    {
        throw invalid_argument("invalid employee name\n");
    }

    // Validate guest name if applicable
    if (!args.isEmployee && !isValidGuestName(args.name))
    {
        throw invalid_argument("invalid guest name\n");
    }

    // Validate token
    if (!args.room.empty() && !(isValidRoomID(args.room)))
    {
        throw invalid_argument("invalid room number\n");
    }

    // Validate room event
    if (!args.room.empty() && !validateRoomEvent(args, logFilePath))
    {
        throw invalid_argument("invalid room event\n");
    }

    // Validate arrival
    if (args.isArrival && !validateArrival(args, logFilePath))
    {
        throw invalid_argument("invalid arrival event\n");
    }

    // Validate departure
    if (!args.isArrival && !validateDeparture(args, logFilePath))
    {
        throw invalid_argument("invalid departure event\n");
    }

    // Store the log entry
    storeLogEntry(args, logFilePath);
}

string findIntersection(const string &logFilePath, const vector<string> &employees, const vector<string> &guests)
{
    ifstream logFile(logFilePath);
    if (!logFile.is_open())
    {
        throw runtime_error("Unable to open log file");
    }

    map<string, set<string>> roomOccupants; // Map room -> set of occupants (employees/guests)
   string encrypted;
    while (getline(logFile, encrypted)) {
        std::string key = get_key_from_env(); 
        std::string line = LINEBYLINE_decrypt(encrypted, key);

        
        LogAppendArgs logEntry = parseLogAppend(line);

        if (logEntry.isArrival)
        {
            // Add employee or guest to the room
            if (logEntry.isEmployee)
            {
                roomOccupants[logEntry.room].insert(logEntry.name);
            }
            else if (logEntry.isGuest)
            {
                roomOccupants[logEntry.room].insert(logEntry.name);
            }
        }
        else if (logEntry.isLeave)
        {
            // Remove employee or guest from the room
            roomOccupants[logEntry.room].erase(logEntry.name);
        }
    }

    stringstream result;
    for (const auto &room : roomOccupants)
    {
        set<string> commonOccupants;

        // Check if both employees and guests are in the same room
        for (const string &employee : employees)
        {
            if (room.second.find(employee) != room.second.end())
            {
                for (const string &guest : guests)
                {
                    if (room.second.find(guest) != room.second.end())
                    {
                        commonOccupants.insert(employee);
                        commonOccupants.insert(guest);
                    }
                }
            }
        }

        if (!commonOccupants.empty())
        {
            result << "Room: " << room.first << " has common occupants: ";
            for (const auto &name : commonOccupants)
            {
                result << name << " ";
            }
            result << "\n";
        }
    }

    if (result.str().empty())
    {
        return "No intersection found.\n";
    }

    return result.str();
}

string readLog(const LogReadArgs &args)
{
    // Ensure the logs directory exists
    const string logDir = "logs";
    mkdir(logDir.c_str(), 0777);
    string logFilePath = logDir + "/" + args.logFile;
    string message;
    // Validate log file
    if (!(isValidLogFilePath(logFilePath)))
    {
        throw invalid_argument("invalid log file format");
    }

    if (!filesystem::exists(logFilePath))
    {
        throw runtime_error("Log file does not exist");
    }

    // Validate token
    if (!validateToken(args.token, logFilePath))
    {
        throw invalid_argument("integrity violation");
    }

    // Read the log file
    ifstream logFile(logFilePath);
    if (!logFile.is_open())
    {
        throw runtime_error("Unable to open log file");
    }

    if (args.isState && !args.isRooms && !args.isTime)
    {
        message = printLogState(logFilePath);
    }

    else if (!args.isState && args.isRooms && !args.isTime)
    {
        if (!args.employees.empty())
        {
            message = printLogRooms(logFilePath, args.employees[0], true);
        }
        else
        {
            message = printLogRooms(logFilePath, args.guests[0], false);
        }
    }

    else if (!args.isState && !args.isRooms && args.isTime)
    {
        if (!args.employees.empty())
        {
            message = printLogTime(logFilePath, args.employees[0], true);
        }
        else
        {
            message = printLogTime(logFilePath, args.guests[0], false);
        }
    }
    else{
        throw invalid_argument("invalid command or not implemented\n");
    }

    if (args.isIntersection)
    {
        message = "Unimplemented\n";
    }

    return message;
}

// SSL context creation and configuration
SSL_CTX *create_context()
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    // Load the server's certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Check this part
    // // Load the CA certificate to verify client certificates
    // if (SSL_CTX_load_verify_locations(ctx, "ca-cert.pem", NULL) <= 0) {
    //     ERR_print_errors_fp(stderr);
    //     exit(EXIT_FAILURE);
    // }

    // // Require clients to provide a certificate
    // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
}

// Secure client handling with SSL
void handleClient(SSL *ssl)
{
    // Perform SSL handshake
    if (SSL_accept(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
    }
    else
    {
        // Welcome message and guide to commands
        string welcomeMessage = "\nWelcome to the Log Server!\n"
                                "Available commands:\n"
                                "1. logappend -T <timestamp> -K <token> [-A | -L] [-R <room> | <> for campus] [-E <employee_name> | -G <guest_name>] <logfile>\n"
                                "   Example: logappend -T 1 -K s1 -A -E Alice log1\n"
                                "2. logappend -B <file>\n"
                                "3. logread -K <token> [-S | -R | -T] [-E <employee_name> | -G <guest_name>] <logfile>\n"
                                "   Example: logread -K s1 -S log1\nEnter a command\n";
        SSL_write(ssl, welcomeMessage.c_str(), welcomeMessage.length());

        bool b = true;
        while (true)
        {
            if (!b)
            {
                string countMessage = "\nPlease wait for 1 second\n";
                SSL_write(ssl, countMessage.c_str(), countMessage.length());
                sleep(1);
                string promptMessage = "Enter another command now\n";
                SSL_write(ssl, promptMessage.c_str(), promptMessage.length());
            }
            b = false;

            char buffer[1024] = {0};
            int valread = SSL_read(ssl, buffer, 1024);

            if (valread > 0)
            {
                string message(buffer);
                if (message.find("logappend -B") == 0)
                {                                    // This is for the batch file
                    std::istringstream iss(message); // Create a stream from the string

                    std::string command, option, filePath;
                    iss >> command >> option >> filePath; // Extract command, option, and file path

                    if (!filePath.empty())
                    {
                        std::ifstream file(filePath); // Open the file
                        if (file.is_open())
                        {
                            std::string line;

                            // Loop through every line in the file
                            while (std::getline(file, line))
                            {
                                string response = "Reading: " + line + "\n";
                                SSL_write(ssl, response.c_str(), response.length());
                                
                                // LogAppendArgs args = parseLogAppend(line); // Pass each line to parseLogAppend
                                // appendLog(args);
                                try
                                {
                                    LogAppendArgs args = parseLogAppend(line); // Pass each line to parseLogAppend
                                    appendLog(args); // Try to append the log
                                    response = "Log appended successfully\n";
                                }
                                catch (const std::exception& e)
                                {
                                    // Log the error message and continue to the next line
                                    response = std::string("Error appending log: ") + e.what() + "\n";
                                }
                                // response = "Log appended successfully\n";
                                SSL_write(ssl, response.c_str(), response.length());
                                sleep(1);
                            }

                            file.close(); // Close the file when done
                        }
                        else{
                            string response = "No such batch file exists. Please Note: Enter the file path relative to the build folder\n";
                            SSL_write(ssl, response.c_str(), response.length());
                            sleep(1);
                        }
                    }
                }
                else if (message.find("logappend") == 0)
                {
                    try
                    {
                        if(message.size() < 10){
                            throw invalid_argument("Invalid command\n");
                        }
                        LogAppendArgs args = parseLogAppend(message.substr(10)); // Remove "logappend " prefix
                        appendLog(args);
                        string response = "Log appended successfully\n";
                        SSL_write(ssl, response.c_str(), response.length());
                    }
                    catch (const invalid_argument &e)
                    {
                        string response = e.what();
                        SSL_write(ssl, response.c_str(), response.length());
                    }
                    catch (const runtime_error &e)
                    {
                        string response = e.what();
                        SSL_write(ssl, response.c_str(), response.length());
                    }
                }
                else if (message.find("logread") == 0)
                {
                    try
                    {
                        if(message.size() < 8){
                            throw invalid_argument("Invalid command\n");
                        }
                        LogReadArgs args = parseLogRead(message.substr(8)); // Remove "logread " prefix
                        string logMessage = readLog(args);
                        SSL_write(ssl, logMessage.c_str(), logMessage.length());
                    }
                    catch (const invalid_argument &e)
                    {
                        string response = e.what();
                        SSL_write(ssl, response.c_str(), response.length());
                    }
                    catch (const runtime_error &e)
                    {
                        string response = e.what();
                        SSL_write(ssl, response.c_str(), response.length());
                    }
                }
                else
                {
                    string response = "Invalid command or not implemented\n";
                    SSL_write(ssl, response.c_str(), response.length());
                }
            }
            else
            {
                cout << "Failed to read message or connection closed" << endl;
                break;
            }
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl); // Free SSL structure
}

int main()
{
    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    store_key_in_env();
    // Create and configure SSL context
    SSL_CTX *ctx = create_context();
    configure_context(ctx); // Existing function to load server cert/key

    // Check this part
    // // Load the CA certificate to verify the client certificate
    // if (SSL_CTX_load_verify_locations(ctx, "ca-cert.pem", nullptr) <= 0) {
    //     ERR_print_errors_fp(stderr);
    //     exit(EXIT_FAILURE);
    // }

    // // Require client certificate
    // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);

    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attach socket to the port 6969
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(6969);

    // Bind the socket to the network address and port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, 3) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    // Print server information
    cout << "Server listening on your localhost, use ./client to use commands" << endl;

    int num_con = 0;

    while (true) {

        // Accept incoming client connections
        new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
        if (new_socket < 0)
        {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        if(num_con == 35){
            cout<<"Maximum number of client connections reached\n";
            continue;
        }
        num_con++;
        // Create an SSL structure for the connection
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, new_socket);

        // Create a new thread to handle the client connection
        thread clientThread(handleClient, ssl);
        clientThread.detach(); // Detach thread to allow it to run independently
    }

    // Clean up
    close(server_fd);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}
