#include <bits/stdc++.h>
#include <unistd.h>
#include <arpa/inet.h>
//#include <winsock2.h>
#include <sys/time.h>
using namespace std;
#define PORT 8080
#define Secret_key 1234
#include "ciphering.cpp"
#include "input_validation.cpp"

// Get current time in milliseconds
long long current_time_in_ms()
{
    struct timeval time_now;
    gettimeofday(&time_now, NULL);
    return (time_now.tv_sec * 1000LL) + (time_now.tv_usec / 1000);
}

bool build_connection(int &sockfd){

    struct sockaddr_in server_addr;

    // Create TCP socket
    if (sockfd < 0) {
        perror("Socket creation failed");
        return false;
    }

    // Server address setup
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Connect to the server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        return false;
    }
    return true;
}

void send_info(string &s, int &sockfd){

    string encript_str =str_encription(s);
    send(sockfd, encript_str.c_str(), encript_str.size(), 0);
    cout << "Message sent to server" << endl;
}

int Client(string info){
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(build_connection(sockfd) ==false){
        close(sockfd);
        return 255;
    }
    
    string info_type,info_key,info_path;
    long long start_time = current_time_in_ms();

    send_info(info, sockfd);
    
    char recieved_info[1000];
    int n = read(sockfd, recieved_info, 999);
    recieved_info[n] = '\0';
    string decript_str =str_decription(string(recieved_info));
    if (n < 0) {
        perror("failed");
        close(sockfd);
        return 255;
    }
    cout << decript_str << endl;

    long long end_time = current_time_in_ms();

    // Calculate RTT
    long long rtt = end_time - start_time;
    cout << ("RTT: %lld ms\n", rtt) << endl;

    close(sockfd);
    return 0;
}

int main(int argc, char *argv[]) {
    string info="";
    info +=string(argv[0]);
    info =info.substr(2,info.length()-2);
    for (int i = 1; i < argc; i++) {
        info +=" ";
        info +=string(argv[i]);
    }
    if(!input_validation(info)){
        cout<<"Not valid info";
        return 255;
    }
    if(string(argv[0])=="./logappend" && string(argv[1])=="-B"){
        string filepath=string(argv[2]);
        ifstream file(filepath);
        if(!file.is_open()){
            cout<<"Invalid";
            return 255;
        }
        string line;
        while(getline(file,line)){
            line="logappend "+line;
            Client(line);
        }
        file.close();
    }
    else return Client(info);
    return 0;
}