#include <bits/stdc++.h>
using namespace std;

bool is_alphanumeric(const string &s) {
    for (char c : s) {
        if (!isalnum(c)) return false;
    }
    return true;
}

bool is_alpha(const string &s) {
    for (char c : s) {
        if (!isalpha(c)) return false;
    }
    return true;
}

bool is_valid_number(const string &s) {
    if (s.empty() || (!isdigit(s[0]) && s[0] != '-')) return false;
    for (int i = 1; i < s.size(); i++) {
        if (!isdigit(s[i])) return false;
    }
    return true;
}
bool is_number(string &s){
    for(int i=0;i<s.size();i++){
        if(!isdigit(s[i])) return false;
    }
    return true;
}
bool validate_I(vector<string> &tokens){
    bool hasToken = false, hasLogFile = false, hasGuest=false;string currentFlag = "";
    for(int i=1;i<tokens.size();i++){
        string token = tokens[i];
        if (token == "-K") {
            if (i + 1 >= tokens.size() || !is_alphanumeric(tokens[i+1])) {
                cout << "1" << endl;
                return false;
            }
            hasToken = true;
            i++;
        }else if (token == "-E" || token == "-G") {
            if (i + 1 >= tokens.size() || !is_alpha(tokens[i+1])) {
                cout << "3" << endl;
                return false;
            }
            hasGuest=true;
            i++; 
        } else if (token == "-I") {
            if (!currentFlag.empty()) {
                return false;
            }
            currentFlag = token;
        }else {
            if(hasLogFile==true){
                cout << "5" << endl;
                return false;
            }
            hasLogFile = true;
        }
    }
    if (!hasToken || !hasLogFile || currentFlag.empty()||!hasGuest) {
            return false;
    }
    return true;
}
bool batch_validation(string &s);
bool input_validation(string &s) {
    vector<string> tokens;
    stringstream ss(s);
    string word;

    while (ss >> word) {
        tokens.push_back(word);
    }
    if(tokens.size()<3) return false;
    if(tokens[0]=="logappend" && tokens[1]=="-B"){
        return batch_validation(s);
    }
    if (tokens.size() < 5) {
        cout << "0" << endl;
        return false;
    }

    string logCommand = tokens[0];
    bool hasToken = false, hasLogFile = false, hasTimestamp = false, hasGuest=false;
    string currentFlag = "";
    if (logCommand == "logread") {
        for(int i=1;i<tokens.size();i++){
            if(tokens[i]=="-I") return validate_I(tokens);
        }
        for (int i = 1; i < tokens.size(); ++i) {
            string token = tokens[i];

            if (token == "-K") {
                if (i + 1 >= tokens.size() || !is_alphanumeric(tokens[i+1])) {
                    cout << "1" << endl;
                    return false;
                }
                hasToken = true;
                i++;
            } else if (token == "-S") {
                if (!currentFlag.empty()) {
                    cout << "2" << endl;
                    return false;
                }
                hasGuest=true;
                currentFlag = token;
            } else if(token == "-R"||token=="-I"){
                if(!currentFlag.empty()) return false;
                currentFlag=token;
            }
            else if (token == "-E" || token == "-G") {
                if(hasGuest==true ) return false;
                if (i + 1 >= tokens.size() || !is_alpha(tokens[i+1])) {
                    cout << "3" << endl;
                    return false;
                }
                hasGuest=true;
                i++; 
            } else if (token=="-T"){
                if (!currentFlag.empty()) {
                    cout << "4" << endl;
                    return false;
                }
                currentFlag = token;
                if(is_number(tokens[i+1])) i++;
            }
            else {
                if(hasLogFile==true){
                    cout << "5" << endl;
                    return false;
                }
                hasLogFile = true;
            }
        }

        if (!hasToken || !hasLogFile || currentFlag.empty()||!hasGuest) {
            return false;
        }
        return true;

    } else if (logCommand == "logappend") {
        for (int i = 1; i < tokens.size(); ++i) {
            string token = tokens[i];
            if (token == "-T") {
                if (i + 1 >= tokens.size() || !is_valid_number(tokens[i+1])) {
                    return false;
                }
                if(tokens[i+1]=="0") return false;
                hasTimestamp = true;
                i++;
            } else if (token == "-K") {
                if (i + 1 >= tokens.size() || !is_alphanumeric(tokens[i+1])) {
                    return false; 
                }
                hasToken = true;
                i++;
            } else if (token == "-E" || token == "-G") {
                if(hasGuest==true) return false;
                if (i + 1 >= tokens.size() || !is_alpha(tokens[i + 1])) {
                    return false; 
                }
                hasGuest=true;
                i++;
            } else if (token == "-A" || token == "-L") {
                if (currentFlag == "-A" || currentFlag == "-L") {
                    return false;
                }
                currentFlag = token;
            } else if (token == "-R") {
                if (i + 1 >= tokens.size() || !is_valid_number(tokens[i+1])){
                    return false;
                }
                i++;
            } else {
                if(hasLogFile==true) return false;
                hasLogFile = true;
            }
        }
        if (!hasToken || !hasLogFile || !hasTimestamp || currentFlag.empty()) {
            return false;
        }
        return true;

    } else {
        return false;
    }
}

bool batch_validation(string &s){
    vector<string> tokens;
    stringstream ss(s);
    string word;

    while (ss >> word) {
        tokens.push_back(word);
    }
    ifstream batch(tokens[2]);
    if (!batch.is_open()) {
        std::cerr << "Error opening file!" << std::endl;
        return 1;
    }
    string line;
    while (getline(batch,line))
    {
       line = "logappend "+line;
       if(!input_validation(line)){
            batch.close();
            return false;
       }
    }
    batch.close();
    return true;
}