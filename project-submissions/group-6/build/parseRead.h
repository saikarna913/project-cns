// #include<string>
// #include <vector>

// using namespace std;

// typedef struct {
//     const char* K = nullptr;
//     bool S_flag = false;
//     bool R_flag = false;
//     bool T_flag = false;
//     bool I_flag = false;
//     vector<const char*> E_names;
//     vector<const char*> G_names;
//     const char* log = nullptr;
// }ParsedData;

// bool validate_token(const char* token);

// bool validate_name(const char* name);

// bool validate_log_file(const char* log_path);

// void invalid();

// ParsedData parse_input(int argc, char* argv[]);

#include <string>
#include <vector>

using namespace std;

typedef struct
{
    const char *K = nullptr;
    bool S_flag = false;
    bool R_flag = false;
    bool T_flag = false;
    bool I_flag = false;
    bool E_flag = false;
    vector<const char *> E_names;
    vector<const char *> G_names;
    const char *log = nullptr;
} ParsedData;

bool validate_token(const char *token);

bool validate_name(const char *name);

bool validate_log_file(const char *log_path);

void invalid();

ParsedData parse_input(int argc, char *argv[]);