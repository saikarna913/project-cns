#include <string>

using namespace std;

typedef struct
{
    bool A_flag = false;
    bool L_flag = false;
    int T = -1;
    const char *K = nullptr;
    const char *E = nullptr;
    const char *G = nullptr;
    int R = -1;
    const char *log = nullptr;
} ParsedData;

bool validate_timestamp(const char *ts);

bool validate_token(const char *token);

bool validate_name(const char *name);

bool validate_room_id(const char *room_id);

bool validate_log_file(const char *log_path);

void invalid(string s);
void invalid_batch(string s);

ParsedData parse_input(int argc, char *argv[]);