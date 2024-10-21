#include <iostream>
#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <cctype>

using namespace std;

// This struct holds the parsed data
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

void printParsedData(const ParsedData &data)
{
    std::cout << "Parsed Data:" << std::endl;
    std::cout << "A_flag: " << (data.A_flag ? "true" : "false") << std::endl;
    std::cout << "L_flag: " << (data.L_flag ? "true" : "false") << std::endl;
    std::cout << "T: " << data.T << std::endl;
    std::cout << "K: " << (data.K ? data.K : "nullptr") << std::endl;
    std::cout << "E: " << (data.E ? data.E : "nullptr") << std::endl;
    std::cout << "G: " << (data.G ? data.G : "nullptr") << std::endl;
    std::cout << "R: " << data.R << std::endl;
    std::cout << "log: " << (data.log ? data.log : "nullptr") << std::endl;
}
bool validate_timestamp(const char *ts)
{
    for (int i = 0; ts[i] != '\0'; i++)
    {
        if (!isdigit(ts[i]))
        {
            return false;
        }
    }

    int timestamp = atoi(ts);
    return timestamp >= 1 && timestamp <= 1073741823;
}
bool validate_token(const char *token)
{
    for (int i = 0; token[i] != '\0'; i++)
    {
        if (!isalnum(token[i]))
        {
            return false;
        }
    }
    return true;
}

bool validate_name(const char *name)
{
    for (int i = 0; name[i] != '\0'; i++)
    {
        if (!isalpha(name[i]))
        {
            return false;
        }
    }
    return true;
}

bool validate_room_id(const char *room_id)
{
    for (int i = 0; room_id[i] != '\0'; i++)
    {
        if (!isdigit(room_id[i]))
        {
            return false;
        }
    }
    int room = atoi(room_id);
    return room >= 0 && room <= 1073741823;
}

bool validate_log_file(const char *log_path)
{
    bool last_was_slash = false;
    bool last_was_period = false;
    bool contains_alnum = false;
    bool valid_relative_path = false;
    bool alnum_after_slash = false;
    int period_count = 0;

    for (int i = 0; log_path[i] != '\0'; i++)
    {
        char c = log_path[i];

        // Check for valid characters (alphanumeric, _, ., /)
        if (!isalnum(c) && c != '_' && c != '.' && c != '/')
        {
            return false;
        }

        if (c == '/')
        {
            if (last_was_slash)
            {
                return false;
            }
            last_was_slash = true;
            period_count = 0;
            last_was_period = false;
            alnum_after_slash = false;
        }
        else
        {
            last_was_slash = false;

            // Handle periods `.`
            if (c == '.')
            {
                period_count++;
                last_was_period = true;

                if (period_count > 2)
                {
                    return false;
                }
            }
            else
            {
                // Handle valid alphanumeric characters after `.` or `..`
                if (last_was_period && period_count == 1 && c == '/')
                {
                    valid_relative_path = true; // Valid `./` pattern
                }
                else if (last_was_period && period_count == 2 && c == '/')
                {
                    valid_relative_path = true; // Valid `../` pattern
                }
                else if (period_count > 0 && !valid_relative_path)
                {
                    return false;
                }

                period_count = 0;
                last_was_period = false;

                if (isalnum(c))
                {
                    contains_alnum = true;

                    if (alnum_after_slash && last_was_period)
                    {
                        return false; // No period can come after an alphanumeric string
                    }

                    alnum_after_slash = true;
                }
            }
        }
    }

    if (last_was_slash)
    {
        return false;
    }
    if (last_was_period)
    {
        return false;
    }

    if (!contains_alnum && !valid_relative_path)
    {
        return false;
    }
    return true;
}

void invalid(string s)
{
    cout << "invalid " << endl;
    exit(255);
}

void invalid_batch(string s)
{
    cout << "invalid " << endl;
}

ParsedData parse_input(int argc, char *argv[])
{
    ParsedData data;
    int option;
    optind = 1;
    // for (int i = 0; i < argc; i++) {
    //     cout << "Arg[" << i << "]: " << argv[i] << endl;
    // }
    // Parsing command-line options
    opterr = 0;
    while ((option = getopt(argc, argv, "T:K:E:G:ALR:")) != -1)
    {
        switch (option)
        {
        case 'T':
            if (!validate_timestamp(optarg))
                invalid("Timestamp");
            data.T = atoi(optarg);
            break;
        case 'K':
            if (!validate_token(optarg))
                invalid("token");
            data.K = optarg;
            break;
        case 'E':
            if (!validate_name(optarg))
                invalid("Employee");
            data.E = optarg;
            break;
        case 'G':
            if (!validate_name(optarg))
                invalid("Guest");
            data.G = optarg;
            break;
        case 'A':
            if (data.L_flag)
                invalid("");
            data.A_flag = true;
            break;
        case 'L':
            if (data.A_flag)
                invalid("");
            data.L_flag = true;
            break;
        case 'R':
            if (!validate_room_id(optarg))
                invalid("Room ID");
            data.R = atoi(optarg);
            break;

        default:
            invalid("");
        }
    }

    if (optind < argc)
    {
        // Validate the log file path
        if (!validate_log_file(argv[optind]))
        {
            invalid("Log file path");
        }

        // Ensure that the log file is the last argument
        data.log = argv[optind];
        if (optind + 1 < argc)
        {
            invalid("multiple log files");
        }
    }
    else
    {
        invalid("Missing log file");
    }
    // printParsedData(data);

    // Check if required arguments are present
    if (data.T == -1 || data.K == nullptr || (data.E == nullptr && data.G == nullptr) || (!data.A_flag && !data.L_flag))
    {
        invalid("not enough information is present in command");
    }

    return data;
}