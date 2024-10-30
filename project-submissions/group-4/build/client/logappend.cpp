#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <sstream>
#include <vector>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/asio/ssl.hpp>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = net::ip::tcp;




bool send_log_to_server(const std::string& log_data, const std::string& server, const std::string& port) {
    try {
        net::io_context ioc;
        ssl::context ctx{ssl::context::tlsv13_client};

        // Load client certificate and private key
        ctx.use_certificate_file("client.crt", ssl::context::pem);
        ctx.use_private_key_file("client.key", ssl::context::pem);

        // Load Root CA certificate to verify the server
        ctx.load_verify_file("rootCA.crt");
        ctx.set_verify_mode(ssl::verify_peer);  // Require the server's valid certificate

        ssl::stream<tcp::socket> stream{ioc, ctx};
        tcp::resolver resolver{ioc};

        // Resolve the server address and port
        auto const results = resolver.resolve(server, port);
        net::connect(stream.next_layer(), results.begin(), results.end());

        // Perform SSL handshake with the server
        stream.handshake(ssl::stream_base::client);

        // Prepare an HTTP POST request to /logappend
        http::request<http::string_body> req{http::verb::post, "/logappend", 11};
        req.set(http::field::host, server);
        req.set(http::field::content_type, "application/json");
        req.body() = log_data;
        req.prepare_payload();

        // Send the request to the server
        http::write(stream, req);

        // Receive and print the response from the server
        beast::flat_buffer buffer;
        http::response<http::string_body> res;
        http::read(stream, buffer, res);

        std::cout << "Response from server: " << res << std::endl;

        // Graceful shutdown of SSL and TCP connection
        beast::error_code ec;
        stream.shutdown(ec);
        stream.lowest_layer().close(ec);

        return true;  // Indicate success
    } catch (std::exception const& e) {
        std::cerr << "Error in sending log to server: " << e.what() << std::endl;
        return false;
    }
}



bool process_logappend(int argc, char* argv[]);

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Invalid number of arguments" << std::endl;
        return 255;
    }

    // Check if batch file option (-B) is specified
    if (strcmp(argv[1], "-B") == 0) {
        if (argc < 3) {
            std::cerr << "Invalid! Batch file not specified" << std::endl;
            return 255;
        }

        std::ifstream batch_file(argv[2]);
        if (!batch_file) {
            std::cerr << "Invalid! Cannot open batch file" << std::endl;
            return 255;
        }

        std::string line;
        std::vector<std::string> batch_argv;
        bool overall_success = true;

        while (std::getline(batch_file, line)) {
            std::istringstream iss(line);
            std::string word;
            batch_argv.clear();

            while (iss >> word) {
                batch_argv.push_back(word);
            }

            int batch_argc = batch_argv.size();
            if (batch_argc > 0) {
                std::vector<char*> batch_argv_cstr(batch_argc);
                for (size_t i = 0; i < batch_argc; ++i) {
                    batch_argv_cstr[i] = &batch_argv[i][0];
                }

                // Process the command as if passed from the command line
                if (!process_logappend(batch_argc, batch_argv_cstr.data())) {
                    std::cerr << "Invalid command: " << line << std::endl;
                    overall_success = false;
                }
            }
        }

        return overall_success ? 0 : 255;
    } else {
        // Process regular logappend command
        if (!process_logappend(argc, argv)) {
            return 255;
        }
    }

    return 0;
}

void validate_name(const std::string& name) {
    for (char ch : name) {
        if (!std::isalpha(ch)) {  // Check if all characters are alphabetic
            throw std::runtime_error("Error: Name must contain only alphabetic characters (a-z, A-Z) with no spaces.");
        }
    }
}

bool process_logappend(int argc, char* argv[]) {
    std::string timestamp, token, action, name, role, log_file, room_id;
    bool TBool = false;
    bool KBool = false;
    bool RBool = false;
    bool ActionBool = false;
    bool PersonBool = false;
    bool logBool = false;

    // Get the server IP from the environment variable
    const char* server_ip = std::getenv("SERVER_IP");
    if (server_ip == nullptr) {
        server_ip = "10.7.50.57";  // Default IP
        std::cerr << "Server IP not set in environment. Using default: 10.7.50.57" << std::endl;
    }

    // Parse command-line arguments
    for (int i = 0; i < argc; ++i) {
        if(strcmp(argv[i], "./logappend") == 0){
            continue;
        } if (strcmp(argv[i], "-T") == 0) {
            if (TBool) {
                std::cerr << "Invalid! Two timestamps were provided" << std::endl;
                return false;
            }
            TBool = true;
            timestamp = argv[++i];
            if(timestamp[0] )
            // Validate timestamp is a non-negative integer within range
            for (char c : timestamp) {
                if (!std::isdigit(static_cast<unsigned char>(c))) {
                    std::cerr << "Invalid! Timestamp contains non-numeric characters" << std::endl;
                    return 255;
                }
            }
            long ts = std::stol(timestamp);
            
            if (ts < 1 || ts > 1073741823) {
                std::cerr << "Invalid! Timestamp out of bounds" << std::endl;
                return false;
            }
        } else if (strcmp(argv[i], "-K") == 0) {
            if (KBool) {
                std::cerr << "Invalid! Two tokens were provided" << std::endl;
                return false;
            }
            KBool = true;
            token = argv[++i];
            // Validate token (alphanumeric check)
            for (char c : token) {
                if (!isalnum(c)) {
                    std::cerr << "Invalid! Token contains non-alphanumeric characters" << std::endl;
                    return false;
                }
            }
        } else if (strcmp(argv[i], "-A") == 0 || strcmp(argv[i], "-L") == 0) {
            if (ActionBool) {
                std::cerr << "Invalid! Two actions were provided" << std::endl;
                return false;
            }
            ActionBool = true;
            action = (strcmp(argv[i], "-A") == 0) ? "Arrival" : "Leaving";
        } else if (strcmp(argv[i], "-E") == 0) {
            if (PersonBool) {
                std::cerr << "Invalid! Two persons were provided" << std::endl;
                return false;
            }
            PersonBool = true;
            name = argv[++i];
            role = "Employee";
            try {
                for (char c : name) {
                    if (!std::isalpha(static_cast<unsigned char>(c)) || c == '"') {
                        std::cerr << "Invalid! Name contains non-alphabetic characters" << std::endl;
                        return 255;
                    }
                }
                validate_name(name);  // Validate the name
                std::cout << "Valid name: " << name << std::endl;
            } catch (const std::runtime_error& e) {
                std::cerr << e.what() << std::endl;
                return 1;  // Exit with error
            }
        } else if (strcmp(argv[i], "-G") == 0) {
            if (PersonBool) {
                std::cerr << "Invalid! Two persons were provided" << std::endl;
                return false;
            }
            PersonBool = true;
            name = argv[++i];
            role = "Guest";
            try {
                for (char c : name) {
                    if (!std::isalpha(static_cast<unsigned char>(c)) || c == '"') {
                        std::cerr << "Invalid! Name contains non-alphabetic characters" << std::endl;
                        return 255;
                    }
                }
                validate_name(name);  // Validate the name
                std::cout << "Valid name: " << name << std::endl;
            } catch (const std::runtime_error& e) {
                std::cerr << e.what() << std::endl;
                return 1;  // Exit with error
            }
        } else if (strcmp(argv[i], "-R") == 0) {
            if (RBool) {
                std::cerr << "Invalid! Multiple rooms provided" << std::endl;
                return false;
            }
            RBool = true;
            room_id = argv[++i];
            // Validate room ID (non-negative integer)
            long room = std::stol(room_id);
            if (room < 0 || room > 1073741823) {
                std::cerr << "Invalid! Room ID out of bounds" << std::endl;
                return false;
            }
        } else {
            if(logBool){
                std::cerr << "Invalid! Give proper command" << std::endl;
                return false;
            }
            log_file = argv[i]; 
            logBool = true; // Final argument is the log file
        }
    }


    // Basic validation: Ensure all required flags are set
    if (!TBool || !KBool || !ActionBool || !PersonBool || !logBool) {
        std::cerr << "Invalid! Missing required arguments" << std::endl;
        return false;
    }
  
    std::string log_data = R"({"log_name": ")" + log_file + R"(", "timestamp": ")" + timestamp +
                       R"(", "token": ")" + token + R"(", "action": ")" + action + 
                       R"(", "name": ")" + name + R"(", "role": ")" + role + 
                       R"(", "room_id": ")" + room_id + R"("})";

    std::cout << "Log data being sent: " << log_data << std::endl;      
    // Send log data to the server via HTTPS
    if (!send_log_to_server(log_data, server_ip, "8051")) {
        std::cerr << "Failed to send log entry to server" << std::endl;
        return 255;
    }

    std::cerr << "Log entry successfully sent to server" << std::endl;
    return true;
}
