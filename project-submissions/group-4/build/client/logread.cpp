#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <sstream>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/asio/ssl.hpp>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = net::ip::tcp;



bool send_read_request(const std::string& query, const std::string& server, const std::string& port) {
    try {
        // Initialize SSL context
        ssl::context ctx{ssl::context::tlsv13_client};

        // Load client certificate and key
        ctx.use_certificate_file("client.crt", ssl::context::pem);
        ctx.use_private_key_file("client.key", ssl::context::pem);

        // Load the CA certificate for server verification
        ctx.load_verify_file("rootCA.crt");

        // Set verification mode to ensure the server's certificate is checked
        ctx.set_verify_mode(ssl::verify_peer);

        net::io_context ioc;
        ssl::stream<tcp::socket> stream{ioc, ctx};
        tcp::resolver resolver{ioc};

        // Resolve the server address and port
        auto const results = resolver.resolve(server, port);
        net::connect(stream.next_layer(), results.begin(), results.end());

        // Perform SSL handshake
        stream.handshake(ssl::stream_base::client);

        // Prepare HTTP POST request for reading logs
        http::request<http::string_body> req{http::verb::post, "/logread", 11};
        req.set(http::field::host, server);
        req.set(http::field::content_type, "application/json");
        req.body() = query;
        req.prepare_payload();

        // Send the request to the server
        http::write(stream, req);

        // Receive and print the response
        beast::flat_buffer buffer;
        http::response<http::string_body> res;
        http::read(stream, buffer, res);

        std::cout << "Response from server: " << res.body() << std::endl;

        // Gracefully shut down SSL and TCP connections
        beast::error_code ec;
        stream.shutdown(ec);
        if (ec && ec != beast::errc::not_connected) {
            std::cerr << "Error during SSL shutdown: " << ec.message() << std::endl;
        } else {
            std::cout << "SSL connection shutdown gracefully." << std::endl;
        }

        stream.lowest_layer().close(ec);
        if (ec) {
            std::cerr << "Error during TCP close: " << ec.message() << std::endl;
        } else {
            std::cout << "TCP connection closed gracefully." << std::endl;
        }

        return true;
    } 
    catch (std::exception const& e) {
        std::cerr << "Error in sending query to server: " << e.what() << std::endl;
        return false;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 5) {  // Adjust this based on required flags
        std::cerr << "Invalid number of arguments" << std::endl;
        return 255;
    }

    // Variables to hold parsed values
    std::string token, log_file, name, role, timestamp;
    bool SBool = false, RBool = false, TBool = false, KBool = false, EBool = false, GBool = false, logBool = false;

    // Get the server IP from the environment variable
    const char* server_ip = std::getenv("SERVER_IP");
    if (server_ip == nullptr) {
        server_ip = "10.7.50.57";  // Default IP
        std::cerr << "Server IP not set in environment. Using default: 10.7.50.57" << std::endl;
    }

    // Parse command-line arguments
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-S") == 0) {
            if (SBool) {
                std::cerr << "Invalid! Multiple states (-S) provided" << std::endl;
                return 255;
            }
            SBool = true;
        } else if (strcmp(argv[i], "-R") == 0) {
            if (RBool) {
                std::cerr << "Invalid! Multiple room queries (-R) provided" << std::endl;
                return 255;
            }
            RBool = true;
        } else if (strcmp(argv[i], "-T") == 0) {
            if (TBool) {
                std::cerr << "Invalid! Multiple time queries (-T) provided" << std::endl;
                return 255;
            }
            TBool = true;
            timestamp = argv[++i];
        } 
        else if (strcmp(argv[i], "-I") == 0) {
            std::cerr << "Unimplemented" << std::endl;
            return false;
        }else if (strcmp(argv[i], "-K") == 0) {
            if (KBool) {
                std::cerr << "Invalid! Multiple tokens (-K) provided" << std::endl;
                return 255;
            }
            KBool = true;
            token = argv[++i];
            // Validate token (alphanumeric check)
            for (char c : token) {
                if (!isalnum(c)) {
                    std::cerr << "Invalid! Token contains non-alphanumeric characters" << std::endl;
                    return 255;
                }
            }
        } else if (strcmp(argv[i], "-E") == 0) {
            if (EBool) {
                std::cerr << "Invalid! Multiple employees (-E) provided" << std::endl;
                return 255;
            }
            EBool = true;
            name = argv[++i];
            role = "Employee";
        } else if (strcmp(argv[i], "-G") == 0) {
            if (GBool) {
                std::cerr << "Invalid! Multiple guests (-G) provided" << std::endl;
                return 255;
            }
            GBool = true;
            name = argv[++i];
            role = "Guest";
        }else {
            if(logBool){
                std::cerr << "Invalid! Give proper command" << std::endl;
                return false;
            }
            log_file = argv[i];
            logBool = true;  // Final argument is the log file
        }
    }
    
    // Basic validation: Ensure token (-K) is set
    if (!KBool) {
        std::cerr << "Invalid! Missing token (-K)" << std::endl;
        return 255;
    }

    // Check for exclusive use of flags -S, -R, -T
    if ((SBool && (RBool || TBool)) || (RBool && TBool)) {
        std::cerr << "Invalid! Only one of -S, -R, -T can be used" << std::endl;
        return 255;
    }
    

    // Build the query string based on the provided arguments
    std::string query = R"({"token": ")" + token + R"(", "log_name": ")" + log_file + R"(", )";
    
    // Check which type of query is being made
    if (SBool) {
        
        query += R"("query_type": "state"})";
    } else if (RBool) {
        query += R"("query_type": "room", "name": ")" + name + R"(", "role": ")" + role + R"("})";
    } else if (TBool) {
        query += R"("query_type": "time", "timestamp": ")" + timestamp + R"(", "name": ")" + name + R"(", "role": ")" + role + R"("})";
    }

    std::cout << "Query being sent: " << query << std::endl; 

    // Send the query to the server over HTTPS
    if (!send_read_request(query, server_ip, "8051")) {
        std::cerr << "Failed to send log read request to server" << std::endl;
        return 255;
    }

   
    return 0;
}
