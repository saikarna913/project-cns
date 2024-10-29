#include <iostream>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/asio/ssl.hpp>
#include <mongocxx/pool.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/uri.hpp>
#include <mongocxx/collection.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/json.hpp>   // For bsoncxx::to_json
#include <mongocxx/client.hpp>
#include <mongocxx/database.hpp>
#include <mongocxx/uri.hpp>
#include <nlohmann/json.hpp>  // For JSON parsing
#include <sstream>            // For std::ostringstream

#include <unordered_map>
#include <chrono>
#include <mutex>
#include <boost/asio/steady_timer.hpp>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = net::ip::tcp;
using json = nlohmann::json;


const int MAX_REQUESTS_PER_MINUTE = 10;  // Limit each client to 10 requests per minute
std::unordered_map<std::string, int> client_requests;
std::unordered_map<std::string, std::chrono::steady_clock::time_point> last_reset;
std::mutex rate_limit_mutex;

bool is_rate_limited(const std::string& client_ip) {
    std::lock_guard<std::mutex> lock(rate_limit_mutex);

    auto now = std::chrono::steady_clock::now();
    if (last_reset[client_ip] + std::chrono::minutes(1) < now) {
        // Reset counter after 1 minute
        client_requests[client_ip] = 0;
        last_reset[client_ip] = now;
    }

    if (client_requests[client_ip] >= MAX_REQUESTS_PER_MINUTE) {
        return true;  // Client is rate-limited
    }

    client_requests[client_ip]++;
    return false;
}
static mongocxx::instance instance{};
// Class for handling MongoDB pool setup and database operations
class MongoDBHandler {
private:
    static mongocxx::pool* pool;  // Static pool to manage MongoDB connections
    std::string log;  // Private attribute to store the database name
    static mongocxx::pool* person_pool; 

    // Initialize the pool if it has not been initialized
    void initialize_pool() {
        if (pool == nullptr) {
            
            std::string uri_string = "mongodb://localhost";  // Base URI without database
            std::cout << "Initializing MongoDB pool at URI: " << uri_string << std::endl;
            pool = new mongocxx::pool{mongocxx::uri{uri_string}};
        }
    }
    void initialize_persons_pool() {
        if (person_pool == nullptr) {
            std::string uri_string = "mongodb://localhost";  // Base URI without database
            std::cout << "Initializing MongoDB pool at URI: " << uri_string << std::endl;
            person_pool = new mongocxx::pool{mongocxx::uri{uri_string}};
        }
    }

public:
    // Constructor to set the database name (log value)
    MongoDBHandler(const std::string& log_value) : log(log_value) {}

    // Get a database object using the log value as the database name
    mongocxx::database get_db() {
        initialize_pool();
        auto client = pool->acquire();  // Acquire a connection from the pool
        return (*client)[log];  // Use log value as the database name
    }
    mongocxx::database get_persons_db() {
        initialize_persons_pool();
        auto client = person_pool->acquire();  // Acquire a connection from the pool
        return (*client)["total_persons"];  // Use log value as the database name
    }
    // Validate log token
    bool validate_log_token(const std::string& log_name, const std::string& token) {
        mongocxx::database db = get_db();
        mongocxx::collection collection = db["log_tokens"];

        // Search for the log_name in the collection
        bsoncxx::stdx::optional<bsoncxx::document::value> maybe_result =
            collection.find_one(bsoncxx::builder::stream::document{} << "log_name" << log_name << bsoncxx::builder::stream::finalize);

        if (maybe_result) {
        // Log name exists, check token
        auto view = maybe_result->view();
        std::string existing_token = view["token"].get_string().value.to_string();

        if (existing_token == token) {
            return true;  // Token matches
        } else {
            return false; // Token does not match
        }
        } else {
        // Log name doesn't exist, insert new document
        bsoncxx::builder::stream::document document{};
        document << "log_name" << log_name << "token" << token;
        collection.insert_one(document.view());
        return true;  // New log added, so return true
        }
    }    


    // Read last log time from the database
    int read_last_log_time() {
        mongocxx::database db = get_db();
        mongocxx::collection collection = db["last_log"];

        bsoncxx::stdx::optional<bsoncxx::document::value> maybe_document =
            collection.find_one(bsoncxx::builder::stream::document{} << "title" << "Last entry" << bsoncxx::builder::stream::finalize);

        // If the document exists, return the time
        if (maybe_document) {
        auto view = maybe_document->view();
        int last_time = view["time"].get_int32().value;
        return last_time;
        } else {
        // If document doesn't exist, create it with time = -1
        bsoncxx::builder::stream::document new_log;
        new_log << "title" << "Last entry" << "time" << -1;
        collection.insert_one(new_log.view());
        return -1;  // Returning -1 as per the specification
        }
    }

    // Write last log time to the database
    void write_last_log_time(int new_time) {
        mongocxx::database db = get_db();
        mongocxx::collection collection = db["last_log"];

        bsoncxx::stdx::optional<bsoncxx::document::value> maybe_document =
            collection.find_one(bsoncxx::builder::stream::document{} << "title" << "Last entry" << bsoncxx::builder::stream::finalize);

        if (maybe_document) {
        // Document exists, update the time
        collection.update_one(
            bsoncxx::builder::stream::document{} << "title" << "Last entry" << bsoncxx::builder::stream::finalize,
            bsoncxx::builder::stream::document{} << "$set" 
            << bsoncxx::builder::stream::open_document 
            << "time" << new_time 
            << bsoncxx::builder::stream::close_document 
            << bsoncxx::builder::stream::finalize);
        return;
        } else {
        // If document doesn't exist, create it
        bsoncxx::builder::stream::document new_log;
        new_log << "title" << "Last entry" << "time" << new_time;
        collection.insert_one(new_log.view());
        return;
        }
    }

    bool logappend(const std::string& name, const std::string& role, const std::string& action, const std::string& timestamp, const std::string& room_id, const std::string& log_name) {
        mongocxx::database person_db = get_persons_db();
        mongocxx::collection p_db = person_db["persons"];
        bsoncxx::stdx::optional<bsoncxx::document::value> maybe_present =
            p_db.find_one(bsoncxx::builder::stream::document{}
                                        << "Name" << name 
                                        << "Role" << role 
                                        << bsoncxx::builder::stream::finalize);
        mongocxx::database db = get_db();
        mongocxx::collection persons_collection = db["persons"];
        mongocxx::collection rooms_collection = db["rooms"];
        if(!maybe_present){
            bsoncxx::stdx::optional<bsoncxx::document::value> maybe_person =
            persons_collection.find_one(bsoncxx::builder::stream::document{}
                                        << "Name" << name 
                                        << "Role" << role 
                                        << bsoncxx::builder::stream::finalize);

        // If the person does not exist
        if (!maybe_person) {
            if (!room_id.empty()) {
                std::cout << "Person is not on campus" << std::endl;
                return false;
            }

            // Add new person with attributes
            bool campus_status = action == "Arrival";
            if (!campus_status) {
                std::cout << "Person is not on campus to leave" << std::endl;
                return false;  // If the action is not Arrival, return false
            }

            auto builder = bsoncxx::builder::stream::document{};
            bsoncxx::v_noabi::document::value new_person =
                builder << "Name" << name
                        << "Role" << role
                        << "Campus" << campus_status
                        << "Room" << "-1"
                        << "Time" << 0
                        << "Last_entry" << std::stoi(timestamp)
                        << "entered_rooms" << bsoncxx::builder::stream::open_array << bsoncxx::builder::stream::close_array  // Initialize empty array
                        << bsoncxx::builder::stream::finalize;
            persons_collection.insert_one(new_person.view());

            // Check if room document exists, create if it doesn't
            bsoncxx::stdx::optional<bsoncxx::document::value> maybe_room =
                rooms_collection.find_one(bsoncxx::builder::stream::document{} << "room_number" << -1 << bsoncxx::builder::stream::finalize);

            if (!maybe_room) {
                // Create a new room document with separate arrays for employees and guests
                bsoncxx::builder::stream::document room_builder;
                if (role == "Employee") {
                    room_builder << "room_number" << -1 << "employees" << bsoncxx::builder::stream::open_array << name << bsoncxx::builder::stream::close_array
                                << "guests" << bsoncxx::builder::stream::open_array << bsoncxx::builder::stream::close_array; // Empty guests array
                } else {
                    room_builder << "room_number" << -1 << "employees" << bsoncxx::builder::stream::open_array << bsoncxx::builder::stream::close_array
                                << "guests" << bsoncxx::builder::stream::open_array << name << bsoncxx::builder::stream::close_array; // Add to guests array
                }
                rooms_collection.insert_one(room_builder.view());
            } else {
                // Update the room document to add the person to the correct array
                if (role == "Employee") {
                    rooms_collection.update_one(
                        bsoncxx::builder::stream::document{} << "room_number" << -1 << bsoncxx::builder::stream::finalize,
                        bsoncxx::builder::stream::document{} << "$addToSet"
                                << bsoncxx::builder::stream::open_document
                                    << "employees" << name
                                << bsoncxx::builder::stream::close_document
                            << bsoncxx::builder::stream::finalize);
                } else {
                    rooms_collection.update_one(
                        bsoncxx::builder::stream::document{} << "room_number" << -1 << bsoncxx::builder::stream::finalize,
                        bsoncxx::builder::stream::document{} << "$addToSet"
                                << bsoncxx::builder::stream::open_document
                                    << "guests" << name
                                << bsoncxx::builder::stream::close_document
                            << bsoncxx::builder::stream::finalize);
                }
            }
            auto builder2 = bsoncxx::builder::stream::document{};
            bsoncxx::v_noabi::document::value new_person_t =
                builder2 << "Name" << name
                        << "Role" << role
                        << "log_name" << log_name// Initialize empty array
                        << bsoncxx::builder::stream::finalize;
            p_db.insert_one(new_person_t.view());

            return true;
        }
            auto person_view = maybe_person->view();

        // Check if the roles match
        std::string existing_role = person_view["Role"].get_string().value.to_string();
        if (existing_role != role) {
            std::cout << "Role mismatch" << std::endl;
            return false;  // Role mismatch
        }

        // Handle actions based on room_id and action
        std::string existing_room = person_view["Room"].get_string().value.to_string();
        bool campus_status = person_view["Campus"].get_bool().value;
        int existing_time = person_view["Time"].get_int32().value;
        int last_entry = person_view["Last_entry"].get_int32().value;
        auto entered_rooms_array = person_view["entered_rooms"].get_array().value;

        if (action == "Arrival") {
            // Person must already be on campus to enter a room
            if (!campus_status && !room_id.empty()) {
                std::cout << "Person must already be on campus to enter a room" << std::endl;
                return false;
            } else if (campus_status && room_id.empty()) {
                std::cout << "Person already on campus" << std::endl;
                return false;
            } else if(campus_status && existing_room != "-1") {
                std::cout << "Person already in another room" << std::endl;
                return false;
            } else {
                existing_room = room_id;  // Assign the new room
                if (!campus_status) {
                    existing_room = "-1";
                    last_entry = std::stoi(timestamp);
                }
                campus_status = true;

                // Add room to entered_rooms array if it's not "0"
                if (existing_room != "-1") {
                    persons_collection.update_one(
                        bsoncxx::builder::stream::document{} << "Name" << name << bsoncxx::builder::stream::finalize,
                        bsoncxx::builder::stream::document{} << "$addToSet"
                            << bsoncxx::builder::stream::open_document
                                << "entered_rooms" << existing_room
                            << bsoncxx::builder::stream::close_document
                        << bsoncxx::builder::stream::finalize);
                }

                // Check if room document exists, create if it doesn't
                bsoncxx::stdx::optional<bsoncxx::document::value> maybe_room =
                    rooms_collection.find_one(bsoncxx::builder::stream::document{} << "room_number" << std::stoi(existing_room) << bsoncxx::builder::stream::finalize);
                if (!maybe_room) {
                    // Create a new room document
                    bsoncxx::builder::stream::document room_builder;
                    if (role == "Employee") {
                        room_builder << "room_number" << std::stoi(existing_room) << "employees" << bsoncxx::builder::stream::open_array << name << bsoncxx::builder::stream::close_array
                                    << "guests" << bsoncxx::builder::stream::open_array << bsoncxx::builder::stream::close_array; // Empty guests array
                    } else {
                        room_builder << "room_number" << std::stoi(existing_room) << "employees" << bsoncxx::builder::stream::open_array << bsoncxx::builder::stream::close_array
                                    << "guests" << bsoncxx::builder::stream::open_array << name << bsoncxx::builder::stream::close_array; // Add to guests array
                    }
                    rooms_collection.insert_one(room_builder.view());
                } else {
                    // Update the room document to add the person to the correct array
                    if (role == "Employee") {
                        rooms_collection.update_one(
                            bsoncxx::builder::stream::document{} << "room_number" << std::stoi(existing_room) <<  bsoncxx::builder::stream::finalize,
                            bsoncxx::builder::stream::document{} << "$addToSet" 
                                << bsoncxx::builder::stream::open_document 
                                    << "employees" << name 
                                << bsoncxx::builder::stream::close_document 
                            << bsoncxx::builder::stream::finalize);
                    } else {
                        rooms_collection.update_one(
                            bsoncxx::builder::stream::document{} << "room_number" << std::stoi(existing_room) <<  bsoncxx::builder::stream::finalize,
                            bsoncxx::builder::stream::document{} << "$addToSet" 
                                << bsoncxx::builder::stream::open_document 
                                    << "guests" << name 
                                << bsoncxx::builder::stream::close_document 
                            << bsoncxx::builder::stream::finalize);
                    }
                }
            }
        } else if (action == "Leaving") {
            // Person can leave the campus only if they are not in any room (except room 0, which represents being on campus but not in any specific room)
            if (existing_room != "-1" && room_id.empty()) {
                std::cout << "Person must leave the room before leaving the campus" << std::endl;
                return false;
            } else if (!campus_status) {
                std::cout << "Person not on campus" << std::endl;
                return false;
            }else if(existing_room == "-1"  && !room_id.empty()){
                std::cout << "Person is not present in the room" << std::endl;
                return false;
            } else {
                if (existing_room != "-1") {
                    // If the person is in a room, check if they are leaving from the correct room
                    if (existing_room != room_id) {
                        std::cout << "Person not present in this room" << std::endl;
                        return false;
                    }

                    // Remove the person from the appropriate array (employees or guests) based on their role
                    if (role == "Employee") {
                        rooms_collection.update_one(
                            bsoncxx::builder::stream::document{} << "room_number" << std::stoi(existing_room) << bsoncxx::builder::stream::finalize,
                            bsoncxx::builder::stream::document{} << "$pull"
                                << bsoncxx::builder::stream::open_document
                                    << "employees" << name
                                << bsoncxx::builder::stream::close_document
                            << bsoncxx::builder::stream::finalize);
                    } else {
                        rooms_collection.update_one(
                            bsoncxx::builder::stream::document{} << "room_number" << std::stoi(existing_room) << bsoncxx::builder::stream::finalize,
                            bsoncxx::builder::stream::document{} << "$pull"
                                << bsoncxx::builder::stream::open_document
                                    << "guests" << name
                                << bsoncxx::builder::stream::close_document
                            << bsoncxx::builder::stream::finalize);
                    }

                    // Mark that the person is now on campus but not in any specific room
                    existing_room = "-1";
                } else {
                    // If the person is already in room 0 (on campus but not in a specific room), they are leaving the campus
                    campus_status = false;  // Mark the person as having left the campus
                    existing_room = "";  // Empty room field since they're off campus

                    // Adjust the person's time to reflect how long they were on campus
                    existing_time += std::stoi(timestamp) - last_entry;

                    // Remove the person from the campus (room 0) list
                    if (role == "Employee") {
                        rooms_collection.update_one(
                            bsoncxx::builder::stream::document{} << "room_number" << -1 << bsoncxx::builder::stream::finalize,
                            bsoncxx::builder::stream::document{} << "$pull"
                                << bsoncxx::builder::stream::open_document
                                    << "employees" << name
                                << bsoncxx::builder::stream::close_document
                            << bsoncxx::builder::stream::finalize);
                    } else {
                        rooms_collection.update_one(
                            bsoncxx::builder::stream::document{} << "room_number" << -1 << bsoncxx::builder::stream::finalize,
                            bsoncxx::builder::stream::document{} << "$pull"
                                << bsoncxx::builder::stream::open_document
                                    << "guests" << name
                                << bsoncxx::builder::stream::close_document
                            << bsoncxx::builder::stream::finalize);
                    }
                }
            }
        }

        // Update the person's document in the collection
        persons_collection.update_one(
            bsoncxx::builder::stream::document{} << "Name" << name << bsoncxx::builder::stream::finalize,
            bsoncxx::builder::stream::document{} << "$set"
                << bsoncxx::builder::stream::open_document
                    << "Campus" << campus_status
                    << "Room" << existing_room
                    << "Time" << existing_time
                    << "Last_entry" << last_entry
                << bsoncxx::builder::stream::close_document
            << bsoncxx::builder::stream::finalize);
        if(room_id.empty() && action == "Leaving"){
            auto result = p_db.delete_one(maybe_present->view());
            if (result && result->deleted_count() > 0) {
                std::cout << "Person deleted successfully.\n";
                return true;
            } else {
                std::cout << "Person not found.\n";
                return false;
            }
        }
        return true;
        }
        else{
             auto total_person_view = maybe_present->view();

            // Check if the roles match
            std::string log_name_p = total_person_view["log_name"].get_string().value.to_string();
            if (log_name_p!= log_name) {
                std::cout << "person cannot be appended using this log" << std::endl;
                return false;  // Role mismatch
            }
        


        // Search for the person in the 'persons' collection by name and role
        bsoncxx::stdx::optional<bsoncxx::document::value> maybe_person =
            persons_collection.find_one(bsoncxx::builder::stream::document{}
                                        << "Name" << name 
                                        << "Role" << role 
                                        << bsoncxx::builder::stream::finalize);

        // If the person does not exist
        if (!maybe_person) {
            if (!room_id.empty()) {
                std::cout << "Person is not on campus" << std::endl;
                return false;
            }

            // Add new person with attributes
            bool campus_status = action == "Arrival";
            if (!campus_status) {
                std::cout << "Person is not on campus to leave" << std::endl;
                return false;  // If the action is not Arrival, return false
            }

            auto builder = bsoncxx::builder::stream::document{};
            bsoncxx::v_noabi::document::value new_person =
                builder << "Name" << name
                        << "Role" << role
                        << "Campus" << campus_status
                        << "Room" << "-1"
                        << "Time" << 0
                        << "Last_entry" << std::stoi(timestamp)
                        << "entered_rooms" << bsoncxx::builder::stream::open_array << bsoncxx::builder::stream::close_array  // Initialize empty array
                        << bsoncxx::builder::stream::finalize;
            persons_collection.insert_one(new_person.view());

            // Check if room document exists, create if it doesn't
            bsoncxx::stdx::optional<bsoncxx::document::value> maybe_room =
                rooms_collection.find_one(bsoncxx::builder::stream::document{} << "room_number" << -1 << bsoncxx::builder::stream::finalize);

            if (!maybe_room) {
                // Create a new room document with separate arrays for employees and guests
                bsoncxx::builder::stream::document room_builder;
                if (role == "Employee") {
                    room_builder << "room_number" << -1 << "employees" << bsoncxx::builder::stream::open_array << name << bsoncxx::builder::stream::close_array
                                << "guests" << bsoncxx::builder::stream::open_array << bsoncxx::builder::stream::close_array; // Empty guests array
                } else {
                    room_builder << "room_number" << -1 << "employees" << bsoncxx::builder::stream::open_array << bsoncxx::builder::stream::close_array
                                << "guests" << bsoncxx::builder::stream::open_array << name << bsoncxx::builder::stream::close_array; // Add to guests array
                }
                rooms_collection.insert_one(room_builder.view());
            } else {
                // Update the room document to add the person to the correct array
                if (role == "Employee") {
                    rooms_collection.update_one(
                        bsoncxx::builder::stream::document{} << "room_number" << -1 << bsoncxx::builder::stream::finalize,
                        bsoncxx::builder::stream::document{} << "$addToSet"
                                << bsoncxx::builder::stream::open_document
                                    << "employees" << name
                                << bsoncxx::builder::stream::close_document
                            << bsoncxx::builder::stream::finalize);
                } else {
                    rooms_collection.update_one(
                        bsoncxx::builder::stream::document{} << "room_number" << -1 << bsoncxx::builder::stream::finalize,
                        bsoncxx::builder::stream::document{} << "$addToSet"
                                << bsoncxx::builder::stream::open_document
                                    << "guests" << name
                                << bsoncxx::builder::stream::close_document
                            << bsoncxx::builder::stream::finalize);
                }
            }

            return true;
        }

        // If the person exists
        auto person_view = maybe_person->view();

        // Check if the roles match
        std::string existing_role = person_view["Role"].get_string().value.to_string();
        if (existing_role != role) {
            std::cout << "Role mismatch" << std::endl;
            return false;  // Role mismatch
        }

        // Handle actions based on room_id and action
        std::string existing_room = person_view["Room"].get_string().value.to_string();
        bool campus_status = person_view["Campus"].get_bool().value;
        int existing_time = person_view["Time"].get_int32().value;
        int last_entry = person_view["Last_entry"].get_int32().value;
        auto entered_rooms_array = person_view["entered_rooms"].get_array().value;

        if (action == "Arrival") {
            // Person must already be on campus to enter a room
            if (!campus_status && !room_id.empty()) {
                std::cout << "Person must already be on campus to enter a room" << std::endl;
                return false;
            } else if (campus_status && room_id.empty()) {
                std::cout << "Person already on campus" << std::endl;
                return false;
            } else if(campus_status && existing_room != "-1") {
                std::cout << "Person already in another room" << std::endl;
                return false;
            } else {
                existing_room = room_id;  // Assign the new room
                if (!campus_status) {
                    existing_room = "-1";
                    last_entry = std::stoi(timestamp);
                }
                campus_status = true;

                // Add room to entered_rooms array if it's not "0"
                if (existing_room != "-1") {
                    persons_collection.update_one(
                        bsoncxx::builder::stream::document{} << "Name" << name << bsoncxx::builder::stream::finalize,
                        bsoncxx::builder::stream::document{} << "$addToSet"
                            << bsoncxx::builder::stream::open_document
                                << "entered_rooms" << existing_room
                            << bsoncxx::builder::stream::close_document
                        << bsoncxx::builder::stream::finalize);
                }

                // Check if room document exists, create if it doesn't
                bsoncxx::stdx::optional<bsoncxx::document::value> maybe_room =
                    rooms_collection.find_one(bsoncxx::builder::stream::document{} << "room_number" << std::stoi(existing_room) << bsoncxx::builder::stream::finalize);
                if (!maybe_room) {
                    // Create a new room document
                    bsoncxx::builder::stream::document room_builder;
                    if (role == "Employee") {
                        room_builder << "room_number" << std::stoi(existing_room) << "employees" << bsoncxx::builder::stream::open_array << name << bsoncxx::builder::stream::close_array
                                    << "guests" << bsoncxx::builder::stream::open_array << bsoncxx::builder::stream::close_array; // Empty guests array
                    } else {
                        room_builder << "room_number" << std::stoi(existing_room) << "employees" << bsoncxx::builder::stream::open_array << bsoncxx::builder::stream::close_array
                                    << "guests" << bsoncxx::builder::stream::open_array << name << bsoncxx::builder::stream::close_array; // Add to guests array
                    }
                    rooms_collection.insert_one(room_builder.view());
                } else {
                    // Update the room document to add the person to the correct array
                    if (role == "Employee") {
                        rooms_collection.update_one(
                            bsoncxx::builder::stream::document{} << "room_number" << std::stoi(existing_room) <<  bsoncxx::builder::stream::finalize,
                            bsoncxx::builder::stream::document{} << "$addToSet" 
                                << bsoncxx::builder::stream::open_document 
                                    << "employees" << name 
                                << bsoncxx::builder::stream::close_document 
                            << bsoncxx::builder::stream::finalize);
                    } else {
                        rooms_collection.update_one(
                            bsoncxx::builder::stream::document{} << "room_number" << std::stoi(existing_room) <<  bsoncxx::builder::stream::finalize,
                            bsoncxx::builder::stream::document{} << "$addToSet" 
                                << bsoncxx::builder::stream::open_document 
                                    << "guests" << name 
                                << bsoncxx::builder::stream::close_document 
                            << bsoncxx::builder::stream::finalize);
                    }
                }
            }
        } else if (action == "Leaving") {
            // Person can leave the campus only if they are not in any room (except room 0, which represents being on campus but not in any specific room)
            if (existing_room != "-1" && room_id.empty()) {
                std::cout << "Person must leave the room before leaving the campus" << std::endl;
                return false;
            } else if (!campus_status) {
                std::cout << "Person not on campus" << std::endl;
                return false;
            }else if(existing_room == "-1"  && !room_id.empty()){
                std::cout << "Person is not present in the room" << std::endl;
                return false;
            } else {
                if (existing_room != "-1") {
                    // If the person is in a room, check if they are leaving from the correct room
                    if (existing_room != room_id) {
                        std::cout << "Person not present in this room" << std::endl;
                        return false;
                    }

                    // Remove the person from the appropriate array (employees or guests) based on their role
                    if (role == "Employee") {
                        rooms_collection.update_one(
                            bsoncxx::builder::stream::document{} << "room_number" << std::stoi(existing_room) << bsoncxx::builder::stream::finalize,
                            bsoncxx::builder::stream::document{} << "$pull"
                                << bsoncxx::builder::stream::open_document
                                    << "employees" << name
                                << bsoncxx::builder::stream::close_document
                            << bsoncxx::builder::stream::finalize);
                    } else {
                        rooms_collection.update_one(
                            bsoncxx::builder::stream::document{} << "room_number" << std::stoi(existing_room) << bsoncxx::builder::stream::finalize,
                            bsoncxx::builder::stream::document{} << "$pull"
                                << bsoncxx::builder::stream::open_document
                                    << "guests" << name
                                << bsoncxx::builder::stream::close_document
                            << bsoncxx::builder::stream::finalize);
                    }

                    // Mark that the person is now on campus but not in any specific room
                    existing_room = "-1";
                } else {
                    // If the person is already in room 0 (on campus but not in a specific room), they are leaving the campus
                    campus_status = false;  // Mark the person as having left the campus
                    existing_room = "";  // Empty room field since they're off campus

                    // Adjust the person's time to reflect how long they were on campus
                    existing_time += std::stoi(timestamp) - last_entry;

                    // Remove the person from the campus (room 0) list
                    if (role == "Employee") {
                        rooms_collection.update_one(
                            bsoncxx::builder::stream::document{} << "room_number" << -1 << bsoncxx::builder::stream::finalize,
                            bsoncxx::builder::stream::document{} << "$pull"
                                << bsoncxx::builder::stream::open_document
                                    << "employees" << name
                                << bsoncxx::builder::stream::close_document
                            << bsoncxx::builder::stream::finalize);
                    } else {
                        rooms_collection.update_one(
                            bsoncxx::builder::stream::document{} << "room_number" << -1 << bsoncxx::builder::stream::finalize,
                            bsoncxx::builder::stream::document{} << "$pull"
                                << bsoncxx::builder::stream::open_document
                                    << "guests" << name
                                << bsoncxx::builder::stream::close_document
                            << bsoncxx::builder::stream::finalize);
                    }
                }
            }
        }

        // Update the person's document in the collection
        persons_collection.update_one(
            bsoncxx::builder::stream::document{} << "Name" << name << bsoncxx::builder::stream::finalize,
            bsoncxx::builder::stream::document{} << "$set"
                << bsoncxx::builder::stream::open_document
                    << "Campus" << campus_status
                    << "Room" << existing_room
                    << "Time" << existing_time
                    << "Last_entry" << last_entry
                << bsoncxx::builder::stream::close_document
            << bsoncxx::builder::stream::finalize);
        if(room_id.empty() && action == "Leaving"){
            auto result = p_db.delete_one(maybe_present->view());
            if (result && result->deleted_count() > 0) {
                std::cout << "Person deleted successfully.\n";
                return true;
            } else {
                std::cout << "Person not found.\n";
                return false;
            }
        }
        return true;
        }
        return false;
    }

    std::string logread_S() {
        mongocxx::database db = get_db();
        mongocxx::collection rooms_collection = db["rooms"];

        // Fetch all rooms in ascending order
        mongocxx::cursor rooms_cursor = rooms_collection.find(
            bsoncxx::builder::stream::document{} << bsoncxx::builder::stream::finalize,
            mongocxx::options::find{}.sort(bsoncxx::builder::stream::document{} << "room_number" << 1 << bsoncxx::builder::stream::finalize)
        );

        std::vector<std::string> employees_on_campus;
        std::vector<std::string> guests_on_campus;
        std::vector<std::string> room_outputs;
        std::string output;

        // Loop through each room
        for (auto&& room_doc : rooms_cursor) {
            int room_number = room_doc["room_number"].get_int32().value;

            if (room_number == -1) {
                // Handle the campus list separately
                auto employees_array = room_doc["employees"].get_array().value;
                auto guests_array = room_doc["guests"].get_array().value;

                // Populate campus employees and guests
                for (const auto& employee_elem : employees_array) {
                    employees_on_campus.push_back(employee_elem.get_string().value.to_string());
                }

                for (const auto& guest_elem : guests_array) {
                    guests_on_campus.push_back(guest_elem.get_string().value.to_string());
                }
            } else {
                // Handle other rooms, merging employees and guests into a single list
                std::vector<std::string> room_persons;
                auto employees_array = room_doc["employees"].get_array().value;
                auto guests_array = room_doc["guests"].get_array().value;

                for (const auto& employee_elem : employees_array) {
                    room_persons.push_back(employee_elem.get_string().value.to_string());
                }

                for (const auto& guest_elem : guests_array) {
                    room_persons.push_back(guest_elem.get_string().value.to_string());
                }

                // Sort room persons lexicographically
                std::sort(room_persons.begin(), room_persons.end());

                // Build the room's output string
                std::string room_output = std::to_string(room_number) + ": ";
                for (size_t i = 0; i < room_persons.size(); ++i) {
                    room_output += room_persons[i];
                    if (i != room_persons.size() - 1) {
                        room_output += ",";
                    }
                }

                // Store the output for this room
                room_outputs.push_back(room_output);
            }
        }

        // Sort employees and guests on campus lexicographically
        std::sort(employees_on_campus.begin(), employees_on_campus.end());
        std::sort(guests_on_campus.begin(), guests_on_campus.end());

        // Append employees list to output
        if (!employees_on_campus.empty()) {
            for (size_t i = 0; i < employees_on_campus.size(); ++i) {
                output += employees_on_campus[i];
                if (i != employees_on_campus.size() - 1) {
                    output += ",";
                }
            }
            output += "\n";
        }

        // Append guests list to output
        if (!guests_on_campus.empty()) {
            for (size_t i = 0; i < guests_on_campus.size(); ++i) {
                output += guests_on_campus[i];
                if (i != guests_on_campus.size() - 1) {
                    output += ",";
                }
            }
            output += "\n";
        }

        // Append room-wise details to output
        for (const auto& room_output : room_outputs) {
            output += room_output + "\n";
        }

        return output;
    }
    int GetTotalTime(const std::string& name,const std::string& role, int current_timestamp) {
        mongocxx::database db = get_db();
        mongocxx::collection persons_collection = db["persons"];

        // Query the person by name and role
        bsoncxx::stdx::optional<bsoncxx::document::value> maybe_person = persons_collection.find_one(bsoncxx::builder::stream::document{}
                                                << "Name" << name
                                                << "Role" << role
                                                << bsoncxx::builder::stream::finalize);

        
        // If person exists, calculate total time
        
        if (maybe_person) {
        auto person_doc = maybe_person->view();

        bool on_campus = person_doc["Campus"].get_bool();
        int total_time = person_doc["Time"].get_int32();
        int last_entry = person_doc["Last_entry"].get_int32();
        // If person is currently on campus, add time since last entry
        if (on_campus) {

            total_time += (current_timestamp - last_entry);
        }

        return total_time;
        } else {
        // If person doesn't exist, return -1 as an indicator
        return -1;
        }
    }
    std::string logread_R(const std::string& name, const std::string& role) {
        mongocxx::database db = get_db();
        mongocxx::collection persons_collection = db["persons"];

        // Search for the person in the 'persons' collection
        bsoncxx::stdx::optional<bsoncxx::document::value> maybe_person =
            persons_collection.find_one(bsoncxx::builder::stream::document{} << "Name" << name << "Role" << role << bsoncxx::builder::stream::finalize);

        // If the person is not found, print nothing and return false
        if (!maybe_person) {
            return "";
        }

        // Get the person's document
        auto person_view = maybe_person->view();

        // Verify the role
        std::string existing_role = person_view["Role"].get_string().value.to_string();
        if (existing_role != role) {
            return "";
        }

        // Retrieve the entered_rooms array
        auto entered_rooms_array = person_view["entered_rooms"].get_array().value;

        // If entered_rooms is empty, print nothing and return true
        if (entered_rooms_array.empty()) {
            return "";
        }

        // Print the rooms in chronological order as a comma-separated list
        std::string room_list;
        for (const auto& room : entered_rooms_array) {
            if (!room_list.empty()) {
                room_list += ",";  // Add comma separator
            }
            room_list += room.get_string().value.to_string();
        }

        return room_list;
    }
   
};

// Static pool member initializatio

mongocxx::pool* MongoDBHandler::pool = nullptr;
mongocxx::pool* MongoDBHandler::person_pool = nullptr;

// Function to handle log append requests
void handle_logappend(const json& log_data, ssl::stream<tcp::socket>& ssl_stream) {
    try {

        std::string name = log_data.at("name");
        std::string role = log_data.at("role");
        std::string action = log_data.at("action");
        std::string timestamp = log_data.at("timestamp");
        std::string room_id = log_data.at("room_id");
        std::string log_file = log_data.at("log_name");
        std::string token = log_data.at("token");
        MongoDBHandler db_handler(log_file);
        if (!db_handler.validate_log_token(log_file, token)) {
            std::cerr << "Invalid authentication!" << std::endl;
            throw std::runtime_error("Invalid token");
            return;
        }
        
        int last = db_handler.read_last_log_time();
        if (std::stoi(timestamp) <= last) {
            std::cerr << "Time inconsistent!" << std::endl;
            throw std::runtime_error("Time inconsistent");
        }

        if (!db_handler.logappend(name, role, action, timestamp, room_id, log_file)) {
            std::cerr << "Inconsistent entry! Cannot update" << std::endl;
            throw std::runtime_error("Inconsistent entry! Cannot update");
        }

        db_handler.write_last_log_time(std::stoi(timestamp));
        std::cerr << "Update successful" << std::endl;
        
        http::response<http::string_body> res{http::status::ok, 11};
        res.set(http::field::content_type, "text/plain");
        res.body() = "Log entry recorded successfully.";
        res.prepare_payload();
        http::write(ssl_stream, res);

    } catch (const std::runtime_error& e) {
        // Send error response to the client
        http::response<http::string_body> res{http::status::bad_request, 11};
        res.set(http::field::content_type, "text/plain");
        res.body() = e.what(); // Set the error message from the exception
        res.prepare_payload();
        http::write(ssl_stream, res);
    } catch (const std::exception& e) {
        // Handle other exceptions
        http::response<http::string_body> res{http::status::internal_server_error, 11};
        res.set(http::field::content_type, "text/plain");
        res.body() = "Internal server error: " + std::string(e.what());
        res.prepare_payload();
        http::write(ssl_stream, res);
    }
}

// Utility function to join strings
std::string join(const std::vector<std::string>& vec, const std::string& delimiter) {
    std::ostringstream os;
    for (size_t i = 0; i < vec.size(); ++i) {
        os << vec[i];
        if (i < vec.size() - 1) {
            os << delimiter;
        }
    }
    return os.str();
}

// Handle log read requests
std::string handle_logread(const json& log_data, ssl::stream<tcp::socket>& ssl_stream) {
    try {
        std::string log_file = log_data.at("log_name");
        std::string token = log_data.at("token");
        std::string query_type = log_data.at("query_type");
        MongoDBHandler db_handler(log_file);
    if (!db_handler.validate_log_token(log_file, token)) {
        std::cerr << "Invalid authentication!" << std::endl;
        throw std::runtime_error("Invalid token");
    }
   

    if (query_type == "state") {
        // Logic for -S (state query)
        return "\n" + db_handler.logread_S();
    } else if (query_type == "room") {
        // Logic for -R (room query)
        std::string name = log_data.at("name");
        std::string role = log_data.at("role");
        return db_handler.logread_R(name, role);
    } else if (query_type == "time") {
        // Logic for -T (time query)
        std::string name = log_data.at("name");
        std::string role = log_data.at("role");
        std::string  timestamp = log_data.at("timestamp");

        int last = db_handler.read_last_log_time();
            bool time_consistent = false;
            if(std::stoi(timestamp) <= last){
                std::cerr << "Time inconsistent!" << std::endl;
                        return "255";
        }
        int time_spent = db_handler.GetTotalTime(name, role, std::stoi(timestamp));
        std::cout << name << ": " << time_spent << std::endl;
        db_handler.write_last_log_time(std::stoi(timestamp));
        return R"({"total_time": ")" + std::to_string(time_spent) + R"("})";
    }

    } catch (const std::runtime_error& e) {
        // Send error response to the client
        http::response<http::string_body> res{http::status::bad_request, 11};
        res.set(http::field::content_type, "text/plain");
        res.body() = e.what(); // Set the error message from the exception
        res.prepare_payload();
        http::write(ssl_stream, res);
        return ""; // Return empty string after error
    } catch (const std::exception& e) {
        // Handle other exceptions
        http::response<http::string_body> res{http::status::internal_server_error, 11};
        res.set(http::field::content_type, "text/plain");
        res.body() = "Internal server error: " + std::string(e.what());
        res.prepare_payload();
        http::write(ssl_stream, res);
        return ""; // Return empty string after error
    }
    return "";
}

// Function to handle HTTPS requests from clients
void handle_request(ssl::stream<tcp::socket>& ssl_stream) {
    beast::flat_buffer buffer;
    http::request<http::string_body> req;
    http::read(ssl_stream, buffer, req);

    if (req.method() == http::verb::post && req.target() == "/logappend") {
        json log_data = json::parse(req.body());
        handle_logappend(log_data, ssl_stream);
        
    } else if (req.method() == http::verb::post && req.target() == "/logread") {
        json query = json::parse(req.body());
        std::string result = handle_logread(query, ssl_stream);

        if (!result.empty()) {
            http::response<http::string_body> res{http::status::ok, 11};
            res.set(http::field::content_type, "application/json");
            res.body() = result;
            res.prepare_payload();
            http::write(ssl_stream, res);
        }
    }
}


int main() {
    try {
       
        net::io_context ioc;
        ssl::context ctx{ssl::context::tlsv13_server};

        // Load server's certificate and private key
        ctx.use_certificate_file("server.crt", ssl::context::pem);
        ctx.use_private_key_file("server.key", ssl::context::pem);

        // Load the Root CA certificate to verify client certificates
        ctx.load_verify_file("rootCA.crt");

        // Require the client to present a valid certificate
        ctx.set_verify_mode(ssl::verify_peer | ssl::verify_fail_if_no_peer_cert);

        tcp::acceptor acceptor{ioc, tcp::endpoint{tcp::v4(), 8051}};

        while (true) {
            tcp::socket socket{ioc};

            // Accept TCP connection
            boost::system::error_code ec;
            acceptor.accept(socket, ec);
            if (ec) {
                std::cerr << "Error accepting connection: " << ec.message() << std::endl;
                continue;  // Skip to the next iteration on error
            }

            // Get the client IP address from the accepted socket
            std::string client_ip = socket.remote_endpoint().address().to_string();
            std::cout << "Connected to client at: " << client_ip << std::endl;

            // Check if the client is rate-limited
            if (is_rate_limited(client_ip)) {
                std::cerr << "Client " << client_ip << " is rate-limited." << std::endl;

                // Respond with a 429 Too Many Requests error
                ssl::stream<tcp::socket> ssl_stream{std::move(socket), ctx};
                ssl_stream.handshake(ssl::stream_base::server);

                http::response<http::string_body> res{http::status::too_many_requests, 11};
                res.set(http::field::content_type, "text/plain");
                res.body() = "Too Many Requests";
                res.prepare_payload();

                http::write(ssl_stream, res);
                ssl_stream.shutdown(ec);
                continue;  // Move to the next client connection
            }

            // Wrap the socket with SSL
            ssl::stream<tcp::socket> ssl_stream{std::move(socket), ctx};

            // Perform SSL handshake
            ssl_stream.handshake(ssl::stream_base::server, ec);
            if (ec) {
                std::cerr << "SSL handshake failed: " << ec.message() << std::endl;
                continue;
            }

            // Handle the request
            handle_request(ssl_stream);
        }
    } catch (std::exception const& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    return 0;
}
