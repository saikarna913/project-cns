cmake_minimum_required(VERSION 3.10)
project(MyServerClientProject)

# Specify C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add include directories for header files
include_directories(include)
message("Include directories: ${CMAKE_INCLUDE_PATH}")

# Find OpenSSL and Threads packages
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Set the directory for certificate output
set(CERT_DIR "${CMAKE_SOURCE_DIR}/build")

# Create certs directory if it doesn't exist and generate certificate
add_custom_command(
    OUTPUT ${CERT_DIR}/cert.pem ${CERT_DIR}/key.pem
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CERT_DIR}
    COMMAND openssl req -x509 -newkey rsa:2048 -keyout ${CERT_DIR}/key.pem -out ${CERT_DIR}/cert.pem -days 365 -nodes -config ${CMAKE_SOURCE_DIR}/openssl.cnf
    DEPENDS ${CMAKE_SOURCE_DIR}/openssl.cnf
    COMMENT "Generating SSL certificate and key..."
)

# Add a custom target for generating the certificates
add_custom_target(generate_certificates
    DEPENDS ${CERT_DIR}/cert.pem ${CERT_DIR}/key.pem
)

# Add executables for server and client
add_executable(server src/server.cpp src/utils.cpp)
add_executable(client src/client.cpp src/utils.cpp)

# Ensure certificates are generated before building server and client
add_dependencies(server generate_certificates)
add_dependencies(client generate_certificates)

# Link OpenSSL and pthread to server and client executables
target_link_libraries(server OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
target_link_libraries(client OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

# Include additional directory for utilities (if needed)
target_include_directories(server PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_include_directories(client PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Custom target to clear logs directory
set(LOGS_DIR "${CMAKE_SOURCE_DIR}/build/logs")
add_custom_target(clear
    COMMAND ${CMAKE_COMMAND} -E echo "Clearing logs..."
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${LOGS_DIR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${LOGS_DIR}
    COMMENT "Clear all files from the logs directory"
)

# Enable verbose logging in case of any errors
set(CMAKE_VERBOSE_MAKEFILE ON)
