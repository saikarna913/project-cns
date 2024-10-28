# Directory structure
SRC_DIR = src
BUILD_DIR = build
CERT_DIR = certs
BIN_DIR = $(BUILD_DIR)/bin

# Compiler and flags
CXX = g++
CXXFLAGS = -Wall -std=c++17
LDFLAGS = -lssl -lcrypto

# Source files
CLIENT_SRC = $(SRC_DIR)/Bank_client.cpp
SERVER_SRC = $(SRC_DIR)/Bank_Server.cpp

# Output binaries
CLIENT_BIN = $(BIN_DIR)/atm
SERVER_BIN = $(BIN_DIR)/bank

# Certificate and key files
SERVER_CERT = $(CERT_DIR)/server_cert.pem
SERVER_KEY = $(CERT_DIR)/server_key.pem
CLIENT_CERT = $(CERT_DIR)/client_cert.pem
CLIENT_KEY = $(CERT_DIR)/client_key.pem
CA_CERT = $(CERT_DIR)/ca_cert.pem
PUBLIC_KEY_FILE = $(CERT_DIR)/public_key.pem
PRIVATE_KEY_FILE = $(CERT_DIR)/private_key.pem

# Create necessary directories
$(shell mkdir -p $(BUILD_DIR) $(BIN_DIR) $(CERT_DIR))

# Default target
all: $(CLIENT_BIN) $(SERVER_BIN) certs

# Compile client
$(CLIENT_BIN): $(CLIENT_SRC)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

# Compile server
$(SERVER_BIN): $(SERVER_SRC)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

# Generate certificates and keys
certs: $(SERVER_CERT) $(SERVER_KEY) $(CLIENT_CERT) $(CLIENT_KEY) $(CA_CERT) $(PUBLIC_KEY_FILE) $(PRIVATE_KEY_FILE)

$(SERVER_CERT) $(SERVER_KEY):
	openssl req -x509 -newkey rsa:2048 -keyout $(SERVER_KEY) -out $(SERVER_CERT) -days 365 -nodes -subj "/CN=localhost"

$(CLIENT_CERT) $(CLIENT_KEY):
	openssl req -x509 -newkey rsa:2048 -keyout $(CLIENT_KEY) -out $(CLIENT_CERT) -days 365 -nodes -subj "/CN=localhost"

$(CA_CERT):
	openssl req -x509 -newkey rsa:2048 -keyout $(CERT_DIR)/ca_key.pem -out $(CA_CERT) -days 365 -nodes -subj "/CN=CA"

$(PUBLIC_KEY_FILE) $(PRIVATE_KEY_FILE):
	openssl genpkey -algorithm RSA -out $(PRIVATE_KEY_FILE) -pkeyopt rsa_keygen_bits:2048
	openssl rsa -pubout -in $(PRIVATE_KEY_FILE) -out $(PUBLIC_KEY_FILE)

# Clean up generated files
clean:
	rm -rf $(BUILD_DIR)/* $(CERT_DIR)/*

# Phony targets
.PHONY: all clean certs