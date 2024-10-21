# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -Wall -Wextra -std=c++11 -I/opt/homebrew/include -I/opt/homebrew/Cellar/openssl@3/include

# Library paths
JSON_LIB_PATH = /opt/homebrew/Cellar/jsoncpp/1.9.5/lib
SSL_LIB_PATH = /opt/homebrew/Cellar/openssl@3/3.3.2/lib  # Updated path to OpenSSL

# Libraries
LIBS = -ljsoncpp -lssl.3 -lcrypto.3  # Updated to link against OpenSSL version 3

# Source files
ATM_SRC = atm_final.cpp
BANK_SRC = bank_final.cpp

# Executables
ATM = atm
BANK = bank

# Default target
.PHONY: all clean
all: $(ATM) $(BANK)

# Build ATM
$(ATM): $(ATM_SRC)
	@echo "Building $(ATM)..."
	$(CXX) $(CXXFLAGS) -o $@ $^ -L$(JSON_LIB_PATH) -L$(SSL_LIB_PATH) $(LIBS)
	@echo "$(ATM) built successfully."

# Build Bank
$(BANK): $(BANK_SRC)
	@echo "Building $(BANK)..."
	$(CXX) $(CXXFLAGS) -o $@ $^ -L$(JSON_LIB_PATH) -L$(SSL_LIB_PATH) $(LIBS)
	@echo "$(BANK) built successfully."

# Clean build artifacts
clean:
	@echo "Cleaning up..."
	rm -f $(ATM) $(BANK)
	@echo "Cleanup complete."
