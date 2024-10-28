# Compiler
CXX = g++

# Flags
CXXFLAGS = -lsodium

# Build directory
BUILD_DIR = build


# Executable files
EXECUTABLES = $(BUILD_DIR)/logappend $(BUILD_DIR)/logread

REMOVALS = logappend logread

# Object files for logappend and logread (point to the source directory)
LOGAPPEND_OBJS = logappend.cpp security.cpp parseAppend.cpp
LOGREAD_OBJS = logread.cpp security.cpp parseRead.cpp

# Default target: build all executables
all: $(BUILD_DIR) $(EXECUTABLES)

# Create the build directory if it doesn't exist
$(BUILD_DIR):

# Rule to build logappend
$(BUILD_DIR)/logappend: $(LOGAPPEND_OBJS)
	$(CXX) $(LOGAPPEND_OBJS) -o logappend $(CXXFLAGS)

# Rule to build logread
$(BUILD_DIR)/logread: $(LOGREAD_OBJS)
	$(CXX) $(LOGREAD_OBJS) -o logread $(CXXFLAGS)

# Clean up generated files
clean:
	rm -f $(REMOVALS)
