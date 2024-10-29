# Security Guard
### This repository contains the codebase of Security Guard Project.
#### It mainly has two functions, logappend and logread.
- `logappend`: Used to securely append data to the log files.
- `logread`: Used to securely read data from the log files.

The project uses the `libsodium` library for cryptographic operations and `nlohmann-json` for JSON parsing.


## Project Structure

The project directory structure is as follows:

All the source files and `Makefile` are located in the `build` directory. After building, the executables `logappend` and `logread` will be created within the `build` directory.

## Prerequisites

This project requires:
1. `libsodium` - for cryptographic functions.
2. `nlohmann-json` - for JSON parsing.

### Installing libsodium and nlohmann-json

#### Linux (Debian/Ubuntu)
```bash
sudo apt update
sudo apt install libsodium-dev
sudo apt install nlohmann-json3-dev
```
If you are a root user omit `sudo` from above commands.
#### Mac

```bash 
brew install libsodium
brew install nlohmann-json
```

### Building the Project

To build the project, follow these steps:

1. Navigate to the build directory:

```bash
cd build
```

2.Run make to compile the executables:
```bash
make
```
This will create two executable files in the build directory:

logappend  
logread

### Running the Programs
After building the project, you can run the executables from the build directory.

Running logappend
```bash
./logappend [options]

```
Running logread
```bash
./logread [options]

```
Details about [options] is provided in the Problem Statement of the Security Guard Project.




