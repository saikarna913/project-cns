# Security Guard Project 10

## Overview

This project implements a secure logging system that tracks the state of an institute, including the movements of guests and employees. The logging functionality is divided into two main components: `logappend` for appending logs and `logread` for reading logs.

## Prerequisites

Before you begin, ensure you have the necessary libraries installed:

### On Linux

```bash
sudo apt-get update
sudo apt-get install libssl-dev
```

### On macOS

```bash
brew install openssl
```

## Building the Project

To build the project, use the `make` command in your terminal. This will compile the source files and link them with the necessary libraries.

```bash
make
```

## Usage

To append a log entry, use the following command format:

```bash
./logappend -T <timestamp> -K <secret_key> -A <additional_info> -E <name> <log_file>
```

### Example

```bash
./logappend -T 1 -K secret -A -E Fred log1
```

In this example:
- `-T 1`: Specifies the timestamp.
- `-K secret`: Sets the secret key for authentication.
- `-A`: Indicates additional information (optional).
- `-E Fred`: Specifies the name associated with the log entry.
- `log1`: The log file to which the entry will be appended.


This will place the `logappend` and `logread` executables in `/usr/local/bin/`.

