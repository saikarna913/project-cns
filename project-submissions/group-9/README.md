Here’s a README file for your ATM communication protocol project:


# ATM Communication Protocol Project

## Overview

This project implements a secure ATM communication protocol that enables customers to perform transactions like deposits, withdrawals, and balance inquiries. It ensures secure communication between the ATM client and the bank server using mutual authentication and encryption.

## Project Structure

The project consists of the following files:

- `atm.cpp`: The client program that allows customers to interact with the ATM.
- `bank.cpp`: The server program that manages customer accounts and transactions.
- `ca.crt`: Certificate authority certificate for validating the server and client certificates.
- `client.crt`: Client certificate used for authentication with the server.
- `client.key`: Private key corresponding to the client certificate.
- `Makefile`: Script for compiling the project.
- `secret_key.h`: Header file containing definitions and declarations for encryption keys.
- `server.crt`: Server certificate used for authentication with the client.
- `server.key`: Private key corresponding to the server certificate.

## Features

- **Mutual Authentication**: Both the client and server authenticate each other using certificates.
- **Secure Communication**: Data exchanged between the client and server is encrypted to prevent eavesdropping.
- **JSON Output**: The program outputs transaction results in JSON format for easy parsing.
- **Error Handling**: Comprehensive error handling for various input scenarios.

## Requirements

- A POSIX-compliant environment.
- OpenSSL library for handling SSL/TLS communications.

## How to Build

1. Clone the repository:
   ```bash
   git clone https://github.com/Destructor169/CNS_Group_9.git
   cd CNS_Group_9
   ```

2. Compile the project using the Makefile:
   ```bash
   make
   ```

## Usage

### ATM Client

Run the ATM client with the following command-line options:
- `-a <account_number>`: Specify the account number.
- `-c <card_file_name>`: Specify the card file name.
- `-n <initial_balance>`: Specify the initial balance (for new accounts).
- `-d <amount>`: Specify the amount to deposit.
- `-w <amount>`: Specify the amount to withdraw.
- `-g`: Get the current balance.

Example command:
```bash
./atm -a my_account -c my_account.card -n 1000
```

### Bank Server

Run the bank server:
```bash
./bank -s bank.auth
```

## Security Features

- The communication between the ATM client and bank server is secured using SSL/TLS.
- The CA certificate (`ca.crt`) is used to verify the authenticity of the server and client certificates.
