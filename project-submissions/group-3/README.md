# Banking System

This is a Python project named `banking_system` designed to simulate basic banking operations like account creation, transactions, and balance checks. The project uses [Poetry](https://python-poetry.org/), a Python dependency manager, for managing dependencies, virtual environments, and packaging. It also uses Docker to containerize the application for consistent and isolated development environments.

## Table of Contents

- [Banking System](#banking-system)
  - [Table of Contents](#table-of-contents)
  - [Project Overview](#project-overview)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
    - [Setting up Docker](#setting-up-docker)
    - [Setting up Poetry](#setting-up-poetry)
      - [macOS / Linux / Windows Subsystem for Linux (WSL)](#macos--linux--windows-subsystem-for-linux-wsl)
      - [Windows (PowerShell)](#windows-powershell)
    - [Setting up the Project](#setting-up-the-project)
    - [Recommended Development Environment](#recommended-development-environment)
  - [Setup](#setup)
  - [Usage](#usage)
    - [Command Flow](#command-flow)
  - [Assumptions](#assumptions)

## Project Overview

The `banking_system` is a simple banking simulation. It includes functionalities such as:

- Creating bank accounts
- Depositing and withdrawing money
- Checking account balances

It contains a central server and a client(atm). 

## Prerequisites

- Python 3.8 or higher
- Poetry for managing dependencies
- Docker Desktop & Services

## Installation

### Setting up Docker

To set up Docker, follow these steps:

1. **Install Docker Desktop:**

  - **macOS:**
    Download and install Docker Desktop for Mac from [Docker's official website](https://www.docker.com/products/docker-desktop).

  - **Windows:**
    Download and install Docker Desktop for Windows from [Docker's official website](https://www.docker.com/products/docker-desktop).

  - **Linux:**
    Follow the instructions for your specific Linux distribution on the [Docker installation page](https://docs.docker.com/engine/install/).

2. **Verify Docker Installation:**
  Open a terminal (or PowerShell on Windows) and run the following command to verify that Docker is installed correctly:

  ```bash
  docker --version
  ```

  You should see the Docker version information.

### Setting up Poetry

First, you need to install Poetry on your machine. Follow the instructions below based on your operating system:

#### macOS / Linux / Windows Subsystem for Linux (WSL)

Run the following command to install Poetry:

```bash
curl -sSL https://install.python-poetry.org | python3 -
```

Add Poetry to your environment by adding the following line to your shell configuration file (`~/.bashrc`, `~/.zshrc`, or similar):

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Then restart your terminal or run:

```bash
source ~/.bashrc   # or source ~/.zshrc, depending on your shell
```

#### Windows (PowerShell)

Use the following command to install Poetry on Windows:

```powershell
(Invoke-WebRequest -Uri https://install.python-poetry.org -UseBasicParsing).Content | python -
```

You may also need to add Poetry to your system PATH. Follow the instructions in the terminal after the installation.

For detailed installation instructions or troubleshooting, visit the [official Poetry documentation](https://python-poetry.org/docs/#installation).

### Setting up the Project

1. Clone this repository to your local machine:

```bash
git clone https://github.com/YYashraj/Banking_System.git
cd banking_system
```

2. Install the project dependencies using Poetry:

```bash
poetry install
```

This will install all dependencies and set up a virtual environment for the project.

3. To activate the virtual environment (optional, but recommended):

```bash
poetry shell
```

Now, the project is ready to run!

### Recommended Development Environment

For the best experience, please use a Unix-based environment (Linux or macOS) to avoid potential setup issues. 

For Windows users, consider the following alternatives to achieve a similar Unix-like environment:

- **Git Bash**: A simple and lightweight option that provides a bash emulation.
- **Windows Subsystem for Linux (WSL)**: Allows you to run a Linux distribution directly on Windows.
- **Linux Virtual Machine (VM)**: Use virtualization software like VirtualBox or VMware to run a full Linux environment.
- **Cygwin**: A large collection of GNU and Open Source tools which provide functionality similar to a Linux distribution on Windows.

These alternatives can help you avoid common setup issues and provide a more consistent development experience.

## Setup

To run the server after Docker installation, use the `server` script (this automates the process):

```bash
./server -p <port>
```

For the client setup, first run:

```bash
chmod +x setup.sh
./setup.sh
```

Also create a `.env` file to set the environment variables. An example for that is provided below:

```bash
SERVER_PORT=8000
PG_USER=yyashraj
PG_PASSWORD=sahilbad
PG_DATABASE=bank
DATABASE_URL=postgresql+asyncpg://${PG_USER}:${PG_PASSWORD}@db:5432/${PG_DATABASE}
```

## Usage

Now, you are all set to use the ATM client:

```bash
Usage: atm.py [OPTIONS]

Options:
  -s, --auth-file TEXT       Authentication file
  -i, --ip-address TEXT      Bank server IP address
  -p, --port INTEGER         Bank server port
  -c, --card-file TEXT       Customer's ATM card file
  -a, --account TEXT         Customer's account number  [required]
  -n, --new-account DECIMAL  Initial balance for new account
  -d, --deposit DECIMAL      Amount to deposit
  -w, --withdraw DECIMAL     Amount to withdraw
  -g, --get-balance          Get account balance
  -l, --login                Login to account
  -o, --logout               Logout from account
  --help                     Show this message and exit.
```

**Note:** Use the `atm_cleaner.sh` script to clear all the saved files from the client side. Please do this after ending a session, preferably even before the session is started.

### Command Flow

1. If you are a new user, begin with creating an account. You will need to provide a name for your account and an initial balance amount. Then you will be prompted to input a PIN for your account. It should be a purely numeric value of size in range 4 to 8. You can also provide a name for your card file, otherwise, the default value will be used.
2. For an existing user, to perform any transaction, you need to log in first. You will need to input your account name and card file name if you have set it to anything other than the default value. You can also provide a name for this session's auth file, otherwise, it is set to the default value.
3. For deposit and withdrawal, you need to provide the account number and the amount you want to deposit/withdraw. Provide auth and card file names as required.
4. For checking balance and terminating the session, you need to provide your account number. Provide auth and card file names as required.

Note: Follow the input criteria specified here - [Valid Inputs](https://github.com/IITGN-CS431/problems/blob/main/atm/index.md#valid-inputs). Provide IP address and port in each command if you are not using the default connections. Currency values are only defined up to 2 decimal places. If an amount with more than two floating points is received, the value will be truncated with a warning.

## Assumptions

1. **Certificate File Requirement:** For secure communication between the ATM and the Bank, a certificate file is required. If you plan to test the system from different devices, ensure the following:
  - Update the IP addresses (server device's private IP) and ports accordingly.
  - Ensure the certificate file from the `/certs` folder on the server side is copied to the corresponding `/certs` folder on the client side.
  - Note that certificates may change with each server run, so always use the latest certificate.
2. The auth file is valid for the duration of a user's session. In case of timeout or logout, users need to re-login to initiate a new session with the bank, which results in the creation of a new auth file. The default auth file format has been changed to incorporate multiple ongoing user sessions.
3. Different terminals running the same file/location are not considered as different "ATMs". However, if one could change the location and then run, the card and auth files will be formed respectively. The bank system supports multiple active logins, allowing any authenticated user to perform transactions as long as they provide valid identification.
4. It was mentioned in the requirements document to not allow more than 2 decimal places in the `amount` field. We print out a warning related to it and truncate it for further operations.
