# CS431-Project-8-SecurityGuard

## Prerequisites

Ensure you have the following installed on your system:
- GCC (g++)
- Make
- CMake


## Project Outline
The Project has a **server** executable and a **client** executable. Follow the following steps to buid the project and use the application

## Building the Project

1. **Clone the repository**:
    ```bash
    git clone https://github.com/Demolus13/CS431-Project-8-SecurityGuard.git
    cd CS431-Project-8-SecurityGuard
    ```
    

2. **Build the Project using Make**:
    ```bash
    rm -rf build
    mkdir -p build
    cd build
    cmake ..
    make
    ```

3. **Clearing previous logs**(this will clear guard logs):
    ```bash
    make clear
    ```

4. **Rebuild after changes**:
   No need to run build again, just do:
   ```bash
    make
    ```

## Running the Project

### Navigate to the [`build`](./build/) folder
```bash
cd build
```

## To run the server
Run this in your terminal:

```
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```
This is required as first step for creating the SSL certificate for secure communication.

Then, run:

`./server`

The server will start and listen for connections on you **localhost**, share your device IP with clients to connect with the server.

## To run the client

in client device, follow build steps as mentioned above and navigate to the build folder. 
execute **client**
```
./client
```

Enter either localhost or the IP of server device accordingly when asked. 

If unable to connect due to firewall, use the following command to disable firewall.
```
sudo systemctl stop ufw
```

### Running the client commands

The following commands are supported:

```
logappend -T <timestamp> -K <token> (-E <employee-name> | -G <guest-name>) (-A | -L) [-R <room-id>] <log>
logappend -B <file>
logread -K <token> -S <log>
logread -K <token> -R (-E <name> | -G <name>) <log>
logread -K <token> -T (-E <name> | -G <name>) <log>
```

-------

To know about application constraints, please find the [constraints.md](constraints.md) file.