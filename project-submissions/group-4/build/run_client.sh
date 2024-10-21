#!/bin/bash

# Default server IP
SERVER_IP="10.7.50.57"

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --server-ip) SERVER_IP="$2"; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

# Navigate to the client directory
cd client

# Build the client Docker image
docker build -f Dockerfile.client -t client .

# Run the client container, passing the SERVER_IP as an environment variable
docker run -it --name client -e SERVER_IP="$SERVER_IP" client
