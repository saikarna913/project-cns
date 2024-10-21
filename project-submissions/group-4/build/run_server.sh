#!/bin/bash

cd server

# Build the server Docker image
docker build -f Dockerfile.server -t server .

# Run the server container, mapping port 8051
docker run -it --name server -p 8051:8051 server
