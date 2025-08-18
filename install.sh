#!/bin/bash

# A script to download, build, and run the GoDNS server.
# This script requires that Go is already installed on your system.

# Exit immediately if a command exits with a non-zero status.
set -e

# --- 1. Check for Go installation ---
echo "Checking for Go installation..."
if ! command -v go &> /dev/null; then
    echo "Error: 'go' command not found. Please install Go before running this script."
    exit 1
fi
echo "Go is installed. Proceeding with installation."

# --- 2. Define GOPATH and project path ---
# Use the existing GOPATH or set a default if not defined.
export GOPATH=${GOPATH:-$HOME/go}
export PATH=$PATH:$GOPATH/bin

GODNS_REPO="github.com/ProxyFi/GoDNS"
GODNS_PATH="$GOPATH/src/$GODNS_REPO"
GODNS_CONFIG_DIR="$GODNS_PATH/etc"
GODNS_CONFIG_FILE="$GODNS_CONFIG_DIR/godns.conf"

echo "Using GOPATH: $GOPATH"

# --- 3. Download the project ---
echo "Downloading GoDNS project from $GODNS_REPO..."
# The 'go get' command clones the repository and its dependencies.
go get $GODNS_REPO

# Check if the project directory was created successfully.
if [ ! -d "$GODNS_PATH" ]; then
    echo "Error: Failed to download the GoDNS project."
    exit 1
fi
echo "Download successful. Navigating to the project directory."
cd "$GODNS_PATH"

# --- 4. Create configuration file ---
echo "Creating basic configuration file at $GODNS_CONFIG_FILE..."
mkdir -p "$GODNS_CONFIG_DIR"
cat <<EOF > "$GODNS_CONFIG_FILE"
# GoDNS configuration file (TOML format)

[resolv]
resolv-file = "/etc/resolv.conf"

[cache]
backend = "memory"
expire = 600
maxcount = 100000

[hosts]
host-file = "/etc/hosts"
EOF
echo "Configuration file created with default settings."

# --- 5. Build the executable ---
echo "Building the 'godns' executable..."
go build -o godns

# Check if the binary was successfully created.
if [ ! -f "godns" ]; then
    echo "Error: Go build failed. The 'godns' executable was not created."
    exit 1
fi
echo "Build successful. The 'godns' executable is ready."

# --- 6. Run the server ---
echo "Attempting to run the GoDNS server..."
echo "Note: This command requires 'sudo' to run as root and may prompt for your password."
sudo ./godns -c "$GODNS_CONFIG_FILE"

echo "GoDNS server has been started."
echo "You can test it with a command like: dig www.github.com @127.0.0.1"

