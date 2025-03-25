#!/bin/bash

# Create a writable bin directory
mkdir -p ./bin

# Install Syft into ./bin (inside your project)
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ./bin

# Make sure ./bin is in the PATH
echo 'export PATH=$PATH:./bin' >> ~/.profile
