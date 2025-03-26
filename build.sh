#!/bin/bash
set -e

# Create bin directory and install syft into it
mkdir -p ./bin
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ./bin

# Add it to PATH for Render
export PATH="$PATH:$(pwd)/bin"
echo 'export PATH=$PATH:$(pwd)/bin' >> ~/.profile
