#!/bin/bash

# Create a bin folder if it doesn't exist
mkdir -p ./bin

# Install Syft into ./bin
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ./bin

# Add it to PATH for runtime
echo 'export PATH=$PATH:/opt/render/project/src/bin' >> ~/.profile
