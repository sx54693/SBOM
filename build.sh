#!/usr/bin/env bash

set -e  # Exit on error

# 🛠️ Install Syft CLI to /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# 🐍 Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt


