#!/bin/bash
# Snort 3 Installation Script

set -e

echo "========================================"
echo "Snort 3 Installation & Setup"
echo "========================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root (sudo)."
    exit 1
fi

echo "1. Removing any existing Snort 2.9 installations..."
apt-get remove -y snort snort-rules-default || true
apt-get autoremove -y || true

echo "2. Installing Build Dependencies..."
apt-get update -qq
apt-get install -y -qq build-essential libpcap-dev libpcre3-dev libdumbnet-dev bison flex \
    zlib1g-dev liblzma-dev openssl libssl-dev pkg-config git wget curl cmake libjemalloc-dev \
    python3-dev libhwloc-dev libboost-all-dev libflatbuffers-dev flatbuffers-compiler \
    libluajit-5.1-dev uuid-dev jq tcpdump sqlite3 python3 python3-pip

echo "3. Building libDAQ (Snort 3 Dependency)..."
TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"
wget -q https://github.com/snort3/libdaq/archive/refs/tags/v3.0.13.tar.gz -O libdaq.tar.gz
tar -xzf libdaq.tar.gz
cd libdaq-3.0.13
./bootstrap > /dev/null 2>&1
./configure > /dev/null 2>&1
make > /dev/null 2>&1
make install > /dev/null 2>&1
ldconfig
cd ..

echo "4. Building Snort 3..."
wget -q https://github.com/snort3/snort3/archive/refs/tags/3.1.75.0.tar.gz -O snort3.tar.gz
tar -xzf snort3.tar.gz
cd snort3-3.1.75.0
./configure_cmake.sh --prefix=/usr/local > /dev/null 2>&1
cd build
make -j"$(nproc)" > /dev/null 2>&1
make install > /dev/null 2>&1
ldconfig

cd /
rm -rf "$TMP_DIR"

echo "5. Snort 3 Installation Complete!"
snort -V | head -n 4