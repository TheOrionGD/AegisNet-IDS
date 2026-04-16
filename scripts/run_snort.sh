#!/bin/bash
# Helper script to run Snort 3 for the CNS project
# Ensures proper setup and error handling

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}--- CNS IDS: Snort 3 Runner ---${NC}"

# 1. Check if running as root or with sudo
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}ERROR: This script must be run with sudo privileges.${NC}"
    echo "Usage: sudo bash scripts/run_snort.sh"
    exit 1
fi

# 2. Check if snort is installed
if ! command -v snort &> /dev/null; then
    echo -e "${RED}ERROR: Snort 3 is not installed or not in PATH.${NC}"
    echo "Please install Snort 3 first. See docs/README_VMWARE.md for instructions."
    exit 1
fi

# 3. Check if snort.lua config exists
CONFIG_FILE="snort.lua"
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo -e "${RED}ERROR: Configuration file '$CONFIG_FILE' not found.${NC}"
    exit 1
fi

# 4. Detect Network Interface
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
if [[ -z "$INTERFACE" ]]; then
    echo -e "${YELLOW}WARNING: Could not detect default interface, falling back to eth0.${NC}"
    INTERFACE="eth0"
fi

echo "Detected Interface: $INTERFACE"
echo "Using Configuration: $CONFIG_FILE"

# 5. Ensure logs directory exists and set permissions
mkdir -p logs
touch logs/alert.json
chmod 666 logs/alert.json

# 6. Validate configuration (optional, uncomment for testing)
# echo -e "${YELLOW}Validating configuration...${NC}"
# if ! snort -c "$CONFIG_FILE" --warn-all 2>&1; then
#     echo -e "${RED}ERROR: Configuration validation failed.${NC}"
#     exit 1
# fi

# 7. Run Snort
echo -e "${GREEN}Starting Snort 3...${NC}"
echo "Press Ctrl+C to stop."
snort -c "$CONFIG_FILE" -i "$INTERFACE" -l logs
