#!/bin/bash
# Helper script to run Snort 3 for the CNS project

# 1. Detect Network Interface
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
if [ -z "$INTERFACE" ]; then
    INTERFACE="eth0"
fi

echo "--- CNS IDS: Snort 3 Runner ---"
echo "Detected Interface: $INTERFACE"
echo "Using Configuration: snort.lua"

# 2. Ensure logs directory exists
mkdir -p logs
touch logs/alert.json
chmod 666 logs/alert.json

# 3. Validation Mode (uncomment to test config)
# snort -c snort.lua --warn-all

# 4. Run Snort
# We use -i for interface and -l for log directory (though snort.lua defines the file)
sudo snort -c snort.lua -i $INTERFACE -l logs
