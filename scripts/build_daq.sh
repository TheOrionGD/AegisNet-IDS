#!/bin/bash
set -euo pipefail

echo "=== PHASE 3: Building DAQ ==="

# Final cleanup of stale libs
sudo rm -f /lib/x86_64-linux-gnu/libdaq.so.2* 2>/dev/null || true
sudo rm -f /lib/x86_64-linux-gnu/libdaq.so* 2>/dev/null || true
sudo ldconfig

cd /tmp
rm -rf snort3-build
mkdir -p snort3-build && cd snort3-build

echo "--- Cloning libdaq ---"
git clone --depth 1 https://github.com/snort3/libdaq.git
cd libdaq

echo "--- Bootstrap ---"
./bootstrap

echo "--- Configure ---"
./configure --prefix=/usr/local

NPROC=$(nproc)
echo "--- Make with $NPROC threads ---"
make -j"$NPROC"

echo "--- Install ---"
sudo make install
sudo ldconfig

echo ""
echo "=== PHASE 4: DAQ Validation ==="
echo "--- ldconfig check ---"
ldconfig -p | grep daq || echo "WARNING: No daq in ldconfig"

echo ""
echo "--- DAQ files in /usr/local ---"
ls -la /usr/local/lib/libdaq* 2>/dev/null || echo "No libdaq files found"
echo ""
ls -la /usr/local/lib/daq/ 2>/dev/null || echo "No daq module dir"

echo ""
echo "--- pkg-config ---"
export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
pkg-config --modversion libdaq 2>/dev/null || echo "pkg-config: libdaq not found"

echo ""
echo "--- daq-modules-config ---"
if [ -x /usr/local/bin/daq-modules-config ]; then
    /usr/local/bin/daq-modules-config --version 2>/dev/null || echo "daq-modules-config failed"
else
    echo "daq-modules-config not found at /usr/local/bin"
fi

echo ""
echo "=== DAQ BUILD COMPLETE ==="
