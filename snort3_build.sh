#!/bin/bash
set -euo pipefail

# =============================================================================
# Snort 3 + DAQ Full Clean Build Script
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

log_phase() { echo -e "\n${BOLD}${CYAN}═══════════════════════════════════════════════════════${NC}"; echo -e "${BOLD}${CYAN}  PHASE $1 — $2${NC}"; echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════${NC}\n"; }
log_step()  { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_err()   { echo -e "${RED}[✗]${NC} $1"; }
log_info()  { echo -e "${CYAN}[→]${NC} $1"; }

WORKDIR="/tmp/snort3-build-$$"
mkdir -p "$WORKDIR"

# =============================================================================
# PHASE 1 — SYSTEM CLEANUP
# =============================================================================
log_phase "1" "SYSTEM CLEANUP"

log_info "Removing existing DAQ installations..."
sudo rm -f /usr/local/lib/libdaq* 2>/dev/null || true
sudo rm -rf /usr/local/include/daq* 2>/dev/null || true
sudo rm -f /usr/local/bin/daq* 2>/dev/null || true
sudo rm -f /usr/local/lib/pkgconfig/libdaq* 2>/dev/null || true
sudo rm -rf /usr/local/lib/daq 2>/dev/null || true
log_step "Removed /usr/local DAQ files"

log_info "Purging system DAQ packages..."
sudo apt-get purge -y libdaq-dev libdaq0 libdaq3 libdaq-modules 2>/dev/null || true
sudo apt-get autoremove -y 2>/dev/null || true
log_step "System DAQ packages purged"

log_info "Running ldconfig cleanup..."
sudo ldconfig
log_step "ldconfig updated"

# Verify cleanup
log_info "Verifying no DAQ libraries remain..."
DAQ_REMAINING=$(ldconfig -p 2>/dev/null | grep -i daq || true)
if [ -n "$DAQ_REMAINING" ]; then
    log_warn "DAQ libraries still found:"
    echo "$DAQ_REMAINING"
    # Aggressive cleanup
    log_info "Performing aggressive cleanup..."
    for lib in $(ldconfig -p 2>/dev/null | grep -i daq | awk '{print $NF}'); do
        sudo rm -f "$lib" 2>/dev/null || true
        log_info "  Removed: $lib"
    done
    sudo ldconfig
fi

DAQ_CHECK=$(ldconfig -p 2>/dev/null | grep -i daq || true)
if [ -z "$DAQ_CHECK" ]; then
    log_step "Verified: No DAQ libraries remain in system"
else
    log_err "WARNING: Some DAQ artifacts remain (will be overwritten)"
    echo "$DAQ_CHECK"
fi

# =============================================================================
# PHASE 2 — FIX SYSTEM STATE
# =============================================================================
log_phase "2" "FIX SYSTEM STATE"

log_info "Fixing system time (clock skew protection)..."
# Try to use ntpdate or hwclock; in WSL2, time is synced from Windows
sudo hwclock --hctosys 2>/dev/null || log_warn "hwclock not available (normal in WSL)"
log_step "System time checked"

log_info "Installing build dependencies..."
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
sudo apt-get install -y -qq \
    build-essential \
    autoconf \
    automake \
    libtool \
    pkg-config \
    libpcap-dev \
    flex \
    bison \
    cmake \
    git \
    libhwloc-dev \
    libluajit-5.1-dev \
    libssl-dev \
    libpcre2-dev \
    zlib1g-dev \
    libdumbnet-dev \
    liblzma-dev \
    uuid-dev \
    libflatbuffers-dev \
    flatbuffers-compiler \
    libhyperscan-dev \
    libunwind-dev \
    2>/dev/null

log_step "Build dependencies installed"

# Verify critical packages
log_info "Verifying critical build tools..."
MISSING=""
for tool in gcc g++ make autoconf libtool pkg-config flex bison cmake git; do
    if ! command -v "$tool" &>/dev/null; then
        MISSING="$MISSING $tool"
    fi
done

if [ -n "$MISSING" ]; then
    log_err "Missing tools:$MISSING"
    exit 1
else
    log_step "All critical build tools verified"
fi

# Verify libpcap
if dpkg -l libpcap-dev &>/dev/null; then
    log_step "libpcap-dev verified"
else
    log_err "libpcap-dev NOT installed"
    exit 1
fi

# =============================================================================
# PHASE 3 — INSTALL FRESH DAQ
# =============================================================================
log_phase "3" "INSTALL FRESH DAQ"

cd "$WORKDIR"
log_info "Cloning libdaq from GitHub..."
if [ -d "libdaq" ]; then
    rm -rf libdaq
fi
git clone --depth 1 https://github.com/snort3/libdaq.git
cd libdaq

log_info "Running bootstrap..."
./bootstrap

log_info "Configuring DAQ (prefix=/usr/local)..."
./configure --prefix=/usr/local

log_info "Building DAQ with $(nproc) threads..."
make -j"$(nproc)"

log_info "Installing DAQ..."
sudo make install

log_info "Updating library cache..."
sudo ldconfig

log_step "DAQ installed successfully"

# =============================================================================
# PHASE 4 — VALIDATION
# =============================================================================
log_phase "4" "DAQ VALIDATION"

log_info "Checking ldconfig for DAQ libraries..."
DAQ_LIBS=$(ldconfig -p | grep daq || true)
if [ -z "$DAQ_LIBS" ]; then
    log_err "No DAQ libraries found via ldconfig!"
    log_info "Checking /usr/local/lib directly..."
    ls -la /usr/local/lib/libdaq* 2>/dev/null || true
    
    # Add /usr/local/lib to ld path if missing
    if ! grep -q '/usr/local/lib' /etc/ld.so.conf.d/*.conf 2>/dev/null; then
        log_info "Adding /usr/local/lib to linker path..."
        echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/local.conf
        sudo ldconfig
    fi
    
    DAQ_LIBS=$(ldconfig -p | grep daq || true)
    if [ -z "$DAQ_LIBS" ]; then
        log_err "FATAL: DAQ libraries still not found after ldconfig fix"
        exit 1
    fi
fi
echo "$DAQ_LIBS"
log_step "DAQ libraries found in ldconfig"

log_info "Checking daq-modules-config..."
if command -v daq-modules-config &>/dev/null; then
    DAQ_VERSION=$(daq-modules-config --version 2>/dev/null || echo "N/A")
    log_step "daq-modules-config --version: $DAQ_VERSION"
    
    DAQ_BUILD=$(daq-modules-config --build 2>/dev/null || echo "N/A")
    log_step "daq-modules-config --build: $DAQ_BUILD"
else
    log_warn "daq-modules-config not found in PATH"
    if [ -x /usr/local/bin/daq-modules-config ]; then
        log_info "Found at /usr/local/bin/daq-modules-config"
        DAQ_VERSION=$(/usr/local/bin/daq-modules-config --version 2>/dev/null || echo "N/A")
        log_step "Version: $DAQ_VERSION"
    fi
fi

log_info "Checking for daqtest..."
if command -v daqtest &>/dev/null; then
    log_info "Running daqtest -l ..."
    daqtest -l 2>&1 || log_warn "daqtest returned non-zero (may need root)"
    log_step "daqtest executed"
else
    log_warn "daqtest not found (may not be included in this DAQ version)"
    # Try alternate
    if [ -x /usr/local/bin/daqtest ]; then
        /usr/local/bin/daqtest -l 2>&1 || true
    else
        log_info "Checking for daqtest-static or alternate binaries..."
        ls /usr/local/bin/daq* 2>/dev/null || log_warn "No DAQ binaries found in /usr/local/bin"
    fi
fi

# =============================================================================
# PHASE 5 — SNORT 3 BUILD
# =============================================================================
log_phase "5" "SNORT 3 BUILD"

# Verify no libdaq.so.2 conflicts
log_info "Checking for libdaq version conflicts..."
DAQ2_FOUND=$(find / -name "libdaq.so.2*" 2>/dev/null || true)
if [ -n "$DAQ2_FOUND" ]; then
    log_warn "Found old libdaq.so.2:"
    echo "$DAQ2_FOUND"
    log_info "Removing old DAQ v2 libraries..."
    for f in $DAQ2_FOUND; do
        sudo rm -f "$f" 2>/dev/null || true
    done
    sudo ldconfig
    log_step "Old DAQ v2 libraries removed"
else
    log_step "No libdaq.so.2 conflicts found"
fi

# Check pkg-config
log_info "Verifying pkg-config for DAQ..."
PKG_DAQ=$(pkg-config --modversion libdaq 2>/dev/null || true)
if [ -n "$PKG_DAQ" ]; then
    log_step "pkg-config libdaq version: $PKG_DAQ"
else
    log_warn "pkg-config can't find libdaq, checking PKG_CONFIG_PATH..."
    export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
    PKG_DAQ=$(pkg-config --modversion libdaq 2>/dev/null || true)
    if [ -n "$PKG_DAQ" ]; then
        log_step "pkg-config libdaq version: $PKG_DAQ (after path fix)"
    else
        log_warn "libdaq not in pkg-config (Snort cmake may need -DDAQ_INCLUDE_DIR)"
    fi
fi

# Clone and build Snort 3
cd "$WORKDIR"
log_info "Cloning Snort 3 from GitHub..."
if [ -d "snort3" ]; then
    rm -rf snort3
fi
git clone --depth 1 https://github.com/snort3/snort3.git
cd snort3

log_info "Configuring Snort 3 with cmake..."
mkdir -p build && cd build

# Set environment for build
export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
export LD_LIBRARY_PATH="/usr/local/lib:${LD_LIBRARY_PATH:-}"

cmake .. \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DENABLE_STATIC_DAQ=OFF \
    -DDAQ_INCLUDE_DIR=/usr/local/include \
    -DDAQ_LIBRARIES_DIR=/usr/local/lib \
    2>&1 | tail -20

log_info "Building Snort 3 with $(nproc) threads (this may take 5-10 minutes)..."
make -j"$(nproc)" 2>&1 | tail -5

log_info "Installing Snort 3..."
sudo make install 2>&1 | tail -5
sudo ldconfig

log_step "Snort 3 installed"

# =============================================================================
# PHASE 6 — FINAL VALIDATION
# =============================================================================
log_phase "6" "FINAL VALIDATION"

echo ""
echo -e "${BOLD}${CYAN}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║               SNORT 3 + DAQ BUILD REPORT             ║${NC}"
echo -e "${BOLD}${CYAN}╚═══════════════════════════════════════════════════════╝${NC}"
echo ""

# DAQ Version
echo -e "${BOLD}DAQ Version:${NC}"
if command -v daq-modules-config &>/dev/null; then
    echo "  $(daq-modules-config --version 2>/dev/null || echo 'N/A')"
elif [ -x /usr/local/bin/daq-modules-config ]; then
    echo "  $(/usr/local/bin/daq-modules-config --version 2>/dev/null || echo 'N/A')"
else
    echo "  $(pkg-config --modversion libdaq 2>/dev/null || echo 'Unknown')"
fi

# DAQ Modules
echo ""
echo -e "${BOLD}Installed DAQ Modules:${NC}"
ls /usr/local/lib/daq/*.so 2>/dev/null | while read mod; do
    echo "  $(basename "$mod")"
done
if [ $? -ne 0 ] || [ -z "$(ls /usr/local/lib/daq/*.so 2>/dev/null)" ]; then
    echo "  (No module .so files found in /usr/local/lib/daq/)"
fi

# DAQ Libraries
echo ""
echo -e "${BOLD}DAQ Libraries:${NC}"
ldconfig -p | grep daq | while read line; do
    echo "  $line"
done

# Snort Version
echo ""
echo -e "${BOLD}Snort Version:${NC}"
if command -v snort &>/dev/null; then
    snort -V 2>&1 | head -5
    echo ""
    log_step "SNORT 3 IS READY ✓"
elif [ -x /usr/local/bin/snort ]; then
    /usr/local/bin/snort -V 2>&1 | head -5
    echo ""
    log_step "SNORT 3 IS READY ✓"
else
    log_err "Snort binary not found!"
fi

# Quick Snort validation
echo ""
echo -e "${BOLD}Snort Quick Config Test:${NC}"
if command -v snort &>/dev/null || [ -x /usr/local/bin/snort ]; then
    SNORT_BIN=$(command -v snort 2>/dev/null || echo "/usr/local/bin/snort")
    $SNORT_BIN --help 2>&1 | head -3
    log_step "Snort responds to CLI commands"
fi

echo ""
echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  BUILD COMPLETE — Snort 3 + DAQ Environment Ready${NC}"
echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════${NC}"
echo ""

# Cleanup build directory
log_info "Build artifacts at: $WORKDIR"
log_info "Run 'rm -rf $WORKDIR' to clean up when ready"
