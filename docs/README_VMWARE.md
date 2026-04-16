# CNS IDS: VMware & Windows 11 Configuration Guide

This guide describes how to configure **VMware Workstation/Player** and **Windows 11** for accurate network traffic monitoring using the AegisNet IDS.

## 1. Prerequisites

- **VMware Workstation Pro/Player** (Version 16+ recommended).
- **Npcap** installed on Windows 11 (Download from [nmap.org/npcap/](https://nmap.org/npcap/)).
    - **IMPORTANT**: During installation, ensure you check the box: **"Install Npcap in WinPcap API-compatible mode"**.
- **Snort 3 for Windows** (Installed and added to your PATH).

## 2. VMware Network Configuration

To allow the IDS to capture traffic from virtual machines, you must enable **Promiscuous Mode** on the VMware virtual network adapters.

### Step 2.1: Identify the VMnet Adapter
By default, VMware uses:
- **VMnet0**: Bridged (Directly connected to physical network).
- **VMnet1**: Host-Only (Internal private network).
- **VMnet8**: NAT (Shared host IP).

### Step 2.2: Enable Promiscuous Mode (Windows Host)
1. Open **Virtual Network Editor** (Run as Administrator).
2. Select the adapter you want to monitor (e.g., VMnet8).
3. Ensure the host OS can see the traffic. On Windows hosts, you may need to set the permissions on the VMnet adapter:
    - Open `PowerShell` as Administrator.
    - Run: `Get-NetAdapter` to find your VMnet index.
    - (Advanced) VMware usually handles promiscuous mode automatically if Snort/Npcap requests it, but ensuring the VMnet is not "Disabled" in Windows is key.

## 3. Running Snort on Windows 11

Use the provided PowerShell script to start Snort with the correct VMware interface:

```powershell
.\scripts\run_snort_windows.ps1
```

This script will:
1. List all available network interfaces.
2. Search for active VMware/VMnet adapters.
3. Launch Snort 3 using the project's `snort.lua` configuration.

## 4. Troubleshooting

- **No packets captured**: Ensure Npcap is installed in "WinPcap compatibility mode".
- **Interface not found**: Run `snort --list-interfaces` in CMD to see if Snort recognizes your VMware adapters.
- **Permission Denied**: Always run the Snort runner script as **Administrator**.
