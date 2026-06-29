# Switch-Viewer
A lightweight web tool to view MAC address tables from SNMP-enabled switches and map them to IP addresses using ARP scanning.
.

# Features

- Display MAC-to-port mapping for any SNMP-enabled switch
- Automatically resolve IP addresses using `arp-scan`
- Filter by switch and port
- Search by MAC or IP
- Supports multiple switches via config file
- Lightweight, no database required

# Installation

# Requirements

- Python 3.8+
- `snmpwalk` (net-snmp-utils)
- `arp-scan`
- sudo privileges for `arp-scan`

# Quick Install (Linux)

```bash
git clone https://github.com/piromanster-beep/Switch-Viewer.git
cd switch-viewer
sudo ./install.sh
````
