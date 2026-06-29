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
# Мanual Install

# Debian/Ubuntu: 

```bash
apt update
apt install -y python3 python3-pip snmp arp-scan
pip3 install -r requirements.txt
```
#RHEL/CentOS/Fedora:

```bash
dnf install -y python3 python3-pip net-snmp-utils arp-scan
pip3 install -r requirements.txt
```
Then edit `config.json` and run:
`python3 app.py`


# Usage

1. Open browser: `http://your-server:5000`
2. Select a switch from the dropdown
3. Click "Show" to view MAC/IP table
4. Use search to find by MAC or IP

# Configuration

#`config.json` options

| Parameter | Description |
|-----------|-------------|
| `switches` | List of switches to monitor |
| `switches[].name` | Display name |
| `switches[].ip` | Switch IP address |
| `switches[].community` | SNMP community string |
| `switches[].exclude_ports` | Ports to ignore (e.g., CPU/Management) |
| `switches[].exclude_macs` | MACs to ignore |
| `settings.subnets` | Network subnets for `arp-scan` |
| `settings.arp_scan_interval` | ARP cache refresh interval (seconds) |
| `settings.snmp_timeout` | SNMP query timeout |
| `settings.cache_ttl` | MAC table cache TTL |

# Running as a Service

```bash
cp systemd/switch-viewer.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable switch-viewer
systemctl start switch-viewer
```

Pull requests are welcome. For major changes, please open an issue first.

