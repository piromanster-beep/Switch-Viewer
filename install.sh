#!/bin/bash
set -e

echo "=== Switch Viewer Installation ==="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo ./install.sh)"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Cannot detect OS. Only Debian/Ubuntu and RHEL/CentOS are supported."
    exit 1
fi

echo "Detected OS: $OS"

# Install dependencies based on OS
case $OS in
    ubuntu|debian)
        echo "Installing dependencies (apt)..."
        apt update
        apt install -y python3 python3-pip snmp arp-scan
        ;;
    rhel|centos|fedora)
        echo "Installing dependencies (yum/dnf)..."
        if command -v dnf &> /dev/null; then
            dnf install -y python3 python3-pip net-snmp-utils arp-scan
        else
            yum install -y python3 python3-pip net-snmp-utils arp-scan
        fi
        ;;
    *)
        echo "Unsupported OS: $OS. Please install manually: python3, snmpwalk, arp-scan"
        exit 1
        ;;
esac

# Install Python packages
echo "Installing Python dependencies..."
pip3 install -r requirements.txt

# Setup sudo for arp-scan
echo "Configuring sudo for arp-scan..."
echo "www-data ALL=(ALL) NOPASSWD: /usr/bin/arp-scan" > /etc/sudoers.d/arp-scan

# Verify installations
echo ""
echo "=== Verification ==="
python3 --version
snmpwalk --version 2>/dev/null || echo "snmpwalk installed"
arp-scan --version 2>/dev/null || echo "arp-scan installed"

# Create default config if not exists
if [ ! -f config.json ]; then
    echo ""
    echo "Creating default config.json..."
    cat > config.json <<'EOF'
{
    "switches": [
        {
            "name": "Switch-1",
            "ip": "10.1.100.77",
            "community": "public",
            "exclude_ports": ["3"],
            "exclude_macs": []
        }
    ],
    "settings": {
        "subnets": ["10.1.100.0/24"],
        "arp_scan_interval": 120,
        "snmp_timeout": 30,
        "cache_ttl": 60
    }
}
EOF
fi

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Next steps:"
echo "1. Edit config.json with your switches"
echo "2. Run: python3 app.py"
echo "3. Open http://$(hostname -I | awk '{print $1}'):5000"
