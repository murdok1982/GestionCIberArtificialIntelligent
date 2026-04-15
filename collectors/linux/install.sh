#!/bin/bash
# CyberGuard Linux Collector Installer
# Usage: AGENT_TOKEN=<token> DEVICE_ID=<id> BACKEND_URL=<url> bash install.sh

set -e

INSTALL_DIR="/opt/cyberguard"
SERVICE_NAME="cyberguard-collector"
COLLECTOR_USER="cyberguard"

echo "=== CyberGuard Collector Installer ==="

if [[ $EUID -ne 0 ]]; then
   echo "ERROR: This script must be run as root"
   exit 1
fi

if [[ -z "$AGENT_TOKEN" || -z "$DEVICE_ID" ]]; then
    echo "ERROR: AGENT_TOKEN and DEVICE_ID environment variables are required"
    echo "Usage: AGENT_TOKEN=<token> DEVICE_ID=<id> BACKEND_URL=<url> bash install.sh"
    exit 1
fi

BACKEND_URL="${BACKEND_URL:-https://api.cyberguard.example.com}"

echo "[1/5] Creating system user..."
id -u "$COLLECTOR_USER" &>/dev/null || useradd -r -s /bin/false -d "$INSTALL_DIR" "$COLLECTOR_USER"

echo "[2/5] Installing dependencies..."
python3 -m pip install psutil httpx --quiet

echo "[3/5] Installing collector..."
mkdir -p "$INSTALL_DIR"
cp "$(dirname "$0")/collector.py" "$INSTALL_DIR/collector.py"
chmod 750 "$INSTALL_DIR/collector.py"
chown -R "$COLLECTOR_USER:$COLLECTOR_USER" "$INSTALL_DIR"

echo "[4/5] Creating systemd service..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=CyberGuard Security Collector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$COLLECTOR_USER
Group=$COLLECTOR_USER
ExecStart=/usr/bin/python3 $INSTALL_DIR/collector.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cyberguard-collector

Environment=CYBERGUARD_BACKEND_URL=$BACKEND_URL
Environment=CYBERGUARD_AGENT_TOKEN=$AGENT_TOKEN
Environment=CYBERGUARD_DEVICE_ID=$DEVICE_ID
Environment=CYBERGUARD_INTERVAL=60

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadOnlyPaths=/
ReadWritePaths=/var/log
PrivateTmp=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

echo "[5/5] Starting service..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

echo ""
echo "=== Installation Complete ==="
echo "Status: $(systemctl is-active $SERVICE_NAME)"
echo "Logs: journalctl -u $SERVICE_NAME -f"
echo "Config: /etc/systemd/system/${SERVICE_NAME}.service"
