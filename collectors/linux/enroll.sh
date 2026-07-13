#!/bin/bash
# CyberGuard Linux Collector Enrollment Script
# Usage: ENROLLMENT_CODE=<code> BACKEND_URL=<url> bash enroll.sh
# Run as root

set -e

INSTALL_DIR="/opt/cyberguard"
SERVICE_NAME="cyberguard-collector"
COLLECTOR_USER="cyberguard"

echo "=== CyberGuard Collector Enrollment ==="

if [[ $EUID -ne 0 ]]; then
   echo "ERROR: This script must be run as root"
   exit 1
fi

if [[ -z "$ENROLLMENT_CODE" ]]; then
    echo "ERROR: ENROLLMENT_CODE environment variable is required"
    echo "Usage: ENROLLMENT_CODE=<code> BACKEND_URL=<url> bash enroll.sh"
    exit 1
fi

BACKEND_URL="${BACKEND_URL:-https://api.cyberguard.example.com}"

echo "[1/6] Creating system user..."
id -u "$COLLECTOR_USER" &>/dev/null || useradd -r -s /bin/false -d "$INSTALL_DIR" "$COLLECTOR_USER"

echo "[2/6] Installing dependencies..."
python3 -m pip install psutil httpx --quiet

echo "[3/6] Installing collector..."
mkdir -p "$INSTALL_DIR"
cp "$(dirname "$0")/collector.py" "$INSTALL_DIR/collector.py"
chmod 750 "$INSTALL_DIR/collector.py"
chown -R "$COLLECTOR_USER:$COLLECTOR_USER" "$INSTALL_DIR"

echo "[4/6] Exchanging enrollment code for agent token..."
ENROLL_RESPONSE=$(curl -sSf -X POST \
    -H "Content-Type: application/json" \
    -d "{\"enrollment_code\": \"$ENROLLMENT_CODE\"}" \
    "${BACKEND_URL}/api/v1/devices/enroll")

if [[ $? -ne 0 ]]; then
    echo "ERROR: Failed to exchange enrollment code"
    exit 1
fi

AGENT_TOKEN=$(echo "$ENROLL_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['agent_token'])")
DEVICE_ID=$(echo "$ENROLL_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['device_id'])")

if [[ -z "$AGENT_TOKEN" || -z "$DEVICE_ID" ]]; then
    echo "ERROR: Invalid enrollment response"
    exit 1
fi

echo "[5/6] Creating systemd service..."
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

echo "[6/6] Starting service..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

echo ""
echo "=== Enrollment Complete ==="
echo "Status: $(systemctl is-active $SERVICE_NAME)"
echo "Logs: journalctl -u $SERVICE_NAME -f"
echo "Config: /etc/systemd/system/${SERVICE_NAME}.service"