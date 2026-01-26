#!/bin/bash
# LeathGuard Migration Script
# Migrates non-standard installations to /opt/wg-panel
#
# Usage: sudo ./migrate.sh

set -e

CANONICAL_PATH="/opt/wg-panel"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}LeathGuard Migration Script${NC}"
echo "============================"
echo ""

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Run as root: sudo $0${NC}"
    exit 1
fi

# Detect current installation
CURRENT_PATH="$SCRIPT_DIR"
echo "Current install path: $CURRENT_PATH"
echo "Canonical path: $CANONICAL_PATH"
echo ""

if [[ "$CURRENT_PATH" == "$CANONICAL_PATH" ]]; then
    echo -e "${GREEN}Already at canonical path. No migration needed.${NC}"
    exit 0
fi

# Detect service
SERVICE_NAME=""
for svc in wg-panel wg-panel-home wg-panel-aws wg-panel-raspi; do
    if systemctl is-enabled "$svc" &>/dev/null; then
        SERVICE_NAME="$svc"
        break
    fi
done

if [[ -z "$SERVICE_NAME" ]]; then
    echo -e "${YELLOW}Warning: Could not detect service name${NC}"
    read -p "Enter service name (or press Enter for 'wg-panel'): " SERVICE_NAME
    SERVICE_NAME="${SERVICE_NAME:-wg-panel}"
fi

echo "Detected service: $SERVICE_NAME"
echo ""

# Confirm
echo -e "${YELLOW}This will:${NC}"
echo "  1. Stop $SERVICE_NAME"
echo "  2. Move $CURRENT_PATH -> $CANONICAL_PATH"
echo "  3. Update systemd service to use new path"
echo "  4. Rename service to 'wg-panel' if different"
echo "  5. Update leathguard CLI and wgdeploy alias"
echo "  6. Restart service"
echo ""
read -p "Continue? (y/N) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi

# Check if canonical path exists
if [[ -d "$CANONICAL_PATH" ]]; then
    echo -e "${RED}Error: $CANONICAL_PATH already exists${NC}"
    echo "Remove it first or merge manually."
    exit 1
fi

# Stop service
echo "[1/6] Stopping service..."
systemctl stop "$SERVICE_NAME" || true

# Move directory
echo "[2/6] Moving installation..."
mv "$CURRENT_PATH" "$CANONICAL_PATH"

# Preserve database by copying from old venv location if needed
if [[ -f "$CANONICAL_PATH/venv/wg-panel.db" ]]; then
    cp "$CANONICAL_PATH/venv/wg-panel.db" "$CANONICAL_PATH/wg-panel.db" 2>/dev/null || true
fi

# Update systemd service
echo "[3/6] Updating systemd service..."
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

if [[ -f "$SERVICE_FILE" ]]; then
    # Update paths in service file
    sed -i "s|$CURRENT_PATH|$CANONICAL_PATH|g" "$SERVICE_FILE"

    # Update WG_PANEL_DB path if present
    sed -i "s|WG_PANEL_DB=.*|WG_PANEL_DB=$CANONICAL_PATH/wg-panel.db|g" "$SERVICE_FILE"
fi

# Rename service if needed
echo "[4/6] Standardizing service name..."
if [[ "$SERVICE_NAME" != "wg-panel" ]]; then
    NEW_SERVICE_FILE="/etc/systemd/system/wg-panel.service"
    mv "$SERVICE_FILE" "$NEW_SERVICE_FILE"
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    SERVICE_NAME="wg-panel"
fi

systemctl daemon-reload
systemctl enable wg-panel

# Update CLI and aliases
echo "[5/6] Updating CLI and aliases..."

# Install/update leathguard CLI
if [[ -f "$CANONICAL_PATH/leathguard" ]]; then
    cp "$CANONICAL_PATH/leathguard" /usr/local/bin/leathguard
    chmod +x /usr/local/bin/leathguard
    echo "    Updated leathguard CLI"
fi

ALIAS_LINE="alias wgdeploy='cd $CANONICAL_PATH && sudo ./update.sh'"

for bashrc in /root/.bashrc /home/*/.bashrc; do
    if [[ -f "$bashrc" ]]; then
        # Remove old alias
        sed -i '/wgdeploy/d' "$bashrc"
        # Add new alias
        echo "$ALIAS_LINE" >> "$bashrc"
    fi
done

# Start service
echo "[6/6] Starting service..."
systemctl start wg-panel

# Verify
sleep 2
if systemctl is-active --quiet wg-panel; then
    echo ""
    echo -e "${GREEN}Migration complete!${NC}"
    echo ""
    echo "New path: $CANONICAL_PATH"
    echo "Service: wg-panel"
    echo ""
    echo "Commands:"
    echo "  leathguard status    # Check status"
    echo "  leathguard update    # Update to latest"
    echo ""
    echo "Run 'source ~/.bashrc' to refresh aliases, then use 'wgdeploy'"
else
    echo -e "${RED}Service failed to start. Check: sudo journalctl -u wg-panel -n 50${NC}"
    exit 1
fi
