#!/bin/bash
set -euo pipefail

#
# LeathGuard Installer
# Installs both wg-tool (CLI) and wg-panel (Web UI)
#

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║               LeathGuard Installer                        ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo

# Check root
if [[ $EUID -ne 0 ]]; then
    echo "❌ Run as root: sudo $0"
    exit 1
fi

# Detect script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/wg-panel"
PORT="${WG_PANEL_PORT:-5000}"

# Prompt for credentials
echo "📝 Web Panel Authentication Setup"
echo "─────────────────────────────────"
read -p "Username [admin]: " WG_USER
WG_USER="${WG_USER:-admin}"

while true; do
    read -sp "Password: " WG_PASS
    echo
    if [[ -n "$WG_PASS" ]]; then
        break
    fi
    echo "Password cannot be empty."
done

# Generate password hash
PASS_HASH=$(echo -n "$WG_PASS" | sha256sum | cut -d' ' -f1)
echo

# Install dependencies
echo "[1/8] Installing dependencies..."
apt-get update -qq
apt-get install -y python3 python3-venv python3-pip qrencode >/dev/null 2>&1

# Install wg-tool
echo "[2/8] Installing wg-tool CLI..."
cp "$SCRIPT_DIR/wg-tool" /usr/local/sbin/wg-tool
chmod 755 /usr/local/sbin/wg-tool

# Install leathguard global CLI
echo "[3/8] Installing leathguard CLI..."
cp "$SCRIPT_DIR/leathguard" /usr/local/bin/leathguard
chmod +x /usr/local/bin/leathguard

# Create install directory
echo "[4/8] Setting up web panel..."
mkdir -p "$INSTALL_DIR"
cp "$SCRIPT_DIR/wg-panel/app.py" "$INSTALL_DIR/app.py"
# Copy VERSION file for semantic versioning
if [[ -f "$SCRIPT_DIR/VERSION" ]]; then
    cp "$SCRIPT_DIR/VERSION" "$INSTALL_DIR/VERSION"
fi

# Create virtual environment
echo "[5/8] Creating Python environment..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet flask

# Initialize database
touch "$INSTALL_DIR/wg-panel.db"
chmod 600 "$INSTALL_DIR/wg-panel.db"

# Detect WireGuard interface for systemd dependency
WG_IFACE=""
if command -v wg &>/dev/null; then
    WG_IFACE=$(wg show interfaces 2>/dev/null | awk '{print $1}')
fi
if [[ -z "$WG_IFACE" ]]; then
    # Fallback: check for .conf files
    for conf in /etc/wireguard/*.conf; do
        [[ -f "$conf" ]] || continue
        WG_IFACE=$(basename "$conf" .conf)
        break
    done
fi
WG_SERVICE=""
if [[ -n "$WG_IFACE" ]]; then
    WG_SERVICE=" wg-quick@${WG_IFACE}.service"
fi

# Install systemd service
echo "[6/8] Configuring systemd service..."
cat > /etc/systemd/system/wg-panel.service <<EOF
[Unit]
Description=LeathGuard Web Panel
After=network.target${WG_SERVICE}

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
Environment="WG_PANEL_USER=$WG_USER"
Environment="WG_PANEL_PASS_HASH=$PASS_HASH"
Environment="WG_PANEL_DB=$INSTALL_DIR/wg-panel.db"
# WG_INTERFACE is auto-detected. Uncomment below to override for multi-interface setups:
# Environment="WG_INTERFACE=wg1"
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/app.py $PORT
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wg-panel >/dev/null 2>&1
systemctl restart wg-panel

# Firewall
echo "[7/8] Configuring firewall..."
if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    ufw allow "$PORT/tcp" >/dev/null 2>&1
    echo "    UFW: Opened port $PORT/tcp"
else
    echo "    UFW not active (ensure cloud firewall allows port $PORT)"
fi

# Setup update alias
echo "[8/8] Setting up update alias..."
ALIAS_LINE="alias wgdeploy='cd $INSTALL_DIR && sudo ./update.sh'"

# Add to root's bashrc if not present
if ! grep -q "alias wgdeploy=" /root/.bashrc 2>/dev/null; then
    {
        echo ""
        echo "# LeathGuard update alias"
        echo "$ALIAS_LINE"
    } >> /root/.bashrc
    echo "    Added wgdeploy alias to /root/.bashrc"
fi

# Add to invoking user's bashrc if running via sudo
if [[ -n "$SUDO_USER" && "$SUDO_USER" != "root" ]]; then
    USER_HOME=$(eval echo "~$SUDO_USER")
    USER_BASHRC="$USER_HOME/.bashrc"
    if [[ -f "$USER_BASHRC" ]] && ! grep -q "alias wgdeploy=" "$USER_BASHRC" 2>/dev/null; then
        {
            echo ""
            echo "# LeathGuard update alias"
            echo "$ALIAS_LINE"
        } >> "$USER_BASHRC"
        echo "    Added wgdeploy alias to $USER_BASHRC"
    fi
fi

# Get server IP
SERVER_IP=$(curl -sS --max-time 3 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')

echo
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║           Installation Complete                           ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo
VERSION=$(cat "$SCRIPT_DIR/VERSION" 2>/dev/null || echo "?")
echo "LeathGuard v$VERSION is now running"
echo
echo "Web Panel:  http://$SERVER_IP:$PORT"
echo "Username:   $WG_USER"
echo "Password:   (as entered)"
echo
echo "Quick commands:"
echo "   leathguard status                 # Check installation status"
echo "   leathguard update                 # Update to latest version"
echo "   leathguard logs -f                # Follow service logs"
echo "   sudo wg-tool --help               # Manage WireGuard clients"
echo
echo "Service management:"
echo "   sudo systemctl status wg-panel    # Check status"
echo "   sudo journalctl -u wg-panel -f    # View logs"
echo "   sudo systemctl restart wg-panel   # Restart"
echo
echo "Note: Open port $PORT in your cloud firewall if needed."
echo "(Restart your shell or run 'source ~/.bashrc' to use wgdeploy)"
echo
