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

# Ensure scripts have execute permission (git may not preserve execute bit)
chmod +x "$SCRIPT_DIR"/*.sh "$SCRIPT_DIR"/leathguard 2>/dev/null || true

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

# Detect WireGuard interfaces
echo ""
echo "[4.5/8] Detecting WireGuard interfaces..."
WG_INTERFACES=""
WG_IFACE=""
WG_INTERFACE_ENV=""

# Get interfaces from wg show
if command -v wg &>/dev/null; then
    WG_INTERFACES=$(wg show interfaces 2>/dev/null)
fi

# Fallback: check for .conf files
if [[ -z "$WG_INTERFACES" ]]; then
    for conf in /etc/wireguard/*.conf; do
        [[ -f "$conf" ]] || continue
        name=$(basename "$conf" .conf)
        # Skip files that look like client configs
        [[ "$name" != *_clients* ]] && WG_INTERFACES="$WG_INTERFACES $name"
    done
    WG_INTERFACES=$(echo "$WG_INTERFACES" | xargs)  # Trim whitespace
fi

IFACE_COUNT=$(echo "$WG_INTERFACES" | wc -w)

if [[ $IFACE_COUNT -eq 0 ]]; then
    echo "   No WireGuard interfaces found in /etc/wireguard/"
    echo "   Install will continue, but you'll need to configure WireGuard first."
    WG_IFACE=""
elif [[ $IFACE_COUNT -eq 1 ]]; then
    WG_IFACE=$(echo "$WG_INTERFACES" | tr -d ' ')
    echo "   Found interface: $WG_IFACE"
else
    echo "   Found multiple interfaces: $WG_INTERFACES"
    echo ""
    echo "   Which interface should LeathGuard manage?"
    echo ""

    # Create selection menu
    i=1
    for iface in $WG_INTERFACES; do
        echo "      $i) $iface"
        eval "IFACE_$i=$iface"
        ((i++))
    done
    echo ""

    while true; do
        read -p "   Select [1-$((i-1))]: " selection
        if [[ "$selection" =~ ^[0-9]+$ ]] && [[ "$selection" -ge 1 ]] && [[ "$selection" -lt "$i" ]]; then
            eval "WG_IFACE=\$IFACE_$selection"
            echo "   Selected: $WG_IFACE"
            WG_INTERFACE_ENV="$WG_IFACE"
            break
        else
            echo "   Invalid selection. Please enter a number 1-$((i-1))"
        fi
    done
fi

WG_SERVICE=""
if [[ -n "$WG_IFACE" ]]; then
    WG_SERVICE=" wg-quick@${WG_IFACE}.service"
fi

# Install systemd service
echo "[6/8] Configuring systemd service..."

# Build the service file content
SERVICE_CONTENT="[Unit]
Description=LeathGuard Web Panel
After=network.target${WG_SERVICE}

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
Environment=\"WG_PANEL_USER=$WG_USER\"
Environment=\"WG_PANEL_PASS_HASH=$PASS_HASH\"
Environment=\"WG_PANEL_DB=$INSTALL_DIR/wg-panel.db\""

# Add WG_INTERFACE if it was explicitly selected from multiple interfaces
if [[ -n "$WG_INTERFACE_ENV" ]]; then
    SERVICE_CONTENT="$SERVICE_CONTENT
Environment=\"WG_INTERFACE=$WG_INTERFACE_ENV\""
    echo "   Setting WG_INTERFACE=$WG_INTERFACE_ENV in service file"
else
    SERVICE_CONTENT="$SERVICE_CONTENT
# WG_INTERFACE is auto-detected. Uncomment below to override for multi-interface setups:
# Environment=\"WG_INTERFACE=wg1\""
fi

SERVICE_CONTENT="$SERVICE_CONTENT
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/app.py $PORT
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target"

echo "$SERVICE_CONTENT" > /etc/systemd/system/wg-panel.service

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
