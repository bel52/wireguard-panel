#!/bin/bash
# LeathGuard Status Script
# Quick health check for the installation
#
# Usage: ./status.sh
#    or: sudo ./status.sh   (for full WireGuard details)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}LeathGuard Status${NC}"
echo "================="
echo ""

# Version
VERSION="unknown"
if [[ -f "$SCRIPT_DIR/VERSION" ]]; then
    VERSION=$(cat "$SCRIPT_DIR/VERSION")
fi
echo "Version:      $VERSION"
echo "Install path: $SCRIPT_DIR"

# Git status
echo ""
echo -e "${CYAN}Git Status:${NC}"
if git -C "$SCRIPT_DIR" rev-parse --git-dir &>/dev/null; then
    # Fix safe.directory quietly
    git config --global --add safe.directory "$SCRIPT_DIR" 2>/dev/null || true

    BRANCH=$(git -C "$SCRIPT_DIR" branch --show-current 2>/dev/null || echo "unknown")
    COMMIT=$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")
    echo "  Branch: $BRANCH"
    echo "  Commit: $COMMIT"

    # Check for local modifications
    if ! git -C "$SCRIPT_DIR" diff --quiet 2>/dev/null; then
        MOD_COUNT=$(git -C "$SCRIPT_DIR" diff --name-only 2>/dev/null | wc -l)
        echo -e "  ${YELLOW}! Local modifications ($MOD_COUNT files)${NC}"
    fi

    # Check if behind remote (quietly fetch)
    DEFAULT_BRANCH=$(git -C "$SCRIPT_DIR" symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's@^refs/remotes/origin/@@' || echo "main")
    git -C "$SCRIPT_DIR" fetch origin "$DEFAULT_BRANCH" --quiet 2>/dev/null || true

    LOCAL=$(git -C "$SCRIPT_DIR" rev-parse HEAD 2>/dev/null)
    REMOTE=$(git -C "$SCRIPT_DIR" rev-parse "origin/$DEFAULT_BRANCH" 2>/dev/null || echo "")

    if [[ -n "$REMOTE" && "$LOCAL" != "$REMOTE" ]]; then
        BEHIND=$(git -C "$SCRIPT_DIR" rev-list HEAD.."origin/$DEFAULT_BRANCH" --count 2>/dev/null || echo "?")
        echo -e "  ${YELLOW}! Behind origin/$DEFAULT_BRANCH by $BEHIND commit(s)${NC}"
    else
        echo -e "  ${GREEN}Up to date${NC}"
    fi
else
    echo -e "  ${RED}Not a git repository${NC}"
fi

# Service detection
echo ""
echo -e "${CYAN}Service Status:${NC}"
SERVICE_NAME=""

# Find the running service
for svc in wg-panel wg-panel-home wg-panel-aws wg-panel-raspi wg-panel-test; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        SERVICE_NAME="$svc"
        break
    fi
done

# If not running, check enabled services
if [[ -z "$SERVICE_NAME" ]]; then
    for svc in wg-panel wg-panel-home wg-panel-aws wg-panel-raspi wg-panel-test; do
        if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
            SERVICE_NAME="$svc"
            break
        fi
    done
fi

if [[ -n "$SERVICE_NAME" ]]; then
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        echo -e "  ${GREEN}$SERVICE_NAME is running${NC}"

        # Get PID and memory
        PID=$(systemctl show "$SERVICE_NAME" --property=MainPID --value 2>/dev/null)
        if [[ -n "$PID" && "$PID" != "0" ]]; then
            MEM=$(ps -p "$PID" -o rss= 2>/dev/null | awk '{printf "%.1f MB", $1/1024}')
            UPTIME=$(ps -p "$PID" -o etime= 2>/dev/null | xargs)
            echo "  PID: $PID | Memory: $MEM | Uptime: $UPTIME"
        fi
    else
        echo -e "  ${RED}$SERVICE_NAME is not running${NC}"
        echo "  Start with: sudo systemctl start $SERVICE_NAME"
    fi
else
    echo -e "  ${RED}No LeathGuard service detected${NC}"
    echo "  Run ./install.sh to set up the service"
fi

# wg-tool status
echo ""
echo -e "${CYAN}wg-tool:${NC}"
if [[ -x /usr/local/sbin/wg-tool ]]; then
    echo -e "  ${GREEN}Installed at /usr/local/sbin/wg-tool${NC}"

    # Check if it matches repo version
    if [[ -f "$SCRIPT_DIR/wg-tool" ]]; then
        if diff -q "$SCRIPT_DIR/wg-tool" /usr/local/sbin/wg-tool &>/dev/null; then
            echo "  Matches repo version"
        else
            echo -e "  ${YELLOW}! Differs from repo version (run update.sh)${NC}"
        fi
    fi
else
    echo -e "  ${RED}Not installed${NC}"
    echo "  Run: sudo cp $SCRIPT_DIR/wg-tool /usr/local/sbin/wg-tool"
fi

# WireGuard interface
echo ""
echo -e "${CYAN}WireGuard:${NC}"
if command -v wg &>/dev/null; then
    # Need root for wg show
    if [[ $EUID -eq 0 ]]; then
        INTERFACES=$(wg show interfaces 2>/dev/null || true)
        if [[ -n "$INTERFACES" ]]; then
            echo "  Interfaces: $INTERFACES"
            for iface in $INTERFACES; do
                PEERS=$(wg show "$iface" peers 2>/dev/null | wc -l)
                LATEST=$(wg show "$iface" latest-handshakes 2>/dev/null | awk '{if($2>0)count++} END{print count+0}')
                echo "    $iface: $PEERS peers ($LATEST active)"
            done
        else
            echo -e "  ${YELLOW}! No active interfaces${NC}"
        fi
    else
        # Without root, check config files
        CONFS=$(ls /etc/wireguard/*.conf 2>/dev/null | wc -l || echo "0")
        echo "  Config files: $CONFS (run as root for full status)"
    fi
else
    echo -e "  ${RED}WireGuard not installed${NC}"
fi

# Network check
echo ""
echo -e "${CYAN}Web Panel:${NC}"
PORT="${WG_PANEL_PORT:-5000}"

# Try to get port from systemd environment
if [[ -n "$SERVICE_NAME" ]]; then
    SVC_PORT=$(systemctl show "$SERVICE_NAME" -p Environment 2>/dev/null | grep -oP 'ExecStart.*\s(\d+)$' | awk '{print $NF}' || true)
    if [[ -z "$SVC_PORT" ]]; then
        # Try to get from ExecStart
        SVC_PORT=$(systemctl show "$SERVICE_NAME" -p ExecStart --value 2>/dev/null | grep -oE '[0-9]+$' || true)
    fi
    [[ -n "$SVC_PORT" ]] && PORT="$SVC_PORT"
fi

if curl -s --max-time 3 "http://127.0.0.1:$PORT/login" &>/dev/null; then
    echo -e "  ${GREEN}Responding on http://127.0.0.1:$PORT${NC}"
else
    echo -e "  ${YELLOW}! Not responding on port $PORT${NC}"
fi

# Show external IP if available
EXTERNAL_IP=$(curl -sS --max-time 2 https://api.ipify.org 2>/dev/null || true)
if [[ -n "$EXTERNAL_IP" ]]; then
    echo "  External: http://$EXTERNAL_IP:$PORT"
fi

echo ""
