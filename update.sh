#!/bin/bash
# LeathGuard Update Script
# Handles all edge cases for updating across diverse server configurations
#
# Usage: sudo ./update.sh
#    or: sudo ./update.sh --no-restart   (update files only)
#    or: sudo ./update.sh --check        (check for updates without applying)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NO_RESTART=false
CHECK_ONLY=false

# Parse args
for arg in "$@"; do
    case $arg in
        --no-restart) NO_RESTART=true ;;
        --check) CHECK_ONLY=true ;;
        --help|-h)
            echo "LeathGuard Update Script"
            echo ""
            echo "Usage: sudo $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --no-restart  Update files but don't restart service"
            echo "  --check       Check for updates without applying them"
            echo "  --help, -h    Show this help message"
            exit 0
            ;;
    esac
done

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}LeathGuard Update Script${NC}"
echo "========================"
echo ""

# Ensure running as root (skip for --check)
if [[ $EUID -ne 0 && "$CHECK_ONLY" != "true" ]]; then
    echo -e "${RED}Error: Run as root: sudo $0${NC}"
    exit 1
fi

cd "$SCRIPT_DIR"

# Step 1: Fix git safe.directory if needed
echo "[1/6] Checking git configuration..."
git config --global --add safe.directory "$SCRIPT_DIR" 2>/dev/null || true

# Detect default branch (main or master)
DEFAULT_BRANCH=$(git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's@^refs/remotes/origin/@@' || echo "main")
echo "  Default branch: $DEFAULT_BRANCH"

# Step 2: Check for local modifications
echo "[2/6] Checking local modifications..."
LOCAL_MODS=false
if ! git diff --quiet 2>/dev/null; then
    LOCAL_MODS=true
    echo -e "  ${YELLOW}Local modifications detected:${NC}"
    git diff --name-only 2>/dev/null | while read f; do echo "    - $f"; done
fi

# Step 3: Fetch and check for updates
echo "[3/6] Fetching latest changes..."
git fetch origin "$DEFAULT_BRANCH" 2>/dev/null || {
    echo -e "${RED}  Error: Failed to fetch from origin${NC}"
    exit 1
}

BEFORE=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
REMOTE=$(git rev-parse "origin/$DEFAULT_BRANCH" 2>/dev/null || echo "unknown")

if [[ "$BEFORE" == "$REMOTE" && "$LOCAL_MODS" != "true" ]]; then
    echo -e "  ${GREEN}Already up to date${NC}"
    if [[ "$CHECK_ONLY" == "true" ]]; then
        exit 0
    fi
else
    COMMITS_BEHIND=$(git rev-list HEAD.."origin/$DEFAULT_BRANCH" --count 2>/dev/null || echo "?")
    echo -e "  ${YELLOW}$COMMITS_BEHIND commit(s) behind origin/$DEFAULT_BRANCH${NC}"

    if [[ "$CHECK_ONLY" == "true" ]]; then
        echo ""
        echo "Updates available:"
        git log --oneline HEAD.."origin/$DEFAULT_BRANCH" 2>/dev/null | head -10
        exit 0
    fi
fi

# If check only, exit here
if [[ "$CHECK_ONLY" == "true" ]]; then
    exit 0
fi

# Step 4: Reset local modifications and pull
echo "[4/6] Applying updates..."
if [[ "$LOCAL_MODS" == "true" ]]; then
    echo -e "  ${YELLOW}Resetting local modifications...${NC}"
    git checkout -- . 2>/dev/null || true
fi

# Pull latest (reset to remote to handle diverged histories)
git reset --hard "origin/$DEFAULT_BRANCH" 2>/dev/null || {
    # Fallback to regular pull
    git pull origin "$DEFAULT_BRANCH" 2>/dev/null || {
        echo -e "${RED}  Error: Failed to pull updates${NC}"
        exit 1
    }
}

AFTER=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
if [[ "$BEFORE" != "$AFTER" ]]; then
    echo -e "  ${GREEN}Updated: ${BEFORE:0:7} -> ${AFTER:0:7}${NC}"
    echo ""
    echo "  Changes:"
    git log --oneline "${BEFORE}..${AFTER}" 2>/dev/null | head -5 | while read line; do
        echo "    $line"
    done
fi

# Step 5: Update system files (wg-tool, leathguard CLI, app.py)
echo "[5/6] Updating system files..."

# Update wg-tool
if [[ -f "$SCRIPT_DIR/wg-tool" ]]; then
    cp "$SCRIPT_DIR/wg-tool" /usr/local/sbin/wg-tool
    chmod 755 /usr/local/sbin/wg-tool
    echo "  Copied wg-tool to /usr/local/sbin/"
else
    echo -e "  ${YELLOW}Warning: wg-tool not found in repo${NC}"
fi

# Update leathguard CLI
if [[ -f "$SCRIPT_DIR/leathguard" ]]; then
    cp "$SCRIPT_DIR/leathguard" /usr/local/bin/leathguard
    chmod +x /usr/local/bin/leathguard
    echo "  Copied leathguard to /usr/local/bin/"
fi

# Update app.py if install directory exists
INSTALL_DIR="/opt/wg-panel"
if [[ -d "$INSTALL_DIR" ]]; then
    # Copy app.py only if source and destination are different files
    if [[ -f "$SCRIPT_DIR/wg-panel/app.py" ]]; then
        SRC="$SCRIPT_DIR/wg-panel/app.py"
        DST="$INSTALL_DIR/app.py"
        if [[ ! "$SRC" -ef "$DST" ]] 2>/dev/null; then
            cp "$SRC" "$DST"
            echo "  Synced app.py to $INSTALL_DIR/"
        fi
    fi
    # Copy VERSION only if source and destination are different files
    if [[ -f "$SCRIPT_DIR/VERSION" ]]; then
        SRC="$SCRIPT_DIR/VERSION"
        DST="$INSTALL_DIR/VERSION"
        if [[ ! "$SRC" -ef "$DST" ]] 2>/dev/null; then
            cp "$SRC" "$DST"
            echo "  Synced VERSION to $INSTALL_DIR/"
        fi
    fi
fi

# Step 6: Detect and restart service
echo "[6/6] Managing service..."

# Detect service name
SERVICE_NAME=""

# Method 1: Check common service names
for svc in wg-panel wg-panel-home wg-panel-aws wg-panel-raspi wg-panel-test; do
    if systemctl list-unit-files "$svc.service" &>/dev/null 2>&1; then
        if systemctl is-enabled "$svc" &>/dev/null 2>&1; then
            SERVICE_NAME="$svc"
            break
        fi
    fi
done

# Method 2: Find by pattern in running services
if [[ -z "$SERVICE_NAME" ]]; then
    SERVICE_NAME=$(systemctl list-units --type=service --state=running --no-legend 2>/dev/null | grep -oE 'wg-panel[a-z0-9-]*' | head -1 || true)
fi

# Method 3: Find by pattern in unit files
if [[ -z "$SERVICE_NAME" ]]; then
    SERVICE_NAME=$(systemctl list-unit-files --type=service --no-legend 2>/dev/null | grep -oE 'wg-panel[a-z0-9-]*' | head -1 || true)
fi

# Default fallback
if [[ -z "$SERVICE_NAME" ]]; then
    SERVICE_NAME="wg-panel"
fi

echo "  Detected service: $SERVICE_NAME"

if [[ "$NO_RESTART" == "true" ]]; then
    echo -e "  ${YELLOW}Skipping restart (--no-restart)${NC}"
else
    if systemctl restart "$SERVICE_NAME" 2>/dev/null; then
        echo -e "  ${GREEN}Service restarted${NC}"
    else
        echo -e "  ${YELLOW}Warning: Failed to restart $SERVICE_NAME${NC}"
        echo "  Try: sudo systemctl restart $SERVICE_NAME"
    fi
fi

# Show result
echo ""
echo "========================"

# Get version
VERSION="unknown"
if [[ -f "$SCRIPT_DIR/VERSION" ]]; then
    VERSION=$(cat "$SCRIPT_DIR/VERSION")
fi

# Check service status
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    echo -e "${GREEN}LeathGuard v${VERSION} running${NC}"

    # Show recent logs
    echo ""
    echo "Recent logs:"
    journalctl -u "$SERVICE_NAME" -n 3 --no-pager 2>/dev/null | tail -3 || true
else
    echo -e "${RED}Service $SERVICE_NAME is not running${NC}"
    echo "  Check: sudo systemctl status $SERVICE_NAME"
fi
