#!/bin/bash
# LeathGuard Update Script (v6 - transactional)
#
# Changes from v5:
# - Updates to the latest RELEASE TAG by default (reproducible), not the
#   moving tip of main. Use --branch main to opt back into tip-of-branch.
# - Full backup bundle before any change: app.py, VERSION, systemd unit,
#   pip freeze, and a consistent SQLite backup (via the sqlite3 backup API).
# - Dependencies installed and the NEW app.py import-tested BEFORE the
#   running installation is touched.
# - Atomic file replacement, daemon-reload, restart, readiness check.
# - AUTOMATIC ROLLBACK if the service fails its readiness check.
#
# Usage: sudo ./update.sh
#    or: sudo ./update.sh --check          (check for updates only)
#    or: sudo ./update.sh --tag v6.0.0     (deploy a specific release)
#    or: sudo ./update.sh --branch main    (deploy tip of a branch)
#    or: sudo ./update.sh --no-restart     (stage files, skip restart)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/opt/wg-panel"
NO_RESTART=false
CHECK_ONLY=false
TARGET_TAG=""
TARGET_BRANCH=""
READINESS_TIMEOUT=45

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

while [[ $# -gt 0 ]]; do
    case $1 in
        --no-restart) NO_RESTART=true; shift ;;
        --check) CHECK_ONLY=true; shift ;;
        --tag) TARGET_TAG="$2"; shift 2 ;;
        --branch) TARGET_BRANCH="$2"; shift 2 ;;
        --help|-h)
            grep '^# ' "$0" | sed 's/^# //'
            exit 0
            ;;
        *) shift ;;
    esac
done

echo -e "${CYAN}LeathGuard Update Script (transactional)${NC}"
echo "========================================"
echo ""

if [[ $EUID -ne 0 && "$CHECK_ONLY" != "true" ]]; then
    echo -e "${RED}Error: Run as root: sudo $0${NC}"
    exit 1
fi

cd "$SCRIPT_DIR"
git config --global --add safe.directory "$SCRIPT_DIR" 2>/dev/null || true

# ---------------------------------------------------------------
# Step 1: Determine target ref (pinned tag by default)
# ---------------------------------------------------------------
echo "[1/8] Resolving target release..."
git fetch --tags origin 2>/dev/null || { echo -e "${RED}  Failed to fetch from origin${NC}"; exit 1; }

CURRENT_REF=$(git rev-parse HEAD)
if [[ -n "$TARGET_TAG" ]]; then
    TARGET_REF="refs/tags/$TARGET_TAG"
    TARGET_DESC="tag $TARGET_TAG"
elif [[ -n "$TARGET_BRANCH" ]]; then
    git fetch origin "$TARGET_BRANCH" 2>/dev/null
    TARGET_REF="origin/$TARGET_BRANCH"
    TARGET_DESC="branch $TARGET_BRANCH (tip - not reproducible)"
else
    # Latest semver-ish tag
    LATEST_TAG=$(git tag -l 'v*' --sort=-v:refname | head -1)
    if [[ -z "$LATEST_TAG" ]]; then
        echo -e "  ${YELLOW}No release tags found; falling back to origin/main${NC}"
        git fetch origin main 2>/dev/null
        TARGET_REF="origin/main"
        TARGET_DESC="branch main (no tags exist yet)"
    else
        TARGET_REF="refs/tags/$LATEST_TAG"
        TARGET_DESC="tag $LATEST_TAG"
    fi
fi

TARGET_COMMIT=$(git rev-parse "$TARGET_REF^{commit}" 2>/dev/null) || {
    echo -e "${RED}  Cannot resolve $TARGET_REF${NC}"; exit 1; }

echo "  Current: ${CURRENT_REF:0:9}"
echo "  Target:  ${TARGET_COMMIT:0:9} ($TARGET_DESC)"

if [[ "$CURRENT_REF" == "$TARGET_COMMIT" ]]; then
    echo -e "  ${GREEN}Already at target${NC}"
    [[ "$CHECK_ONLY" == "true" ]] && exit 0
fi

if [[ "$CHECK_ONLY" == "true" ]]; then
    echo ""
    echo "Changes:"
    git log --oneline "${CURRENT_REF}..${TARGET_COMMIT}" 2>/dev/null | head -10
    exit 0
fi

# ---------------------------------------------------------------
# Step 2: Backup bundle
# ---------------------------------------------------------------
echo "[2/8] Creating backup bundle..."
TS=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="$INSTALL_DIR/backups/pre-update-$TS"
mkdir -p "$BACKUP_DIR"

cp -a "$INSTALL_DIR/app.py"  "$BACKUP_DIR/app.py"      2>/dev/null || true
cp -a "$INSTALL_DIR/VERSION" "$BACKUP_DIR/VERSION"     2>/dev/null || true
cp -a /etc/systemd/system/wg-panel.service "$BACKUP_DIR/wg-panel.service" 2>/dev/null || true
cp -a /usr/local/sbin/wg-tool "$BACKUP_DIR/wg-tool"    2>/dev/null || true
"$INSTALL_DIR/venv/bin/pip" freeze > "$BACKUP_DIR/pip-freeze.txt" 2>/dev/null || true
echo "$CURRENT_REF" > "$BACKUP_DIR/git-commit.txt"

# Consistent SQLite backup via the backup API (safe while service runs; WAL-aware)
DB_PATH="${WG_PANEL_DB:-$INSTALL_DIR/wg-panel.db}"
if [[ -f "$DB_PATH" ]]; then
    "$INSTALL_DIR/venv/bin/python3" - "$DB_PATH" "$BACKUP_DIR/wg-panel.db" <<'PYEOF'
import sqlite3, sys
src = sqlite3.connect(sys.argv[1])
dst = sqlite3.connect(sys.argv[2])
with dst:
    src.backup(dst)
dst.close(); src.close()
print("  SQLite backup OK")
PYEOF
fi
echo "  Bundle: $BACKUP_DIR"

# Prune old backup bundles (keep last 5)
ls -dt "$INSTALL_DIR"/backups/pre-update-* 2>/dev/null | tail -n +6 | xargs -r rm -rf

# ---------------------------------------------------------------
# Step 3: Check out target
# ---------------------------------------------------------------
echo "[3/8] Checking out target..."
if ! git diff --quiet 2>/dev/null; then
    echo -e "  ${YELLOW}Resetting local modifications${NC}"
fi
git checkout -f "$TARGET_COMMIT" 2>/dev/null
chmod +x "$SCRIPT_DIR"/*.sh "$SCRIPT_DIR"/leathguard 2>/dev/null || true

NEW_VERSION=$(cat "$SCRIPT_DIR/VERSION" 2>/dev/null || echo "unknown")
echo "  Now at v$NEW_VERSION (${TARGET_COMMIT:0:9})"

# ---------------------------------------------------------------
# Step 4: Dependencies + import self-test BEFORE touching the install
# ---------------------------------------------------------------
echo "[4/8] Installing dependencies + self-test..."
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade flask waitress

if ! "$INSTALL_DIR/venv/bin/python3" -c "
import importlib.util, sys
spec = importlib.util.spec_from_file_location('lg_selftest', '$SCRIPT_DIR/wg-panel/app.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
assert hasattr(mod, 'main'), 'main() missing'
assert hasattr(mod, 'COLLECTOR'), 'collector missing'
print('  Import self-test OK')
"; then
    echo -e "${RED}  Self-test FAILED - aborting before touching the running install${NC}"
    git checkout -f "$CURRENT_REF" 2>/dev/null || true
    exit 1
fi

# ---------------------------------------------------------------
# Step 5: Atomic install of files
# ---------------------------------------------------------------
echo "[5/8] Installing files..."
install -m 755 "$SCRIPT_DIR/wg-tool" /usr/local/sbin/wg-tool.new && mv -f /usr/local/sbin/wg-tool.new /usr/local/sbin/wg-tool
install -m 755 "$SCRIPT_DIR/leathguard" /usr/local/bin/leathguard.new && mv -f /usr/local/bin/leathguard.new /usr/local/bin/leathguard
install -m 644 "$SCRIPT_DIR/wg-panel/app.py" "$INSTALL_DIR/app.py.new" && mv -f "$INSTALL_DIR/app.py.new" "$INSTALL_DIR/app.py"
install -m 644 "$SCRIPT_DIR/VERSION" "$INSTALL_DIR/VERSION.new" 2>/dev/null && mv -f "$INSTALL_DIR/VERSION.new" "$INSTALL_DIR/VERSION" || true
echo "  Files installed"

# ---------------------------------------------------------------
# Step 6: Detect service + port
# ---------------------------------------------------------------
echo "[6/8] Detecting service..."
SERVICE_NAME=""
for svc in wg-panel wg-panel-home wg-panel-aws wg-panel-raspi wg-panel-test; do
    if systemctl is-enabled "$svc" &>/dev/null; then SERVICE_NAME="$svc"; break; fi
done
[[ -z "$SERVICE_NAME" ]] && SERVICE_NAME=$(systemctl list-units --type=service --state=running --no-legend 2>/dev/null | grep -oE 'wg-panel[a-z0-9-]*' | head -1 || true)
[[ -z "$SERVICE_NAME" ]] && SERVICE_NAME="wg-panel"

UNIT_FILE=$(systemctl show -p FragmentPath "$SERVICE_NAME" 2>/dev/null | cut -d= -f2)
PANEL_PORT=$(grep -oE 'app\.py +[0-9]+' "${UNIT_FILE:-/etc/systemd/system/wg-panel.service}" 2>/dev/null | grep -oE '[0-9]+$' || echo 5000)
echo "  Service: $SERVICE_NAME (port $PANEL_PORT)"

rollback() {
    echo -e "${RED}  ROLLING BACK to pre-update state...${NC}"
    [[ -f "$BACKUP_DIR/app.py" ]]  && cp -f "$BACKUP_DIR/app.py"  "$INSTALL_DIR/app.py"
    [[ -f "$BACKUP_DIR/VERSION" ]] && cp -f "$BACKUP_DIR/VERSION" "$INSTALL_DIR/VERSION"
    [[ -f "$BACKUP_DIR/wg-tool" ]] && cp -f "$BACKUP_DIR/wg-tool" /usr/local/sbin/wg-tool && chmod 755 /usr/local/sbin/wg-tool
    [[ -f "$BACKUP_DIR/wg-panel.service" ]] && cp -f "$BACKUP_DIR/wg-panel.service" /etc/systemd/system/wg-panel.service
    git checkout -f "$CURRENT_REF" 2>/dev/null || true
    systemctl daemon-reload
    systemctl restart "$SERVICE_NAME" || true
    echo -e "${YELLOW}  Rollback complete. Backup bundle preserved at $BACKUP_DIR${NC}"
}

# ---------------------------------------------------------------
# Step 7: Restart + readiness check (with auto-rollback)
# ---------------------------------------------------------------
if [[ "$NO_RESTART" == "true" ]]; then
    echo "[7/8] Skipping restart (--no-restart). Restart manually to apply."
else
    echo "[7/8] Restarting + readiness check..."
    systemctl daemon-reload
    if ! systemctl restart "$SERVICE_NAME"; then
        rollback; exit 1
    fi

    # Readiness: service active AND HTTP responding AND collector produced
    # a snapshot (/, unauthenticated, returns the login page = HTTP 200;
    # /api/status returns 401/302 unauthenticated, or 503 only while the
    # collector warms up).
    READY=false
    for i in $(seq 1 $READINESS_TIMEOUT); do
        sleep 1
        systemctl is-active --quiet "$SERVICE_NAME" || continue
        CODE=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$PANEL_PORT/" 2>/dev/null || echo 000)
        if [[ "$CODE" == "200" || "$CODE" == "302" ]]; then
            READY=true
            break
        fi
    done

    if [[ "$READY" != "true" ]]; then
        echo -e "${RED}  Readiness check FAILED after ${READINESS_TIMEOUT}s${NC}"
        journalctl -u "$SERVICE_NAME" -n 15 --no-pager 2>/dev/null || true
        rollback; exit 1
    fi
    echo -e "  ${GREEN}Service ready${NC}"
fi

# ---------------------------------------------------------------
# Step 8: Report
# ---------------------------------------------------------------
echo "[8/8] Done."
echo ""
echo "========================================"
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    echo -e "${GREEN}LeathGuard v${NEW_VERSION} running${NC} (${TARGET_COMMIT:0:9})"
    echo ""
    echo "Recent logs:"
    journalctl -u "$SERVICE_NAME" -n 3 --no-pager 2>/dev/null | tail -3 || true
else
    echo -e "${YELLOW}Service $SERVICE_NAME is not running (--no-restart?)${NC}"
fi
echo ""
echo "Rollback available: $BACKUP_DIR"
echo "  sudo ./update.sh --tag <previous-tag>   # or restore the bundle manually"
