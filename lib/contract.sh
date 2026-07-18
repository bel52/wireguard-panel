#!/bin/bash
# lib/contract.sh - LeathGuard environment contract (v6.3)
#
# THE CONTRACT: every box declares its own shape in /etc/leathguard/env.conf.
# Updaters and tooling read the contract instead of guessing paths. A box
# whose reality doesn't match its contract fails preflight loudly BEFORE any
# change is made. This is what makes unattended updates safe across
# heterogeneous environments.
#
# Sourced by: update.sh, leathguard (doctor/adopt/auto-update), install.sh

LG_CONF_DIR="/etc/leathguard"
LG_CONF="${LG_CONF_DIR}/env.conf"

# ---- Defaults (overridden by env.conf) ----
INSTALL_DIR="${INSTALL_DIR:-/opt/wg-panel}"
APP_ENTRY=""            # absolute path to the app.py that ExecStart runs
SERVICE_NAME=""         # systemd unit name
PANEL_PORT=""           # HTTP port
WG_INTERFACE="${WG_INTERFACE:-}"
CLIENT_DIR=""           # /etc/wireguard/<iface>_clients
VENV_DIR=""             # $INSTALL_DIR/venv
UPDATE_HOUR="3"         # per-box stagger for auto-update cron
UPDATE_MINUTE="0"
PUSHOVER_TOKEN=""       # optional; enables update notifications
PUSHOVER_USER=""
BOX_NAME="$(hostname -s 2>/dev/null || echo unknown)"

lg_load_contract() {
    if [[ -f "$LG_CONF" ]]; then
        # shellcheck disable=SC1090
        source "$LG_CONF"
        return 0
    fi
    return 1
}

# ---- Detection (used by `leathguard adopt` and as fallback) ----

lg_detect_service() {
    local svc
    for svc in wg-panel wg-panel-home wg-panel-aws wg-panel-raspi wg-panel-test; do
        if systemctl list-unit-files "${svc}.service" 2>/dev/null | grep -q "$svc"; then
            echo "$svc"; return 0
        fi
    done
    systemctl list-units --type=service --all --no-legend 2>/dev/null \
        | grep -oE 'wg-panel[a-z0-9-]*' | head -1
}

lg_detect_from_unit() {
    # Sets: DET_APP_ENTRY, DET_PORT, DET_IFACE, DET_VENV from the unit file
    local svc="$1"
    local unit
    unit=$(systemctl show -p FragmentPath "$svc" 2>/dev/null | cut -d= -f2)
    [[ -f "$unit" ]] || return 1
    local exec
    exec=$(grep -E '^ExecStart=' "$unit" | head -1 | sed 's/^ExecStart=//')
    DET_VENV=$(echo "$exec" | awk '{print $1}' | sed 's|/bin/python.*||')
    DET_APP_ENTRY=$(echo "$exec" | awk '{print $2}')
    DET_PORT=$(echo "$exec" | awk '{print $3}')
    DET_IFACE=$(grep -oE 'WG_INTERFACE=[a-z0-9-]+' "$unit" | head -1 | cut -d= -f2)
    DET_UNIT_FILE="$unit"
    return 0
}

lg_detect_interface() {
    # Prefer unit-declared, then single live interface
    if [[ -n "${DET_IFACE:-}" ]]; then echo "$DET_IFACE"; return; fi
    local ifs
    ifs=$(wg show interfaces 2>/dev/null)
    if [[ $(echo "$ifs" | wc -w) -eq 1 ]]; then echo "$ifs"; fi
}

# ---- Notifications (Pushover; silent no-op when unconfigured) ----

lg_notify() {
    # lg_notify <title> <message> [priority]
    local title="$1" msg="$2" prio="${3:-0}"
    [[ -n "$PUSHOVER_TOKEN" && -n "$PUSHOVER_USER" ]] || return 0
    curl -s --max-time 10 \
        -F "token=$PUSHOVER_TOKEN" -F "user=$PUSHOVER_USER" \
        -F "title=[$BOX_NAME] $title" -F "message=$msg" -F "priority=$prio" \
        https://api.pushover.net/1/messages.json >/dev/null 2>&1 || true
}

# ---- Doctor checks (each prints PASS/FAIL line; returns 0/1) ----

_ok()   { printf '  \033[0;32mPASS\033[0m  %s\n' "$1"; }
_bad()  { printf '  \033[0;31mFAIL\033[0m  %s\n' "$1"; }
_warn() { printf '  \033[1;33mWARN\033[0m  %s\n' "$1"; }

lg_doctor() {
    # Returns 0 when the box is safe to update; nonzero otherwise.
    local failures=0 fix="${1:-}"

    echo "LeathGuard doctor - preflight against the environment contract"
    echo "=============================================================="

    # 1. Contract present
    if [[ -f "$LG_CONF" ]]; then
        _ok "contract present: $LG_CONF"
    else
        _bad "no contract at $LG_CONF - run: sudo leathguard adopt"
        return 1
    fi

    # 2. Install dir + git repo
    if [[ -d "$INSTALL_DIR/.git" ]]; then
        _ok "install dir is a git checkout: $INSTALL_DIR"
    else
        _bad "install dir missing or not a git repo: $INSTALL_DIR"; ((failures++))
    fi

    # 3. Venv interpreter runs
    local vpy="${VENV_DIR:-$INSTALL_DIR/venv}/bin/python"
    if [[ -x "$vpy" ]] && "$vpy" -c 'import sys' 2>/dev/null; then
        _ok "venv interpreter runs: $vpy"
    else
        _bad "venv interpreter missing/broken: $vpy"; ((failures++))
    fi

    # 4. python -m pip functional
    if "$vpy" -m pip --version >/dev/null 2>&1; then
        _ok "python -m pip functional"
    else
        _bad "python -m pip broken in venv"; ((failures++))
    fi

    # 5. pip wrapper shebangs point at a real interpreter (self-healable)
    local w bad_shebang=0
    for w in "${VENV_DIR:-$INSTALL_DIR/venv}"/bin/pip*; do
        [[ -f "$w" ]] || continue
        local sb; sb=$(head -1 "$w" | sed 's/^#!//')
        if [[ "$sb" == /* && ! -x "$sb" ]]; then
            bad_shebang=1
            if [[ "$fix" == "--fix" ]]; then
                sed -i "1s|^#!.*|#!$vpy|" "$w" && _ok "healed shebang: $w"
            fi
        fi
    done
    if [[ $bad_shebang -eq 1 && "$fix" != "--fix" ]]; then
        _warn "stale pip wrapper shebang(s) - run: sudo leathguard doctor --fix"
    elif [[ $bad_shebang -eq 0 ]]; then
        _ok "venv wrapper shebangs valid"
    fi

    # 6. APP_ENTRY exists
    if [[ -f "$APP_ENTRY" ]]; then
        _ok "app entry exists: $APP_ENTRY"
    else
        _bad "app entry missing: $APP_ENTRY"; ((failures++))
    fi

    # 7. Service unit exists
    if systemctl list-unit-files "${SERVICE_NAME}.service" 2>/dev/null | grep -q "$SERVICE_NAME"; then
        _ok "service unit present: $SERVICE_NAME"
    else
        _bad "service unit not found: $SERVICE_NAME"; ((failures++))
    fi

    # 8. WireGuard interface conf exists
    if [[ -n "$WG_INTERFACE" && -f "/etc/wireguard/${WG_INTERFACE}.conf" ]]; then
        _ok "wireguard conf present: /etc/wireguard/${WG_INTERFACE}.conf"
    else
        _bad "wireguard conf missing for interface: '${WG_INTERFACE}'"; ((failures++))
    fi

    # 9. CLIENT_DIR exists and matches convention
    if [[ -d "$CLIENT_DIR" ]]; then
        if [[ "$CLIENT_DIR" == "/etc/wireguard/${WG_INTERFACE}_clients" ]]; then
            _ok "client dir matches <iface>_clients convention: $CLIENT_DIR"
        else
            _warn "client dir exists but off-convention: $CLIENT_DIR (expected /etc/wireguard/${WG_INTERFACE}_clients)"
        fi
    else
        _bad "client dir missing: $CLIENT_DIR"; ((failures++))
    fi

    # 10. Disk space for backup bundle (require 200MB free on install dir fs)
    local free_kb
    free_kb=$(df --output=avail "$INSTALL_DIR" 2>/dev/null | tail -1 | tr -d ' ')
    if [[ -n "$free_kb" && "$free_kb" -gt 204800 ]]; then
        _ok "disk space ok ($(( free_kb / 1024 )) MB free)"
    else
        _bad "insufficient disk space for backup bundle"; ((failures++))
    fi

    # 11. Panel currently answering (informational - not a blocker: the whole
    #     point of an update might be to fix a down panel)
    if curl -s -o /dev/null --max-time 3 "http://127.0.0.1:${PANEL_PORT}/"; then
        _ok "panel answering on 127.0.0.1:${PANEL_PORT}"
    else
        _warn "panel not answering on 127.0.0.1:${PANEL_PORT} (not a blocker)"
    fi

    echo "=============================================================="
    if [[ $failures -eq 0 ]]; then
        echo "RESULT: healthy - safe to update"
        return 0
    else
        echo "RESULT: $failures blocking failure(s) - update will refuse to run"
        return 1
    fi
}
