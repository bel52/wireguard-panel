# LeathGuard Deployment Guide

## Quick Start

```bash
# Fresh installation
git clone https://github.com/bel52/wireguard-panel.git /opt/wg-panel
cd /opt/wg-panel
sudo ./install.sh

# Update existing installation
wgdeploy
# or
cd /opt/wg-panel && sudo ./update.sh
```

## Supported Configurations

LeathGuard supports multiple WireGuard interfaces on the same server or across different servers.

### Recommended Install Path

| Server Type | Install Path | Service Name |
|-------------|--------------|--------------|
| Any server | `/opt/wg-panel` | `wg-panel` |

For legacy installations with different paths, the update script will auto-detect the service name.

## Installation

### Prerequisites

- Ubuntu/Debian-based Linux
- WireGuard installed and configured (`/etc/wireguard/*.conf`)
- Root access

### Fresh Install

```bash
git clone https://github.com/bel52/wireguard-panel.git /opt/wg-panel
cd /opt/wg-panel
sudo ./install.sh
```

The installer will:
1. Install dependencies (Python, Flask, qrencode)
2. Copy wg-tool to `/usr/local/sbin/`
3. Set up the web panel in `/opt/wg-panel/`
4. Create a Python virtual environment
5. Configure systemd service
6. Open firewall port (if UFW is active)
7. Create the `wgdeploy` alias for easy updates

## Updating

The recommended way to update is with the `leathguard` CLI (available from anywhere):

```bash
sudo leathguard update
```

Or use the legacy `wgdeploy` alias:

```bash
wgdeploy
```

Or run the update script directly:

```bash
cd /opt/wg-panel && sudo ./update.sh
```

### Update Options

```bash
sudo ./update.sh              # Full update with service restart
sudo ./update.sh --no-restart # Update files only, skip restart
sudo ./update.sh --check      # Check for updates without applying
```

### What the Update Script Handles

- **Git safe.directory issues** - Automatically adds the install directory to git's safe directories
- **Local modifications** - Resets any local changes before pulling
- **wg-tool sync** - Copies latest wg-tool to `/usr/local/sbin/`
- **app.py sync** - Updates the web panel application
- **Service detection** - Auto-detects your service name (wg-panel, wg-panel-home, etc.)
- **Service restart** - Restarts the service after updating

## Checking Status

```bash
./status.sh         # Basic status (no root needed)
sudo ./status.sh    # Full status with WireGuard details
```

Status shows:
- Current version and git status
- Service status, PID, and memory usage
- wg-tool installation status
- WireGuard interface summary (active peers)
- Web panel connectivity

## Multi-Interface Setup

If running multiple WireGuard interfaces (e.g., wg0 for external, wg1 for home):

1. Create additional interface config in `/etc/wireguard/wg1.conf`
2. Edit the systemd service to specify the interface:

```bash
sudo systemctl edit wg-panel
```

Add:
```ini
[Service]
Environment="WG_INTERFACE=wg1"
```

3. Restart the service:
```bash
sudo systemctl restart wg-panel
```

The panel auto-detects SERVER_PORT, DNS, and subnet from the interface config.

## File Locations

| File | Location | Purpose |
|------|----------|---------|
| Web panel | `/opt/wg-panel/wg-panel/app.py` | Main Flask application |
| Database | `/opt/wg-panel/wg-panel.db` | SQLite (notes, history, settings) |
| wg-tool | `/usr/local/sbin/wg-tool` | CLI management tool |
| Service | `/etc/systemd/system/wg-panel.service` | Systemd unit file |
| WireGuard | `/etc/wireguard/*.conf` | Interface configurations |
| Client keys | `/etc/wireguard/{iface}_clients/` | Generated client configs |

## Troubleshooting

### "Permission denied" on git pull

```bash
sudo git config --global --add safe.directory /opt/wg-panel
```

Or just run `sudo ./update.sh` - it handles this automatically.

### Local modifications blocking pull

The update script handles this automatically by resetting local changes. Manual fix:

```bash
git checkout -- .
git pull origin main
```

### Service not detected

Check your service name:

```bash
systemctl list-units | grep wg-panel
```

Then restart manually:

```bash
sudo systemctl restart <your-service-name>
```

### wg-tool out of date

```bash
sudo cp /opt/wg-panel/wg-tool /usr/local/sbin/wg-tool
```

Or run `sudo ./update.sh` to sync all files.

### Web panel not responding

Check service status and logs:

```bash
sudo systemctl status wg-panel
sudo journalctl -u wg-panel -f
```

### wgdeploy alias not working

The alias is added to `~/.bashrc`. Either:
- Start a new shell session, or
- Run `source ~/.bashrc`

## Service Management

```bash
sudo systemctl status wg-panel    # Check status
sudo systemctl start wg-panel     # Start service
sudo systemctl stop wg-panel      # Stop service
sudo systemctl restart wg-panel   # Restart service
sudo journalctl -u wg-panel -f    # View live logs
```

## Security Notes

- The web panel runs as root (required for WireGuard operations)
- Password is stored as SHA256 hash in systemd environment
- Database file has 600 permissions
- Client private keys are stored with 600 permissions
