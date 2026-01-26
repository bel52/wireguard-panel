# LeathGuard

A modern, self-hosted WireGuard VPN management panel with a beautiful dark-themed UI.

![LeathGuard Dashboard](docs/screenshot.png)

## Features

- **Beautiful Dashboard** - Real-time client status, traffic stats, and connection map
- **Easy Client Management** - Add, edit, revoke clients with QR code generation
- **Multi-Interface Support** - Manage multiple WireGuard interfaces from one panel
- **Automatic Updates** - In-app update notifications with one-click updates
- **Auto-Update Option** - Optional automatic updates via cron (3 AM daily)
- **Global CLI** - `leathguard` command works from anywhere
- **Secure by Default** - Session-based auth, CSRF protection, password hashing

## Quick Start

### Prerequisites

- Ubuntu/Debian Linux (tested on Ubuntu 22.04, Debian 12, Raspberry Pi OS)
- WireGuard installed and configured
- Python 3.8+
- Root access

### Installation

```bash
# Clone the repository
git clone https://github.com/bel52/wireguard-panel.git /opt/wg-panel
cd /opt/wg-panel

# Run installer
sudo ./install.sh
```

The installer will:
1. Install dependencies (Python, Flask, qrencode)
2. Set up the `wg-tool` CLI for WireGuard management
3. Install the `leathguard` global CLI
4. Create a Python virtual environment
5. Configure and start the systemd service
6. Set up firewall rules (if UFW is active)

### First Login

After installation, access the panel at `http://your-server-ip:5000`

Default credentials are set during installation, or you can set them via environment variables:
- `WG_PANEL_USER` - Username (default: admin)
- `WG_PANEL_PASS` - Plain text password, OR
- `WG_PANEL_PASS_HASH` - SHA256 hash of password

## Usage

### Global CLI

LeathGuard installs a global `leathguard` command:

```bash
# Check status
leathguard status

# Update to latest version
sudo leathguard update

# Check for updates without applying
sudo leathguard check

# View logs
sudo leathguard logs 50      # Last 50 lines
sudo leathguard logs -f      # Follow logs

# Service management
sudo leathguard restart
sudo leathguard start
sudo leathguard stop

# Show version
leathguard version
```

### WireGuard Client Management (wg-tool)

```bash
# Add a new client
sudo wg-tool add clientname [endpoint]

# Show QR code for client
sudo wg-tool qr clientname

# List all clients
sudo wg-tool list

# Show live WireGuard status
sudo wg-tool show

# Revoke a client
sudo wg-tool revoke clientname
```

### Web Interface

The web panel provides:

- **Dashboard** - Overview of all clients, traffic, and server health
- **Client Management** - Add, edit, suspend, and delete clients
- **QR Codes** - Generate QR codes for mobile clients
- **Traffic Stats** - Per-client bandwidth usage
- **Settings** - Change credentials, select interface, enable auto-updates

## Configuration

### Environment Variables

Set these in `/etc/systemd/system/wg-panel.service`:

| Variable | Description | Default |
|----------|-------------|---------|
| `WG_PANEL_USER` | Login username | admin |
| `WG_PANEL_PASS` | Plain text password | (none) |
| `WG_PANEL_PASS_HASH` | SHA256 password hash | (none) |
| `WG_PANEL_DB` | Database file path | /opt/wg-panel/wg-panel.db |
| `WG_INTERFACE` | WireGuard interface to manage | auto-detected |

### Multi-Interface Setup

If you have multiple WireGuard interfaces (e.g., wg0, wg1), set `WG_INTERFACE` in the service file:

```ini
Environment="WG_INTERFACE=wg1"
```

Or select the interface in the web panel's Settings page.

### Changing Credentials

**Option 1: Environment Variables (recommended for production)**

```bash
# Generate password hash
echo -n "yourpassword" | sha256sum | cut -d' ' -f1

# Edit service file
sudo systemctl edit wg-panel --full
# Add/modify:
# Environment="WG_PANEL_USER=yourusername"
# Environment="WG_PANEL_PASS_HASH=yourhash"

sudo systemctl restart wg-panel
```

**Option 2: Web Interface**

Go to Settings -> Account Settings to change username/password (only if not set via environment variables).

### Reverse Proxy (Nginx)

```nginx
server {
    listen 443 ssl;
    server_name vpn.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Cloudflare Tunnel

LeathGuard works great with Cloudflare Tunnels for secure external access without opening ports.

## Updates

### Manual Update

```bash
sudo leathguard update
```

### Automatic Updates

Enable in Settings -> Updates -> Automatic Updates, or manually:

```bash
# Create cron job for daily 3 AM updates
echo '0 3 * * * root /opt/wg-panel/update.sh >> /var/log/leathguard-update.log 2>&1' | sudo tee /etc/cron.d/leathguard-autoupdate
```

### Update Notifications

The dashboard shows a banner when updates are available. Click "Update Now" to apply.

## Migration

If you have an existing installation at a non-standard path:

```bash
cd /path/to/current/installation
sudo ./migrate.sh
```

This will:
1. Move files to `/opt/wg-panel`
2. Recreate the Python virtual environment
3. Update systemd service
4. Standardize service name to `wg-panel`
5. Preserve your database and settings

## Troubleshooting

### Service won't start

```bash
# Check logs
sudo journalctl -u wg-panel -n 50 --no-pager

# Common issues:
# - Missing venv: sudo python3 -m venv /opt/wg-panel/venv && sudo /opt/wg-panel/venv/bin/pip install flask
# - Wrong permissions: sudo chown -R root:root /opt/wg-panel
# - Port in use: Check if another service is using port 5000
```

### Can't login

```bash
# Reset password via environment variable
sudo systemctl edit wg-panel --full
# Add: Environment="WG_PANEL_PASS=newpassword"
sudo systemctl restart wg-panel
```

### WireGuard interface not detected

```bash
# Check WireGuard is running
sudo wg show

# Specify interface explicitly
sudo systemctl edit wg-panel --full
# Add: Environment="WG_INTERFACE=wg0"
sudo systemctl restart wg-panel
```

### Database issues

```bash
# Database location
ls -la /opt/wg-panel/wg-panel.db

# Reset database (WARNING: loses all settings)
sudo rm /opt/wg-panel/wg-panel.db
sudo systemctl restart wg-panel
```

## File Structure

```
/opt/wg-panel/
├── wg-panel/
│   └── app.py          # Main Flask application
├── wg-tool             # WireGuard CLI tool
├── leathguard          # Global CLI tool
├── install.sh          # Installation script
├── update.sh           # Update script
├── migrate.sh          # Migration script
├── status.sh           # Status check script
├── VERSION             # Current version
├── venv/               # Python virtual environment
└── wg-panel.db         # SQLite database (created at runtime)

/usr/local/sbin/wg-tool     # Symlink to wg-tool
/usr/local/bin/leathguard   # Symlink to leathguard CLI
/etc/systemd/system/wg-panel.service  # Systemd service
```

## API Endpoints

LeathGuard provides a REST API (requires authentication):

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | Server and WireGuard status |
| `/api/clients` | GET | List all clients |
| `/api/health` | GET | Health check with version |
| `/api/updates/check` | GET | Check for updates |
| `/api/updates/apply` | POST | Apply available update |
| `/api/settings/interface` | GET/POST | Get/set WireGuard interface |
| `/api/settings/auto-update` | GET/POST | Get/set auto-update setting |

## Security Considerations

- **Always use HTTPS** in production (via reverse proxy or Cloudflare Tunnel)
- **Change default credentials** immediately after installation
- **Use environment variables** for credentials in production
- **Restrict network access** to the panel (firewall, VPN-only, etc.)
- **Keep updated** - enable auto-updates or check regularly

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Acknowledgments

- WireGuard is a registered trademark of Jason A. Donenfeld
- Built with Flask, SQLite, and vanilla JavaScript
- Dark theme inspired by modern dashboard designs
