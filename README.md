# WireGuard Panel

A lightweight, self-hosted WireGuard VPN management solution with both CLI and web interfaces. Designed to be simple like PiVPN but with a modern web dashboard.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Ubuntu%2022.04%2B-orange.svg)

## Features

### CLI Tool (`wg-tool`)
- **PiVPN-like simplicity** — add, revoke, list clients with single commands
- **Live reload** — changes apply instantly via `wg syncconf` (no client disconnections)
- **Auto IP assignment** — allocates next available IP in your subnet
- **QR code generation** — for easy mobile setup

### Web Panel (`wg-panel`)
- **Realtime dashboard** — auto-refreshes every 5 seconds
- **Connection status** — live connected/offline indicators with 5-minute threshold
- **Connection duration** — shows how long each client has been connected
- **Bandwidth monitoring** — per-client sparkline graphs showing live activity
- **GeoIP location** — shows country/city for connected clients
- **Client management** — add, revoke, download configs, view QR codes
- **Client notes** — add descriptions like "Dad's laptop"
- **Connection history** — logs of all connect/disconnect/create/revoke events
- **Dark/Light mode** — toggle with saved preference
- **Mobile-friendly** — responsive design

## Requirements

- Ubuntu 22.04+ (tested on Ubuntu 24.04)
- WireGuard installed and configured
- Python 3.10+
- Root access

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/bel52/wireguard-panel.git
cd wireguard-panel
```

### 2. Run the installer

```bash
sudo ./install.sh
```

The installer will:
- Install dependencies (Python, Flask, qrencode)
- Install `wg-tool` to `/usr/local/sbin/`
- Install `wg-panel` to `/opt/wg-panel/`
- Create a systemd service
- Prompt for web panel credentials

### 3. Access the panel

```
http://YOUR_SERVER_IP:5000
```

## CLI Usage

```bash
# Add a new client
sudo wg-tool add laptop

# Show QR code for mobile import
sudo wg-tool qr laptop

# List all clients
sudo wg-tool list

# Show live connection status
sudo wg-tool show

# Revoke a client
sudo wg-tool revoke laptop
```

## Configuration

### WireGuard Setup

The tools expect a standard WireGuard setup:

```
/etc/wireguard/
├── wg0.conf           # Server config
├── server.key         # Server private key
├── server.pub         # Server public key
└── clients/           # Client configs and keys
    ├── client1.conf
    ├── client1.key
    └── client1.pub
```

### Environment Variables

The web panel can be configured via environment variables in the systemd service:

| Variable | Description | Default |
|----------|-------------|---------|
| `WG_PANEL_USER` | Login username | `admin` |
| `WG_PANEL_PASS_HASH` | SHA256 hash of password | — |
| `WG_PANEL_SECRET` | Flask session secret | (random) |

### Changing the Password

```bash
# Generate new hash
echo -n "yournewpassword" | sha256sum | cut -d' ' -f1

# Edit the service file
sudo systemctl edit wg-panel

# Add:
[Service]
Environment="WG_PANEL_PASS_HASH=your_new_hash_here"

# Restart
sudo systemctl restart wg-panel
```

### Changing the Port

```bash
sudo systemctl edit wg-panel

# Add:
[Service]
ExecStart=
ExecStart=/opt/wg-panel/venv/bin/python /opt/wg-panel/app.py 8080

sudo systemctl restart wg-panel
```

## Security Considerations

- **Run behind a VPN or firewall** — The panel has basic auth but is not hardened for public internet exposure
- **Use HTTPS** — Consider putting it behind a reverse proxy (nginx/Caddy) with TLS
- **Restrict access** — Limit the port in your firewall to trusted IPs only
- **Private repository** — Keep your deployment private if it contains sensitive configs

## File Locations

| Path | Description |
|------|-------------|
| `/usr/local/sbin/wg-tool` | CLI management script |
| `/opt/wg-panel/app.py` | Web panel application |
| `/opt/wg-panel/wg-panel.db` | SQLite database (notes, history) |
| `/etc/wireguard/wg0.conf` | WireGuard server config |
| `/etc/wireguard/clients/` | Client configuration files |

## Troubleshooting

### Panel won't start

```bash
# Check service status
sudo systemctl status wg-panel

# View logs
sudo journalctl -u wg-panel -f
```

### "Permission denied" errors

The panel needs root access to read WireGuard configs and run `wg` commands. Ensure the systemd service runs as root.

### Clients not showing

Verify WireGuard is running:

```bash
sudo wg show
```

### Firewall issues

```bash
# Check if port is open
sudo ufw status

# Open port if needed
sudo ufw allow 5000/tcp
```

## Uninstall

```bash
sudo systemctl stop wg-panel
sudo systemctl disable wg-panel
sudo rm /etc/systemd/system/wg-panel.service
sudo rm -rf /opt/wg-panel
sudo rm /usr/local/sbin/wg-tool
sudo systemctl daemon-reload
```

## License

MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Pull requests welcome. For major changes, please open an issue first.

## Acknowledgments

- Inspired by [PiVPN](https://pivpn.io/)
- Built with [Flask](https://flask.palletsprojects.com/)
- Maps powered by [Leaflet](https://leafletjs.com/) (coming soon)
