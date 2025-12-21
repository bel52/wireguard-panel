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
- **GeoIP location** — shows country/city for connected clients with map view
- **Client management** — add, revoke, download configs, view QR codes
- **Client notes** — add descriptions like "Dad's laptop"
- **Connection history** — logs of all connect/disconnect/create/revoke events
- **Dark/Light mode** — toggle with saved preference
- **Mobile-friendly** — responsive design

## Requirements

### System Requirements
- **OS:** Ubuntu 22.04 LTS or newer (tested on Ubuntu 24.04 LTS)
- **Architecture:** x86_64 or ARM64
- **RAM:** 512 MB minimum
- **Disk:** 100 MB free space

### Prerequisites
Before running the installer, you must have:

1. **WireGuard installed and configured** with a working `wg0` interface:
   ```bash
   # Install WireGuard
   sudo apt update
   sudo apt install wireguard wireguard-tools

   # Verify installation
   wg --version
   ```

2. **A working WireGuard server configuration** at `/etc/wireguard/wg0.conf`:
   ```ini
   [Interface]
   PrivateKey = <your_server_private_key>
   Address = 10.6.0.1/24
   ListenPort = 51820
   PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
   PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
   ```

3. **Server keys generated**:
   ```bash
   # Generate server keys (if not already done)
   cd /etc/wireguard
   umask 077
   wg genkey | tee server.key | wg pubkey > server.pub
   ```

4. **IP forwarding enabled**:
   ```bash
   # Enable IP forwarding
   echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
   sudo sysctl -p
   ```

5. **WireGuard interface running**:
   ```bash
   sudo systemctl enable wg-quick@wg0
   sudo systemctl start wg-quick@wg0
   sudo wg show  # Verify it's running
   ```

### Network Requirements
- **UDP port 51820** open for WireGuard VPN traffic
- **TCP port 5000** open for web panel (configurable)
- Public IP or domain name for VPN endpoint

## Installation

### Quick Install

```bash
# Clone the repository
git clone https://github.com/bel52/wireguard-panel.git
cd wireguard-panel

# Run installer (interactive - will prompt for credentials)
sudo ./install.sh
```

### What the Installer Does

1. Installs system dependencies:
   - `python3`, `python3-venv`, `python3-pip`
   - `qrencode` (for QR code generation)

2. Installs `wg-tool` CLI to `/usr/local/sbin/wg-tool`

3. Sets up the web panel:
   - Creates `/opt/wg-panel/` directory
   - Creates Python virtual environment
   - Installs Flask web framework
   - Initializes SQLite database for notes/history

4. Configures systemd service `wg-panel.service`

5. Opens firewall port (if UFW is active)

### Manual Installation

If you prefer to install manually:

```bash
# Install dependencies
sudo apt update
sudo apt install -y python3 python3-venv python3-pip qrencode

# Install CLI tool
sudo cp wg-tool /usr/local/sbin/wg-tool
sudo chmod 755 /usr/local/sbin/wg-tool

# Set up web panel
sudo mkdir -p /opt/wg-panel
sudo cp wg-panel/app.py /opt/wg-panel/
sudo python3 -m venv /opt/wg-panel/venv
sudo /opt/wg-panel/venv/bin/pip install flask

# Create systemd service (see install.sh for template)
# Configure environment variables for authentication
```

### Post-Installation

1. **Open firewall port** (if not done automatically):
   ```bash
   sudo ufw allow 5000/tcp
   ```

2. **Open cloud firewall** (AWS/GCP/Azure):
   - Add inbound rule for TCP port 5000

3. **Access the panel**:
   ```
   http://YOUR_SERVER_IP:5000
   ```

## Directory Structure

After installation:

```
/etc/wireguard/
├── wg0.conf              # WireGuard server config
├── server.key            # Server private key
├── server.pub            # Server public key
└── clients/              # Client configs (created by wg-tool)
    ├── client1.conf
    ├── client1.key
    └── client1.pub

/opt/wg-panel/
├── app.py                # Web panel application
├── wg-panel.db           # SQLite database (notes, history)
└── venv/                 # Python virtual environment

/usr/local/sbin/
└── wg-tool               # CLI management script
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
