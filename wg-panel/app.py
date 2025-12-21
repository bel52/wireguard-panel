#!/usr/bin/env python3
"""
WireGuard Web Panel v4

Features:
- Realtime auto-refresh (5 second polling)
- Connection status with 5-minute threshold
- Connection duration tracking ("Connected for 2d 5h 12m")
- Per-client bandwidth sparklines (30-60 sec window, showing deltas)
- Last seen timestamps for offline clients
- Client notes/descriptions
- Connection history logging
- GeoIP endpoint location
- Dark/light mode toggle
- Mobile-friendly responsive design
- Health & Risk monitoring
- Rolling window traffic stats (1h/24h)
- Demo-safe mode for presentations
- Collapsible map view
"""

import subprocess
import os
import re
import secrets
import sqlite3
import json
import time
import threading
from collections import deque
from functools import wraps
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, render_template_string, request, redirect, url_for, session, flash, Response, jsonify

app = Flask(__name__)
app.secret_key = os.environ.get('WG_PANEL_SECRET', secrets.token_hex(32))
app.permanent_session_lifetime = timedelta(hours=8)

# Config
AUTH_USER = os.environ.get('WG_PANEL_USER', 'admin')
AUTH_PASS_HASH = os.environ.get('WG_PANEL_PASS_HASH', '')
AUTH_PASS_PLAIN = os.environ.get('WG_PANEL_PASS', '')
DB_PATH = os.environ.get('WG_PANEL_DB', '/opt/wg-panel/wg-panel.db')
DNS_CHECK_ENABLED = os.environ.get('WG_PANEL_DNS_CHECK', '').lower() in ('1', 'true', 'yes')
DNS_CHECK_SERVER = os.environ.get('WG_PANEL_DNS_SERVER', '10.6.0.1')
GEOIP_CACHE = {}
BANDWIDTH_CACHE = {}  # Store last known bandwidth for delta calculation
CONNECTION_THRESHOLD_SECONDS = 300  # 5 minutes

# Traffic ring buffer for 1h/24h stats (stores samples with timestamps)
# Each sample: {'timestamp': epoch, 'rx': bytes, 'tx': bytes}
TRAFFIC_RING_BUFFER = deque(maxlen=17280)  # 24h at 5s intervals
TRAFFIC_BUFFER_LOCK = threading.Lock()
LAST_TRAFFIC_SAMPLE = {'rx': 0, 'tx': 0, 'time': 0}

# --------------- Database ---------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS client_notes (
            name TEXT PRIMARY KEY,
            note TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS connection_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_name TEXT,
            event_type TEXT,
            endpoint TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS bandwidth_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_name TEXT,
            rx_delta INTEGER,
            tx_delta INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS client_sessions (
            name TEXT PRIMARY KEY,
            session_start TIMESTAMP,
            last_seen TIMESTAMP,
            last_endpoint TEXT,
            is_connected INTEGER DEFAULT 0
        );
        
        CREATE INDEX IF NOT EXISTS idx_history_client ON connection_history(client_name);
        CREATE INDEX IF NOT EXISTS idx_history_time ON connection_history(timestamp);
        CREATE INDEX IF NOT EXISTS idx_bandwidth_client ON bandwidth_samples(client_name);
        CREATE INDEX IF NOT EXISTS idx_bandwidth_time ON bandwidth_samples(timestamp);
    ''')
    conn.commit()
    conn.close()

def cleanup_old_samples():
    """Remove bandwidth samples older than 2 minutes."""
    conn = get_db()
    conn.execute("DELETE FROM bandwidth_samples WHERE timestamp < datetime('now', '-2 minutes')")
    conn.commit()
    conn.close()

# --------------- Auth ---------------

def check_password(password):
    if AUTH_PASS_HASH:
        import hashlib
        return hashlib.sha256(password.encode()).hexdigest() == AUTH_PASS_HASH
    return password == AUTH_PASS_PLAIN

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'error': 'unauthorized'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# --------------- Helpers ---------------

def run_cmd(cmd, sudo=True):
    if sudo:
        cmd = ['sudo'] + cmd
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout + result.stderr, result.returncode
    except Exception as e:
        return str(e), 1

def parse_bytes(s):
    if not s:
        return 0
    try:
        parts = s.strip().split()
        if len(parts) < 2:
            return int(float(parts[0]))
        num = float(parts[0])
        unit = parts[1].lower()
        multipliers = {'b': 1, 'kib': 1024, 'mib': 1024**2, 'gib': 1024**3, 'tib': 1024**4,
                       'kb': 1000, 'mb': 1000**2, 'gb': 1000**3, 'tb': 1000**4}
        return int(num * multipliers.get(unit, 1))
    except:
        return 0

def format_bytes(b):
    for unit in ['B', 'KiB', 'MiB', 'GiB', 'TiB']:
        if abs(b) < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PiB"

def format_duration(seconds):
    """Format seconds into human readable duration."""
    if seconds is None or seconds < 0:
        return "—"
    
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    
    if days > 0:
        return f"{days}d {hours}h {minutes}m"
    elif hours > 0:
        return f"{hours}h {minutes}m"
    elif minutes > 0:
        return f"{minutes}m {secs}s"
    else:
        return f"{secs}s"

def get_geoip(ip):
    if not ip or ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.'):
        return None
    
    ip = ip.split(':')[0]
    
    if ip in GEOIP_CACHE:
        cached = GEOIP_CACHE[ip]
        # Cache for 1 hour
        if cached.get('_time', 0) > time.time() - 3600:
            return cached
    
    try:
        import urllib.request
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,lat,lon"
        with urllib.request.urlopen(url, timeout=2) as resp:
            data = json.loads(resp.read().decode())
            if data.get('status') == 'success':
                result = {
                    'country': data.get('country', ''),
                    'country_code': data.get('countryCode', '').lower(),
                    'city': data.get('city', ''),
                    'isp': data.get('isp', ''),
                    'lat': data.get('lat'),
                    'lon': data.get('lon'),
                    '_time': time.time()
                }
                GEOIP_CACHE[ip] = result
                return result
    except:
        pass
    
    return None

def get_server_uptime():
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
        return format_duration(uptime_seconds)
    except:
        return "unknown"

def get_wg_uptime():
    try:
        result = subprocess.run(['sudo', 'wg', 'show', 'wg0'],
                                capture_output=True, text=True, timeout=5)
        return "active" if result.returncode == 0 else "down"
    except:
        return "unknown"


# --------------- Health Check Functions ---------------

def check_wg_interface():
    """Check if WireGuard interface wg0 is up."""
    try:
        result = subprocess.run(['sudo', 'wg', 'show', 'wg0'],
                                capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return {'name': 'WireGuard interface', 'status': 'ok', 'detail': 'wg0 up and running'}
        return {'name': 'WireGuard interface', 'status': 'fail', 'detail': 'wg0 not found or down'}
    except subprocess.TimeoutExpired:
        return {'name': 'WireGuard interface', 'status': 'fail', 'detail': 'Command timed out'}
    except Exception as e:
        return {'name': 'WireGuard interface', 'status': 'fail', 'detail': str(e)[:50]}

def check_ip_forwarding():
    """Check if IPv4 forwarding is enabled."""
    try:
        result = subprocess.run(['sysctl', 'net.ipv4.ip_forward'],
                                capture_output=True, text=True, timeout=5)
        if 'net.ipv4.ip_forward = 1' in result.stdout:
            return {'name': 'IP forwarding', 'status': 'ok', 'detail': 'net.ipv4.ip_forward=1'}
        return {'name': 'IP forwarding', 'status': 'warn', 'detail': 'IPv4 forwarding disabled'}
    except Exception as e:
        return {'name': 'IP forwarding', 'status': 'warn', 'detail': str(e)[:50]}

def check_nat_masquerade():
    """Check if NAT/masquerade rules exist."""
    try:
        # Try iptables first
        result = subprocess.run(['sudo', 'iptables', '-t', 'nat', '-L', 'POSTROUTING', '-n'],
                                capture_output=True, text=True, timeout=5)
        if 'MASQUERADE' in result.stdout or 'SNAT' in result.stdout:
            return {'name': 'NAT/masquerade', 'status': 'ok', 'detail': 'iptables NAT rule present'}

        # Try nftables
        result = subprocess.run(['sudo', 'nft', 'list', 'ruleset'],
                                capture_output=True, text=True, timeout=5)
        if 'masquerade' in result.stdout.lower() or 'snat' in result.stdout.lower():
            return {'name': 'NAT/masquerade', 'status': 'ok', 'detail': 'nftables NAT rule present'}

        return {'name': 'NAT/masquerade', 'status': 'warn', 'detail': 'No NAT rules found'}
    except Exception as e:
        return {'name': 'NAT/masquerade', 'status': 'warn', 'detail': str(e)[:50]}

def check_dns_reachability():
    """Check if DNS server is reachable (optional check)."""
    if not DNS_CHECK_ENABLED:
        return None

    try:
        result = subprocess.run(['dig', f'@{DNS_CHECK_SERVER}', 'google.com', '+short', '+time=2'],
                                capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            return {'name': 'DNS reachability', 'status': 'ok', 'detail': f'DNS @{DNS_CHECK_SERVER} responding'}
        return {'name': 'DNS reachability', 'status': 'warn', 'detail': f'DNS @{DNS_CHECK_SERVER} not responding'}
    except Exception as e:
        return {'name': 'DNS reachability', 'status': 'warn', 'detail': str(e)[:50]}

def get_health_status():
    """Get comprehensive health status with all checks."""
    checks = []

    # Run all checks
    checks.append(check_wg_interface())
    checks.append(check_ip_forwarding())
    checks.append(check_nat_masquerade())

    # DNS check (optional)
    dns_check = check_dns_reachability()
    if dns_check:
        checks.append(dns_check)

    # Determine overall status
    statuses = [c['status'] for c in checks]
    if 'fail' in statuses:
        overall = 'down'
    elif 'warn' in statuses:
        overall = 'degraded'
    else:
        overall = 'healthy'

    return {
        'overall': overall,
        'checks': checks,
        'timestamp': datetime.now().isoformat()
    }


# --------------- Traffic Ring Buffer Functions ---------------

def record_traffic_sample(total_rx, total_tx):
    """Record a traffic sample to the ring buffer for 1h/24h stats."""
    global LAST_TRAFFIC_SAMPLE

    now = time.time()

    with TRAFFIC_BUFFER_LOCK:
        # Calculate delta from last sample
        if LAST_TRAFFIC_SAMPLE['time'] > 0:
            rx_delta = max(0, total_rx - LAST_TRAFFIC_SAMPLE['rx'])
            tx_delta = max(0, total_tx - LAST_TRAFFIC_SAMPLE['tx'])

            # Only record if there's actual traffic or it's been a while
            TRAFFIC_RING_BUFFER.append({
                'timestamp': now,
                'rx': rx_delta,
                'tx': tx_delta
            })

        LAST_TRAFFIC_SAMPLE = {'rx': total_rx, 'tx': total_tx, 'time': now}

def get_traffic_windows():
    """Calculate traffic for last 1h and 24h windows."""
    now = time.time()
    hour_ago = now - 3600
    day_ago = now - 86400

    rx_1h = 0
    tx_1h = 0
    rx_24h = 0
    tx_24h = 0

    with TRAFFIC_BUFFER_LOCK:
        for sample in TRAFFIC_RING_BUFFER:
            ts = sample['timestamp']
            if ts >= day_ago:
                rx_24h += sample['rx']
                tx_24h += sample['tx']
                if ts >= hour_ago:
                    rx_1h += sample['rx']
                    tx_1h += sample['tx']

    return {
        'last1h': {'rxBytes': rx_1h, 'txBytes': tx_1h},
        'last24h': {'rxBytes': rx_24h, 'txBytes': tx_24h}
    }


# --------------- WireGuard Functions ---------------

def parse_handshake_to_seconds(hs_string):
    """Parse handshake string like '1 minute, 30 seconds ago' to seconds."""
    if not hs_string:
        return None
    
    total = 0
    
    # Match patterns like "1 hour", "30 minutes", "45 seconds"
    hour_match = re.search(r'(\d+)\s*hour', hs_string)
    min_match = re.search(r'(\d+)\s*minute', hs_string)
    sec_match = re.search(r'(\d+)\s*second', hs_string)
    
    if hour_match:
        total += int(hour_match.group(1)) * 3600
    if min_match:
        total += int(min_match.group(1)) * 60
    if sec_match:
        total += int(sec_match.group(1))
    
    return total if total > 0 or sec_match else None

def parse_wg_show():
    output, _ = run_cmd(['wg', 'show'])
    peers = []
    current_peer = None
    
    for line in output.split('\n'):
        line = line.strip()
        if line.startswith('peer:'):
            if current_peer:
                peers.append(current_peer)
            current_peer = {
                'public_key': line.split('peer:')[1].strip(),
                'endpoint': '',
                'allowed_ips': '',
                'latest_handshake': '',
                'handshake_seconds': None,
                'transfer_rx': 0,
                'transfer_tx': 0,
            }
        elif current_peer:
            if line.startswith('endpoint:'):
                current_peer['endpoint'] = line.split('endpoint:')[1].strip()
            elif line.startswith('allowed ips:'):
                current_peer['allowed_ips'] = line.split('allowed ips:')[1].strip()
            elif line.startswith('latest handshake:'):
                hs = line.split('latest handshake:')[1].strip()
                current_peer['latest_handshake'] = hs
                current_peer['handshake_seconds'] = parse_handshake_to_seconds(hs)
            elif line.startswith('transfer:'):
                transfer = line.split('transfer:')[1].strip()
                match = re.match(r'([\d.]+\s*\w+)\s+received,\s*([\d.]+\s*\w+)\s+sent', transfer)
                if match:
                    current_peer['transfer_rx'] = parse_bytes(match.group(1))
                    current_peer['transfer_tx'] = parse_bytes(match.group(2))
    
    if current_peer:
        peers.append(current_peer)
    
    return peers

def get_clients():
    global BANDWIDTH_CACHE
    
    output, _ = run_cmd(['wg-tool', 'list'])
    
    clients = []
    peers_live = {p['public_key']: p for p in parse_wg_show()}
    
    conn = get_db()
    now = datetime.now()
    
    # Cleanup old bandwidth samples periodically
    cleanup_old_samples()
    
    in_peers = False
    for line in output.split('\n'):
        line = line.strip()
        if 'Peers in wg0.conf' in line:
            in_peers = True
            continue
        
        if in_peers and line.startswith('- '):
            parts = line[2:].split('|')
            if len(parts) >= 3:
                name = parts[0].strip()
                pubkey = parts[1].strip()
                ip = parts[2].strip().replace('/32', '')
                
                live = peers_live.get(pubkey, {})
                handshake_seconds = live.get('handshake_seconds')
                
                # Determine connection status (5 minute threshold)
                is_connected = (handshake_seconds is not None and 
                               handshake_seconds < CONNECTION_THRESHOLD_SECONDS)
                
                # Get note
                note_row = conn.execute('SELECT note FROM client_notes WHERE name = ?', (name,)).fetchone()
                note = note_row['note'] if note_row else ''
                
                # Get/update session info
                session_row = conn.execute('SELECT * FROM client_sessions WHERE name = ?', (name,)).fetchone()
                
                endpoint = live.get('endpoint', '')
                
                if is_connected:
                    if session_row and session_row['is_connected']:
                        # Still connected — keep existing session_start
                        session_start = session_row['session_start']
                    else:
                        # Newly connected — start new session
                        session_start = now.isoformat()
                        log_connection_event(name, 'connected', endpoint)
                    
                    conn.execute('''
                        INSERT OR REPLACE INTO client_sessions (name, session_start, last_seen, last_endpoint, is_connected)
                        VALUES (?, ?, ?, ?, 1)
                    ''', (name, session_start, now.isoformat(), endpoint))
                    
                    # Calculate connection duration
                    try:
                        start_dt = datetime.fromisoformat(session_start)
                        connection_duration = (now - start_dt).total_seconds()
                    except:
                        connection_duration = 0
                else:
                    # Not connected
                    if session_row and session_row['is_connected']:
                        # Just disconnected — log it
                        log_connection_event(name, 'disconnected', session_row['last_endpoint'] or '')
                    
                    if session_row:
                        conn.execute('''
                            UPDATE client_sessions SET is_connected = 0 WHERE name = ?
                        ''', (name,))
                    
                    connection_duration = None
                
                conn.commit()
                
                # Get last seen for offline clients
                if not is_connected and session_row and session_row['last_seen']:
                    last_seen = session_row['last_seen']
                    last_endpoint = session_row['last_endpoint']
                else:
                    last_seen = None
                    last_endpoint = None
                
                # Calculate bandwidth deltas
                current_rx = live.get('transfer_rx', 0)
                current_tx = live.get('transfer_tx', 0)
                
                cache_key = name
                if cache_key in BANDWIDTH_CACHE:
                    prev_rx, prev_tx = BANDWIDTH_CACHE[cache_key]
                    rx_delta = max(0, current_rx - prev_rx)
                    tx_delta = max(0, current_tx - prev_tx)
                else:
                    rx_delta = 0
                    tx_delta = 0
                
                BANDWIDTH_CACHE[cache_key] = (current_rx, current_tx)
                
                # Store bandwidth sample if there's activity
                if rx_delta > 0 or tx_delta > 0:
                    conn.execute('''
                        INSERT INTO bandwidth_samples (client_name, rx_delta, tx_delta)
                        VALUES (?, ?, ?)
                    ''', (name, rx_delta, tx_delta))
                    conn.commit()
                
                # Get recent bandwidth samples (last 60 seconds = ~12 samples at 5s intervals)
                bw_rows = conn.execute('''
                    SELECT rx_delta, tx_delta FROM bandwidth_samples 
                    WHERE client_name = ? AND timestamp > datetime('now', '-60 seconds')
                    ORDER BY timestamp ASC
                ''', (name,)).fetchall()
                bandwidth_history = [{'rx': r['rx_delta'], 'tx': r['tx_delta']} for r in bw_rows]
                
                # GeoIP
                geo = get_geoip(endpoint) if endpoint else None
                if not geo and last_endpoint:
                    geo = get_geoip(last_endpoint)
                
                clients.append({
                    'name': name,
                    'public_key': pubkey,
                    'ip': ip,
                    'connected': is_connected,
                    'connection_duration': connection_duration,
                    'connection_duration_fmt': format_duration(connection_duration) if connection_duration else None,
                    'endpoint': endpoint if is_connected else '',
                    'handshake_seconds': handshake_seconds,
                    'handshake_fmt': live.get('latest_handshake', ''),
                    'transfer_rx': current_rx,
                    'transfer_tx': current_tx,
                    'transfer_rx_fmt': format_bytes(current_rx),
                    'transfer_tx_fmt': format_bytes(current_tx),
                    'note': note,
                    'last_seen': last_seen,
                    'last_endpoint': last_endpoint,
                    'geo': geo,
                    'bandwidth_history': bandwidth_history
                })
    
    conn.close()
    return clients

def get_server_stats():
    peers = parse_wg_show()

    connected = sum(1 for p in peers
                    if p.get('handshake_seconds') is not None
                    and p['handshake_seconds'] < CONNECTION_THRESHOLD_SECONDS)

    total_rx = sum(p.get('transfer_rx', 0) for p in peers)
    total_tx = sum(p.get('transfer_tx', 0) for p in peers)

    # Record traffic sample for rolling window stats
    record_traffic_sample(total_rx, total_tx)

    # Get traffic windows (1h/24h)
    traffic_windows = get_traffic_windows()

    return {
        'uptime': get_server_uptime(),
        'wg_status': get_wg_uptime(),
        'total_clients': len(peers),
        'connected_clients': connected,
        'total_rx': total_rx,
        'total_tx': total_tx,
        'total_rx_fmt': format_bytes(total_rx),
        'total_tx_fmt': format_bytes(total_tx),
        'traffic': {
            'total': {'rxBytes': total_rx, 'txBytes': total_tx},
            'last1h': traffic_windows['last1h'],
            'last24h': traffic_windows['last24h'],
            'last1h_rx_fmt': format_bytes(traffic_windows['last1h']['rxBytes']),
            'last1h_tx_fmt': format_bytes(traffic_windows['last1h']['txBytes']),
            'last24h_rx_fmt': format_bytes(traffic_windows['last24h']['rxBytes']),
            'last24h_tx_fmt': format_bytes(traffic_windows['last24h']['txBytes'])
        }
    }

def get_connection_history(client_name=None, limit=50):
    conn = get_db()
    if client_name:
        rows = conn.execute('''
            SELECT * FROM connection_history 
            WHERE client_name = ? 
            ORDER BY timestamp DESC LIMIT ?
        ''', (client_name, limit)).fetchall()
    else:
        rows = conn.execute('''
            SELECT * FROM connection_history 
            ORDER BY timestamp DESC LIMIT ?
        ''', (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def log_connection_event(client_name, event_type, endpoint=''):
    conn = get_db()
    conn.execute('''
        INSERT INTO connection_history (client_name, event_type, endpoint)
        VALUES (?, ?, ?)
    ''', (client_name, event_type, endpoint))
    conn.commit()
    conn.close()

def add_client(name):
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        return False, "Invalid name. Use only letters, numbers, underscore, dash."
    if len(name) > 32:
        return False, "Name too long (max 32 chars)."
    
    output, code = run_cmd(['wg-tool', 'add', name])
    if code == 0:
        log_connection_event(name, 'created')
    return code == 0, output

def revoke_client(name):
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        return False, "Invalid name."
    
    output, code = run_cmd(['wg-tool', 'revoke', name])
    if code == 0:
        log_connection_event(name, 'revoked')
        conn = get_db()
        conn.execute('DELETE FROM client_notes WHERE name = ?', (name,))
        conn.execute('DELETE FROM client_sessions WHERE name = ?', (name,))
        conn.execute('DELETE FROM bandwidth_samples WHERE client_name = ?', (name,))
        conn.commit()
        conn.close()
    return code == 0, output

def get_client_config(name):
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        return None
    try:
        result = subprocess.run(['sudo', 'cat', f'/etc/wireguard/clients/{name}.conf'], 
                                capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout
    except:
        pass
    return None

def get_client_qr(name):
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        return None
    try:
        result = subprocess.run(
            f'sudo cat /etc/wireguard/clients/{name}.conf | qrencode -o - -t PNG',
            shell=True, capture_output=True
        )
        if result.returncode == 0:
            return result.stdout
    except:
        pass
    return None

def update_client_note(name, note):
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        return False
    conn = get_db()
    conn.execute('''
        INSERT OR REPLACE INTO client_notes (name, note, updated_at)
        VALUES (?, ?, datetime('now'))
    ''', (name, note[:500]))
    conn.commit()
    conn.close()
    return True


# --------------- HTML Template ---------------

TEMPLATE = '''
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WireGuard Panel</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" crossorigin=""/>
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" crossorigin=""></script>
    <style>
        :root {
            --bg-primary: #1a1a2e;
            --bg-secondary: #252542;
            --bg-tertiary: #2d2d4a;
            --text-primary: #eee;
            --text-secondary: #888;
            --accent: #00d4aa;
            --accent-hover: #00b894;
            --danger: #e74c3c;
            --danger-hover: #c0392b;
            --success: #00d4aa;
            --warning: #f39c12;
        }
        
        [data-theme="light"] {
            --bg-primary: #f0f2f5;
            --bg-secondary: #ffffff;
            --bg-tertiary: #e4e6eb;
            --text-primary: #1c1e21;
            --text-secondary: #606770;
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            padding: 24px;
            transition: background 0.3s, color 0.3s;
        }
        
        .container { max-width: 1100px; margin: 0 auto; }
        
        h1 { 
            color: var(--accent); 
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 1.6em;
            font-weight: 600;
            letter-spacing: -0.5px;
        }
        h1::before { 
            content: "◈"; 
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 28px;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--bg-tertiary);
            flex-wrap: wrap;
            gap: 16px;
        }
        
        .header-actions {
            display: flex;
            gap: 10px;
            align-items: center;
            flex-wrap: wrap;
        }
        
        .btn {
            background: var(--accent);
            color: var(--bg-primary);
            border: none;
            padding: 10px 18px;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 0.9em;
            transition: all 0.2s ease;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .btn:hover { 
            background: var(--accent-hover); 
            transform: translateY(-1px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        }
        .btn-danger { background: var(--danger); color: white; }
        .btn-danger:hover { background: var(--danger-hover); }
        .btn-secondary { 
            background: var(--bg-tertiary); 
            color: var(--text-primary);
            box-shadow: none;
        }
        .btn-secondary:hover { 
            background: #3d3d5c; 
            transform: translateY(-1px);
        }
        .btn-small { padding: 6px 12px; font-size: 0.8em; }
        
        .card {
            background: var(--bg-secondary);
            border-radius: 16px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.25);
            border: 1px solid rgba(255,255,255,0.05);
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        
        .stat-box {
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
            padding: 20px 16px;
            border-radius: 14px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
            border: 1px solid rgba(255,255,255,0.05);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }
        .stat-box:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0,0,0,0.3);
        }
        .stat-box .number { 
            font-size: 1.6em; 
            color: var(--accent); 
            font-weight: 700;
            letter-spacing: -0.5px;
        }
        .stat-box .label { 
            color: var(--text-secondary); 
            font-size: 0.75em; 
            margin-top: 6px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 500;
        }
        .stat-box.warning .number { color: var(--warning); }
        
        .client-grid { display: grid; gap: 16px; }
        
        .map-container {
            height: 300px;
            border-radius: 12px;
            overflow: hidden;
            margin-bottom: 20px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.25);
            border: 1px solid rgba(255,255,255,0.05);
        }
        #client-map {
            height: 100%;
            width: 100%;
            background: var(--bg-tertiary);
        }
        .leaflet-popup-content-wrapper {
            background: var(--bg-secondary);
            color: var(--text-primary);
            border-radius: 8px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
        }
        .leaflet-popup-tip {
            background: var(--bg-secondary);
        }
        .leaflet-popup-content {
            margin: 10px 12px;
            font-size: 0.9em;
        }
        .map-popup-title {
            font-weight: 600;
            color: var(--accent);
            margin-bottom: 4px;
        }
        .map-popup-info {
            color: var(--text-secondary);
            font-size: 0.85em;
        }
        
        .client-card {
            background: var(--bg-tertiary);
            border-radius: 12px;
            padding: 18px;
            display: grid;
            grid-template-columns: auto 1fr auto;
            gap: 16px;
            align-items: start;
            box-shadow: 0 2px 10px rgba(0,0,0,0.15);
            border: 1px solid rgba(255,255,255,0.03);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }
        .client-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 16px rgba(0,0,0,0.25);
        }
        
        .status-indicator {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 4px;
            padding-top: 4px;
        }
        
        .status-dot {
            width: 14px;
            height: 14px;
            border-radius: 50%;
            background: #444;
            transition: all 0.3s;
            box-shadow: inset 0 1px 3px rgba(0,0,0,0.3);
        }
        .status-dot.connected { 
            background: var(--success); 
            box-shadow: 0 0 12px var(--success), inset 0 1px 3px rgba(255,255,255,0.3);
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.6; }
        }
        
        .client-info { min-width: 0; }
        .client-info h3 { 
            margin-bottom: 6px; 
            color: var(--text-primary);
            font-size: 1.1em;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
        }
        .client-info h3 .note-badge {
            font-size: 0.7em;
            font-weight: 500;
            color: var(--text-secondary);
            background: var(--bg-secondary);
            padding: 3px 8px;
            border-radius: 6px;
        }
        .live-speed {
            font-size: 0.8em;
            display: flex;
            align-items: center;
            gap: 10px;
            margin-top: 8px;
            padding-top: 8px;
            border-top: 1px solid rgba(255,255,255,0.05);
            color: var(--text-secondary);
        }
        .live-speed .rx-speed { color: var(--accent); font-weight: 500; }
        .live-speed .tx-speed { color: var(--warning); font-weight: 500; }
        
        .client-meta { 
            color: var(--text-secondary); 
            font-size: 0.85em;
            display: flex;
            flex-wrap: wrap;
            gap: 8px 16px;
            margin-top: 6px;
        }
        .client-meta span {
            display: inline-flex;
            align-items: center;
            gap: 5px;
        }
        
        .geo-flag {
            width: 16px;
            height: 12px;
            border-radius: 2px;
            object-fit: cover;
        }
        
        .sparkline {
            width: 60px;
            height: 20px;
            display: inline-block;
            vertical-align: middle;
        }
        .sparkline svg { width: 100%; height: 100%; }
        .sparkline .rx { fill: none; stroke: var(--accent); stroke-width: 1.5; }
        .sparkline .tx { fill: none; stroke: var(--warning); stroke-width: 1.5; }
        
        .client-actions { 
            display: flex; 
            gap: 8px; 
            flex-wrap: wrap;
            justify-content: flex-end;
        }
        
        .last-seen {
            font-size: 0.8em;
            color: var(--text-secondary);
            margin-top: 8px;
            font-style: italic;
            opacity: 0.8;
        }
        
        .flash {
            padding: 12px;
            border-radius: 5px;
            margin-bottom: 15px;
            font-size: 0.9em;
        }
        .flash.success { background: rgba(0,212,170,0.2); border: 1px solid var(--accent); }
        .flash.error { background: rgba(231,76,60,0.2); border: 1px solid var(--danger); }
        
        .modal {
            display: none;
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0,0,0,0.85);
            backdrop-filter: blur(4px);
            justify-content: center;
            align-items: center;
            z-index: 1000;
            padding: 20px;
        }
        .modal.active { display: flex; }
        
        .modal-content {
            background: var(--bg-secondary);
            padding: 28px;
            border-radius: 16px;
            max-width: 480px;
            width: 100%;
            max-height: 90vh;
            overflow-y: auto;
            box-shadow: 0 20px 60px rgba(0,0,0,0.5);
            border: 1px solid rgba(255,255,255,0.1);
        }
        .modal-content h2 { 
            margin-bottom: 20px; 
            color: var(--accent);
            font-size: 1.3em;
            font-weight: 600;
        }
        
        .form-group { margin-bottom: 16px; }
        .form-group label { 
            display: block; 
            margin-bottom: 6px; 
            color: var(--text-secondary);
            font-size: 0.85em;
            font-weight: 500;
        }
        .form-group input, .form-group textarea {
            width: 100%;
            padding: 12px 14px;
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 8px;
            background: var(--bg-primary);
            color: var(--text-primary);
            font-size: 0.95em;
            transition: border-color 0.2s ease, box-shadow 0.2s ease;
        }
        .form-group input:focus, .form-group textarea:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(0, 212, 170, 0.15);
        }
        .form-group textarea { resize: vertical; min-height: 80px; }
        
        .form-actions { 
            display: flex; 
            gap: 10px; 
            justify-content: flex-end;
            margin-top: 20px;
        }
        
        .qr-container { text-align: center; padding: 15px; }
        .qr-container img { 
            max-width: 200px; 
            background: white; 
            padding: 8px; 
            border-radius: 8px; 
        }
        
        .config-box {
            background: var(--bg-primary);
            padding: 12px;
            border-radius: 5px;
            font-family: monospace;
            font-size: 0.8em;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 250px;
            overflow-y: auto;
        }
        
        .history-list {
            max-height: 300px;
            overflow-y: auto;
        }
        .history-item {
            padding: 8px 0;
            border-bottom: 1px solid var(--bg-tertiary);
            font-size: 0.85em;
        }
        .history-item:last-child { border-bottom: none; }
        .history-item .time { color: var(--text-secondary); }
        .history-item .event { margin-left: 10px; }
        .history-item .event.created { color: var(--accent); }
        .history-item .event.revoked { color: var(--danger); }
        .history-item .event.connected { color: var(--success); }
        .history-item .event.disconnected { color: var(--warning); }
        
        .login-container { max-width: 350px; margin: 80px auto; }
        
        .theme-toggle {
            background: var(--bg-tertiary);
            border: 1px solid rgba(255,255,255,0.1);
            color: var(--text-primary);
            padding: 8px 12px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1em;
            transition: all 0.2s ease;
        }
        .theme-toggle:hover {
            background: var(--bg-secondary);
            border-color: rgba(255,255,255,0.2);
        }
        
        .refresh-indicator {
            font-size: 0.8em;
            color: var(--text-secondary);
            display: flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            background: var(--bg-tertiary);
            border-radius: 20px;
        }
        .refresh-indicator .dot {
            width: 8px;
            height: 8px;
            background: var(--success);
            border-radius: 50%;
            animation: blink 1s infinite;
        }
        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }
        
        .empty-state {
            text-align: center;
            padding: 30px;
            color: var(--text-secondary);
        }
        
        @media (max-width: 600px) {
            .client-card {
                grid-template-columns: auto 1fr;
            }
            .client-actions {
                grid-column: span 2;
                justify-content: flex-start;
                margin-top: 8px;
            }
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            .client-controls {
                flex-direction: column;
            }
            .filter-group {
                flex-wrap: wrap;
            }
        }

        /* Health Card Styles */
        .health-card {
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
            padding: 16px 20px;
            border-radius: 14px;
            margin-bottom: 20px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
            border: 1px solid rgba(255,255,255,0.05);
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .health-card:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(0,0,0,0.25);
        }
        .health-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .health-status {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .health-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: var(--success);
            box-shadow: 0 0 8px var(--success);
        }
        .health-indicator.degraded {
            background: var(--warning);
            box-shadow: 0 0 8px var(--warning);
        }
        .health-indicator.down {
            background: var(--danger);
            box-shadow: 0 0 8px var(--danger);
        }
        .health-title {
            font-weight: 600;
            font-size: 1em;
        }
        .health-title .status-text {
            color: var(--success);
            margin-left: 8px;
        }
        .health-title .status-text.degraded { color: var(--warning); }
        .health-title .status-text.down { color: var(--danger); }
        .health-chevron {
            color: var(--text-secondary);
            transition: transform 0.2s ease;
        }
        .health-chevron.expanded {
            transform: rotate(180deg);
        }
        .health-details {
            display: none;
            margin-top: 16px;
            padding-top: 16px;
            border-top: 1px solid rgba(255,255,255,0.05);
        }
        .health-details.expanded {
            display: block;
        }
        .health-check {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 8px 0;
            font-size: 0.9em;
        }
        .check-status {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            flex-shrink: 0;
        }
        .check-status.ok { background: var(--success); }
        .check-status.warn { background: var(--warning); }
        .check-status.fail { background: var(--danger); }
        .check-name { color: var(--text-primary); min-width: 140px; }
        .check-detail { color: var(--text-secondary); font-size: 0.85em; }

        /* Demo Mode Styles */
        .demo-toggle {
            background: var(--bg-tertiary);
            border: 1px solid rgba(255,255,255,0.1);
            color: var(--text-primary);
            padding: 8px 12px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.85em;
            transition: all 0.2s ease;
        }
        .demo-toggle:hover {
            background: var(--bg-secondary);
        }
        .demo-toggle.active {
            background: var(--warning);
            color: var(--bg-primary);
            border-color: var(--warning);
        }
        .demo-pill {
            display: none;
            background: var(--warning);
            color: var(--bg-primary);
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.75em;
            font-weight: 600;
        }
        .demo-pill.active {
            display: inline-block;
        }

        /* Map Collapse Styles */
        .map-collapse-header {
            background: var(--bg-secondary);
            padding: 14px 18px;
            border-radius: 12px;
            margin-bottom: 20px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: space-between;
            box-shadow: 0 2px 10px rgba(0,0,0,0.15);
            border: 1px solid rgba(255,255,255,0.05);
            transition: all 0.2s ease;
        }
        .map-collapse-header:hover {
            background: var(--bg-tertiary);
        }
        .map-collapse-title {
            display: flex;
            align-items: center;
            gap: 10px;
            font-weight: 500;
        }
        .map-collapse-count {
            color: var(--text-secondary);
            font-size: 0.9em;
        }
        .map-wrapper {
            display: none;
        }
        .map-wrapper.expanded {
            display: block;
        }

        /* Client Controls */
        .client-controls {
            display: flex;
            gap: 12px;
            margin-bottom: 16px;
            flex-wrap: wrap;
            align-items: center;
        }
        .search-box {
            flex: 1;
            min-width: 200px;
            position: relative;
        }
        .search-box input {
            width: 100%;
            padding: 10px 14px 10px 36px;
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 8px;
            background: var(--bg-primary);
            color: var(--text-primary);
            font-size: 0.9em;
        }
        .search-box input:focus {
            outline: none;
            border-color: var(--accent);
        }
        .search-box::before {
            content: "🔍";
            position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            font-size: 0.85em;
            opacity: 0.6;
        }
        .filter-group {
            display: flex;
            gap: 6px;
        }
        .filter-btn {
            padding: 8px 14px;
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 6px;
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            font-size: 0.8em;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .filter-btn:hover {
            background: var(--bg-secondary);
        }
        .filter-btn.active {
            background: var(--accent);
            color: var(--bg-primary);
            border-color: var(--accent);
        }
        .sort-select {
            padding: 10px 14px;
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 8px;
            background: var(--bg-tertiary);
            color: var(--text-primary);
            font-size: 0.85em;
            cursor: pointer;
        }

        /* Icon Buttons with Tooltips */
        .icon-btn {
            padding: 8px;
            border: none;
            border-radius: 6px;
            background: var(--bg-secondary);
            color: var(--text-secondary);
            cursor: pointer;
            transition: all 0.2s ease;
            position: relative;
            font-size: 0.9em;
            line-height: 1;
        }
        .icon-btn:hover {
            background: var(--accent);
            color: var(--bg-primary);
        }
        .icon-btn.danger:hover {
            background: var(--danger);
            color: white;
        }
        .icon-btn[title]:hover::after {
            content: attr(title);
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%);
            padding: 4px 8px;
            background: var(--bg-primary);
            color: var(--text-primary);
            font-size: 0.75em;
            border-radius: 4px;
            white-space: nowrap;
            margin-bottom: 4px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.3);
        }
        .copy-btn {
            padding: 2px 6px;
            border: none;
            background: transparent;
            color: var(--text-secondary);
            cursor: pointer;
            font-size: 0.8em;
            opacity: 0.6;
            transition: opacity 0.2s;
        }
        .copy-btn:hover {
            opacity: 1;
            color: var(--accent);
        }

        /* Stat Toggle */
        .stat-toggle {
            display: flex;
            gap: 4px;
            margin-top: 8px;
        }
        .stat-toggle button {
            padding: 2px 8px;
            border: none;
            border-radius: 4px;
            background: transparent;
            color: var(--text-secondary);
            font-size: 0.7em;
            cursor: pointer;
            transition: all 0.2s;
        }
        .stat-toggle button.active {
            background: var(--accent);
            color: var(--bg-primary);
        }
        .stat-total {
            font-size: 0.7em;
            color: var(--text-secondary);
            margin-top: 4px;
        }

        /* Activity Strip */
        .activity-strip {
            background: var(--bg-secondary);
            padding: 12px 16px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.15);
        }
        .activity-strip-title {
            font-size: 0.8em;
            color: var(--text-secondary);
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .activity-items {
            display: flex;
            gap: 12px;
            overflow-x: auto;
            padding-bottom: 4px;
        }
        .activity-item {
            flex-shrink: 0;
            font-size: 0.8em;
            padding: 6px 10px;
            background: var(--bg-tertiary);
            border-radius: 6px;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .activity-item .time {
            color: var(--text-secondary);
        }
        .activity-item.created { border-left: 3px solid var(--accent); }
        .activity-item.revoked { border-left: 3px solid var(--danger); }
        .activity-item.connected { border-left: 3px solid var(--success); }
        .activity-item.disconnected { border-left: 3px solid var(--warning); }

        /* Subtitle */
        .header-subtitle {
            font-size: 0.8em;
            color: var(--text-secondary);
            margin-top: 4px;
            font-weight: 400;
        }

        /* Last handshake prominent */
        .handshake-badge {
            background: var(--bg-secondary);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75em;
            color: var(--accent);
        }
        .handshake-badge.stale {
            color: var(--warning);
        }
    </style>
</head>
<body>
    <div class="container">
        {% if not session.logged_in %}
        <!-- Login -->
        <div class="login-container">
            <div class="card">
                <h1>WireGuard Panel</h1>
                {% for msg in get_flashed_messages() %}
                <div class="flash error">{{ msg }}</div>
                {% endfor %}
                <form method="POST" action="{{ url_for('login') }}">
                    <div class="form-group">
                        <label>Username</label>
                        <input type="text" name="username" required autofocus>
                    </div>
                    <div class="form-group">
                        <label>Password</label>
                        <input type="password" name="password" required>
                    </div>
                    <button type="submit" class="btn" style="width:100%;margin-top:10px;">Login</button>
                </form>
            </div>
        </div>
        {% else %}
        <!-- Dashboard -->
        <div class="header">
            <div>
                <h1>WireGuard Panel</h1>
                <div class="header-subtitle">WireGuard • Clients • Traffic • Activity</div>
            </div>
            <div class="header-actions">
                <span class="demo-pill" id="demoPill">Demo Mode</span>
                <span class="refresh-indicator"><span class="dot"></span> Live</span>
                <button class="btn" onclick="showAddModal()">+ Add Client</button>
                <button class="btn btn-secondary" onclick="showHistoryModal()">History</button>
                <button class="demo-toggle" id="demoToggle" onclick="toggleDemoMode()">Demo</button>
                <button class="theme-toggle" onclick="toggleTheme()">🌓</button>
                <a href="{{ url_for('logout') }}" class="btn btn-secondary">Logout</a>
            </div>
        </div>
        
        <div id="flash-container">
        {% for msg in get_flashed_messages() %}
        <div class="flash success">{{ msg }}</div>
        {% endfor %}
        </div>
        
        <div id="dashboard-content">
            <!-- Health Card -->
            <div class="health-card" id="healthCard" onclick="toggleHealthDetails()">
                <div class="health-header">
                    <div class="health-status">
                        <div class="health-indicator" id="healthIndicator"></div>
                        <div class="health-title">
                            Status: <span class="status-text" id="healthStatusText">Checking...</span>
                        </div>
                    </div>
                    <span class="health-chevron" id="healthChevron">▼</span>
                </div>
                <div class="health-details" id="healthDetails"></div>
            </div>

            <div class="stats-grid" id="stats-grid">
                <div class="stat-box"><div class="number">—</div><div class="label">Loading...</div></div>
            </div>

            <!-- Activity Strip -->
            <div class="activity-strip" id="activityStrip">
                <div class="activity-strip-title">Recent Activity</div>
                <div class="activity-items" id="activityItems">
                    <div class="activity-item">Loading...</div>
                </div>
            </div>

            <div class="card">
                <!-- Client Controls: Search, Filter, Sort -->
                <div class="client-controls">
                    <div class="search-box">
                        <input type="text" id="clientSearch" placeholder="Search clients..." oninput="filterAndSortClients()">
                    </div>
                    <div class="filter-group">
                        <button class="filter-btn active" data-filter="all" onclick="setFilter('all')">All</button>
                        <button class="filter-btn" data-filter="connected" onclick="setFilter('connected')">Connected</button>
                        <button class="filter-btn" data-filter="offline" onclick="setFilter('offline')">Offline</button>
                        <button class="filter-btn" data-filter="recent" onclick="setFilter('recent')">Last 24h</button>
                    </div>
                    <select class="sort-select" id="sortSelect" onchange="filterAndSortClients()">
                        <option value="name">Sort: Name</option>
                        <option value="handshake">Sort: Last Handshake</option>
                        <option value="rx">Sort: Data Received</option>
                        <option value="tx">Sort: Data Sent</option>
                    </select>
                </div>
                <div class="client-grid" id="client-grid">
                    <div class="empty-state">Loading clients...</div>
                </div>
            </div>

            <!-- Collapsible Map -->
            <div class="map-collapse-header" id="mapCollapseHeader" onclick="toggleMap()">
                <div class="map-collapse-title">
                    <span>🗺️ Map</span>
                    <span class="map-collapse-count" id="mapClientCount">(0 with location)</span>
                </div>
                <span id="mapChevron">▼</span>
            </div>
            <div class="map-wrapper" id="mapWrapper">
                <div class="map-container">
                    <div id="client-map"></div>
                </div>
            </div>
        </div>
        
        <!-- Modals -->
        <div class="modal" id="addModal">
            <div class="modal-content">
                <h2>Add New Client</h2>
                <form method="POST" action="{{ url_for('add') }}">
                    <div class="form-group">
                        <label>Client Name</label>
                        <input type="text" name="name" pattern="[a-zA-Z0-9_-]+" 
                               placeholder="e.g., iphone, laptop" required>
                    </div>
                    <div class="form-group">
                        <label>Note (optional)</label>
                        <input type="text" name="note" placeholder="e.g., Dad's laptop">
                    </div>
                    <div class="form-actions">
                        <button type="button" class="btn btn-secondary" onclick="hideModals()">Cancel</button>
                        <button type="submit" class="btn">Add Client</button>
                    </div>
                </form>
            </div>
        </div>
        
        <div class="modal" id="qrModal">
            <div class="modal-content">
                <h2>QR Code: <span id="qrClientName"></span></h2>
                <div class="qr-container">
                    <img id="qrImage" src="" alt="QR Code">
                </div>
                <div class="form-actions">
                    <button class="btn btn-secondary" onclick="hideModals()">Close</button>
                </div>
            </div>
        </div>
        
        <div class="modal" id="configModal">
            <div class="modal-content">
                <h2>Config: <span id="configClientName"></span></h2>
                <div class="config-box" id="configContent"></div>
                <div class="form-actions">
                    <button class="btn btn-secondary" onclick="hideModals()">Close</button>
                    <button class="btn" onclick="copyConfig()">Copy</button>
                </div>
            </div>
        </div>
        
        <div class="modal" id="noteModal">
            <div class="modal-content">
                <h2>Edit Note: <span id="noteClientName"></span></h2>
                <form id="noteForm">
                    <input type="hidden" name="client" id="noteClientInput">
                    <div class="form-group">
                        <label>Note</label>
                        <textarea name="note" id="noteTextarea" placeholder="Add a description..."></textarea>
                    </div>
                    <div class="form-actions">
                        <button type="button" class="btn btn-secondary" onclick="hideModals()">Cancel</button>
                        <button type="submit" class="btn">Save</button>
                    </div>
                </form>
            </div>
        </div>
        
        <div class="modal" id="historyModal">
            <div class="modal-content">
                <h2>Connection History</h2>
                <div class="history-list" id="historyList"></div>
                <div class="form-actions">
                    <button class="btn btn-secondary" onclick="hideModals()">Close</button>
                </div>
            </div>
        </div>
        
        <div class="modal" id="revokeModal">
            <div class="modal-content">
                <h2>Revoke Client</h2>
                <p style="margin-bottom:15px;">Are you sure you want to revoke <strong id="revokeClientName"></strong>?</p>
                <form method="POST" action="{{ url_for('revoke') }}">
                    <input type="hidden" name="name" id="revokeInput">
                    <div class="form-actions">
                        <button type="button" class="btn btn-secondary" onclick="hideModals()">Cancel</button>
                        <button type="submit" class="btn btn-danger">Revoke</button>
                    </div>
                </form>
            </div>
        </div>
        
        <script>
            // ===== State Management =====
            let allClients = [];
            let currentFilter = 'all';
            let trafficTimeWindow = '1h';
            let demoMode = localStorage.getItem('demoMode') === 'true';
            let mapExpanded = localStorage.getItem('mapExpanded') === 'true'; // Default to collapsed (false)

            // ===== Theme =====
            function toggleTheme() {
                const html = document.documentElement;
                const next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
                html.setAttribute('data-theme', next);
                localStorage.setItem('theme', next);
            }
            const savedTheme = localStorage.getItem('theme');
            if (savedTheme) document.documentElement.setAttribute('data-theme', savedTheme);

            // ===== Demo Mode =====
            function toggleDemoMode() {
                demoMode = !demoMode;
                localStorage.setItem('demoMode', demoMode);
                updateDemoModeUI();
                filterAndSortClients();
            }

            function updateDemoModeUI() {
                const toggle = document.getElementById('demoToggle');
                const pill = document.getElementById('demoPill');
                if (demoMode) {
                    toggle.classList.add('active');
                    pill.classList.add('active');
                } else {
                    toggle.classList.remove('active');
                    pill.classList.remove('active');
                }
            }

            function redactIP(ip) {
                if (!demoMode || !ip) return ip;
                // Redact IP addresses
                return ip.replace(/\d+\.\d+\.\d+\.\d+/g, 'xxx.xxx.xxx.xxx')
                         .replace(/:\d+/g, ':xxxxx');
            }

            function redactVPNIP(ip) {
                if (!demoMode || !ip) return ip;
                // Partially mask VPN IPs like 10.6.0.2 -> 10.6.0.x
                return ip.replace(/(\d+\.\d+\.\d+\.)\d+/, '$1x');
            }

            function redactLocation(geo) {
                if (!demoMode || !geo) return geo;
                return { ...geo, city: 'Redacted', country: geo.country_code ? geo.country_code.toUpperCase() : 'XX' };
            }

            // Initialize demo mode UI
            updateDemoModeUI();

            // ===== Map Collapse =====
            function toggleMap() {
                mapExpanded = !mapExpanded;
                localStorage.setItem('mapExpanded', mapExpanded);
                updateMapVisibility();
            }

            function updateMapVisibility() {
                const wrapper = document.getElementById('mapWrapper');
                const chevron = document.getElementById('mapChevron');
                if (mapExpanded) {
                    wrapper.classList.add('expanded');
                    chevron.textContent = '▲';
                    // Initialize map if not done
                    if (!clientMap) {
                        setTimeout(initMap, 100);
                    } else {
                        clientMap.invalidateSize();
                    }
                } else {
                    wrapper.classList.remove('expanded');
                    chevron.textContent = '▼';
                }
            }

            // Set initial map state (collapsed by default)
            mapExpanded = localStorage.getItem('mapExpanded') === 'true';
            updateMapVisibility();

            // ===== Health Card =====
            let healthExpanded = false;

            function toggleHealthDetails() {
                healthExpanded = !healthExpanded;
                const details = document.getElementById('healthDetails');
                const chevron = document.getElementById('healthChevron');
                if (healthExpanded) {
                    details.classList.add('expanded');
                    chevron.classList.add('expanded');
                } else {
                    details.classList.remove('expanded');
                    chevron.classList.remove('expanded');
                }
            }

            function updateHealthCard(health) {
                const indicator = document.getElementById('healthIndicator');
                const statusText = document.getElementById('healthStatusText');
                const details = document.getElementById('healthDetails');

                // Update indicator
                indicator.className = 'health-indicator';
                statusText.className = 'status-text';
                if (health.overall === 'degraded') {
                    indicator.classList.add('degraded');
                    statusText.classList.add('degraded');
                } else if (health.overall === 'down') {
                    indicator.classList.add('down');
                    statusText.classList.add('down');
                }

                statusText.textContent = health.overall.charAt(0).toUpperCase() + health.overall.slice(1);

                // Update details
                details.innerHTML = health.checks.map(check => `
                    <div class="health-check">
                        <div class="check-status ${check.status}"></div>
                        <span class="check-name">${check.name}</span>
                        <span class="check-detail">${check.detail}</span>
                    </div>
                `).join('');
            }

            function fetchHealth() {
                fetch('/api/health')
                    .then(r => r.json())
                    .then(updateHealthCard)
                    .catch(err => {
                        console.error('Health check failed:', err);
                        updateHealthCard({ overall: 'down', checks: [{ name: 'API', status: 'fail', detail: 'Unable to fetch health status' }] });
                    });
            }

            // ===== Activity Strip =====
            function updateActivityStrip() {
                fetch('/api/history')
                    .then(r => r.json())
                    .then(data => {
                        const items = document.getElementById('activityItems');
                        if (data.length === 0) {
                            items.innerHTML = '<div class="activity-item">No recent activity</div>';
                            return;
                        }
                        // Show last 10 events
                        items.innerHTML = data.slice(0, 10).map(h => {
                            const time = h.timestamp.split(' ')[1] || h.timestamp;
                            const endpoint = demoMode ? redactIP(h.endpoint) : h.endpoint;
                            return `
                                <div class="activity-item ${h.event_type}">
                                    <span class="time">${time}</span>
                                    <span>${h.client_name}: ${h.event_type}</span>
                                    ${endpoint ? `<span style="opacity:0.6"> ${endpoint}</span>` : ''}
                                </div>
                            `;
                        }).join('');
                    });
            }

            // ===== Modals =====
            function showAddModal() { document.getElementById('addModal').classList.add('active'); }
            function showQR(name) {
                document.getElementById('qrClientName').textContent = name;
                document.getElementById('qrImage').src = '/qr/' + name + '?' + Date.now();
                document.getElementById('qrModal').classList.add('active');
            }
            function showConfig(name) {
                document.getElementById('configClientName').textContent = name;
                fetch('/config/' + name)
                    .then(r => r.text())
                    .then(t => {
                        document.getElementById('configContent').textContent = t;
                        document.getElementById('configModal').classList.add('active');
                    });
            }
            function showNote(name, currentNote) {
                document.getElementById('noteClientName').textContent = name;
                document.getElementById('noteClientInput').value = name;
                document.getElementById('noteTextarea').value = currentNote || '';
                document.getElementById('noteModal').classList.add('active');
            }
            function showHistoryModal() {
                fetch('/api/history')
                    .then(r => r.json())
                    .then(data => {
                        const list = document.getElementById('historyList');
                        if (data.length === 0) {
                            list.innerHTML = '<div class="empty-state">No history yet</div>';
                        } else {
                            list.innerHTML = data.map(h => {
                                const endpoint = demoMode ? redactIP(h.endpoint) : h.endpoint;
                                return `
                                    <div class="history-item">
                                        <span class="time">${h.timestamp}</span>
                                        <span class="event ${h.event_type}">${h.client_name}: ${h.event_type}</span>
                                        ${endpoint ? `<span style="color:var(--text-secondary);font-size:0.85em;"> from ${endpoint}</span>` : ''}
                                    </div>
                                `;
                            }).join('');
                        }
                        document.getElementById('historyModal').classList.add('active');
                    });
            }
            function confirmRevoke(name) {
                document.getElementById('revokeClientName').textContent = name;
                document.getElementById('revokeInput').value = name;
                document.getElementById('revokeModal').classList.add('active');
            }
            function hideModals() {
                document.querySelectorAll('.modal').forEach(m => m.classList.remove('active'));
            }
            function copyConfig() {
                navigator.clipboard.writeText(document.getElementById('configContent').textContent);
                alert('Copied!');
            }
            function copyToClipboard(text) {
                navigator.clipboard.writeText(text);
            }

            document.addEventListener('keydown', e => { if (e.key === 'Escape') hideModals(); });
            document.querySelectorAll('.modal').forEach(m => {
                m.addEventListener('click', e => { if (e.target === m) hideModals(); });
            });

            // Note form
            document.getElementById('noteForm').addEventListener('submit', function(e) {
                e.preventDefault();
                const name = document.getElementById('noteClientInput').value;
                const note = document.getElementById('noteTextarea').value;
                fetch('/api/note', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({name, note})
                }).then(() => {
                    hideModals();
                    refreshDashboard();
                });
            });

            // ===== Filtering & Sorting =====
            function setFilter(filter) {
                currentFilter = filter;
                document.querySelectorAll('.filter-btn').forEach(btn => {
                    btn.classList.toggle('active', btn.dataset.filter === filter);
                });
                filterAndSortClients();
            }

            function setTrafficWindow(window) {
                trafficTimeWindow = window;
                document.querySelectorAll('.stat-toggle button').forEach(btn => {
                    btn.classList.toggle('active', btn.dataset.window === window);
                });
                updateStatsDisplay();
            }

            function filterAndSortClients() {
                const searchTerm = document.getElementById('clientSearch').value.toLowerCase();
                const sortBy = document.getElementById('sortSelect').value;

                let filtered = allClients.filter(c => {
                    // Search filter
                    const matchesSearch = !searchTerm ||
                        c.name.toLowerCase().includes(searchTerm) ||
                        c.ip.toLowerCase().includes(searchTerm) ||
                        (c.endpoint && c.endpoint.toLowerCase().includes(searchTerm)) ||
                        (c.note && c.note.toLowerCase().includes(searchTerm));

                    if (!matchesSearch) return false;

                    // Status filter
                    switch (currentFilter) {
                        case 'connected': return c.connected;
                        case 'offline': return !c.connected;
                        case 'recent':
                            // Seen in last 24h
                            if (c.connected) return true;
                            if (!c.last_seen) return false;
                            const lastSeen = new Date(c.last_seen);
                            const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
                            return lastSeen > dayAgo;
                        default: return true;
                    }
                });

                // Sort
                filtered.sort((a, b) => {
                    switch (sortBy) {
                        case 'handshake':
                            const aHs = a.handshake_seconds ?? Infinity;
                            const bHs = b.handshake_seconds ?? Infinity;
                            return aHs - bHs;
                        case 'rx':
                            return (b.transfer_rx || 0) - (a.transfer_rx || 0);
                        case 'tx':
                            return (b.transfer_tx || 0) - (a.transfer_tx || 0);
                        default: // name
                            return a.name.localeCompare(b.name);
                    }
                });

                renderClients(filtered);
            }

            // ===== Sparkline Generator =====
            function generateSparkline(data) {
                if (!data || data.length < 2) return '';

                const width = 50, height = 18, padding = 1;
                const rxMax = Math.max(...data.map(p => p.rx || 0), 1);
                const txMax = Math.max(...data.map(p => p.tx || 0), 1);
                const yMax = Math.max(rxMax, txMax);

                const xStep = (width - padding * 2) / Math.max(data.length - 1, 1);

                function toPath(key) {
                    return data.map((p, i) => {
                        const x = padding + i * xStep;
                        const y = height - padding - ((p[key] || 0) / yMax) * (height - padding * 2);
                        return (i === 0 ? 'M' : 'L') + x.toFixed(1) + ',' + y.toFixed(1);
                    }).join(' ');
                }

                return `<span class="sparkline"><svg viewBox="0 0 ${width} ${height}">
                    <path class="rx" d="${toPath('rx')}"/>
                    <path class="tx" d="${toPath('tx')}"/>
                </svg></span>`;
            }

            // ===== Format Helpers =====
            function formatSpeed(bytesPerSec) {
                if (bytesPerSec < 1) return '0 B/s';
                const units = ['B/s', 'KiB/s', 'MiB/s', 'GiB/s'];
                let i = 0;
                while (bytesPerSec >= 1024 && i < units.length - 1) {
                    bytesPerSec /= 1024;
                    i++;
                }
                return bytesPerSec.toFixed(1) + ' ' + units[i];
            }

            function formatHandshake(seconds) {
                if (seconds === null || seconds === undefined) return null;
                if (seconds < 60) return `${seconds}s ago`;
                if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
                if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
                return `${Math.floor(seconds / 86400)}d ago`;
            }

            // ===== Render Clients =====
            function renderClients(clients) {
                const grid = document.getElementById('client-grid');

                if (clients.length === 0) {
                    grid.innerHTML = '<div class="empty-state">No clients match the current filter</div>';
                    return;
                }

                grid.innerHTML = clients.map(c => {
                    // Calculate live speeds from bandwidth history
                    let rxSpeed = '0 B/s', txSpeed = '0 B/s';
                    if (c.bandwidth_history && c.bandwidth_history.length >= 2) {
                        const recent = c.bandwidth_history.slice(-3);
                        const avgRx = recent.reduce((a, b) => a + (b.rx || 0), 0) / recent.length;
                        const avgTx = recent.reduce((a, b) => a + (b.tx || 0), 0) / recent.length;
                        rxSpeed = formatSpeed(avgRx / 5);
                        txSpeed = formatSpeed(avgTx / 5);
                    }

                    // Apply demo mode redaction
                    const displayIP = demoMode ? redactVPNIP(c.ip) : c.ip;
                    const displayEndpoint = demoMode ? redactIP(c.endpoint) : c.endpoint;
                    const displayGeo = demoMode ? redactLocation(c.geo) : c.geo;
                    const displayLastEndpoint = demoMode ? redactIP(c.last_endpoint) : c.last_endpoint;

                    // Handshake badge
                    const handshakeDisplay = formatHandshake(c.handshake_seconds);
                    const handshakeStale = c.handshake_seconds && c.handshake_seconds > 120;

                    return `
                    <div class="client-card" data-name="${c.name}" data-connected="${c.connected}">
                        <div class="status-indicator">
                            <div class="status-dot ${c.connected ? 'connected' : ''}"
                                 title="${c.connected ? 'Connected' : 'Offline'}"></div>
                        </div>
                        <div class="client-info">
                            <h3>
                                ${c.name}
                                ${c.note ? `<span class="note-badge">${c.note}</span>` : ''}
                                ${handshakeDisplay ? `<span class="handshake-badge ${handshakeStale ? 'stale' : ''}">${handshakeDisplay}</span>` : ''}
                            </h3>
                            <div class="client-meta">
                                <span>📍 ${displayIP}</span>
                                ${displayGeo ? `<span><img class="geo-flag" src="https://flagcdn.com/w20/${displayGeo.country_code}.png" alt="${displayGeo.country}" onerror="this.style.display='none'"> ${displayGeo.city || displayGeo.country}</span>` : ''}
                                ${c.connected && displayEndpoint ? `<span>🌐 ${displayEndpoint}<button class="copy-btn" onclick="event.stopPropagation();copyToClipboard('${c.endpoint}')" title="Copy">📋</button></span>` : ''}
                                ${c.connected && c.connection_duration_fmt ? `<span>⏱️ ${c.connection_duration_fmt}</span>` : ''}
                                ${c.connected ? `<span>↓${c.transfer_rx_fmt} ↑${c.transfer_tx_fmt}</span>` : ''}
                            </div>
                            ${c.connected && c.bandwidth_history && c.bandwidth_history.length > 1 ? `
                            <div class="live-speed">
                                ${generateSparkline(c.bandwidth_history)}
                                <span class="rx-speed">↓${rxSpeed}</span>
                                <span class="tx-speed">↑${txSpeed}</span>
                            </div>
                            ` : ''}
                            ${!c.connected && c.last_seen ? `<div class="last-seen">Last seen: ${c.last_seen}${displayLastEndpoint ? ' from ' + displayLastEndpoint : ''}</div>` : ''}
                        </div>
                        <div class="client-actions">
                            <button class="icon-btn" onclick="showQR('${c.name}')" title="QR Code">📱</button>
                            <button class="icon-btn" onclick="showConfig('${c.name}')" title="Config">📄</button>
                            <a href="/download/${c.name}" class="icon-btn" title="Download">⬇️</a>
                            <button class="icon-btn" onclick="showNote('${c.name}', '${(c.note || '').replace(/'/g, "\\'")}')" title="Edit Note">✏️</button>
                            <button class="icon-btn danger" onclick="confirmRevoke('${c.name}')" title="Revoke">🗑️</button>
                        </div>
                    </div>
                `}).join('');
            }

            // ===== Stats Display =====
            let currentStats = null;

            function updateStatsDisplay() {
                if (!currentStats) return;
                const s = currentStats;
                const t = s.traffic || {};

                const rxDisplay = trafficTimeWindow === '1h' ? (t.last1h_rx_fmt || '0 B') : (t.last24h_rx_fmt || '0 B');
                const txDisplay = trafficTimeWindow === '1h' ? (t.last1h_tx_fmt || '0 B') : (t.last24h_tx_fmt || '0 B');

                document.getElementById('stats-grid').innerHTML = `
                    <div class="stat-box">
                        <div class="number">${s.total_clients}</div>
                        <div class="label">Total Clients</div>
                    </div>
                    <div class="stat-box">
                        <div class="number">${s.connected_clients}</div>
                        <div class="label">Connected</div>
                    </div>
                    <div class="stat-box">
                        <div class="number">${rxDisplay}</div>
                        <div class="label">↓ Received</div>
                        <div class="stat-toggle">
                            <button class="${trafficTimeWindow === '1h' ? 'active' : ''}" data-window="1h" onclick="setTrafficWindow('1h')">1h</button>
                            <button class="${trafficTimeWindow === '24h' ? 'active' : ''}" data-window="24h" onclick="setTrafficWindow('24h')">24h</button>
                        </div>
                        <div class="stat-total">Total: ${s.total_rx_fmt}</div>
                    </div>
                    <div class="stat-box">
                        <div class="number">${txDisplay}</div>
                        <div class="label">↑ Sent</div>
                        <div class="stat-toggle">
                            <button class="${trafficTimeWindow === '1h' ? 'active' : ''}" data-window="1h" onclick="setTrafficWindow('1h')">1h</button>
                            <button class="${trafficTimeWindow === '24h' ? 'active' : ''}" data-window="24h" onclick="setTrafficWindow('24h')">24h</button>
                        </div>
                        <div class="stat-total">Total: ${s.total_tx_fmt}</div>
                    </div>
                    <div class="stat-box">
                        <div class="number">${s.uptime}</div>
                        <div class="label">Uptime</div>
                    </div>
                `;
            }

            // ===== Dashboard Refresh =====
            function refreshDashboard() {
                fetch('/api/status')
                    .then(r => {
                        if (!r.ok) throw new Error(`HTTP ${r.status}`);
                        return r.json();
                    })
                    .then(data => {
                        currentStats = data.stats;
                        allClients = data.clients || [];

                        // Update stats
                        updateStatsDisplay();

                        // Update clients
                        filterAndSortClients();

                        // Update map
                        updateMap(data.clients || []);

                        // Update map client count
                        const clients = data.clients || [];
                        const geoCount = clients.filter(c => c.geo && c.geo.lat).length;
                        const connectedGeo = clients.filter(c => c.connected && c.geo && c.geo.lat).length;
                        document.getElementById('mapClientCount').textContent = `(${connectedGeo} connected, ${geoCount} with location)`;
                    })
                    .catch(err => {
                        console.error('Refresh failed:', err);
                        // Show error state in stats grid
                        document.getElementById('stats-grid').innerHTML = `
                            <div class="stat-box warning">
                                <div class="number">!</div>
                                <div class="label">API Error</div>
                            </div>
                        `;
                        document.getElementById('client-grid').innerHTML =
                            '<div class="empty-state">Failed to load data. Check server connection.</div>';
                    });
            }

            // ===== Map =====
            let clientMap = null;
            let mapMarkers = [];
            let lastUserInteraction = 0;
            let mapInitializedOnce = false;
            const MAP_INTERACTION_TIMEOUT = 60000;

            function initMap() {
                if (clientMap) return;

                const mapContainer = document.getElementById('client-map');
                if (!mapContainer || !mapContainer.offsetParent) {
                    // Map container not visible, skip initialization
                    return;
                }

                const darkTiles = L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                    attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> &copy; <a href="https://carto.com/">CARTO</a>',
                    subdomains: 'abcd',
                    maxZoom: 19
                });

                clientMap = L.map('client-map', {
                    center: [39.0, -77.5],
                    zoom: 4,
                    layers: [darkTiles],
                    zoomControl: true,
                    attributionControl: true
                });

                clientMap.on('zoomstart', () => { lastUserInteraction = Date.now(); });
                clientMap.on('dragstart', () => { lastUserInteraction = Date.now(); });

                setTimeout(() => {
                    const attr = document.querySelector('.leaflet-control-attribution');
                    if (attr) {
                        attr.style.cssText = 'background: rgba(37,37,66,0.8) !important; color: #888 !important; font-size: 10px;';
                    }
                }, 100);
            }

            function updateMap(clients) {
                // Only initialize map if expanded
                if (!mapExpanded) return;

                if (!clientMap) {
                    initMap();
                    if (!clientMap) return;
                }

                // Clear existing markers
                mapMarkers.forEach(m => clientMap.removeLayer(m));
                mapMarkers = [];

                // Filter clients with geo data
                let geoClients = clients.filter(c => c.geo && c.geo.lat && c.geo.lon);

                if (geoClients.length === 0) return;

                const bounds = [];
                geoClients.forEach(client => {
                    const pos = [client.geo.lat, client.geo.lon];
                    bounds.push(pos);

                    const color = client.connected ? '#00d4aa' : '#666';
                    const glowColor = client.connected ? 'rgba(0,212,170,0.4)' : 'transparent';

                    const icon = L.divIcon({
                        className: 'custom-marker',
                        html: `<div style="width:16px;height:16px;background:${color};border:2px solid white;border-radius:50%;box-shadow:0 0 10px ${glowColor}, 0 2px 6px rgba(0,0,0,0.3);"></div>`,
                        iconSize: [16, 16],
                        iconAnchor: [8, 8]
                    });

                    const marker = L.marker(pos, { icon }).addTo(clientMap);

                    // Apply demo mode redaction to popup
                    const displayGeo = demoMode ? redactLocation(client.geo) : client.geo;
                    const popupContent = `
                        <div class="map-popup-title">${client.name}</div>
                        <div class="map-popup-info">
                            ${displayGeo.city ? displayGeo.city + ', ' : ''}${displayGeo.country}<br>
                            ${client.connected ? '🟢 Connected' : '⚫ Offline'}
                            ${client.connected && client.connection_duration_fmt ? ' • ' + client.connection_duration_fmt : ''}
                        </div>
                    `;
                    marker.bindPopup(popupContent);
                    mapMarkers.push(marker);
                });

                const timeSinceInteraction = Date.now() - lastUserInteraction;
                const shouldAutoFit = !mapInitializedOnce || timeSinceInteraction > MAP_INTERACTION_TIMEOUT;

                if (bounds.length > 0 && shouldAutoFit) {
                    if (bounds.length === 1) {
                        clientMap.setView(bounds[0], 10);
                    } else {
                        clientMap.fitBounds(bounds, { padding: [30, 30], maxZoom: 12 });
                    }
                    mapInitializedOnce = true;
                }
            }

            // ===== Initial Load =====
            try {
                refreshDashboard();
                fetchHealth();
                updateActivityStrip();
            } catch (e) {
                console.error('Initial load error:', e);
            }

            // Auto-refresh intervals
            setInterval(() => {
                try { refreshDashboard(); } catch (e) { console.error('Refresh error:', e); }
            }, 5000);
            setInterval(() => {
                try { fetchHealth(); } catch (e) { console.error('Health error:', e); }
            }, 30000);
            setInterval(() => {
                try { updateActivityStrip(); } catch (e) { console.error('Activity error:', e); }
            }, 15000);
        </script>
        {% endif %}
    </div>
</body>
</html>
'''


# --------------- Routes ---------------

@app.route('/')
def index():
    return render_template_string(TEMPLATE)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('username') == AUTH_USER and check_password(request.form.get('password', '')):
            session.permanent = True
            session['logged_in'] = True
            return redirect(url_for('index'))
        flash('Invalid credentials')
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/api/status')
@login_required
def api_status():
    return jsonify({
        'stats': get_server_stats(),
        'clients': get_clients()
    })

# Alias routes for compatibility
@app.route('/api/stats')
@login_required
def api_stats():
    return api_status()

@app.route('/api/clients')
@login_required
def api_clients():
    return api_status()

@app.route('/api/history')
@login_required
def api_history():
    return jsonify(get_connection_history())

# Alias for /api/activity
@app.route('/api/activity')
@login_required
def api_activity():
    return api_history()

@app.route('/api/health')
@login_required
def api_health():
    return jsonify(get_health_status())

@app.route('/api/note', methods=['POST'])
@login_required
def api_note():
    data = request.get_json()
    if data and 'name' in data:
        update_client_note(data['name'], data.get('note', ''))
        return jsonify({'ok': True})
    return jsonify({'error': 'invalid'}), 400

@app.route('/add', methods=['POST'])
@login_required
def add():
    name = request.form.get('name', '').strip()
    note = request.form.get('note', '').strip()
    if name:
        success, msg = add_client(name)
        if success:
            if note:
                update_client_note(name, note)
            flash(f'Client "{name}" created')
        else:
            flash(f'Error: {msg}')
    return redirect(url_for('index'))

@app.route('/revoke', methods=['POST'])
@login_required
def revoke():
    name = request.form.get('name', '').strip()
    if name:
        success, msg = revoke_client(name)
        flash(f'Client "{name}" revoked' if success else f'Error: {msg}')
    return redirect(url_for('index'))

@app.route('/qr/<name>')
@login_required
def qr_code(name):
    qr = get_client_qr(name)
    return Response(qr, mimetype='image/png') if qr else ('Not found', 404)

@app.route('/config/<name>')
@login_required
def config(name):
    conf = get_client_config(name)
    return Response(conf, mimetype='text/plain') if conf else ('Not found', 404)

@app.route('/download/<name>')
@login_required
def download_config(name):
    conf = get_client_config(name)
    if conf:
        return Response(conf, mimetype='application/octet-stream',
                        headers={'Content-Disposition': f'attachment; filename={name}.conf'})
    return 'Not found', 404


# --------------- Main ---------------

if __name__ == '__main__':
    import sys
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    init_db()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    print(f"WireGuard Panel v4 starting on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
