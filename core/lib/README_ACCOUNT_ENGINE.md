# TOM_TUNNEL – Central Account Engine

## Purpose

Single source of truth for:

- Account metadata (username, protocol, expiry, status)
- **Real quotas in GB** (quota_gb / used_gb / remaining_gb)
- **IP limits** (distinct IPs)
- **Concurrent connection limits**
- Active sessions tracking
- Quota events (80/90/100 %)

Used by:

- VPS menus (Bash)
- Telegram bot
- Web panel

## Files

| File | Role |
|------|------|
| `account_engine.py` | Core Python library + CLI |
| `account_engine.sh` | Bash wrapper |
| `migrate_accounts.py` | One-shot import of existing accounts |

## Installation (on a real VPS)

```bash
mkdir -p /usr/local/lib/tom_tunnel
cp core/lib/account_engine.py /usr/local/lib/tom_tunnel/
cp core/lib/account_engine.sh /usr/local/bin/tom-account
chmod +x /usr/local/bin/tom-account
```

Default DB locations (first existing wins):

1. `/etc/tom_tunnel-web/data/tom_tunnel.db`  (shared with panel)
2. `/etc/tom_tunnel/accounts.db`
3. `/var/lib/tom_tunnel/accounts.db`

## Quick CLI examples

```bash
# Initialise schema
tom-account init-schema

# Create account with 25 GB, max 2 IPs, max 3 connections
tom-account create alice vless --quota 25 --ip-limit 2 --conn-limit 3 --days 30

# Show account
tom-account get alice --protocol vless

# Add traffic (bytes)
tom-account add-traffic alice vless --up 1073741824 --down 2147483648

# SSH-style banner
tom-account banner alice --protocol ssh

# List accounts near 80 % quota
tom-account list --near-quota 0.8
```

## Python API (for bot & panel)

```python
from account_engine import get_engine

eng = get_engine()
acc = eng.create_account("bob", "ssh", password="secret", quota_gb=10, ip_limit=1, conn_limit=2)
eng.add_traffic("bob", "ssh", bytes_up=500_000_000, bytes_down=300_000_000)
allowed, reason = eng.register_session("bob", "ssh", "203.0.113.10")
print(eng.format_account_banner("bob", "ssh"))
```

## Migration of existing accounts

```bash
# Dry-run first
python3 core/lib/migrate_accounts.py --dry-run

# Real migration (idempotent)
python3 core/lib/migrate_accounts.py
```

Imports from:

- `/etc/xray/config.json` (VLESS/VMess/Trojan/SOCKS)
- System users with `/bin/false` (SSH)
- `/etc/tom_tunnel_bot/ssh_accounts/*.txt`

All imported accounts start with **quota_gb = 0** (unlimited) to preserve current behaviour.

## Convention

- **1 GB = 1024³ bytes** (GiB). This is the only conversion used everywhere.
- `quota_gb = 0` → unlimited
- `ip_limit = 0` / `conn_limit = 0` → unlimited
- Status values: `active`, `expired`, `quota_exhausted`, `suspended`, `deleted`

## Next steps (already planned)

- Traffic collector daemon (Xray Stats + iptables)
- Integration into `menu/ssh.sh`, `vless.sh`, …
- MOTD / banner after SSH authentication
- Web panel form fields + API
- Bot commands
- V2RAY-DNS module
"""
