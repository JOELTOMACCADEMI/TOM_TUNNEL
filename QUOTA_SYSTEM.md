# TOM_TUNNEL — Quota / IP / Connection system

## Components

| Path | Role |
|------|------|
| `core/lib/account_engine.py` | Central SQLite engine (source of truth) |
| `core/lib/migrate_accounts.py` | Import existing SSH/Xray/bot accounts |
| `core/lib/traffic_collector.py` | Xray stats + SSH session cleanup |
| `core/lib/zivpn_engine.py` | ZiVPN per-account ports, iptables traffic metering and conntrack limits |
| `core/lib/tom_motd.sh` | Dynamic SSH banner after login |
| `core/lib/install_engine.sh` | Install engine + MOTD + general and ZiVPN systemd timers |
| `core/lib/account_engine.sh` | Bash CLI wrapper (`tom-account`) |
| `menu/v2raydns.sh` | V2RAY-DNS module (option 17) |
| `tom_tunnel-web/Server/db.ts` | Panel DB + quota columns |
| `tom_tunnel-web/Server/accountBridge.ts` | Panel → engine bridge |
| `tom_tunnel-web/Server/routes/auth.ts` | Auth routes (restored) |
| `tom_tunnel-web/Server/routes/clients.ts` | Create with quota/ip/conn |
| Frontend create + accounts pages | Quota fields & display |

## Install on a VPS

```bash
# From project root
bash core/lib/install_engine.sh

# Optional: migrate existing accounts
python3 /usr/local/lib/tom_tunnel/migrate_accounts.py --dry-run
python3 /usr/local/lib/tom_tunnel/migrate_accounts.py
```

## Conventions

- `quota_gb = 0` → unlimited
- `ip_limit = 0` / `conn_limit = 0` → unlimited
- 1 GB = 1024³ bytes
- Status values: active | expired | quota_exhausted | suspended | deleted

## V2RAY-DNS

Menu option **[17]**. Creates real VLESS/Trojan accounts (Xray) and displays
existing SlowDNS NS/PUB metadata when available. Does **not** invent fake
DNS-transport links. Dual-stack clients (HTTP Custom, ZIVPN, etc.) can use
both the VLESS/Trojan link and the DNS parameters.

## Known limits

- New ZiVPN accounts use dedicated UDP ports and can be metered individually. Legacy shared accounts on 5667 remain unmetered.
- ZiVPN source-IP and conntrack-flow caps are sampled every 10 seconds, not synchronously in the closed-source server binary. Multiple devices behind one NAT share one public IP.
- SlowDNS / UDP Custom / OpenVPN / OHP remain without reliable per-user traffic attribution in the current collector.
- Xray stats require the Stats API to be enabled in Xray config.
- SSH MOTD only shows for interactive sessions (not pure tunnel logins with
  `/bin/false` and no TTY).
