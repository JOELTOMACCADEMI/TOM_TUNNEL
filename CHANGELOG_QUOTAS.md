# Changelog — Quota / IP / Connection system

## Added
- Central Account Engine (`core/lib/account_engine.py`) — SQLite source of truth
- Migration tool for existing accounts
- Traffic collector + systemd timer
- Dynamic SSH MOTD banner (`tom_motd.sh`)
- Installer `core/lib/install_engine.sh`
- V2RAY-DNS module (`menu/v2raydns.sh`, menu option 17)
- Panel: reconstructed `db.ts`, `routes/auth.ts`, `accountBridge.ts`
- Panel + frontend: quota_gb / ip_limit / conn_limit on create & list
- VPS menus ssh/vless/vmess/trojan: quota prompts + engine sync
- Telegram bot: multi-step create (quota/IP/conn) + engine sync

## Rules
- 0 = unlimited for quota, IP limit, connection limit
- 1 GB = 1024³ bytes
- Status includes `quota_exhausted`

## Limits
- SlowDNS / UDP Custom / legacy shared ZiVPN: no reliable per-user traffic attribution
- Xray Stats API must be enabled for automatic quota enforcement
- MOTD only for interactive sessions

## ZiVPN isolated-account enforcement
- New ZiVPN accounts are provisioned on an individual UDP port (20000–29999) with one password and one systemd service instance per account.
- Added per-port iptables traffic counters and a 10-second enforcement timer; quota exhaustion, suspension and expiry stop only the matching account instance.
- Added conntrack sampling for distinct source-IP and concurrent-flow limits.
- Wired the VPS menu, Telegram bot and Web panel to collect quota, IP and flow limits at account creation; quota commands now support `zivpn`.
- Existing shared-listener accounts on port 5667 remain legacy and are not auto-migrated.
- Important: IP/flow enforcement is sampled (up to ~10 seconds), not synchronous inside the upstream binary. Real VPS/client validation is still required.
