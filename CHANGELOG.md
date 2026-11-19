# CHANGELOG

## Unreleased (after 1.0.0) — protocol management & audit fixes
Added
- `core/lib/protocol_manager.py` + `tom-protocol`: enable/disable/status/restart/logs/ports/errors for 14 protocols, shared by VPS menu ([19]), Telegram bot (⚙️ PROTOCOLES, super-admin for changes) and Web panel (`/api/protocols`, real page replacing the mock-data page).
- `core/lib/backup_restore.sh` (backup/restore of DB, bot config, Xray config; pre-restore safety backup).
- `tests/run_all.py` (no pytest needed); new tests: protocol manager (8), bot protocol menu (5), V2RAY-DNS bot quota/limits/suspend.
Fixed
- Standard installers (`tom_tunnel.sh`, `install_perso.sh`) never installed the account engine / quota collector timer: now installed and existing accounts migrated (idempotent, non-destructive). `install_perso.sh` also now installs the `v2raydns` and `protocols` menus.
- Bot `/quota /setquota /limits /suspend …` rejected `v2raydns`; `udp` is aliased to the engine's `udpcustom`.
- `AccountEngine("path-as-str")` crashed (`'str' has no attribute 'parent'`).
- Panel "Protocoles" page was a local mock (toggle did nothing on the server).
- Collector now also blocks Shadowsocks/socks clients on expiry/suspension (`#@` marker).
- `tests/test_v2raydns_integration.py` was silently not run by `unittest`.
Unchanged on purpose: all existing protocols, commands, DB data and the VLESS-based V2RAY-DNS (not a native DNS transport).

## Earlier: see CHANGELOG_QUOTAS.md, CHANGELOG_V2RAY_DNS.md

## ZiVPN engine update
- Added isolated per-user ZiVPN server instances on dedicated UDP ports, per-port traffic metering, quota enforcement, conntrack-based IP/flow sampling, and shared engine integration.
- Connected VPS menu, Telegram bot, Web panel, protocol enable/disable and systemd timer workflows.
- Kept legacy shared ZiVPN accounts on 5667 available; legacy accounts are not automatically converted.

## Protocol engines and management audit hardening
- Added a conservative per-protocol capability matrix exposed by `tom-protocol capabilities [id]` and in protocol status JSON.
- VPS menu `[19] PROTOCOLS ON/OFF` now includes `[7] Configure` (known existing native config only, backup before edit, JSON/Xray validation and rollback) and `[8] Capability check`.
- Telegram protocol detail and Web protocol cards now display whether quota, IP limit and simultaneous connection limit are actually supported.
- Documented unsupported per-user accounting for shared SlowDNS, UDP Custom, OpenVPN and OHP; Xray simultaneous connection limits are explicitly not advertised as supported.
- No quota or connection-limit support is claimed where traffic cannot be attributed to an individual account.
- Added a capability-matrix regression test. Test suite: 53 passed.


## OpenVPN per-account adapter
- Added OpenVPN status-file parsing for TCP/UDP client byte counters, per-account traffic deltas, live IP/connection session registration and management-interface disconnects.
- Added loopback-only management directives to the initial OpenVPN setup and focused parser tests.
- SlowDNS, UDP Custom and OHP remain unsupported for reliable per-user quota enforcement; do not interpret protocol availability as per-user accounting support.
