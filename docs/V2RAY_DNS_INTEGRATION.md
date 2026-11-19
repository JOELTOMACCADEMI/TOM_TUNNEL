# V2RAY-DNS integration

## What is included

`V2RAY-DNS` is now exposed as a separate account type in the TOM_TUNNEL Telegram bot and Web panel. The account is provisioned as a dedicated VLESS identity in the existing Xray VLESS inbounds and includes the configured SlowDNS metadata when available:

- username and UUID
- domain / server address
- expiry date
- quota (GB)
- IP limit and connection-limit values
- NS domain (`/etc/slowdns/nsdomain`)
- SlowDNS public key (`/etc/slowdns/server.pub`)
- VLESS WebSocket TLS / NTLS / gRPC links

The bot supports create, renew, delete, list and account details. The panel supports creation, listing, renewal and deletion through its client routes. The central account engine recognizes `v2raydns`; the traffic collector records Xray usage against that protocol and can enforce exhausted/suspended accounts using `#VDNS` markers.

## Important transport distinction

The current repository's V2RAY-DNS module does **not** implement a native DNS-only V2Ray transport. It provisions VLESS over the configured Xray transports and displays NS/PUB as SlowDNS metadata for compatible dual-stack client setups. The generated links are VLESS links, not fabricated DNS tunnel links. A true DNS encapsulation requires a separately installed and configured DNS tunnel server/client transport.

## Database sharing

The account engine now honors `TOM_TUNNEL_DB` and `TOM_TUNNEL_DB_DIR` and defaults to the Web installer's database path (`/etc/tom_tunnel-tunnel-web/tom_tunnel.db`). This keeps bot-created V2RAY-DNS accounts and panel quota records in the same SQLite database while retaining the legacy database path as a fallback.

## Validation

- Python syntax checks passed for the bot, account engine and traffic collector.
- Bash syntax check passed for `menu/v2raydns.sh`.
- TypeScript/TSX syntax transpilation passed for all 88 source files.
- Test runner note: `tests/test_v2raydns_integration.py` uses pytest-style functions, so `python -m unittest` silently ran 0 of them. Use `python3 tests/run_all.py` (no pytest needed), which runs every suite.
- Full npm/TypeScript type build could not be run in this environment because npm dependency installation timed out; run `npm install && npm run build` in `tom_tunnel-web/frontend` and `npm install && npm run build` in `tom_tunnel-web` on the VPS before deployment.

## Update (protocol management)

- `v2raydns` is now accepted by the bot's `/quota`, `/setquota`, `/addquota`, `/limits`, `/suspend`, `/unsuspend` commands (it was missing from the whitelist, so these actions were impossible for V2RAY-DNS accounts).
- V2RAY-DNS can be enabled/disabled independently of VLESS even though they share Xray inbounds: its `#VDNS` clients are neutralised/restored without touching VLESS clients or stopping Xray (see `docs/PROTOCOL_MANAGEMENT.md`).
- Still true: this is **not** a native DNS-only V2Ray transport.
