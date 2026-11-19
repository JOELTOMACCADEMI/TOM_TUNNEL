# TOM_TUNNEL — V2RAY-DNS

- Added V2RAY-DNS as a distinct protocol in the Telegram bot and Web panel.
- Added dedicated VLESS client markers (`#VDNS`) for expiry/status enforcement.
- Added V2RAY-DNS support to the central quota engine and Xray traffic collector.
- Added panel-side create/delete operations with Xray config backup, validation and rollback.
- Added NS domain and SlowDNS public-key metadata to generated account details.
- Added bot-side create, renew, delete, list and details support with quota/IP/connection fields.
- Aligned the account engine database path with the Web installer's SQLite database path.
- Fixed Web TypeScript build paths to match the actual `Server/` directory casing.

Note: the implemented V2RAY-DNS account uses VLESS over Xray and displays SlowDNS NS/PUB metadata. It is not a native DNS-only V2Ray transport.
