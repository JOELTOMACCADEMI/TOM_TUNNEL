# Update, backup, restore

Backup (do this first, always):
    bash /usr/local/lib/tom_tunnel/backup_restore.sh backup            # → /root/tom_tunnel_backups/*.tar.gz
Restore:
    bash /usr/local/lib/tom_tunnel/backup_restore.sh restore <archive>  # makes a pre-restore backup first

Update an existing VPS from this project:
1. Backup (above).
2. `bash core/lib/install_engine.sh`   (installs engine, collector timer, `tom-account`, `tom-protocol`; idempotent)
3. `python3 /usr/local/lib/tom_tunnel/migrate_accounts.py --dry-run`, then without `--dry-run` (read-only on sources).
4. Menus: copy `menu/*.sh` to `/usr/local/sbin/<name>` (without `.sh`), including `protocols`.
5. Bot: copy `tom_tunnel_core_bot/` over `/etc/tom_tunnel_bot/` (keep `config.json`), `systemctl restart tom_tunnel_bot`.
6. Panel: in `tom_tunnel-web/frontend` run `npm install && npm run build`, then in `tom_tunnel-web` `npm install && npm run build`, restart `tom_tunnel-web`. (The bundled `public/` is the OLD build and does not contain the new Protocols page until you rebuild.)
Important: `tom_tunnel.sh`/`install_perso.sh`/`install_bot.sh` download from the GitHub repo (`SERVER_HOST`, `REPO_URL`). To deploy this version through them, publish these files to that repo (or change those variables).
