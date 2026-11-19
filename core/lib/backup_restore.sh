#!/bin/bash
# TOM_TUNNEL — sauvegarde / restauration des données (comptes, quotas, config bot, config Xray).
# Usage : backup_restore.sh backup [dossier]   |   backup_restore.sh restore <archive.tar.gz>
# Les chemins sont surchargeables par variables d'environnement (utile pour les tests).
set -euo pipefail
DB="${TOM_TUNNEL_DB:-/etc/tom_tunnel-tunnel-web/tom_tunnel.db}"
BOT_DIR="${TOM_BOT_DIR:-/etc/tom_tunnel_bot}"
XRAY_CFG="${XRAY_CONFIG:-/etc/xray/config.json}"
OUT_DIR="${2:-/root/tom_tunnel_backups}"

case "${1:-}" in
  backup)
    mkdir -p "$OUT_DIR"; chmod 700 "$OUT_DIR"
    TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
    mkdir -p "$TMP/data"
    if [ -f "$DB" ]; then
      if command -v sqlite3 >/dev/null; then sqlite3 "$DB" ".backup '$TMP/data/tom_tunnel.db'"
      else python3 -c "import sqlite3,sys; s=sqlite3.connect(sys.argv[1]); d=sqlite3.connect(sys.argv[2]); s.backup(d); d.close()" "$DB" "$TMP/data/tom_tunnel.db"; fi
    fi
    [ -d "$BOT_DIR" ] && cp -a "$BOT_DIR" "$TMP/data/bot"
    [ -f "$XRAY_CFG" ] && cp -a "$XRAY_CFG" "$TMP/data/xray_config.json"
    F="$OUT_DIR/tom_tunnel_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
    tar -C "$TMP" -czf "$F" data; chmod 600 "$F"
    echo "Sauvegarde : $F" ;;
  restore)
    A="${2:?archive requise}"; [ -f "$A" ] || { echo "Archive introuvable"; exit 1; }
    TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
    tar -C "$TMP" -xzf "$A"
    [ -d "$TMP/data" ] || { echo "Archive invalide"; exit 1; }
    # filet de sécurité : sauvegarde de l'état actuel avant d'écraser
    "$0" backup "${TOM_PRE_RESTORE_DIR:-/root/tom_tunnel_backups/pre_restore}" >/dev/null 2>&1 || true
    [ -f "$TMP/data/tom_tunnel.db" ] && { mkdir -p "$(dirname "$DB")"; cp -f "$TMP/data/tom_tunnel.db" "$DB"; }
    [ -d "$TMP/data/bot" ] && { mkdir -p "$BOT_DIR"; cp -a "$TMP/data/bot/." "$BOT_DIR/"; }
    [ -f "$TMP/data/xray_config.json" ] && cp -f "$TMP/data/xray_config.json" "$XRAY_CFG"
    command -v systemctl >/dev/null && { systemctl restart xray tom_tunnel_bot tom_tunnel-web 2>/dev/null || true; }
    echo "Restauration terminée depuis $A" ;;
  *) echo "Usage: $0 backup [dossier] | restore <archive>"; exit 1 ;;
esac
