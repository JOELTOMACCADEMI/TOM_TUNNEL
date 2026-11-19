#!/bin/bash
# Install central account engine, MOTD banner and traffic collector timer
# Idempotent — safe to re-run.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LIB_DST="/usr/local/lib/tom_tunnel"
BIN_DST="/usr/local/bin"

echo "[TOM_TUNNEL] Installing account engine..."
if ! command -v conntrack >/dev/null 2>&1 || ! command -v iptables-save >/dev/null 2>&1; then
  apt-get update -qq || true
  apt-get install -y conntrack iptables || echo "[WARN] conntrack/iptables not installed; ZiVPN IP/flow limits will not work"
fi

mkdir -p "$LIB_DST" /etc/tom_tunnel /var/lib/tom_tunnel /etc/tom_tunnel-tunnel-web /etc/tom_tunnel-web/data

cp -f "$SCRIPT_DIR/account_engine.py" "$LIB_DST/"
cp -f "$SCRIPT_DIR/migrate_accounts.py" "$LIB_DST/" 2>/dev/null || true
cp -f "$SCRIPT_DIR/traffic_collector.py" "$LIB_DST/" 2>/dev/null || true
cp -f "$SCRIPT_DIR/zivpn_engine.py" "$LIB_DST/" 2>/dev/null || true
cp -f "$SCRIPT_DIR/xray_realip.py" "$LIB_DST/" 2>/dev/null || true
cp -f "$SCRIPT_DIR/protocol_manager.py" "$LIB_DST/"
cp -f "$SCRIPT_DIR/backup_restore.sh" "$LIB_DST/" 2>/dev/null || true
chmod +x "$LIB_DST/backup_restore.sh" 2>/dev/null || true
cp -f "$SCRIPT_DIR/tom_motd.sh" "$LIB_DST/"
cp -f "$SCRIPT_DIR/account_engine.sh" "$BIN_DST/tom-account" 2>/dev/null || \
  printf '#!/bin/bash\nexec python3 %s/account_engine.py "$@"\n' "$LIB_DST" > "$BIN_DST/tom-account"
printf '#!/bin/bash\nexec python3 %s/protocol_manager.py "$@"\n' "$LIB_DST" > "$BIN_DST/tom-protocol"
chmod +x "$BIN_DST/tom-account" "$BIN_DST/tom-protocol" "$LIB_DST/"*.py "$LIB_DST/tom_motd.sh" 2>/dev/null || true

# Init schema
python3 "$LIB_DST/account_engine.py" init-schema || true

# MOTD integration (Ubuntu/Debian update-motd.d)
if [ -d /etc/update-motd.d ]; then
  ln -sf "$LIB_DST/tom_motd.sh" /etc/update-motd.d/99-tom-tunnel
  chmod +x /etc/update-motd.d/99-tom-tunnel
  echo "[TOM_TUNNEL] MOTD installed → /etc/update-motd.d/99-tom-tunnel"
fi

# Also append a safe call for accounts with /bin/false via sshd ForceCommand is NOT done
# (would break tunnels). Banner is for interactive shells only.

# Traffic collector systemd timer
cat > /etc/systemd/system/tom-traffic-collector.service << 'UNIT'
[Unit]
Description=TOM_TUNNEL traffic collector
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/lib/tom_tunnel/traffic_collector.py
Nice=10
UNIT

cat > /etc/systemd/system/tom-traffic-collector.timer << 'UNIT'
[Unit]
Description=Run TOM_TUNNEL traffic collector every minute

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
AccuracySec=10s
Persistent=true

[Install]
WantedBy=timers.target
UNIT

# Log rotation for enforcement / bot audit logs
cat > /etc/logrotate.d/tom-tunnel << 'LR'
/var/log/tom-tunnel-enforce.log /var/log/tom-tunnel-bot-audit.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    create 0640 root root
}
LR

systemctl daemon-reload 2>/dev/null || true
systemctl enable --now tom-traffic-collector.timer 2>/dev/null || true

# Dedicated ZiVPN sampler: per-port byte counters + conntrack IP/flow limits.
cat > /etc/systemd/system/tom-zivpn-enforce.service << 'UNIT'
[Unit]
Description=TOM_TUNNEL per-account ZiVPN quota and session enforcement
After=network-online.target zivpn.service

[Service]
Type=oneshot
ExecStart=/usr/bin/flock -n /run/lock/tom-zivpn-enforce.lock /usr/bin/python3 /usr/local/lib/tom_tunnel/zivpn_engine.py collect
Nice=5
UNIT
cat > /etc/systemd/system/tom-zivpn-enforce.timer << 'UNIT'
[Unit]
Description=Sample ZiVPN traffic and enforce account limits every 10 seconds

[Timer]
OnBootSec=30s
OnUnitActiveSec=10s
AccuracySec=2s
Persistent=true

[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload 2>/dev/null || true
systemctl enable --now tom-zivpn-enforce.timer 2>/dev/null || true

# Ensure v2raydns is on PATH for menu
if [ -f "$ROOT/menu/v2raydns.sh" ]; then
  cp -f "$ROOT/menu/v2raydns.sh" /usr/local/sbin/v2raydns 2>/dev/null || true
  chmod +x /usr/local/sbin/v2raydns 2>/dev/null || true
fi

echo "[TOM_TUNNEL] Account engine + MOTD + collector installed."
echo "  CLI: tom-account --help"
echo "  Xray IP limits (optional, restarts Xray): python3 $LIB_DST/xray_realip.py --dry-run  then without --dry-run"
echo "  DB : /etc/tom_tunnel-tunnel-web/tom_tunnel.db (shared with Web panel; legacy fallback supported)"
