#!/bin/bash
# Install dynamic MOTD for TOM_TUNNEL SSH accounts
set -e
MOTD_SRC="$(cd "$(dirname "$0")" && pwd)/tom_motd.sh"
install -d /usr/local/lib/tom_tunnel
install -m 755 "$MOTD_SRC" /usr/local/lib/tom_tunnel/tom_motd.sh

# Ubuntu/Debian update-motd.d
if [ -d /etc/update-motd.d ]; then
  cat > /etc/update-motd.d/99-tom-tunnel << 'EOF'
#!/bin/sh
[ -x /usr/local/lib/tom_tunnel/tom_motd.sh ] && /usr/local/lib/tom_tunnel/tom_motd.sh
EOF
  chmod +x /etc/update-motd.d/99-tom-tunnel
fi

# Also source from profile.d for non-PAM MOTD setups
cat > /etc/profile.d/tom-tunnel-motd.sh << 'EOF'
# TOM_TUNNEL dynamic account banner
if [ -n "$SSH_CONNECTION" ] && [ -x /usr/local/lib/tom_tunnel/tom_motd.sh ]; then
  . /usr/local/lib/tom_tunnel/tom_motd.sh
fi
EOF
chmod 644 /etc/profile.d/tom-tunnel-motd.sh

# Ensure PrintMotd is compatible (do not force Banner change that breaks keys)
if [ -f /etc/ssh/sshd_config ]; then
  if ! grep -q "^PrintMotd" /etc/ssh/sshd_config; then
    echo "PrintMotd yes" >> /etc/ssh/sshd_config
  fi
fi

echo "[TOM_TUNNEL] Dynamic MOTD installed."
