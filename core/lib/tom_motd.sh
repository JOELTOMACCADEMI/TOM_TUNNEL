#!/bin/bash
# TOM_TUNNEL — Dynamic MOTD / post-login banner
# Displays account quota / IP / connection info for the authenticated user.
# Safe: only shows data for the current user; never leaks other accounts.
# Installed typically as /etc/update-motd.d/99-tom-tunnel or called from .bashrc

# Only for interactive SSH sessions
[ -n "$SSH_CONNECTION" ] || [ -n "$SSH_TTY" ] || exit 0
# Skip if not a real login user with a home (or false shell accounts used by tunnel)
USER_NAME="${USER:-$(id -un 2>/dev/null)}"
[ -z "$USER_NAME" ] && exit 0
[ "$USER_NAME" = "root" ] && exit 0

ENGINE=""
for p in /usr/local/lib/tom_tunnel/account_engine.py \
         /opt/tom_tunnel/core/lib/account_engine.py; do
  [ -f "$p" ] && ENGINE="$p" && break
done

if [ -z "$ENGINE" ] || ! command -v python3 >/dev/null 2>&1; then
  # Fallback minimal banner
  printf '\n  TOM_TUNNEL — welcome %s\n\n' "$USER_NAME"
  exit 0
fi

# Prefer SSH protocol; engine falls back to any protocol for this username
python3 "$ENGINE" banner "$USER_NAME" --protocol ssh 2>/dev/null || \
python3 -c "
import sys
sys.path.insert(0, '$(dirname "$ENGINE")')
try:
    from account_engine import get_engine
    eng = get_engine()
    acc = eng.get_account('$USER_NAME')
    if not acc:
        print('')
        sys.exit(0)
    print(eng.format_account_banner('$USER_NAME', acc.get('protocol') or 'ssh'))
except Exception:
    print('')
" 2>/dev/null

exit 0
