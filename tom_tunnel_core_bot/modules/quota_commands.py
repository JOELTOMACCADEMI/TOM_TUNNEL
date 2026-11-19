"""
TOM_TUNNEL bot — quota / limits commands (admins only, checked server-side).

Talks to the central account engine through the `tom-account` CLI (no shell,
arguments validated). Commands:
  /quota <user> [proto]            show quota, usage, limits, status
  /setquota <user> <proto> <gb>    set total quota (0 = unlimited)
  /addquota <user> <proto> <gb>    add (or remove with a negative value) GB
  /resetused <user> <proto>        reset consumed traffic to 0
  /limits <user> <proto> <ip> <conn>   0 = unlimited
  /suspend <user> <proto>   /unsuspend <user> <proto>
  /near [percent]                  accounts at or above N % of quota (default 80)
  /sessions [user]                 active sessions

Not offered here on purpose: renew/delete. Expiry and account existence live in
the system tools (chage / Xray config), so they must go through the existing bot
flows that change the real account; those flows should call `tom-account renew|delete`.
Every action is written to an audit log. Secrets (passwords, UUIDs) are never shown.
"""
import json
import re
import subprocess
import time

AUDIT_LOG = "/var/log/tom-tunnel-bot-audit.log"
# Must stay aligned with account_engine.PROTOCOLS ("v2raydns" was missing: quota/limits/suspend
# commands were impossible for V2RAY-DNS accounts). "udp" is kept as an alias of "udpcustom".
PROTOS = {"ssh", "vless", "vmess", "trojan", "socks", "zivpn", "udp", "udpcustom", "openvpn", "ohp",
          "slowdns", "dropbear", "v2raydns"}
PROTO_ALIAS = {"udp": "udpcustom"}
USER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
SHOW = ("username", "protocol", "status", "quota_gb", "used_gb", "remaining_gb", "quota_percent",
        "expires_at", "ip_limit", "conn_limit", "last_activity")


class BadInput(Exception):
    pass


def _user(v):
    if not USER_RE.match(v or ""):
        raise BadInput("Nom d'utilisateur invalide (a-z, 0-9, _ . - ; 32 max).")
    return v


def _proto(v):
    v = (v or "").lower()
    if v not in PROTOS:
        raise BadInput("Protocole invalide. Valeurs : " + ", ".join(sorted(PROTOS)))
    return PROTO_ALIAS.get(v, v)


def _num(v, lo, hi, typ=float, name="valeur"):
    try:
        x = typ(v)
    except (TypeError, ValueError):
        raise BadInput(f"{name} invalide.")
    if not (lo <= x <= hi):
        raise BadInput(f"{name} hors limites ({lo} à {hi}).")
    return x


def cli(args, run=subprocess.run):
    """Run tom-account; return parsed JSON (or None). Raises RuntimeError with a clean message."""
    try:
        p = run(["tom-account", *args], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("Moteur de comptes indisponible.")
    if p.returncode != 0:
        last = (p.stderr or "").strip().splitlines()[-1:] or ["erreur"]
        raise RuntimeError(last[0][:200])
    out = (p.stdout or "").strip()
    return json.loads(out) if out else None


def fmt(acc):
    if not acc:
        return "Compte introuvable."
    q = acc.get("quota_gb") or 0
    status = {"quota_exhausted": "QUOTA ÉPUISÉ", "active": "ACTIF", "expired": "EXPIRÉ", "suspended": "SUSPENDU"}.get(
        acc.get("status"), str(acc.get("status")))
    quota = "illimité" if not q else f"{q:g} Go"
    rem = "illimité" if not q else f"{acc.get('remaining_gb', 0):.2f} Go"
    return (f"👤 {acc.get('username')} ({acc.get('protocol')})\n"
            f"État : {status}\nQuota : {quota} — utilisé {float(acc.get('used_gb') or 0):.2f} Go ({acc.get('quota_percent', 0):g}%)\n"
            f"Restant : {rem}\nExpire : {acc.get('expires_at') or '-'}\n"
            f"Limite IP : {acc.get('ip_limit') or 'illimitée'} — Connexions : {acc.get('conn_limit') or 'illimitées'}")


def audit(admin_id, action, detail, ok, path=AUDIT_LOG):
    try:
        with open(path, "a") as f:
            f.write(json.dumps({"ts": time.strftime("%Y-%m-%d %H:%M:%S"), "admin": admin_id,
                                "action": action, "detail": detail, "ok": ok}) + "\n")
    except OSError:
        pass


def handle(text, admin_id, is_admin, run=subprocess.run, audit_path=AUDIT_LOG):
    """Pure command handler → reply text. Authorization is enforced HERE, server-side."""
    if not is_admin(admin_id):
        return "⛔ Action réservée aux administrateurs."
    parts = (text or "").split()
    if not parts:
        return "Commande vide."
    cmd = parts[0].lstrip("/").split("@")[0].lower()
    a = parts[1:]
    try:
        if cmd == "quota":
            if not a:
                raise BadInput("Usage : /quota <user> [proto]")
            u = _user(a[0])
            if len(a) > 1:
                p = _proto(a[1])
                return fmt(cli(["get", u, "--protocol", p], run))
            return fmt(cli(["get", u], run))
        if cmd in ("setquota", "addquota"):
            if len(a) != 3:
                raise BadInput(f"Usage : /{cmd} <user> <proto> <gb>")
            u, p = _user(a[0]), _proto(a[1])
            gb = _num(a[2], 0 if cmd == "setquota" else -100000, 100000, float, "Go")
            acc = cli(["set-quota", u, p, "--quota" if cmd == "setquota" else "--add", str(gb)], run)
        elif cmd == "resetused":
            if len(a) != 2:
                raise BadInput("Usage : /resetused <user> <proto>")
            u, p = _user(a[0]), _proto(a[1])
            acc = cli(["set-quota", u, p, "--reset-used"], run)
        elif cmd == "limits":
            if len(a) != 4:
                raise BadInput("Usage : /limits <user> <proto> <ip> <conn>  (0 = illimité)")
            u, p = _user(a[0]), _proto(a[1])
            ip, cn = int(_num(a[2], 0, 1000, int, "Limite IP")), int(_num(a[3], 0, 1000, int, "Limite connexions"))
            acc = cli(["set-limits", u, p, "--ip-limit", str(ip), "--conn-limit", str(cn)], run)
        elif cmd in ("suspend", "unsuspend"):
            if len(a) != 2:
                raise BadInput(f"Usage : /{cmd} <user> <proto>")
            u, p = _user(a[0]), _proto(a[1])
            acc = cli(["status", u, p, "suspended" if cmd == "suspend" else "active"], run)
        elif cmd == "near":
            pct = _num(a[0], 1, 100, float, "Pourcentage") if a else 80.0
            accs = cli(["list", "--near-quota", str(pct / 100)], run) or []
            if not accs:
                return f"Aucun compte à {pct:g}% ou plus."
            return "\n".join(f"• {x['username']} ({x['protocol']}) : {x.get('quota_percent', 0):g}% — {x['status']}" for x in accs[:40])
        elif cmd == "sessions":
            args = ["sessions"] + (["--username", _user(a[0])] if a else [])
            ss = cli(args, run) or []
            if not ss:
                return "Aucune session active."
            return "\n".join(f"• {s['username']} ({s['protocol']}) {s['ip']} depuis {s['started_at']}" for s in ss[:40])
        else:
            return "Commande inconnue."
    except BadInput as e:
        return f"⚠️ {e}"
    except RuntimeError as e:
        audit(admin_id, cmd, " ".join(a), False, audit_path)
        return f"❌ {e}"
    audit(admin_id, cmd, " ".join(a), True, audit_path)
    return "✅ Fait.\n" + fmt(acc)


def register(bot, is_admin):
    cmds = ["quota", "setquota", "addquota", "resetused", "limits", "suspend", "unsuspend", "near", "sessions"]

    @bot.message_handler(commands=cmds)
    def _quota(message):
        bot.send_message(message.chat.id, handle(message.text, message.from_user.id, is_admin))
