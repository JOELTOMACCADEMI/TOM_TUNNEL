"""
TOM_TUNNEL bot — protocol management (enable / disable / state / restart / logs / ports / errors).

Talks to the central protocol manager through the `tom-protocol` CLI (no shell,
protocol ids come only from a fixed whitelist). The same backend is used by the
VPS menu and the Web panel, so the three always show the same state.

Permissions (checked server-side on every callback, never trusted from the button):
  * any admin      : view state, ports, errors, logs
  * super admin    : enable, disable, restart (they affect every user of the VPS)
Disabling never deletes accounts, quotas, limits, expiry dates or statistics.
"""
import html
import json
import subprocess

PROTOCOL_IDS = ("ssh", "ssh-ws", "ssh-ssl", "dropbear", "vless", "vmess", "trojan", "socks",
                "v2raydns", "slowdns", "udpcustom", "zivpn", "openvpn", "ohp")
ICON = {"running": "🟢", "disabled": "⛔", "enabled_but_down": "🟠"}
LABEL = {"running": "actif", "disabled": "désactivé", "enabled_but_down": "activé mais service arrêté"}


def cli(args, run=subprocess.run):
    """Run tom-protocol --json; returns parsed JSON or raises RuntimeError."""
    try:
        p = run(["tom-protocol", *args, "--json"], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("tom-protocol indisponible") from exc
    try:
        data = json.loads(p.stdout or "null")
    except ValueError:
        raise RuntimeError((p.stderr or p.stdout or "erreur tom-protocol").strip()[:200])
    return data


def _e(v):
    return html.escape(str(v), quote=False)


def format_list(rows):
    lines = ["<b>⚙️ PROTOCOLES</b>"]
    for r in rows:
        lines.append(f"{ICON[r['state']]} <b>{_e(r['label'])}</b> — {LABEL[r['state']]} "
                     f"({r['accounts_active']}/{r['accounts_total']} comptes actifs)")
    return "\n".join(lines)


def format_detail(s):
    svc = "\n".join(f"  • {_e(x['name'])}: {'🟢 up' if x['active'] else '🔴 down'}" for x in s["services"]) \
        or "  • service non installé"
    prt = "\n".join(f"  • {p['port']}/{p['proto']}: {'🟢 ouvert' if p['listening'] else '🔴 fermé'}" for p in s["ports"]) \
        or "  • partagés/internes"
    mode = ("service indépendant (systemctl)" if s["mode"] == "service"
            else "comptes neutralisés (processus partagé non arrêté)")
    cap = s.get("capabilities", {})
    yesno = lambda key: "✅" if cap.get(key) else "❌"
    capline = (f"\nQuota: {yesno('quota')} | IP: {yesno('ip_limit')} | Connexions: {yesno('conn_limit')}"
               f"\nMesure: {_e(cap.get('meter') or 'non disponible')}"
               f"\nLimite: {_e(cap.get('note') or '')}")
    return (f"{ICON[s['state']]} <b>{_e(s['label'])}</b>\nÉtat : <b>{LABEL[s['state']]}</b>\n"
            f"Mode : {mode}\nComptes actifs : {s['accounts_active']}/{s['accounts_total']}\n"
            f"Services :\n{svc}\nPorts :\n{prt}{capline}")


def register(bot, is_admin, is_super_admin, home_markup):
    from telebot.types import InlineKeyboardButton, InlineKeyboardMarkup

    def ans(c, t=""):
        try:
            bot.answer_callback_query(c.id, t)
        except Exception:  # noqa: BLE001
            pass

    def show(c, text, markup):
        ans(c)
        try:
            bot.edit_message_text(text, c.message.chat.id, c.message.message_id, parse_mode="HTML", reply_markup=markup)
        except Exception:  # noqa: BLE001
            bot.send_message(c.message.chat.id, text, parse_mode="HTML", reply_markup=markup)

    def parse(c):
        """-> (action, pid) or None; pid must be whitelisted."""
        parts = (c.data or "").split(":")
        if len(parts) == 3 and parts[2] in PROTOCOL_IDS:
            return parts[1], parts[2]
        return None

    @bot.callback_query_handler(func=lambda c: c.data == "menu_protocols")
    def menu(c):
        if not is_admin(c.from_user.id):
            return
        try:
            rows = cli(["list"])
        except RuntimeError as exc:
            show(c, f"❌ {_e(exc)}", home_markup()); return
        m = InlineKeyboardMarkup(row_width=2)
        for r in rows:
            m.add(InlineKeyboardButton(f"{ICON[r['state']]} {r['id']}", callback_data=f"pm:view:{r['id']}"))
        m.add(InlineKeyboardButton("🔙 Accueil", callback_data="action_home"))
        show(c, format_list(rows), m)

    def detail(c, pid, prefix=""):
        s = cli(["status", pid])
        m = InlineKeyboardMarkup(row_width=2)
        if s["enabled"]:
            m.add(InlineKeyboardButton("⛔ Désactiver", callback_data=f"pm:askoff:{pid}"))
        else:
            m.add(InlineKeyboardButton("✅ Activer", callback_data=f"pm:on:{pid}"))
        m.add(InlineKeyboardButton("🔁 Redémarrer", callback_data=f"pm:restart:{pid}"),
              InlineKeyboardButton("📜 Journaux", callback_data=f"pm:logs:{pid}"),
              InlineKeyboardButton("🔌 Ports", callback_data=f"pm:ports:{pid}"),
              InlineKeyboardButton("⚠️ Erreurs", callback_data=f"pm:errors:{pid}"))
        m.add(InlineKeyboardButton("🔙 Protocoles", callback_data="menu_protocols"))
        show(c, prefix + format_detail(s), m)

    @bot.callback_query_handler(func=lambda c: (c.data or "").startswith("pm:"))
    def action(c):
        if not is_admin(c.from_user.id):
            return
        parsed = parse(c)
        if not parsed:
            ans(c, "Protocole invalide."); return
        act, pid = parsed
        try:
            if act == "view":
                detail(c, pid)
            elif act in ("askoff", "on", "off", "restart"):
                if not is_super_admin(c.from_user.id):
                    ans(c, "⛔ Super Admin uniquement."); return
                if act == "askoff":
                    m = InlineKeyboardMarkup(row_width=2)
                    m.add(InlineKeyboardButton("✅ Confirmer", callback_data=f"pm:off:{pid}"),
                          InlineKeyboardButton("❌ Annuler", callback_data=f"pm:view:{pid}"))
                    show(c, f"⚠️ Désactiver <b>{_e(pid)}</b> ?\nLes nouvelles connexions seront refusées. "
                            "Comptes, quotas et expirations sont conservés.", m)
                    return
                if act == "restart":
                    r = cli(["restart", pid])
                else:
                    r = cli(["enable" if act == "on" else "disable", pid])
                detail(c, pid, ("✅ " if r.get("ok") else "❌ ") + _e(r.get("message", "")) + "\n\n")
            elif act in ("logs", "errors", "ports"):
                r = cli([act, pid])
                if act == "ports":
                    body = "\n".join(f"{p['port']}/{p['proto']}: {'ouvert' if p['listening'] else 'fermé'}" for p in r["ports"]) \
                        or r.get("note", "")
                else:
                    body = r.get(act, "")
                m = InlineKeyboardMarkup(); m.add(InlineKeyboardButton("🔙", callback_data=f"pm:view:{pid}"))
                show(c, f"<b>{_e(pid)} — {act}</b>\n<pre>{_e(body[-3000:])}</pre>", m)
        except RuntimeError as exc:
            show(c, f"❌ {_e(exc)}", home_markup())
