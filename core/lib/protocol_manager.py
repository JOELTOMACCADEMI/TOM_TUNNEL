#!/usr/bin/env python3
"""
TOM_TUNNEL — central protocol manager.

One implementation shared by the VPS menu (tom-protocol), the Telegram bot and
the Web panel. State lives in the central SQLite DB (engine_meta, key
``proto_disabled:<id>``), so the three front-ends always agree.

Two ways of disabling a protocol, chosen so that nothing shared is broken:

* mode "service"  – the protocol has its own systemd unit(s) (stunnel5, dropbear,
  ws-*, dnstt, udp-custom, ZiVPN legacy + per-user instances, openvpn, ohp).
  Disabling stops and disables all matching instances; enabling restores eligible accounts.
* mode "accounts" – the protocol shares a process with others (VLESS / VMess /
  Trojan / Shadowsocks / V2RAY-DNS share Xray; SSH accounts share sshd). The
  process is NOT stopped. Every account of that protocol is neutralised
  (Xray client id swapped / unix user locked) by the traffic collector's
  enforcement code, which is also what restores them on re-enable.

In both modes accounts, quotas, limits, expiry dates and statistics are never
touched. Nothing here deletes data.

CLI:  tom-protocol list|status|enable|disable|restart|logs|ports|errors [id] [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import shutil
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# id -> definition.  "accounts" = engine protocol names whose accounts belong to it.
REGISTRY = {
    "ssh":       dict(label="SSH (tous les comptes SSH)", mode="accounts", accounts=["ssh"],
                      services=["ssh", "sshd"], ports=[(22, "tcp")], status_only=True),
    "ssh-ws":    dict(label="SSH WebSocket", mode="service", accounts=[],
                      services=["ws-stunnel", "ws-dropbear"], ports=[]),
    "ssh-ssl":   dict(label="SSH SSL / Stunnel", mode="service", accounts=[],
                      services=["stunnel5"], ports=[(8181, "tcp")]),
    "dropbear":  dict(label="Dropbear", mode="service", accounts=[],
                      services=["dropbear"], ports=[(447, "tcp")]),
    "vless":     dict(label="VLESS (Xray)", mode="accounts", accounts=["vless"],
                      services=["xray"], ports=[]),
    "vmess":     dict(label="VMess (Xray)", mode="accounts", accounts=["vmess"],
                      services=["xray"], ports=[]),
    "trojan":    dict(label="Trojan (Xray)", mode="accounts", accounts=["trojan"],
                      services=["xray"], ports=[]),
    "socks":     dict(label="Shadowsocks/Socks (Xray)", mode="accounts", accounts=["socks"],
                      services=["xray"], ports=[]),
    "v2raydns":  dict(label="V2RAY-DNS (VLESS + métadonnées SlowDNS)", mode="accounts",
                      accounts=["v2raydns"], services=["xray"], ports=[]),
    "slowdns":   dict(label="SlowDNS / DNSTT", mode="service", accounts=["slowdns"],
                      services=["dnstt"], ports=[(5300, "udp")]),
    "udpcustom": dict(label="UDP Custom", mode="service", accounts=["udpcustom"],
                      services=["udp-custom"], ports=[(36712, "udp")]),
    "zivpn":     dict(label="ZIVPN (UDP)", mode="service", accounts=["zivpn"],
                      services=["zivpn"], ports=[(5667, "udp")]),
    "openvpn":   dict(label="OpenVPN", mode="service", accounts=["openvpn"],
                      services=["openvpn"], ports=[(1194, "tcp"), (2200, "udp")]),
    "ohp":       dict(label="OHP", mode="service", accounts=["ohp"],
                      services=["ohp"], ports=[(8000, "tcp")]),
}
ID_RE = re.compile(r"^[a-z0-9-]{1,20}$")

# Conservative feature matrix: true only when a real collector/enforcer exists.
CAPABILITIES = {
    "ssh": {"quota": True, "ip_limit": True, "conn_limit": True, "meter": "TCP socket counters + live sshd sessions", "note": "SSH identities; WebSocket/SSL wrappers share this account."},
    "ssh-ws": {"quota": True, "ip_limit": True, "conn_limit": True, "meter": "underlying SSH identity", "note": "Transport wrapper, not a separate account namespace."},
    "ssh-ssl": {"quota": True, "ip_limit": True, "conn_limit": True, "meter": "underlying SSH identity", "note": "Transport wrapper, not a separate account namespace."},
    "dropbear": {"quota": True, "ip_limit": True, "conn_limit": True, "meter": "underlying Linux SSH identity", "note": "Only sessions attributable to an existing SSH account are covered."},
    "vless": {"quota": True, "ip_limit": True, "conn_limit": False, "meter": "Xray per-user API", "note": "IP cap requires real client IP logs; simultaneous stream count is not reliably exposed."},
    "vmess": {"quota": True, "ip_limit": True, "conn_limit": False, "meter": "Xray per-user API", "note": "IP cap requires real client IP logs; simultaneous stream count is not reliably exposed."},
    "trojan": {"quota": True, "ip_limit": True, "conn_limit": False, "meter": "Xray per-user API", "note": "IP cap requires real client IP logs; simultaneous stream count is not reliably exposed."},
    "socks": {"quota": True, "ip_limit": True, "conn_limit": False, "meter": "Xray per-user API", "note": "Requires Xray user stats and real client IP logging."},
    "v2raydns": {"quota": True, "ip_limit": True, "conn_limit": False, "meter": "Xray per-user API", "note": "VLESS/Xray identity; IP cap requires real client IP logging."},
    "zivpn": {"quota": True, "ip_limit": True, "conn_limit": True, "meter": "per-account UDP iptables counters + conntrack", "note": "Dedicated per-account listener only; limits sampled every 10 seconds."},
    "slowdns": {"quota": False, "ip_limit": False, "conn_limit": False, "meter": None, "note": "No per-user traffic/authentication adapter in this build."},
    "udpcustom": {"quota": False, "ip_limit": False, "conn_limit": False, "meter": None, "note": "Shared UDP listener; no per-user traffic attribution adapter."},
    "openvpn": {"quota": True, "ip_limit": True, "conn_limit": True, "meter": "OpenVPN per-client status counters + loopback management interface", "note": "Requires TOM_TUNNEL-managed TCP/UDP configs with management ports 7505/7506; external/manual configs need equivalent directives."},
    "ohp": {"quota": False, "ip_limit": False, "conn_limit": False, "meter": None, "note": "Transport wrapper; no per-user traffic attribution adapter."},
}
CONFIG_CANDIDATES = {
    "ssh": ["/etc/ssh/sshd_config"],
    "ssh-ws": ["/etc/stunnel/stunnel.conf", "/etc/stunnel5/stunnel.conf"],
    "ssh-ssl": ["/etc/stunnel/stunnel.conf", "/etc/stunnel5/stunnel.conf"],
    "dropbear": ["/etc/default/dropbear"],
    "vless": ["/etc/xray/config.json"], "vmess": ["/etc/xray/config.json"],
    "trojan": ["/etc/xray/config.json"], "socks": ["/etc/xray/config.json"],
    "v2raydns": ["/etc/xray/config.json"], "zivpn": ["/etc/zivpn/config.json"],
    "openvpn": ["/etc/openvpn/server/server.conf", "/etc/openvpn/server.conf"],
    "slowdns": ["/etc/dnstt-server/config.json", "/etc/dnstt/config.json"],
    "udpcustom": ["/etc/udp-custom/config.json", "/etc/udp-custom/udp-custom.yaml"],
    "ohp": ["/etc/default/ohp", "/etc/ohp/config"],
}

FLAG = "proto_disabled:"
XRAY_ERR_LOG = os.environ.get("XRAY_ERROR_LOG", "/var/log/xray/error.log")


def _run(cmd, timeout=25):
    """Run without a shell. Returns CompletedProcess or None (missing binary / timeout)."""
    try:
        return subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None


RUN = _run  # replaced by tests


def _engine(db_path=None):
    from account_engine import get_engine
    return get_engine(db_path)


def _meta_conn(eng):
    from account_engine import _db_connection
    return _db_connection(eng.db_path)


# ----------------------------------------------------------------------------
# State (central DB)
# ----------------------------------------------------------------------------
def is_disabled(eng, pid: str) -> bool:
    with _meta_conn(eng) as conn:
        r = conn.execute("SELECT value FROM engine_meta WHERE key = ?", (FLAG + pid,)).fetchone()
    return bool(r and str(r[0]) == "1")


def disabled_set(eng) -> set:
    with _meta_conn(eng) as conn:
        rows = conn.execute("SELECT key FROM engine_meta WHERE key LIKE ? AND value = '1'",
                            (FLAG + "%",)).fetchall()
    return {r[0][len(FLAG):] for r in rows}


def disabled_account_protocols(eng) -> set:
    """Engine protocol names (vless, ssh, …) whose accounts must currently be blocked."""
    out = set()
    for pid in disabled_set(eng):
        d = REGISTRY.get(pid)
        if d and d["mode"] == "accounts":
            out.update(d["accounts"])
    return out


def _set_flag(eng, pid: str, disabled: bool) -> None:
    with _meta_conn(eng) as conn:
        if disabled:
            conn.execute("INSERT OR REPLACE INTO engine_meta (key, value) VALUES (?, '1')", (FLAG + pid,))
        else:
            conn.execute("DELETE FROM engine_meta WHERE key = ?", (FLAG + pid,))
        conn.commit()


# ----------------------------------------------------------------------------
# systemd helpers
# ----------------------------------------------------------------------------
def unit_exists(name: str) -> bool:
    r = RUN(["systemctl", "show", "-p", "LoadState", "--value", name + ".service"])
    return bool(r and r.returncode == 0 and r.stdout.strip() == "loaded")


def unit_active(name: str) -> bool:
    r = RUN(["systemctl", "is-active", name + ".service"])
    return bool(r and r.stdout.strip() == "active")


def unit_enabled(name: str) -> bool:
    r = RUN(["systemctl", "is-enabled", name + ".service"])
    return bool(r and r.stdout.strip() in ("enabled", "static", "alias"))


def listening(port: int, proto: str) -> bool:
    flag = "-ltn" if proto == "tcp" else "-lun"
    r = RUN(["ss", "-H", flag])
    if not r or r.returncode != 0:
        return False
    return any(re.search(rf"[:.\]]{port}\s", line + " ") for line in r.stdout.splitlines())


def _def(pid: str) -> dict:
    if not ID_RE.fullmatch(pid or "") or pid not in REGISTRY:
        raise KeyError(f"protocole inconnu: {pid!r}")
    return REGISTRY[pid]


def _real_units(d: dict) -> list:
    """Units that exist on this VPS (for ssh: ssh OR sshd, only the one present)."""
    units = [u for u in d["services"] if unit_exists(u)]
    if d.get("status_only") and units:
        units = units[:1]
    return units


# ----------------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------------
def status(pid: str, db_path=None) -> dict:
    d = _def(pid)
    eng = _engine(db_path)
    disabled = is_disabled(eng, pid)
    units = _real_units(d)
    accts = []
    for ap in d["accounts"]:
        accts += eng.list_accounts(protocol=ap)
    total = len(accts)
    active = sum(1 for a in accts if a["status"] == "active")
    if pid == "zivpn":
        services = [{"name": u, "active": unit_active(u), "enabled_at_boot": unit_enabled(u)} for u in units]
        instance_units = []
        dynamic_ports = []
        for account in accts:
            try:
                extra = json.loads(account.get("extra_data") or "{}")
                port = int(extra.get("port", 0))
                if not port:
                    continue  # legacy shared-listener account, no dedicated systemd instance
                name = f"zivpn-user@{account['username']}"
                instance_units.append({"name": name, "active": unit_active(name), "enabled_at_boot": unit_enabled(name)})
                dynamic_ports.append({"port": port, "proto": "udp", "listening": listening(port, "udp"), "username": account["username"]})
            except Exception:
                continue
        services.extend(instance_units)
        ports = [{"port": p, "proto": pr, "listening": listening(p, pr)} for p, pr in d["ports"]] + dynamic_ports
        installed = bool(units) or Path("/etc/systemd/system/zivpn-user@.service").is_file()
        active_instances = [x for x in instance_units if any(a["username"] == x["name"].split("@",1)[-1] and a["status"] == "active" for a in accts)]
        services_ok = (all(x["active"] for x in active_instances) if active_instances else bool(services) and any(x["active"] for x in services))
    else:
        services = [{"name": u, "active": unit_active(u), "enabled_at_boot": unit_enabled(u)} for u in units]
        ports = [{"port": p, "proto": pr, "listening": listening(p, pr)} for p, pr in d["ports"]]
        installed = bool(units)
        services_ok = bool(services) and all(s["active"] for s in services)
    if disabled:
        operational = False
    elif d["mode"] == "service":
        operational = services_ok
    else:
        operational = services_ok  # shared process (xray / sshd) must be up
    return {
        "id": pid, "label": d["label"], "mode": d["mode"],
        "enabled": not disabled, "operational": operational,
        "state": "disabled" if disabled else ("running" if operational else "enabled_but_down"),
        "installed": installed, "services": services, "ports": ports,
        "accounts_total": total, "accounts_active": active,
        "capabilities": CAPABILITIES.get(pid, {"quota": False, "ip_limit": False, "conn_limit": False, "meter": None, "note": "Non documenté."}),
    }


def list_all(db_path=None) -> list:
    return [status(pid, db_path) for pid in REGISTRY]


def _enforce_accounts(eng, d: dict) -> tuple:
    """Re-apply account blocking now (instead of waiting for the 1-min collector)."""
    import traffic_collector as tc
    report = {"errors": []}
    if d["accounts"] == ["ssh"]:
        tc.enforce_ssh(eng, report)
    else:
        tc.enforce_xray(eng, report)
    if report["errors"]:
        return False, "; ".join(report["errors"])
    return True, ""


def set_enabled(pid: str, enable: bool, db_path=None) -> dict:
    d = _def(pid)
    eng = _engine(db_path)
    msgs = []
    ok = True
    if pid == "zivpn":
        accounts = eng.list_accounts(protocol="zivpn")
        units = _real_units(d)
        _set_flag(eng, pid, not enable)
        targets = []
        for account in accounts:
            try:
                extra = json.loads(account.get("extra_data") or "{}")
                if int(extra.get("port", 0)):
                    targets.append((f"zivpn-user@{account['username']}", account.get("status") == "active"))
            except Exception:
                continue
        if units:
            targets.extend((u, True) for u in units)
        if not targets and Path("/etc/systemd/system/zivpn-user@.service").is_file():
            return {"ok": False, "id": pid, "message": "Aucun compte ZiVPN individuel à activer."}
        for unit, account_active in targets:
            should_start = enable and account_active
            r = RUN(["systemctl", "enable" if should_start else "disable", "--now", unit + ".service"], timeout=40)
            if r is None or r.returncode != 0:
                ok = False
                msgs.append(f"{unit}: échec systemctl ({(r.stderr.strip() if r else 'indisponible')[:120]})")
        if ok:
            msgs.append("activé" if enable else "désactivé (toutes les instances ZiVPN arrêtées)")
        return {"ok": ok, "id": pid, "enabled": enable, "message": " | ".join(msgs)}
    if d["mode"] == "service":
        units = _real_units(d)
        if not units:
            return {"ok": False, "id": pid, "message": "Service non installé sur ce VPS (rien modifié)."}
        _set_flag(eng, pid, not enable)
        for u in units:
            if enable:
                r = RUN(["systemctl", "enable", "--now", u + ".service"], timeout=40)
            else:
                r = RUN(["systemctl", "disable", "--now", u + ".service"], timeout=40)
            if r is None or r.returncode != 0:
                ok = False
                msgs.append(f"{u}: échec systemctl ({(r.stderr.strip() if r else 'indisponible')[:120]})")
        if enable:  # verify it is really up
            for u in units:
                if not unit_active(u):
                    ok = False
                    msgs.append(f"{u}: inactif après activation")
        else:
            for u in units:
                if unit_active(u):
                    ok = False
                    msgs.append(f"{u}: toujours actif après désactivation")
    else:
        _set_flag(eng, pid, not enable)
        ok, err = _enforce_accounts(eng, d)
        if not ok:
            msgs.append(err)
        if enable:
            main = _real_units(d)
            if main and not all(unit_active(u) for u in main):
                ok = False
                msgs.append(f"service {main[0]} inactif : les comptes sont réactivés mais rien ne fonctionnera")
    if ok:
        msgs.append("activé" if enable else "désactivé (comptes, quotas et expirations conservés)")
    return {"ok": ok, "id": pid, "enabled": enable, "message": " | ".join(msgs)}


def restart(pid: str) -> dict:
    d = _def(pid)
    if pid == "zivpn":
        eng = _engine()
        targets = [u for u in _real_units(d)]
        for account in eng.list_accounts(protocol="zivpn"):
            try:
                extra = json.loads(account.get("extra_data") or "{}")
                if int(extra.get("port", 0)) and account.get("status") == "active":
                    targets.append(f"zivpn-user@{account['username']}")
            except Exception:
                continue
        if not targets:
            return {"ok": False, "id": pid, "message": "Aucune instance ZiVPN individuelle installée."}
        ok, msgs = True, []
        for unit in targets:
            r = RUN(["systemctl", "restart", unit + ".service"], timeout=40)
            if r is None or r.returncode != 0 or not unit_active(unit):
                ok = False; msgs.append(f"{unit}: échec du redémarrage")
        return {"ok": ok, "id": pid, "message": " | ".join(msgs) if msgs else "instances ZiVPN redémarrées"}
    units = _real_units(d)
    if not units:
        return {"ok": False, "id": pid, "message": "Service non installé."}
    ok, msgs = True, []
    for u in units:
        r = RUN(["systemctl", "restart", u + ".service"], timeout=40)
        if r is None or r.returncode != 0 or not unit_active(u):
            ok = False
            msgs.append(f"{u}: échec du redémarrage")
    note = ""
    if d["services"] == ["xray"]:
        note = " (Xray est partagé : VLESS/VMess/Trojan/Socks/V2RAY-DNS redémarrent ensemble)"
    return {"ok": ok, "id": pid, "message": ("; ".join(msgs) if msgs else "redémarré") + note}


def _clip(text: str, limit: int = 3500) -> str:
    return text[-limit:] if len(text) > limit else text


def logs(pid: str, lines: int = 30) -> dict:
    d = _def(pid)
    n = max(1, min(int(lines), 200))
    out = []
    for u in _real_units(d):
        r = RUN(["journalctl", "-u", u + ".service", "-n", str(n), "--no-pager", "-o", "short"])
        if r and r.stdout.strip():
            out.append(f"== {u} ==\n{r.stdout.strip()}")
    if d["services"] == ["xray"] and Path(XRAY_ERR_LOG).exists():
        r = RUN(["tail", "-n", str(n), XRAY_ERR_LOG])
        if r and r.stdout.strip():
            out.append(f"== xray error.log ==\n{r.stdout.strip()}")
    return {"id": pid, "logs": _clip("\n".join(out)) or "(aucun journal disponible)"}


def errors(pid: str) -> dict:
    d = _def(pid)
    out = []
    for u in _real_units(d):
        r = RUN(["journalctl", "-u", u + ".service", "-p", "err", "-n", "20", "--no-pager",
                 "--since", "24 hours ago", "-o", "short"])
        if r and r.stdout.strip() and "-- No entries --" not in r.stdout:
            out.append(f"== {u} ==\n{r.stdout.strip()}")
    if d["services"] == ["xray"] and Path(XRAY_ERR_LOG).exists():
        r = RUN(["tail", "-n", "200", XRAY_ERR_LOG])
        if r:
            bad = [l for l in r.stdout.splitlines() if re.search(r"failed|error|panic", l, re.I)][-15:]
            if bad:
                out.append("== xray error.log ==\n" + "\n".join(bad))
    return {"id": pid, "errors": _clip("\n".join(out)) or "Aucune erreur récente."}


def ports(pid: str) -> dict:
    d = _def(pid)
    res = [{"port": p, "proto": pr, "listening": listening(p, pr)} for p, pr in d["ports"]]
    note = "" if res else "Ports partagés (nginx 80/443/2082-2087 → inbounds Xray en loopback) ou internes."
    return {"id": pid, "ports": res, "note": note}


# ----------------------------------------------------------------------------
def configure(pid: str) -> dict:
    """Open one known existing config; backup first and validate JSON/Xray edits."""
    d = _def(pid)
    paths = [Path(x) for x in CONFIG_CANDIDATES.get(pid, []) if Path(x).is_file()]
    if not paths:
        return {"ok": False, "id": pid, "message": "Aucun fichier de configuration connu présent. Aucun changement effectué."}
    if len(paths) != 1:
        return {"ok": False, "id": pid, "files": [str(x) for x in paths], "message": "Plusieurs fichiers trouvés : édition refusée pour éviter de modifier le mauvais fichier."}
    target = paths[0]
    if os.geteuid() != 0:
        return {"ok": False, "id": pid, "message": "La configuration nécessite les droits root."}
    editor = os.environ.get("EDITOR") or ("nano" if shutil.which("nano") else "vi")
    backup = target.with_name(target.name + ".tomtunnel-" + time.strftime("%Y%m%d-%H%M%S") + ".bak")
    shutil.copy2(target, backup)
    try:
        edit = subprocess.run([editor, str(target)], check=False)
        if edit.returncode != 0:
            raise RuntimeError("éditeur terminé avec une erreur")
        if target.suffix.lower() == ".json":
            json.loads(target.read_text())
        if str(target) == "/etc/xray/config.json" and shutil.which("xray"):
            test = RUN(["xray", "run", "-test", "-config", str(target)], timeout=30)
            if test is None or test.returncode != 0:
                raise RuntimeError("validation Xray échouée")
        note = " Configuration partagée : cela peut affecter VLESS, VMess, Trojan, SOCKS et V2RAY-DNS." if d["services"] == ["xray"] else ""
        return {"ok": True, "id": pid, "file": str(target), "backup": str(backup), "message": f"Fichier enregistré. Sauvegarde : {backup}. Vérifiez puis redémarrez le protocole.{note}"}
    except Exception as exc:
        shutil.copy2(backup, target)
        return {"ok": False, "id": pid, "file": str(target), "backup": str(backup), "message": f"Édition annulée, sauvegarde restaurée : {exc}"}


def capabilities(pid=None):
    if pid:
        _def(pid)
        return {"id": pid, **CAPABILITIES[pid]}
    return [{"id": key, **CAPABILITIES[key]} for key in REGISTRY]


# CLI
# ----------------------------------------------------------------------------
def _fmt_status(s: dict) -> str:
    icon = {"running": "🟢", "disabled": "⛔", "enabled_but_down": "🟠"}[s["state"]]
    svc = ", ".join(f"{x['name']}={'up' if x['active'] else 'down'}" for x in s["services"]) or "non installé"
    return (f"{icon} {s['id']:<10} {s['label']}\n    état={s['state']}  services: {svc}\n"
            f"    comptes: {s['accounts_active']}/{s['accounts_total']} actifs")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="tom-protocol")
    p.add_argument("cmd", choices=["list", "status", "enable", "disable", "restart", "logs", "ports", "errors", "capabilities", "config"])
    p.add_argument("id", nargs="?")
    p.add_argument("--json", action="store_true")
    p.add_argument("--lines", type=int, default=30)
    p.add_argument("--db", default=None)
    a = p.parse_args(argv)
    try:
        if a.cmd == "list":
            res = list_all(a.db)
        elif a.cmd == "capabilities":
            res = capabilities(a.id)
        else:
            if not a.id:
                p.error("id de protocole requis")
            res = {"status": lambda: status(a.id, a.db),
                   "enable": lambda: set_enabled(a.id, True, a.db),
                   "disable": lambda: set_enabled(a.id, False, a.db),
                   "restart": lambda: restart(a.id),
                   "logs": lambda: logs(a.id, a.lines),
                   "ports": lambda: ports(a.id),
                   "errors": lambda: errors(a.id),
                   "config": lambda: configure(a.id)}[a.cmd]()
    except KeyError as e:
        print(json.dumps({"ok": False, "message": str(e)}) if a.json else f"Erreur: {e}")
        return 2
    if a.json:
        print(json.dumps(res, ensure_ascii=False))
    elif a.cmd == "list":
        print("\n".join(_fmt_status(s) for s in res))
    elif a.cmd == "status":
        print(_fmt_status(res))
    elif a.cmd == "capabilities":
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print(res.get("message") or res.get("logs") or res.get("errors") or json.dumps(res, ensure_ascii=False))
    return 0 if (not isinstance(res, dict) or res.get("ok", True)) else 1


if __name__ == "__main__":
    sys.exit(main())
