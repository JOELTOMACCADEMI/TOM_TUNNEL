import html
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

CONF_FILE = Path("/etc/zivpn/config.json")
DB_FILE = Path("/etc/zivpn/user.db")
META_DIR = Path("/etc/tom_tunnel_bot/zivpn_accounts")
LEGACY_META_DIR = Path("/etc/nexus_bot/zivpn_accounts")
USER_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


def _esc(v):
    return html.escape(str(v if v is not None else ""), quote=False)


def _valid_user(user):
    return bool(USER_RE.fullmatch((user or "").strip()))


def _valid_password(password):
    return bool(password) and not re.search(r"\s", password) and len(password) <= 128


def _valid_days(days):
    try:
        n = int(str(days).strip())
        return n if 1 <= n <= 3650 else None
    except (TypeError, ValueError):
        return None


def _run(args, timeout=30):
    try:
        return subprocess.run(
            args,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def _meta_path(user):
    return META_DIR / f"{user}.txt"


def _find_meta(user):
    for path in (
        _meta_path(user),
        LEGACY_META_DIR / f"{user}.txt"
    ):
        if path.is_file():
            return path
    return None


def _read_meta(user):
    path = _find_meta(user)

    if not path:
        return {}

    data = {}

    try:
        for line in path.read_text(
            encoding="utf-8"
        ).splitlines():

            if "=" in line:
                k, v = line.split("=", 1)
                data[k] = v

    except OSError:
        pass

    return data


def _write_meta(user, data):
    META_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    path = _meta_path(user)

    path.write_text(
        "".join(
            f"{k}={v}\n"
            for k, v in data.items()
        ),
        encoding="utf-8"
    )

    os.chmod(path, 0o600)


def _server_info():
    try:
        domain = (
            Path("/etc/xray/domain")
            .read_text()
            .strip()
            or "N/A"
        )
    except OSError:
        domain = "N/A"

    ip = "N/A"

    result = _run(
        [
            "curl",
            "-4",
            "-fsS",
            "--max-time",
            "4",
            "https://ipv4.icanhazip.com"
        ],
        6
    )

    if (
        result
        and result.returncode == 0
        and result.stdout.strip()
    ):
        ip = result.stdout.strip()

    return domain, ip


def _load_config():
    with CONF_FILE.open(
        encoding="utf-8"
    ) as f:
        cfg = json.load(f)

    auth = cfg.setdefault(
        "auth",
        {}
    )

    passwords = auth.setdefault(
        "config",
        []
    )

    if not isinstance(passwords, list):
        raise ValueError(
            "auth.config n'est pas une liste"
        )

    return cfg, passwords


def _save_config(cfg):
    backup = CONF_FILE.with_suffix(
        ".json.bot.bak"
    )

    shutil.copy2(
        CONF_FILE,
        backup
    )

    tmp = CONF_FILE.with_suffix(
        ".json.tmp"
    )

    tmp.write_text(
        json.dumps(
            cfg,
            indent=2,
            ensure_ascii=False
        ) + "\n",
        encoding="utf-8"
    )

    os.replace(
        tmp,
        CONF_FILE
    )

    return backup


def _restart_or_restore(backup):
    result = _run(
        ["systemctl", "restart", "zivpn"],
        30
    )

    if result and result.returncode == 0:
        return True

    try:
        shutil.copy2(
            backup,
            CONF_FILE
        )
    except OSError:
        pass

    _run(
        ["systemctl", "restart", "zivpn"],
        30
    )

    return False


def create_zivpn_account(
    user, password, days, created_by_id=None,
    quota_gb=0, ip_limit=0, conn_limit=0
):
    """Create an isolated ZiVPN instance through the central per-user adapter."""
    user = str(user or "").strip()
    password = str(password or "")
    day_count = _valid_days(days)
    if not _valid_user(user):
        return False, "❌ Nom d'utilisateur ZIVPN invalide."
    if not _valid_password(password):
        return False, "❌ Mot de passe ZIVPN invalide."
    if day_count is None:
        return False, "❌ Durée invalide (1 à 3650 jours)."
    try:
        quota = float(quota_gb or 0)
        ips = int(ip_limit or 0)
        conns = int(conn_limit or 0)
        if quota < 0 or ips < 0 or conns < 0:
            raise ValueError("Quota et limites doivent être positifs ou nuls.")
        helper = Path(__file__).resolve().parents[2] / "core" / "lib" / "zivpn_engine.py"
        installed = Path("/usr/local/lib/tom_tunnel/zivpn_engine.py")
        if installed.is_file():
            helper = installed
        if not helper.is_file():
            raise RuntimeError("zivpn_engine.py introuvable. Relancez l'installation du moteur TOM_TUNNEL.")
        result = _run([
            "python3", str(helper), "create", user, password, str(day_count),
            "--quota", str(quota), "--ip-limit", str(ips), "--conn-limit", str(conns),
            "--created-by", str(created_by_id or "")
        ], 45)
        if not result or result.returncode != 0:
            detail = result.stdout if result else "commande indisponible"
            try:
                detail = json.loads(detail).get("error", detail)
            except Exception:
                pass
            return False, f"❌ Création ZiVPN impossible : <code>{_esc(detail)}</code>"
        payload = json.loads(result.stdout).get("data", {})
        domain, ip = _server_info()
        return True, (
            "╭▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬╮\n"
            "┃ <b>ZIVPN ACCOUNT</b>\n"
            "╰▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬╯\n"
            f"👤 Username : <code>{_esc(user)}</code>\n"
            f"🔑 Password : <code>{_esc(password)}</code>\n"
            f"📅 Expiry : <code>{_esc(payload.get('expiry'))}</code>\n"
            f"🖥️ IP : <code>{_esc(ip)}</code>\n"
            f"🌐 Domain : <code>{_esc(domain)}</code>\n"
            f"📡 Port : <code>{_esc(payload.get('port'))}/UDP</code>\n"
            f"📦 Quota : <code>{quota:g} Go</code>\n"
            f"🌐 IP max : <code>{ips or 'Illimité'}</code>\n"
            f"🔗 Flux max : <code>{conns or 'Illimité'}</code>\n"
            "⚙️ Comptabilisation par port dédié ; limites IP/flux vérifiées par conntrack.\n"
            "▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬"
        )
    except Exception as exc:
        return False, f"❌ Erreur ZiVPN : <code>{_esc(exc)}</code>"


def get_zivpn_usernames():
    names = set()

    if DB_FILE.is_file():
        for line in DB_FILE.read_text(
            encoding="utf-8"
        ).splitlines():

            parts = line.split()

            if (
                len(parts) >= 3
                and _valid_user(parts[0])
            ):
                names.add(parts[0])

    account_root = Path("/etc/zivpn/accounts")
    if account_root.is_dir():
        names.update(p.name for p in account_root.iterdir() if p.is_dir() and _valid_user(p.name))

    for directory in (
        META_DIR,
        LEGACY_META_DIR
    ):
        if directory.is_dir():

            for path in directory.glob("*.txt"):

                if _valid_user(path.stem):
                    names.add(path.stem)

    return sorted(names)


def get_zivpn_account_details(user):
    user = str(user or "").strip()

    if not _valid_user(user):
        return False, (
            "❌ Nom d'utilisateur invalide."
        )

    data = _read_meta(user)

    if not data:
        account_meta = Path("/etc/zivpn/accounts") / user / "account.json"
        if account_meta.is_file():
            try:
                data = json.loads(account_meta.read_text(encoding="utf-8"))
            except Exception:
                data = {}

    if not data and DB_FILE.is_file():

        for line in DB_FILE.read_text(
            encoding="utf-8"
        ).splitlines():

            parts = line.split()

            if (
                len(parts) >= 3
                and parts[0] == user
            ):
                data = {
                    "username": parts[0],
                    "password": parts[1],
                    "expiry": parts[2]
                }
                break

    if not data:
        return False, (
            f"❌ Compte ZIVPN "
            f"<code>{_esc(user)}</code> introuvable."
        )

    if (Path("/etc/zivpn/accounts") / user / "account.json").is_file():
        try:
            sys.path.insert(0, "/usr/local/lib/tom_tunnel")
            from account_engine import get_engine
            engine_account = get_engine().get_account(user, "zivpn") or {}
            data["password"] = engine_account.get("password", data.get("password", "N/A"))
            for field in ("quota_gb", "used_gb", "ip_limit", "conn_limit"):
                data[field] = engine_account.get(field, 0)
        except Exception:
            pass

    domain, ip = _server_info()

    return True, (
        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n"
        "┃ <b>ZIVPN ACCOUNT DETAILS</b>\n"
        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n"

        f"👤 <b>Username:</b> "
        f"<code>{_esc(user)}</code>\n"

        f"🔑 <b>Password:</b> "
        f"<code>{_esc(data.get('password', 'N/A'))}</code>\n"

        f"📅 <b>Expiry:</b> "
        f"<code>{_esc(data.get('expiry', 'N/A'))}</code>\n"

        f"🖥️ <b>IP:</b> "
        f"<code>{_esc(ip)}</code>\n"

        f"🌐 <b>Domain:</b> "
        f"<code>{_esc(domain)}</code>\n"

        f"📡 <b>Port:</b> "
        f"<code>{_esc(data.get('port', 5667))}/UDP</code>\n"
        f"📦 <b>Quota:</b> <code>{_esc(data.get('quota_gb', 0))} Go</code>\n"
        f"📊 <b>Utilisé:</b> <code>{_esc(data.get('used_gb', 0))} Go</code>\n"
        f"🌐 <b>IP max:</b> <code>{_esc(data.get('ip_limit', 0))}</code> | "
        f"🔗 <b>Flux max:</b> <code>{_esc(data.get('conn_limit', 0))}</code>"
    )


def renew_zivpn_account(user, days):
    user = str(user or "").strip()
    day_count = _valid_days(days)
    if not _valid_user(user) or day_count is None:
        return False, "❌ Nom d'utilisateur ou durée invalide."
    helper = Path("/usr/local/lib/tom_tunnel/zivpn_engine.py")
    if not helper.is_file(): helper = Path(__file__).resolve().parents[2] / "core" / "lib" / "zivpn_engine.py"
    if not (Path("/etc/zivpn/accounts") / user / "account.json").is_file():
        if not DB_FILE.is_file(): return False, "❌ Compte ZiVPN introuvable."
        lines=DB_FILE.read_text(encoding="utf-8").splitlines(); found=False; new_lines=[]; expiry=None
        for line in lines:
            parts=line.split()
            if len(parts)>=3 and parts[0]==user:
                found=True
                try:
                    base=datetime.strptime(parts[2], "%Y-%m-%d")
                    if base < datetime.now(): base=datetime.now()
                except ValueError: base=datetime.now()
                expiry=(base+timedelta(days=day_count)).strftime("%Y-%m-%d")
                new_lines.append(f"{parts[0]} {parts[1]} {expiry}")
            else: new_lines.append(line)
        if not found: return False, "❌ Compte ZiVPN introuvable."
        DB_FILE.write_text("\n".join(new_lines)+"\n",encoding="utf-8")
        return True, f"✅ <b>ZIVPN LEGACY RENOUVELÉ</b>\n👤 <code>{_esc(user)}</code>\n📅 <code>{_esc(expiry)}</code>"
    result = _run(["python3", str(helper), "renew", user, str(day_count)], 30)
    if not result or result.returncode != 0:
        return False, f"❌ Renouvellement ZiVPN impossible : <code>{_esc(result.stdout if result else 'commande indisponible')}</code>"
    payload = json.loads(result.stdout).get("data", {})
    return True, f"✅ <b>ZIVPN RENOUVELÉ</b>\n👤 <code>{_esc(user)}</code>\n📅 Expiration : <code>{_esc(payload.get('expiry'))}</code>\n📡 Port : <code>{_esc(payload.get('port'))}/UDP</code>"


def delete_zivpn_account(user):
    user = str(user or "").strip()
    if not _valid_user(user):
        return False, "❌ Nom d'utilisateur invalide."
    helper = Path("/usr/local/lib/tom_tunnel/zivpn_engine.py")
    if not helper.is_file():
        helper = Path(__file__).resolve().parents[2] / "core" / "lib" / "zivpn_engine.py"
    if not (Path("/etc/zivpn/accounts") / user / "account.json").is_file():
        if not DB_FILE.is_file(): return False, "❌ Compte ZiVPN introuvable."
        lines=DB_FILE.read_text(encoding="utf-8").splitlines(); kept=[]; password=None
        for line in lines:
            parts=line.split()
            if len(parts)>=2 and parts[0]==user: password=parts[1]
            else: kept.append(line)
        if password is None: return False, "❌ Compte ZiVPN introuvable."
        try:
            cfg, passwords=_load_config(); cfg["auth"]["config"]=[x for x in passwords if str(x)!=password]
            backup=_save_config(cfg)
            DB_FILE.write_text(("\n".join(kept)+"\n") if kept else "",encoding="utf-8")
            if not _restart_or_restore(backup): return False, "❌ ZiVPN legacy n'a pas redémarré ; configuration restaurée."
            return True, f"🗑️ <b>Compte ZiVPN legacy <code>{_esc(user)}</code> supprimé.</b>"
        except Exception as exc: return False, f"❌ Suppression legacy impossible : <code>{_esc(exc)}</code>"
    if not helper.is_file(): return False, "❌ Moteur ZiVPN individuel introuvable."
    result = _run(["python3", str(helper), "delete", user], 35)
    if not result or result.returncode != 0:
        detail = result.stdout if result else "commande indisponible"
        return False, f"❌ Suppression ZiVPN impossible : <code>{_esc(detail)}</code>"
    return True, f"🗑️ <b>Compte ZiVPN <code>{_esc(user)}</code> supprimé.</b>"


def list_zivpn_accounts():
    users = get_zivpn_usernames()

    if not users:
        return "📋 Aucun compte ZIVPN trouvé."

    lines = [
        "📋 <b>LISTE DES COMPTES ZIVPN</b>",
        ""
    ]

    for user in users:
        data = _read_meta(user)
        account_meta = Path("/etc/zivpn/accounts") / user / "account.json"
        if not data and account_meta.is_file():
            try: data = json.loads(account_meta.read_text(encoding="utf-8"))
            except Exception: data = {}

        if not data and DB_FILE.is_file():

            for line in DB_FILE.read_text(
                encoding="utf-8"
            ).splitlines():

                parts = line.split()

                if (
                    len(parts) >= 3
                    and parts[0] == user
                ):
                    data = {
                        "password": parts[1],
                        "expiry": parts[2]
                    }
                    break

        lines.append(
            f"👤 <code>{_esc(user)}</code> | "
            f"Exp: <code>"
            f"{_esc(data.get('expiry', 'N/A'))}"
            f"</code>"
        )

    lines.append(
        f"\n📊 <b>Total:</b> {len(users)}"
    )

    return "\n".join(lines)