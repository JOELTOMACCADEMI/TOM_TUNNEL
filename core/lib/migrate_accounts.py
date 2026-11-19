#!/usr/bin/env python3
"""
TOM_TUNNEL - One-shot migration of existing accounts into the central engine.

Idempotent: can be run multiple times safely.
Imports from:
  - /etc/xray/config.json  (VLESS, VMess, Trojan, SOCKS)
  - system users (SSH-like accounts with /bin/false)
  - /etc/tom_tunnel_bot/ssh_accounts/*.txt (bot files)

Does NOT delete or modify the original sources.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# Make the engine importable
sys.path.insert(0, str(Path(__file__).resolve().parent))
from account_engine import AccountEngine, STATUS_ACTIVE, get_engine

XRAY_CONFIG = Path(os.environ.get("XRAY_CONFIG", "/etc/xray/config.json"))
BOT_SSH_DIR = Path("/etc/tom_tunnel_bot/ssh_accounts")


def parse_xray_accounts(config_path: Path) -> list[dict]:
    """Parse comments in config.json that store username + expiry + uuid."""
    if not config_path.is_file():
        return []

    try:
        text = config_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    accounts = []
    # Patterns used by the original scripts
    # #& user exp uuid   → VLESS
    # ### user exp uuid  → VMess
    # #! user exp uuid   → Trojan
    # #@ user exp uuid   → SOCKS
    patterns = [
        (r"#&\s+(\S+)\s+(\d{4}-\d{2}-\d{2})\s+([0-9a-fA-F-]{36})", "vless"),
        (r"###\s+(\S+)\s+(\d{4}-\d{2}-\d{2})\s+([0-9a-fA-F-]{36})", "vmess"),
        (r"#!\s+(\S+)\s+(\d{4}-\d{2}-\d{2})\s+([0-9a-fA-F-]{36})", "trojan"),
        (r"#@\s+(\S+)\s+(\d{4}-\d{2}-\d{2})\s+([0-9a-fA-F-]{36})", "socks"),
    ]

    seen = set()
    for pat, proto in patterns:
        for m in re.finditer(pat, text):
            user, exp, uid = m.group(1), m.group(2), m.group(3)
            key = (user, proto)
            if key in seen:
                continue
            seen.add(key)
            accounts.append(
                {
                    "username": user,
                    "protocol": proto,
                    "expires_at": exp,
                    "uuid": uid,
                    "password": None,
                }
            )
    return accounts


def parse_system_ssh_accounts() -> list[dict]:
    """Find system users that look like SSH tunnel accounts."""
    accounts = []
    try:
        # Users with shell /bin/false or /usr/sbin/nologin and an expiry
        result = subprocess.run(
            ["getent", "passwd"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return []

        for line in result.stdout.splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            user, _, uid, _, _, home, shell = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]
            if not shell.endswith(("false", "nologin")):
                continue
            if int(uid) < 1000:  # skip system users
                continue
            # Get expiry via chage
            chage = subprocess.run(
                ["chage", "-l", user],
                capture_output=True,
                text=True,
                timeout=5,
            )
            exp = None
            if chage.returncode == 0:
                for cl in chage.stdout.splitlines():
                    if "Account expires" in cl:
                        val = cl.split(":", 1)[-1].strip()
                        if val and val.lower() != "never":
                            # try to normalise
                            try:
                                # chage can print "Jan 01, 2026" or "2026-01-01"
                                for fmt in ("%Y-%m-%d", "%b %d, %Y", "%d %b %Y"):
                                    try:
                                        exp = datetime.strptime(val, fmt).strftime("%Y-%m-%d")
                                        break
                                    except ValueError:
                                        continue
                            except Exception:
                                exp = None
                        break
            accounts.append(
                {
                    "username": user,
                    "protocol": "ssh",
                    "expires_at": exp,
                    "uuid": None,
                    "password": None,  # never stored
                }
            )
    except Exception:
        pass
    return accounts


def parse_bot_ssh_files() -> list[dict]:
    if not BOT_SSH_DIR.is_dir():
        return []
    accounts = []
    for f in BOT_SSH_DIR.glob("*.txt"):
        data = {}
        try:
            for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    data[k.strip()] = v.strip()
        except OSError:
            continue
        user = data.get("username") or data.get("user") or f.stem
        accounts.append(
            {
                "username": user,
                "protocol": "ssh",
                "expires_at": data.get("exp") or data.get("expires") or data.get("expiry"),
                "uuid": None,
                "password": data.get("password") or data.get("pass"),
                "extra": data,
            }
        )
    return accounts


def migrate(dry_run: bool = False, db_path: Path | None = None) -> dict:
    eng = get_engine(db_path)
    stats = {
        "xray_found": 0,
        "ssh_found": 0,
        "bot_found": 0,
        "created": 0,
        "skipped_existing": 0,
        "errors": [],
    }

    # 1. Xray
    xray_accs = parse_xray_accounts(XRAY_CONFIG)
    stats["xray_found"] = len(xray_accs)
    for a in xray_accs:
        existing = eng.get_account(a["username"], a["protocol"])
        if existing:
            stats["skipped_existing"] += 1
            continue
        if dry_run:
            stats["created"] += 1
            continue
        try:
            # Compute remaining days from expires_at
            days = 30
            if a.get("expires_at"):
                try:
                    exp_d = datetime.strptime(a["expires_at"], "%Y-%m-%d")
                    delta = (exp_d - datetime.utcnow()).days
                    days = max(1, delta)
                except ValueError:
                    pass
            eng.create_account(
                username=a["username"],
                protocol=a["protocol"],
                uuid_str=a.get("uuid"),
                days=days,
                quota_gb=0,  # unlimited by default (preserve current behaviour)
                ip_limit=0,
                conn_limit=0,
                notes="migrated_from_xray_config",
            )
            stats["created"] += 1
        except Exception as e:
            stats["errors"].append(f"xray {a['username']}: {e}")

    # 2. System SSH
    ssh_accs = parse_system_ssh_accounts()
    stats["ssh_found"] = len(ssh_accs)
    for a in ssh_accs:
        existing = eng.get_account(a["username"], "ssh")
        if existing:
            stats["skipped_existing"] += 1
            continue
        if dry_run:
            stats["created"] += 1
            continue
        try:
            days = 30
            if a.get("expires_at"):
                try:
                    exp_d = datetime.strptime(a["expires_at"], "%Y-%m-%d")
                    delta = (exp_d - datetime.utcnow()).days
                    days = max(1, delta)
                except ValueError:
                    pass
            eng.create_account(
                username=a["username"],
                protocol="ssh",
                days=days,
                quota_gb=0,
                ip_limit=0,
                conn_limit=0,
                notes="migrated_from_system_user",
            )
            stats["created"] += 1
        except Exception as e:
            stats["errors"].append(f"ssh {a['username']}: {e}")

    # 3. Bot files
    bot_accs = parse_bot_ssh_files()
    stats["bot_found"] = len(bot_accs)
    for a in bot_accs:
        existing = eng.get_account(a["username"], "ssh")
        if existing:
            stats["skipped_existing"] += 1
            continue
        if dry_run:
            stats["created"] += 1
            continue
        try:
            days = 30
            eng.create_account(
                username=a["username"],
                protocol="ssh",
                password=a.get("password"),
                days=days,
                quota_gb=0,
                ip_limit=0,
                conn_limit=0,
                notes="migrated_from_bot_files",
                extra_data=a.get("extra"),
            )
            stats["created"] += 1
        except Exception as e:
            stats["errors"].append(f"bot {a['username']}: {e}")

    return stats


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Migrate existing TOM_TUNNEL accounts")
    parser.add_argument("--dry-run", action="store_true", help="Only report what would be done")
    parser.add_argument("--db", help="Custom DB path")
    args = parser.parse_args()

    result = migrate(dry_run=args.dry_run, db_path=Path(args.db) if args.db else None)
    print(json.dumps(result, indent=2))
    if result["errors"]:
        sys.exit(1)
