#!/usr/bin/env python3
"""
TOM_TUNNEL - Central Account Engine
====================================
Single source of truth for accounts, quotas (GB), IP limits and concurrent
connection limits. Used by VPS menus (Bash), Telegram bot and Web panel.

Rules:
  - quota_gb  = 0  → unlimited
  - ip_limit  = 0  → unlimited
  - conn_limit= 0  → unlimited
  - All writes are transactional and locked.
  - Never expose passwords/UUIDs of other users.
  - Backward compatible with existing system users + /etc/xray/config.json

Author: TOM_TUNNEL evolution (quota system)
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Paths (production first, then fallback for development / testing)
# ---------------------------------------------------------------------------
_ENV_DB = os.environ.get("TOM_TUNNEL_DB")
_ENV_DB_DIR = os.environ.get("TOM_TUNNEL_DB_DIR")
DEFAULT_DB_PATHS = [
    Path(_ENV_DB) if _ENV_DB else (
        Path(_ENV_DB_DIR) / "tom_tunnel.db" if _ENV_DB_DIR else
        Path("/etc/tom_tunnel-tunnel-web/tom_tunnel.db")
    ),                                                               # shared panel/bot DB
    Path("/etc/tom_tunnel-web/data/tom_tunnel.db"),                  # legacy panel path
    Path("/etc/tom_tunnel/accounts.db"),                             # dedicated legacy DB
    Path("/var/lib/tom_tunnel/accounts.db"),
    Path(__file__).resolve().parent.parent.parent / "data" / "accounts.db",  # local dev
]

XRAY_CONFIG = Path(os.environ.get("XRAY_CONFIG", "/etc/xray/config.json"))
BOT_SSH_DIR = Path("/etc/tom_tunnel_bot/ssh_accounts")
LOCK_FILE = Path("/var/lock/tom_tunnel_account_engine.lock")

# Convention: 1 GB = 1024**3 bytes (GiB). Documented and unique.
BYTES_PER_GB = 1024 ** 3

# Status constants
STATUS_ACTIVE = "active"
STATUS_EXPIRED = "expired"
STATUS_QUOTA_EXHAUSTED = "quota_exhausted"
STATUS_SUSPENDED = "suspended"
STATUS_DELETED = "deleted"

VALID_STATUSES = {
    STATUS_ACTIVE,
    STATUS_EXPIRED,
    STATUS_QUOTA_EXHAUSTED,
    STATUS_SUSPENDED,
    STATUS_DELETED,
}

PROTOCOLS = {
    "ssh", "vless", "vmess", "trojan", "socks",
    "zivpn", "slowdns", "udpcustom", "openvpn", "ohp", "v2raydns",
}

# ---------------------------------------------------------------------------
# Thread-local + process lock
# ---------------------------------------------------------------------------
_local = threading.local()
_file_lock = threading.Lock()


def _find_db_path() -> Path:
    """Return the first existing DB path or the preferred production path."""
    for p in DEFAULT_DB_PATHS:
        if p.exists():
            return p
    # Prefer the panel location even if it does not exist yet
    preferred = DEFAULT_DB_PATHS[0]
    preferred.parent.mkdir(parents=True, exist_ok=True)
    return preferred


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


@contextmanager
def _db_connection(db_path: Optional[Path] = None):
    """Context manager with WAL mode and busy timeout."""
    path = Path(db_path) if db_path else _find_db_path()  # accept str or Path
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        str(path),
        timeout=30.0,
        isolation_level=None,  # autocommit off, we manage transactions
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
    finally:
        conn.close()


def _ensure_schema(conn: sqlite3.Connection) -> None:
    """Create or upgrade the schema. Fully idempotent."""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS clients (
            id              TEXT PRIMARY KEY,
            username        TEXT NOT NULL,
            password        TEXT,
            protocol        TEXT NOT NULL,
            plan_id         TEXT,
            expires_at      TEXT,
            status          TEXT NOT NULL DEFAULT 'active',
            created_by      TEXT,
            extra_data      TEXT,
            created_at      TEXT,
            updated_at      TEXT,

            -- Quota & limits (new)
            quota_gb        REAL NOT NULL DEFAULT 0,
            used_gb         REAL NOT NULL DEFAULT 0,
            ip_limit        INTEGER NOT NULL DEFAULT 0,
            conn_limit      INTEGER NOT NULL DEFAULT 0,
            last_activity   TEXT,
            last_ip         TEXT,
            notes           TEXT,
            uuid            TEXT
        );

        -- Unique constraint (username + protocol) – ignore if already present
        CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_user_proto
            ON clients(username, protocol);

        CREATE INDEX IF NOT EXISTS idx_clients_status ON clients(status);
        CREATE INDEX IF NOT EXISTS idx_clients_expires ON clients(expires_at);
        CREATE INDEX IF NOT EXISTS idx_clients_created_by ON clients(created_by);

        CREATE TABLE IF NOT EXISTS sessions_active (
            id              TEXT PRIMARY KEY,
            client_id       TEXT NOT NULL,
            username        TEXT NOT NULL,
            protocol        TEXT NOT NULL,
            ip              TEXT NOT NULL,
            conn_id         TEXT,
            started_at      TEXT NOT NULL,
            last_seen       TEXT NOT NULL,
            bytes_up        INTEGER NOT NULL DEFAULT 0,
            bytes_down      INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_sess_client ON sessions_active(client_id);
        CREATE INDEX IF NOT EXISTS idx_sess_ip ON sessions_active(ip);
        CREATE INDEX IF NOT EXISTS idx_sess_last ON sessions_active(last_seen);

        CREATE TABLE IF NOT EXISTS traffic_counters (
            client_id       TEXT PRIMARY KEY,
            bytes_up        INTEGER NOT NULL DEFAULT 0,
            bytes_down      INTEGER NOT NULL DEFAULT 0,
            last_update     TEXT,
            source          TEXT,
            FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS quota_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id       TEXT NOT NULL,
            username        TEXT NOT NULL,
            event_type      TEXT NOT NULL,
            used_gb         REAL,
            quota_gb        REAL,
            created_at      TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS engine_meta (
            key             TEXT PRIMARY KEY,
            value           TEXT
        );
        """
    )

    # Migration of older schemas (add missing columns safely)
    existing = {
        row[1]
        for row in conn.execute("PRAGMA table_info(clients)").fetchall()
    }
    migrations = [
        ("quota_gb", "REAL NOT NULL DEFAULT 0"),
        ("used_gb", "REAL NOT NULL DEFAULT 0"),
        ("ip_limit", "INTEGER NOT NULL DEFAULT 0"),
        ("conn_limit", "INTEGER NOT NULL DEFAULT 0"),
        ("last_activity", "TEXT"),
        ("last_ip", "TEXT"),
        ("notes", "TEXT"),
        ("uuid", "TEXT"),
    ]
    for col, typedef in migrations:
        if col not in existing:
            conn.execute(f"ALTER TABLE clients ADD COLUMN {col} {typedef}")

    conn.execute(
        "INSERT OR IGNORE INTO engine_meta (key, value) VALUES ('schema_version', '2')"
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class AccountEngine:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path else _find_db_path()
        with _db_connection(self.db_path) as conn:
            _ensure_schema(conn)

    # ---- helpers ----------------------------------------------------------

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        if row is None:
            return {}
        d = dict(row)
        # Computed remaining
        q = float(d.get("quota_gb") or 0)
        u = float(d.get("used_gb") or 0)
        if q <= 0:
            d["remaining_gb"] = -1.0  # unlimited
            d["quota_percent"] = 0.0
        else:
            d["remaining_gb"] = max(0.0, round(q - u, 4))
            d["quota_percent"] = round(min(100.0, (u / q) * 100), 2)
        return d

    # ---- CRUD -------------------------------------------------------------

    def get_account(
        self, username: str, protocol: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        with _db_connection(self.db_path) as conn:
            if protocol:
                row = conn.execute(
                    "SELECT * FROM clients WHERE username = ? AND protocol = ? AND status != ?",
                    (username, protocol, STATUS_DELETED),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM clients WHERE username = ? AND status != ? ORDER BY created_at DESC LIMIT 1",
                    (username, STATUS_DELETED),
                ).fetchone()
            return self._row_to_dict(row) if row else None

    def get_account_by_id(self, client_id: str) -> Optional[Dict[str, Any]]:
        with _db_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM clients WHERE id = ?", (client_id,)
            ).fetchone()
            return self._row_to_dict(row) if row else None

    def list_accounts(
        self,
        protocol: Optional[str] = None,
        status: Optional[str] = None,
        created_by: Optional[str] = None,
        near_quota: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM clients WHERE status != ?"
        params: List[Any] = [STATUS_DELETED]
        if protocol:
            query += " AND protocol = ?"
            params.append(protocol)
        if status:
            query += " AND status = ?"
            params.append(status)
        if created_by:
            query += " AND created_by = ?"
            params.append(created_by)
        query += " ORDER BY created_at DESC"

        with _db_connection(self.db_path) as conn:
            rows = conn.execute(query, params).fetchall()
            result = [self._row_to_dict(r) for r in rows]

        if near_quota is not None:
            result = [
                a
                for a in result
                if a.get("quota_gb", 0) > 0
                and a.get("quota_percent", 0) >= near_quota * 100
            ]
        return result

    def create_account(
        self,
        username: str,
        protocol: str,
        password: Optional[str] = None,
        uuid_str: Optional[str] = None,
        days: int = 30,
        quota_gb: float = 0,
        ip_limit: int = 0,
        conn_limit: int = 0,
        created_by: Optional[str] = None,
        plan_id: Optional[str] = None,
        extra_data: Optional[Dict] = None,
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        protocol = protocol.lower().strip()
        if protocol not in PROTOCOLS:
            raise ValueError(f"Unsupported protocol: {protocol}")
        if not username or len(username) > 32:
            raise ValueError("Invalid username")

        client_id = str(uuid.uuid4())
        now = _now()
        expires = (datetime.now(timezone.utc) + timedelta(days=max(1, days))).strftime("%Y-%m-%d")
        uid = uuid_str or (str(uuid.uuid4()) if protocol in ("vless", "vmess", "trojan", "socks", "v2raydns") else None)

        with _db_connection(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                # Check uniqueness
                exists = conn.execute(
                    "SELECT id FROM clients WHERE username = ? AND protocol = ? AND status != ?",
                    (username, protocol, STATUS_DELETED),
                ).fetchone()
                if exists:
                    raise ValueError(f"Account {username}/{protocol} already exists")

                conn.execute(
                    """
                    INSERT INTO clients (
                        id, username, password, protocol, plan_id, expires_at,
                        status, created_by, extra_data, created_at, updated_at,
                        quota_gb, used_gb, ip_limit, conn_limit, uuid, notes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
                    """,
                    (
                        client_id,
                        username,
                        password,
                        protocol,
                        plan_id,
                        expires,
                        STATUS_ACTIVE,
                        created_by,
                        json.dumps(extra_data or {}),
                        now,
                        now,
                        float(quota_gb),
                        int(ip_limit),
                        int(conn_limit),
                        uid,
                        notes,
                    ),
                )
                conn.execute(
                    "INSERT OR IGNORE INTO traffic_counters (client_id, bytes_up, bytes_down, last_update, source) VALUES (?, 0, 0, ?, ?)",
                    (client_id, now, "init"),
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

        return self.get_account_by_id(client_id)  # type: ignore

    def update_quota(
        self,
        username: str,
        protocol: str,
        quota_gb: Optional[float] = None,
        add_gb: Optional[float] = None,
        set_used_gb: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Update quota or add traffic credit. Returns updated account."""
        with _db_connection(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT * FROM clients WHERE username = ? AND protocol = ? AND status != ?",
                    (username, protocol, STATUS_DELETED),
                ).fetchone()
                if not row:
                    raise ValueError("Account not found")

                new_quota = float(row["quota_gb"])
                new_used = float(row["used_gb"])

                if quota_gb is not None:
                    new_quota = max(0.0, float(quota_gb))
                if add_gb is not None:
                    # Adding credit = increase quota (or decrease used)
                    new_quota = max(0.0, new_quota + float(add_gb))
                if set_used_gb is not None:
                    new_used = max(0.0, float(set_used_gb))

                # Auto status
                new_status = row["status"]
                if new_quota > 0 and new_used >= new_quota:
                    new_status = STATUS_QUOTA_EXHAUSTED
                elif new_status == STATUS_QUOTA_EXHAUSTED and (new_quota == 0 or new_used < new_quota):
                    new_status = STATUS_ACTIVE

                conn.execute(
                    """
                    UPDATE clients
                    SET quota_gb = ?, used_gb = ?, status = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (new_quota, new_used, new_status, _now(), row["id"]),
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

        return self.get_account(username, protocol)  # type: ignore

    def add_traffic(
        self,
        username: str,
        protocol: str,
        bytes_up: int = 0,
        bytes_down: int = 0,
        source: str = "collector",
    ) -> Dict[str, Any]:
        """Atomically add traffic. Converts bytes → GB with the unique convention."""
        if bytes_up < 0 or bytes_down < 0:
            raise ValueError("Traffic counters cannot be negative")

        added_gb = (bytes_up + bytes_down) / BYTES_PER_GB

        with _db_connection(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT id, quota_gb, used_gb, status FROM clients WHERE username = ? AND protocol = ? AND status != ?",
                    (username, protocol, STATUS_DELETED),
                ).fetchone()
                if not row:
                    conn.execute("ROLLBACK")
                    return {}

                new_used = float(row["used_gb"]) + added_gb
                new_status = row["status"]
                quota = float(row["quota_gb"])

                if quota > 0 and new_used >= quota and new_status == STATUS_ACTIVE:
                    new_status = STATUS_QUOTA_EXHAUSTED
                    # Log event
                    conn.execute(
                        "INSERT INTO quota_events (client_id, username, event_type, used_gb, quota_gb) VALUES (?, ?, '100pct', ?, ?)",
                        (row["id"], username, new_used, quota),
                    )

                conn.execute(
                    "UPDATE clients SET used_gb = ?, status = ?, last_activity = ?, updated_at = ? WHERE id = ?",
                    (new_used, new_status, _now(), _now(), row["id"]),
                )
                conn.execute(
                    """
                    INSERT INTO traffic_counters (client_id, bytes_up, bytes_down, last_update, source)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(client_id) DO UPDATE SET
                        bytes_up = bytes_up + excluded.bytes_up,
                        bytes_down = bytes_down + excluded.bytes_down,
                        last_update = excluded.last_update,
                        source = excluded.source
                    """,
                    (row["id"], bytes_up, bytes_down, _now(), source),
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

        return self.get_account(username, protocol) or {}

    def set_limits(
        self,
        username: str,
        protocol: str,
        ip_limit: Optional[int] = None,
        conn_limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        with _db_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT id FROM clients WHERE username = ? AND protocol = ? AND status != ?",
                (username, protocol, STATUS_DELETED),
            ).fetchone()
            if not row:
                raise ValueError("Account not found")

            updates = []
            params: List[Any] = []
            if ip_limit is not None:
                updates.append("ip_limit = ?")
                params.append(max(0, int(ip_limit)))
            if conn_limit is not None:
                updates.append("conn_limit = ?")
                params.append(max(0, int(conn_limit)))
            if not updates:
                return self.get_account(username, protocol)  # type: ignore

            updates.append("updated_at = ?")
            params.append(_now())
            params.append(row["id"])
            conn.execute(
                f"UPDATE clients SET {', '.join(updates)} WHERE id = ?",
                params,
            )
            conn.commit()
        return self.get_account(username, protocol)  # type: ignore

    def set_status(
        self, username: str, protocol: str, status: str
    ) -> Dict[str, Any]:
        if status not in VALID_STATUSES:
            raise ValueError(f"Invalid status: {status}")
        with _db_connection(self.db_path) as conn:
            conn.execute(
                "UPDATE clients SET status = ?, updated_at = ? WHERE username = ? AND protocol = ?",
                (status, _now(), username, protocol),
            )
            conn.commit()
        return self.get_account(username, protocol)  # type: ignore

    def renew(
        self, username: str, protocol: str, days: int
    ) -> Dict[str, Any]:
        if days < 1:
            raise ValueError("days must be >= 1")
        with _db_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT id, expires_at, status FROM clients WHERE username = ? AND protocol = ? AND status != ?",
                (username, protocol, STATUS_DELETED),
            ).fetchone()
            if not row:
                raise ValueError("Account not found")

            base = datetime.now(timezone.utc)
            if row["expires_at"]:
                try:
                    current = datetime.strptime(row["expires_at"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
                    if current > base:
                        base = current
                except ValueError:
                    pass
            new_exp = (base + timedelta(days=days)).strftime("%Y-%m-%d")
            new_status = STATUS_ACTIVE if row["status"] in (STATUS_EXPIRED, STATUS_SUSPENDED) else row["status"]

            conn.execute(
                "UPDATE clients SET expires_at = ?, status = ?, updated_at = ? WHERE id = ?",
                (new_exp, new_status, _now(), row["id"]),
            )
            conn.commit()
        return self.get_account(username, protocol)  # type: ignore

    def delete_account(self, username: str, protocol: str, hard: bool = False) -> bool:
        with _db_connection(self.db_path) as conn:
            if hard:
                conn.execute(
                    "DELETE FROM clients WHERE username = ? AND protocol = ?",
                    (username, protocol),
                )
            else:
                conn.execute(
                    "UPDATE clients SET status = ?, updated_at = ? WHERE username = ? AND protocol = ?",
                    (STATUS_DELETED, _now(), username, protocol),
                )
            conn.commit()
            return conn.total_changes > 0

    # ---- Sessions & limits ------------------------------------------------

    def register_session(
        self,
        username: str,
        protocol: str,
        ip: str,
        conn_id: Optional[str] = None,
        check_conn: bool = True,
    ) -> Tuple[bool, str]:
        """
        Try to register a new session.
        Returns (allowed: bool, reason: str)
        """
        with _db_connection(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT id, status, quota_gb, used_gb, ip_limit, conn_limit, expires_at FROM clients WHERE username = ? AND protocol = ? AND status != ?",
                    (username, protocol, STATUS_DELETED),
                ).fetchone()
                if not row:
                    conn.execute("ROLLBACK")
                    return False, "account_not_found"

                if row["status"] in (STATUS_SUSPENDED, STATUS_DELETED):
                    conn.execute("ROLLBACK")
                    return False, "account_suspended"
                if row["status"] == STATUS_QUOTA_EXHAUSTED:
                    conn.execute("ROLLBACK")
                    return False, "quota_exhausted"
                if row["expires_at"] and row["expires_at"] < _today():
                    conn.execute(
                        "UPDATE clients SET status = ? WHERE id = ?",
                        (STATUS_EXPIRED, row["id"]),
                    )
                    conn.execute("COMMIT")
                    return False, "expired"

                # Clean old sessions first (ghost connections)
                cutoff = (datetime.now(timezone.utc) - timedelta(minutes=20)).strftime("%Y-%m-%d %H:%M:%S")
                conn.execute(
                    "DELETE FROM sessions_active WHERE client_id = ? AND last_seen < ?",
                    (row["id"], cutoff),
                )

                # Count current
                ips = conn.execute(
                    "SELECT COUNT(DISTINCT ip) FROM sessions_active WHERE client_id = ?",
                    (row["id"],),
                ).fetchone()[0]
                conns = conn.execute(
                    "SELECT COUNT(*) FROM sessions_active WHERE client_id = ?",
                    (row["id"],),
                ).fetchone()[0]

                ip_limit = int(row["ip_limit"] or 0)
                conn_limit = int(row["conn_limit"] or 0)

                # Check if this IP is already known
                existing_ip = conn.execute(
                    "SELECT id FROM sessions_active WHERE client_id = ? AND ip = ?",
                    (row["id"], ip),
                ).fetchone()

                if ip_limit > 0 and not existing_ip and ips >= ip_limit:
                    conn.execute("ROLLBACK")
                    return False, "ip_limit_reached"

                if check_conn and conn_limit > 0 and conns >= conn_limit:
                    conn.execute("ROLLBACK")
                    return False, "conn_limit_reached"

                # Register
                sess_id = str(uuid.uuid4())
                now = _now()
                conn.execute(
                    """
                    INSERT INTO sessions_active
                    (id, client_id, username, protocol, ip, conn_id, started_at, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (sess_id, row["id"], username, protocol, ip, conn_id, now, now),
                )
                conn.execute(
                    "UPDATE clients SET last_activity = ?, last_ip = ?, updated_at = ? WHERE id = ?",
                    (now, ip, now, row["id"]),
                )
                conn.execute("COMMIT")
                return True, "ok"
            except Exception as e:
                conn.execute("ROLLBACK")
                return False, f"error:{e}"

    def unregister_session(
        self, username: str, protocol: str, ip: Optional[str] = None, conn_id: Optional[str] = None
    ) -> None:
        with _db_connection(self.db_path) as conn:
            if conn_id:
                conn.execute(
                    "DELETE FROM sessions_active WHERE username = ? AND protocol = ? AND conn_id = ?",
                    (username, protocol, conn_id),
                )
            elif ip:
                conn.execute(
                    "DELETE FROM sessions_active WHERE username = ? AND protocol = ? AND ip = ?",
                    (username, protocol, ip),
                )
            else:
                # Remove all for this user (rare)
                conn.execute(
                    "DELETE FROM sessions_active WHERE username = ? AND protocol = ?",
                    (username, protocol),
                )
            conn.commit()

    def get_active_sessions(self, username: Optional[str] = None, protocol: Optional[str] = None) -> List[Dict]:
        query = "SELECT * FROM sessions_active WHERE 1=1"
        params: List[Any] = []
        if username:
            query += " AND username = ?"
            params.append(username)
        if protocol:
            query += " AND protocol = ?"
            params.append(protocol)
        query += " ORDER BY last_seen DESC"
        with _db_connection(self.db_path) as conn:
            return [dict(r) for r in conn.execute(query, params).fetchall()]

    def sync_sessions(
        self, protocol: str, live: Dict[str, Tuple[str, str]], check_conn: bool = True
    ) -> Dict[str, List]:
        """
        Reconcile sessions_active with sessions really observed on the system.

        live = {conn_id: (username, ip)}
        - unknown live sessions are registered through register_session()
          (limits enforced there); refused ones are returned in "denied"
        - known sessions get last_seen refreshed
        - DB sessions of this protocol that are no longer live are deleted
        Returns {"denied": [(conn_id, username, ip, reason)], "removed": n}
        """
        denied: List[Tuple[str, str, str, str]] = []
        with _db_connection(self.db_path) as conn:
            known = {
                r["conn_id"]
                for r in conn.execute(
                    "SELECT conn_id FROM sessions_active WHERE protocol = ?", (protocol,)
                ).fetchall()
            }
            now = _now()
            for cid in known & set(live):
                conn.execute(
                    "UPDATE sessions_active SET last_seen = ? WHERE protocol = ? AND conn_id = ?",
                    (now, protocol, cid),
                )
            gone = known - set(live)
            for cid in gone:
                conn.execute(
                    "DELETE FROM sessions_active WHERE protocol = ? AND conn_id = ?",
                    (protocol, cid),
                )
            conn.commit()
        for cid in sorted(set(live) - known):
            user, ip = live[cid]
            ok, reason = self.register_session(user, protocol, ip, cid, check_conn=check_conn)
            if not ok and reason != "account_not_found":
                denied.append((cid, user, ip, reason))
        return {"denied": denied, "removed": len(gone)}

    def cleanup_sessions(self, max_age_minutes: int = 20) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=max_age_minutes)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        with _db_connection(self.db_path) as conn:
            cur = conn.execute(
                "DELETE FROM sessions_active WHERE last_seen < ?", (cutoff,)
            )
            conn.commit()
            return cur.rowcount

    # ---- Display helpers (for SSH MOTD / menus) ---------------------------

    def format_account_banner(self, username: str, protocol: str = "ssh") -> str:
        acc = self.get_account(username, protocol)
        if not acc:
            return (
                "╔══════════════════════════════════════╗\n"
                "║            TOM_TUNNEL                ║\n"
                "╠══════════════════════════════════════╣\n"
                "║  Account data unavailable            ║\n"
                "╚══════════════════════════════════════╝"
            )

        q = acc.get("quota_gb", 0)
        used = acc.get("used_gb", 0)
        rem = acc.get("remaining_gb", -1)
        pct = acc.get("quota_percent", 0)
        exp = acc.get("expires_at") or "N/A"
        status = (acc.get("status") or "unknown").upper()
        ip_lim = acc.get("ip_limit", 0)
        conn_lim = acc.get("conn_limit", 0)

        # Live session counts
        sessions = self.get_active_sessions(username, protocol)
        cur_ips = len({s["ip"] for s in sessions})
        cur_conns = len(sessions)

        quota_str = "Unlimited" if q <= 0 else f"{q:.2f} GB"
        used_str = f"{used:.2f} GB"
        rem_str = "Unlimited" if rem < 0 else f"{rem:.2f} GB"
        ip_str = "Unlimited" if ip_lim <= 0 else f"{cur_ips} / {ip_lim}"
        conn_str = "Unlimited" if conn_lim <= 0 else f"{cur_conns} / {conn_lim}"

        lines = [
            "╔══════════════════════════════════════╗",
            "║            TOM_TUNNEL                ║",
            "╠══════════════════════════════════════╣",
            f"║ USER       : {username:<24} ║",
            f"║ QUOTA      : {quota_str:<24} ║",
            f"║ USED       : {used_str:<24} ║",
            f"║ REMAINING  : {rem_str:<24} ║",
            f"║ USAGE      : {pct:.1f}%{'':<20} ║",
            f"║ EXPIRES    : {exp:<24} ║",
            f"║ IP LIMIT   : {ip_str:<24} ║",
            f"║ CONNECTION : {conn_str:<24} ║",
            f"║ STATUS     : {status:<24} ║",
            "╚══════════════════════════════════════╝",
        ]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Convenience singleton for simple scripts
# ---------------------------------------------------------------------------
_engine: Optional[AccountEngine] = None


def get_engine(db_path: Optional[Path | str] = None) -> AccountEngine:
    global _engine
    path = Path(db_path) if db_path else None
    if _engine is None or (path and path != _engine.db_path):
        _engine = AccountEngine(path)
    return _engine


# ---------------------------------------------------------------------------
# CLI for testing / Bash integration
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="TOM_TUNNEL Account Engine CLI")
    parser.add_argument("--db", help="Path to SQLite DB")
    sub = parser.add_subparsers(dest="cmd")

    # create
    p_create = sub.add_parser("create")
    p_create.add_argument("username")
    p_create.add_argument("protocol")
    p_create.add_argument("--password", default="")
    p_create.add_argument("--days", type=int, default=30)
    p_create.add_argument("--quota", type=float, default=0)
    p_create.add_argument("--ip-limit", type=int, default=0)
    p_create.add_argument("--conn-limit", type=int, default=0)

    # get
    p_get = sub.add_parser("get")
    p_get.add_argument("username")
    p_get.add_argument("--protocol", default=None)

    # list
    p_list = sub.add_parser("list")
    p_list.add_argument("--protocol", default=None)
    p_list.add_argument("--near-quota", type=float, default=None)

    # traffic
    p_traf = sub.add_parser("add-traffic")
    p_traf.add_argument("username")
    p_traf.add_argument("protocol")
    p_traf.add_argument("--up", type=int, default=0)
    p_traf.add_argument("--down", type=int, default=0)

    # banner
    p_ban = sub.add_parser("banner")
    p_ban.add_argument("username")
    p_ban.add_argument("--protocol", default="ssh")

    # management commands (used by menus, bot and scripts)
    p = sub.add_parser("set-quota")
    p.add_argument("username"); p.add_argument("protocol")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--quota", type=float, help="new total quota in GB (0 = unlimited)")
    g.add_argument("--add", type=float, help="add GB of credit (negative removes)")
    g.add_argument("--reset-used", action="store_true", help="set consumed traffic to 0")
    p = sub.add_parser("set-limits")
    p.add_argument("username"); p.add_argument("protocol")
    p.add_argument("--ip-limit", type=int, default=None); p.add_argument("--conn-limit", type=int, default=None)
    p = sub.add_parser("renew")
    p.add_argument("username"); p.add_argument("protocol"); p.add_argument("--days", type=int, required=True)
    p = sub.add_parser("status")
    p.add_argument("username"); p.add_argument("protocol")
    p.add_argument("value", choices=sorted(VALID_STATUSES))
    p = sub.add_parser("delete")
    p.add_argument("username"); p.add_argument("protocol"); p.add_argument("--hard", action="store_true")
    p = sub.add_parser("sessions")
    p.add_argument("--username", default=None); p.add_argument("--protocol", default=None)

    # migrate schema only
    sub.add_parser("init-schema")

    args = parser.parse_args()
    eng = get_engine(Path(args.db) if args.db else None)

    if args.cmd == "create":
        acc = eng.create_account(
            args.username,
            args.protocol,
            password=args.password or None,
            days=args.days,
            quota_gb=args.quota,
            ip_limit=args.ip_limit,
            conn_limit=args.conn_limit,
        )
        print(json.dumps(acc, indent=2, default=str))
    elif args.cmd == "get":
        acc = eng.get_account(args.username, args.protocol)
        print(json.dumps(acc, indent=2, default=str) if acc else "null")
    elif args.cmd == "list":
        accs = eng.list_accounts(protocol=args.protocol, near_quota=args.near_quota)
        print(json.dumps(accs, indent=2, default=str))
    elif args.cmd == "add-traffic":
        acc = eng.add_traffic(args.username, args.protocol, args.up, args.down)
        print(json.dumps(acc, indent=2, default=str))
    elif args.cmd == "set-quota":
        if args.reset_used:
            acc = eng.update_quota(args.username, args.protocol, set_used_gb=0)
        else:
            acc = eng.update_quota(args.username, args.protocol, quota_gb=args.quota, add_gb=args.add)
        print(json.dumps(acc, indent=2, default=str))
    elif args.cmd == "set-limits":
        print(json.dumps(eng.set_limits(args.username, args.protocol, args.ip_limit, args.conn_limit), indent=2, default=str))
    elif args.cmd == "renew":
        print(json.dumps(eng.renew(args.username, args.protocol, args.days), indent=2, default=str))
    elif args.cmd == "status":
        print(json.dumps(eng.set_status(args.username, args.protocol, args.value), indent=2, default=str))
    elif args.cmd == "delete":
        print(json.dumps({"deleted": eng.delete_account(args.username, args.protocol, hard=args.hard)}))
    elif args.cmd == "sessions":
        print(json.dumps(eng.get_active_sessions(args.username, args.protocol), indent=2, default=str))
    elif args.cmd == "banner":
        print(eng.format_account_banner(args.username, args.protocol))
    elif args.cmd == "init-schema":
        print(f"Schema initialized at {eng.db_path}")
    else:
        parser.print_help()
        sys.exit(1)
