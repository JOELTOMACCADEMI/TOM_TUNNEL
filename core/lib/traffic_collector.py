#!/usr/bin/env python3
"""
TOM_TUNNEL — Traffic collector + enforcement (run every minute by systemd timer)

What it does on each run:
  1. Xray: reads cumulative per-user counters, computes the DELTA against a
     stored baseline (no double counting, survives Xray restarts) and adds it
     to the engine.
  2. SSH / Dropbear: detects live sessions (user + client IP), registers them
     in the engine (IP / connection limits enforced) and kills refused ones.
  3. Marks expired accounts.
  4. Enforcement: accounts that are not "active" (quota_exhausted, expired,
     suspended) are blocked (SSH: password lock + kill; Xray: client id
     neutralised in config.json, restored on reactivation). Reactivated
     accounts are unblocked. Everything is idempotent.

ZiVPN is handled by the dedicated zivpn_engine.py sampler (10-second timer),
not by this general collector. SlowDNS, UDP Custom and OHP remain
unattributed per user in the current collector. OpenVPN is metered from its
per-client status files and limited through its local management interfaces.
Convention: 1 GB = 1024**3 bytes (same as account_engine).
"""

from __future__ import annotations

import json
import logging
import os
import pwd
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import uuid as uuidlib
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from account_engine import get_engine, _db_connection  # noqa: E402

XRAY_API = os.environ.get("XRAY_API", "127.0.0.1:10085")
XRAY_CONFIG = os.environ.get("XRAY_CONFIG", "/etc/xray/config.json")
LOG_FILE = os.environ.get("TOM_ENFORCE_LOG", "/var/log/tom-tunnel-enforce.log")
XRAY_PROTOS = ("vless", "vmess", "trojan", "v2raydns")
MARKER_PROTO = {"#&": "vless", "###": "vmess", "#!": "trojan", "#VDNS": "v2raydns", "#@": "socks"}
# Protocols whose Xray clients can be neutralised (expiry/suspend/disabled protocol).
# socks is blocked but not metered (no per-user Xray stats mapping for it).
XRAY_BLOCK_PROTOS = XRAY_PROTOS + ("socks",)


def disabled_protocols(eng) -> set:
    """Engine protocols whose accounts are blocked because the admin disabled the protocol."""
    try:
        import protocol_manager
        return protocol_manager.disabled_account_protocols(eng)
    except Exception as e:  # noqa: BLE001  never break enforcement because of this
        log.info("disabled_protocols unavailable: %s", e)
        return set()

log = logging.getLogger("tom-collector")


def _setup_log() -> None:
    if log.handlers:
        return
    log.setLevel(logging.INFO)
    try:
        h: logging.Handler = logging.FileHandler(LOG_FILE)
    except OSError:
        h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    log.addHandler(h)


def _run(cmd, timeout=15):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None


# --------------------------------------------------------------------------
# 1. Xray traffic (delta against baseline)
# --------------------------------------------------------------------------
def parse_xray_stats(text: str) -> dict:
    """Parse `xray api statsquery` output (JSON in recent versions, text before)."""
    out: dict = {}

    def put(user, direction, value):
        out.setdefault(user, {"up": 0, "down": 0})[direction] = int(value)

    try:
        data = json.loads(text)
        for st in data.get("stat", []):
            parts = st.get("name", "").split(">>>")
            if len(parts) == 4 and parts[0] == "user":
                put(parts[1], "up" if parts[3] == "uplink" else "down", st.get("value", 0) or 0)
        return out
    except (ValueError, AttributeError):
        pass
    for line in text.splitlines():  # legacy text format
        m = re.search(r"user>>>(.+?)>>>traffic>>>(uplink|downlink).*?(\d+)\s*$", line)
        if m:
            put(m.group(1), "up" if m.group(2) == "uplink" else "down", m.group(3))
    return out


def collect_xray_stats() -> dict:
    proc = _run(["xray", "api", "statsquery", f"--server={XRAY_API}", "-pattern", "user>>>"])
    if not proc or proc.returncode != 0 or not proc.stdout:
        return {}
    return parse_xray_stats(proc.stdout)


def _meta_get(conn, key):
    r = conn.execute("SELECT value FROM engine_meta WHERE key = ?", (key,)).fetchone()
    return r["value"] if r else None


def _meta_set(conn, key, value):
    conn.execute("INSERT OR REPLACE INTO engine_meta (key, value) VALUES (?, ?)", (key, str(value)))


def apply_xray_deltas(eng, stats: dict, report: dict) -> None:
    for email, cnt in stats.items():
        acc = None
        proto = None
        for p in XRAY_PROTOS + ("socks",):
            acc = eng.get_account(email, p)
            if acc:
                proto = p
                break
        if not acc:
            continue
        with _db_connection(eng.db_path) as conn:
            deltas = {}
            for d in ("up", "down"):
                base = _meta_get(conn, f"xray_base:{email}:{d}")
                cur = int(cnt.get(d, 0))
                base = int(base) if base is not None else None
                if base is None:
                    # First observation: counters since Xray start belong to this account
                    deltas[d] = cur
                elif cur >= base:
                    deltas[d] = cur - base
                else:  # Xray restarted: counter began again from 0
                    deltas[d] = cur
        try:
            if deltas["up"] or deltas["down"]:
                eng.add_traffic(email, proto, bytes_up=deltas["up"], bytes_down=deltas["down"], source="xray")
            # Baseline stored only after a successful add (a crash in between
            # can at worst re-count one interval, never lose traffic).
            with _db_connection(eng.db_path) as conn:
                for d in ("up", "down"):
                    _meta_set(conn, f"xray_base:{email}:{d}", int(cnt.get(d, 0)))
                conn.commit()
            report["xray"] += 1
        except Exception as e:  # noqa: BLE001
            report["errors"].append(f"xray {email}/{proto}: {e}")


# --------------------------------------------------------------------------
# 2. SSH / Dropbear sessions
# --------------------------------------------------------------------------
_SS_RE = re.compile(r"^\S+\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s+users:\((.*)\)\s*$")


def parse_ss(text: str, with_bytes: bool = False) -> list:
    """
    Return [(local, remote, [(procname, pid), ...])] from `ss -Htnp`.
    With `ss -Htnpi` output and with_bytes=True each row gets a 4th item
    (bytes_received, bytes_acked) read from the tcp_info continuation line.
    """
    rows = []
    for line in text.splitlines():
        if line[:1].isspace() and rows and with_bytes:
            rx = re.search(r"\bbytes_received:(\d+)", line)
            tx = re.search(r"\bbytes_acked:(\d+)", line)
            if rx or tx:
                rows[-1] = rows[-1][:3] + ((int(rx.group(1)) if rx else 0, int(tx.group(1)) if tx else 0),)
            continue
        m = _SS_RE.match(line.strip())
        if not m:
            continue
        procs = [(n, int(p)) for n, p in re.findall(r'\("([^"]+)",pid=(\d+)', m.group(3))]
        rows.append((m.group(1), m.group(2), procs, (0, 0)))
    return rows if with_bytes else [r[:3] for r in rows]


def _split_addr(addr: str):
    host, _, port = addr.rpartition(":")
    return host.strip("[]"), port


def _proc_user(name: str, pid: int):
    """Username owning an sshd / dropbear session process, or None."""
    try:
        if name == "sshd":
            cmd = Path(f"/proc/{pid}/cmdline").read_bytes().decode(errors="ignore").replace("\0", " ")
            m = re.match(r"sshd: (\S+?)(?:@\S+| \[priv\])", cmd)
            return m.group(1) if m else None
        if name == "dropbear":
            for line in Path(f"/proc/{pid}/status").read_text().splitlines():
                if line.startswith("Uid:"):
                    uid = int(line.split()[1])
                    return pwd.getpwuid(uid).pw_name if uid != 0 else None
    except (OSError, KeyError, ValueError):
        return None
    return None


def collect_ssh_sessions(ss_text=None, user_of=_proc_user, counters=None):
    """
    Return (live {conn_id: (user, ip)}, pids {conn_id: [pid,...]}).
    If `counters` is a dict it is filled with {conn_id: (bytes_up, bytes_down)}
    as seen from the server: up = received from the client, down = sent to it.
    """
    if ss_text is None:
        proc = _run(["ss", "-Htnpi", "state", "established"])
        ss_text = proc.stdout if proc and proc.returncode == 0 else ""
    live, pids = {}, {}
    for local, remote, procs, (rx, tx) in parse_ss(ss_text, with_bytes=True):
        cand = [(n, p) for n, p in procs if n in ("sshd", "dropbear")]
        if not cand:
            continue
        user = next((u for u in (user_of(n, p) for n, p in cand) if u), None)
        if not user:
            continue
        ip, port = _split_addr(remote)
        cid = f"{ip}:{port}>{_split_addr(local)[1]}"
        live[cid] = (user, ip)
        pids[cid] = [p for _, p in cand]
        if counters is not None:
            counters[cid] = (rx, tx)
    return live, pids


def sync_ssh(eng, report: dict, ss_text=None, user_of=_proc_user, kill=os.kill):
    counters: dict = {}
    live, pids = collect_ssh_sessions(ss_text, user_of, counters)
    # only users known to the engine
    live = {c: v for c, v in live.items() if eng.get_account(v[0], "ssh")}
    res = eng.sync_sessions("ssh", live)
    for cid, user, ip, reason in res["denied"]:
        for pid in pids.get(cid, []):
            try:
                kill(pid, signal.SIGKILL)
            except OSError:
                pass
        log.info("DENIED ssh user=%s ip=%s reason=%s (session killed)", user, ip, reason)
        report["denied"].append((user, ip, reason))
    report["sessions_removed"] = res["removed"]
    denied_ids = {d[0] for d in res["denied"]}
    count_ssh_traffic(eng, live, counters, denied_ids, report)
    return res


def count_ssh_traffic(eng, live: dict, counters: dict, denied_ids: set, report: dict) -> None:
    """
    Per-user SSH/Dropbear traffic = bytes of the client<->server TCP socket
    (both directions, includes SSH protocol overhead). Per-connection deltas
    against a stored baseline; baseline removed when the connection closes.
    Limitation: bytes sent between the last poll and the close of a connection
    (< 1 poll interval) are not counted.
    """
    totals: dict = {}
    with _db_connection(eng.db_path) as conn:
        stored = {
            r["key"][len("ssh_cb:"):]: r["value"]
            for r in conn.execute("SELECT key, value FROM engine_meta WHERE key LIKE 'ssh_cb:%'").fetchall()
        }
        for cid, (rx, tx) in counters.items():
            if cid in denied_ids or cid not in live:
                continue
            user = live[cid][0]
            base = stored.get(cid)
            if base is not None:
                b_rx, b_tx = (int(x) for x in base.split(","))
            else:
                b_rx = b_tx = 0
            d_rx = rx - b_rx if rx >= b_rx else rx
            d_tx = tx - b_tx if tx >= b_tx else tx
            t = totals.setdefault(user, [0, 0])
            t[0] += d_rx
            t[1] += d_tx
        for cid in set(stored) - set(live):
            conn.execute("DELETE FROM engine_meta WHERE key = ?", (f"ssh_cb:{cid}",))
        conn.commit()
    failed = set()
    for user, (up, down) in totals.items():
        if up or down:
            try:
                eng.add_traffic(user, "ssh", bytes_up=up, bytes_down=down, source="ssh")
            except Exception as e:  # noqa: BLE001
                failed.add(user)  # its baselines stay -> retried next run
                report["errors"].append(f"ssh traffic {user}: {e}")
    with _db_connection(eng.db_path) as conn:
        for cid, (rx, tx) in counters.items():
            if cid in live and cid not in denied_ids and live[cid][0] not in failed:
                _meta_set(conn, f"ssh_cb:{cid}", f"{rx},{tx}")
        conn.commit()


# --------------------------------------------------------------------------
# 2b. Xray client IPs (needs the real client IP in Xray's access log, see
#     core/lib/xray_realip.py) → IP limit with a cooldown ban
# --------------------------------------------------------------------------
XRAY_ACCESS_LOG = os.environ.get("XRAY_ACCESS_LOG", "/var/log/xray/access.log")
XRAY_IP_WINDOW = int(os.environ.get("XRAY_IP_WINDOW", "120"))      # seconds an IP counts as active
XRAY_BAN_SECONDS = int(os.environ.get("XRAY_BAN_SECONDS", "600"))  # account cooldown after an IP-limit breach
_ACC_RE = re.compile(
    r"^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d)(?:\.\d+)?\s+(?:from\s+)?(\[[0-9a-fA-F:.]+\]|[0-9.]+):\d+\s+accepted\s.*?email:\s*(\S+)\s*$"
)
LOOPBACK = {"127.0.0.1", "::1"}


def parse_xray_access(text: str, now=None, window=XRAY_IP_WINDOW):
    """Return ({email: {ip,...}} for recent lines, loopback_seen: bool)."""
    now = now or datetime.now()
    out: dict = {}
    loop = False
    for line in text.splitlines():
        m = _ACC_RE.match(line.strip())
        if not m:
            continue
        try:
            ts = datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S")
        except ValueError:
            continue
        if (now - ts).total_seconds() > window:
            continue
        ip = m.group(2).strip("[]")
        if ip in LOOPBACK:
            loop = True
            continue
        out.setdefault(m.group(3), set()).add(ip)
    return out, loop


def read_tail(path: str, nbytes: int = 2_000_000) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - nbytes))
            return f.read().decode(errors="ignore")
    except OSError:
        return ""


def sync_xray_ips(eng, report: dict, log_text=None, now=None) -> dict:
    text = read_tail(XRAY_ACCESS_LOG) if log_text is None else log_text
    by_email, loop = parse_xray_access(text, now)
    report["xray_real_ip"] = bool(by_email) or not loop
    if loop and not by_email:
        log.info("XRAY access log only shows 127.0.0.1: real client IP unavailable, IP limits not applied (see xray_realip.py)")
    banned = {}
    for proto in XRAY_PROTOS:
        live = {}
        for email, ips in by_email.items():
            if eng.get_account(email, proto):
                for ip in ips:
                    live[f"{email}@{ip}"] = (email, ip)
        # Xray cannot tell connections apart -> only the IP limit is applied here
        res = eng.sync_sessions(proto, live, check_conn=False) if (live or eng.get_active_sessions(protocol=proto)) else {"denied": []}
        for cid, user, ip, reason in res["denied"]:
            if reason == "ip_limit_reached":
                banned[(proto, user)] = ip
                with _db_connection(eng.db_path) as conn:
                    _meta_set(conn, f"xban:{proto}:{user}", int(datetime.now().timestamp()) + XRAY_BAN_SECONDS)
                    conn.commit()
                log.info("DENIED %s user=%s ip=%s reason=%s (account cooldown %ss)", proto, user, ip, reason, XRAY_BAN_SECONDS)
                report["denied"].append((user, ip, reason))
    return banned


def active_xray_bans(eng, now_ts=None) -> set:
    """{(proto, user)} currently in cooldown; expired bans are deleted."""
    now_ts = now_ts or int(datetime.now().timestamp())
    res = set()
    with _db_connection(eng.db_path) as conn:
        for r in conn.execute("SELECT key, value FROM engine_meta WHERE key LIKE 'xban:%'").fetchall():
            _, proto, user = r["key"].split(":", 2)
            if int(r["value"]) > now_ts:
                res.add((proto, user))
            else:
                conn.execute("DELETE FROM engine_meta WHERE key = ?", (r["key"],))
        conn.commit()
    return res


# --------------------------------------------------------------------------
# 2c. OpenVPN status files + management interface
# --------------------------------------------------------------------------
OPENVPN_STATUS_FILES = {
    "tcp": os.environ.get("TOM_OPENVPN_TCP_STATUS", "/etc/openvpn/server/openvpn-tcp.log"),
    "udp": os.environ.get("TOM_OPENVPN_UDP_STATUS", "/etc/openvpn/server/openvpn-udp.log"),
}
OPENVPN_MANAGEMENT = {
    "tcp": (os.environ.get("TOM_OPENVPN_TCP_MGMT_HOST", "127.0.0.1"), int(os.environ.get("TOM_OPENVPN_TCP_MGMT_PORT", "7505"))),
    "udp": (os.environ.get("TOM_OPENVPN_UDP_MGMT_HOST", "127.0.0.1"), int(os.environ.get("TOM_OPENVPN_UDP_MGMT_PORT", "7506"))),
}


def parse_openvpn_status(text: str) -> dict:
    """Parse OpenVPN status v1/v2 CLIENT_LIST rows into {user: [{ip, id, rx, tx}]}.

    OpenVPN's username-as-common-name makes the authenticated PAM username the
    account identity. Rows without a valid username/address/counters are ignored.
    """
    result = {}
    header = None
    for line in text.splitlines():
        if not line.startswith("CLIENT_LIST,"):
            continue
        fields = line.split(",")
        if len(fields) < 6:
            continue
        # v1: CLIENT_LIST,Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since,...
        # v2: CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,...
        try:
            if fields[3].isdigit() and fields[4].isdigit():
                # Older status layout (v1)
                user, remote = fields[1], fields[2]
                rx, tx, since = int(fields[3]), int(fields[4]), fields[5]
            else:
                # v2 status layout
                user, remote = fields[1], fields[2]
                rx, tx, since = int(fields[5]), int(fields[6]), fields[7]
            ip = remote.rsplit(":", 1)[0].strip("[]")
            if not user or not ip or not rx >= 0 or not tx >= 0:
                continue
            cid = f"{ip}|{since}|{remote}"
            result.setdefault(user, []).append({"ip": ip, "id": cid, "rx": rx, "tx": tx})
        except (ValueError, IndexError):
            continue
    return result


def _openvpn_management_command(instance: str, command: str, timeout: float = 2.0) -> bool:
    """Send one command to a loopback-only OpenVPN management interface."""
    host, port = OPENVPN_MANAGEMENT[instance]
    if host not in ("127.0.0.1", "::1", "localhost"):
        log.error("Refusing non-loopback OpenVPN management host: %s", host)
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            # Drain greeting, then send command. Management is line-oriented.
            try:
                sock.recv(4096)
            except socket.timeout:
                pass
            sock.sendall((command + "\n").encode())
            try:
                response = sock.recv(8192).decode(errors="replace")
            except socket.timeout:
                response = ""
        return "SUCCESS" in response
    except OSError:
        return False


def disconnect_openvpn_user(username: str) -> bool:
    """Disconnect a common-name on both configured OpenVPN instances."""
    if not re.fullmatch(r"[A-Za-z0-9_.@+-]{1,64}", username or ""):
        return False
    results = []
    for instance in OPENVPN_MANAGEMENT:
        results.append(_openvpn_management_command(instance, f"kill {username}"))
    return any(results)


def collect_openvpn(eng, report: dict, status_files=None) -> None:
    """Meter OpenVPN per-user byte counters and enforce live IP/connection caps.

    The status file counters are cumulative. Per-instance baselines are stored
    in engine_meta, so restarts/counter resets do not create negative deltas.
    Sessions are checked against account status and limits; refused sessions
    are disconnected via the local management interface.
    """
    files = status_files or OPENVPN_STATUS_FILES
    active = {}
    for instance, path in files.items():
        try:
            content = Path(path).read_text(errors="replace")
        except OSError:
            continue
        clients = parse_openvpn_status(content)
        for username, rows in clients.items():
            acc = eng.get_account(username, "openvpn")
            if not acc:
                continue
            for row in rows:
                cid = f"{instance}:{row['id']}"
                active[cid] = (username, row["ip"])
                key = f"openvpn_base:{instance}:{username}:{row['id']}"
                with _db_connection(eng.db_path) as conn:
                    base_raw = _meta_get(conn, key)
                    try:
                        base_rx, base_tx = map(int, base_raw.split(",")) if base_raw else (0, 0)
                    except (ValueError, AttributeError):
                        base_rx = base_tx = 0
                    d_rx = row["rx"] - base_rx if row["rx"] >= base_rx else row["rx"]
                    d_tx = row["tx"] - base_tx if row["tx"] >= base_tx else row["tx"]
                if d_rx or d_tx:
                    try:
                        eng.add_traffic(username, "openvpn", bytes_up=d_rx, bytes_down=d_tx, source=f"openvpn-{instance}")
                    except Exception as exc:  # noqa: BLE001
                        report["errors"].append(f"openvpn traffic {username}: {exc}")
                        continue
                with _db_connection(eng.db_path) as conn:
                    _meta_set(conn, key, f"{row['rx']},{row['tx']}")
                    conn.commit()
    # Account status + per-account IP/connection limits use the same central engine.
    if active or eng.get_active_sessions(protocol="openvpn"):
        result = eng.sync_sessions("openvpn", active)
        for cid, username, ip, reason in result["denied"]:
            disconnect_openvpn_user(username)
            report["denied"].append((username, ip, f"openvpn:{reason}"))
            log.info("DENIED openvpn user=%s ip=%s reason=%s", username, ip, reason)
        report["openvpn_sessions"] = len(active) - len(result["denied"])


def enforce_openvpn(eng, report: dict) -> None:
    """Disconnect OpenVPN clients whose central account is no longer active."""
    off = disabled_protocols(eng)
    for account in eng.list_accounts(protocol="openvpn"):
        if account.get("status") != "active" or "openvpn" in off:
            if disconnect_openvpn_user(account["username"]):
                log.info("DISCONNECTED openvpn user=%s status=%s", account["username"], account.get("status"))


# --------------------------------------------------------------------------
# 3/4. Expiry + enforcement
# --------------------------------------------------------------------------
def mark_expired(eng) -> int:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    n = 0
    for a in eng.list_accounts(status="active"):
        if a.get("expires_at") and str(a["expires_at"])[:10] < today:
            eng.set_status(a["username"], a["protocol"], "expired")
            log.info("EXPIRED %s/%s", a["username"], a["protocol"])
            n += 1
    return n


def rewrite_xray_config(text: str, blocked: dict) -> str:
    """Apply account status to Xray clients using the account marker immediately before each client object."""
    lines = text.split("\n")
    marker_re = re.compile(r"^(#&|###|#!|#VDNS|#@)\s+(\S+)\s+(\S+)\s+(\S+)\s*$")
    for i, line in enumerate(lines):
        m = marker_re.match(line)
        if not m:
            continue
        proto, user, _expiry, orig_uuid = MARKER_PROTO[m.group(1)], m.group(2), m.group(3), m.group(4)
        # Bot-generated legacy clients are one-line objects; panel-generated
        # clients may be pretty-printed over several lines. Find the matching
        # object by its email and modify its id/password field.
        start = i + 1
        end = min(len(lines), start + 16)
        for j in range(start, end):
            if re.search(r'"email"\s*:\s*"' + re.escape(user) + r'"', lines[j]):
                # Walk back to the object opening when email is not on first line.
                obj_start = j
                for k in range(j, start - 1, -1):
                    if "{" in lines[k]:
                        obj_start = k
                        break
                want = (
                    str(uuidlib.uuid5(uuidlib.NAMESPACE_URL, f"tom-blocked:{user}:{proto}"))
                    if blocked.get((proto, user)) else orig_uuid
                )
                for k in range(obj_start, j + 1):
                    lines[k] = re.sub(
                        r'("(?:id|password)"\s*:\s*")[^"]*(")',
                        lambda mm: mm.group(1) + want + mm.group(2),
                        lines[k], count=1
                    )
                break
    return "\n".join(lines)


def enforce_xray(eng, report: dict, config_path=XRAY_CONFIG, restart=True) -> bool:
    p = Path(config_path)
    if not p.exists():
        return False
    blocked = {}
    off = disabled_protocols(eng)
    for proto in XRAY_BLOCK_PROTOS:
        for a in eng.list_accounts(protocol=proto):
            if a["status"] != "active" or proto in off:
                blocked[(proto, a["username"])] = True
    for key in active_xray_bans(eng):
        blocked[key] = True
    old = p.read_text()
    new = rewrite_xray_config(old, blocked)
    if new == old:
        return False
    bak = p.with_name(p.name + ".tomtunnel.bak")
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".tom-")
        with os.fdopen(fd, "w") as f:
            f.write(new)
        if shutil.which("xray"):
            t = _run(["xray", "run", "-test", "-config", tmp])
            if t is None or t.returncode != 0:
                raise RuntimeError("xray config test failed; config left unchanged")
        shutil.copy2(p, bak)
        os.chmod(tmp, p.stat().st_mode & 0o777)
        os.replace(tmp, p)
        tmp = None
        log.info("XRAY config updated (blocked=%d)", len(blocked))
        if restart:
            _run(["systemctl", "restart", "xray"], timeout=30)
        return True
    except Exception as e:  # noqa: BLE001
        report["errors"].append(f"enforce_xray: {e}")
        return False
    finally:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)


def enforce_ssh(eng, report: dict, run=_run) -> None:
    """Lock non-active SSH users (and kill them); unlock only users WE locked."""
    off = disabled_protocols(eng)
    with _db_connection(eng.db_path) as conn:
        for a in eng.list_accounts(protocol="ssh"):
            user = a["username"]
            try:
                pwd.getpwnam(user)
            except KeyError:
                continue
            key = f"ssh_locked:{user}"
            locked_by_us = _meta_get(conn, key) == "1"
            if a["status"] != "active" or "ssh" in off:
                if not locked_by_us:
                    r = run(["usermod", "-L", user])
                    if r is not None and r.returncode == 0:
                        _meta_set(conn, key, 1)
                        log.info("LOCKED ssh user=%s status=%s", user, a["status"])
                run(["pkill", "-KILL", "-u", user])
            elif locked_by_us:
                r = run(["usermod", "-U", user])
                if r is not None and r.returncode == 0:
                    conn.execute("DELETE FROM engine_meta WHERE key = ?", (key,))
                    log.info("UNLOCKED ssh user=%s", user)
        conn.commit()


# --------------------------------------------------------------------------
# 5. Alerts (quota 80/90/100 %, expiry) → Telegram admins
# --------------------------------------------------------------------------
BOT_CONFIG = os.environ.get("TOM_BOT_CONFIG", "/etc/tom_tunnel_bot/config.json")


def load_alert_settings(path=BOT_CONFIG) -> dict:
    """Thresholds are configurable in the bot config: {"alerts": {"quota": [80,90,100], "expiry_days": [3,1]}}"""
    cfg = {}
    try:
        cfg = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        pass
    a = cfg.get("alerts", {}) if isinstance(cfg.get("alerts"), dict) else {}
    quota = sorted({int(x) for x in a.get("quota", [80, 90, 100]) if 0 < int(x) <= 100})
    days = sorted({int(x) for x in a.get("expiry_days", [3, 1]) if int(x) >= 0}, reverse=True)
    return {"quota": quota, "expiry_days": days, "cfg": cfg}


def compute_alerts(eng, quota_thr, expiry_days, today=None):
    """Return [(meta_key, meta_value, message)] for alerts not yet sent. Re-arms automatically."""
    today = today or datetime.now(timezone.utc).date()
    pending = []
    with _db_connection(eng.db_path) as conn:
        for a in eng.list_accounts():
            cid, who = a["id"], f"{a['username']} ({a['protocol']})"
            q = float(a.get("quota_gb") or 0)
            pct = (float(a.get("used_gb") or 0) / q * 100) if q > 0 else 0.0
            for thr in quota_thr:
                key = f"alert_q:{cid}:{thr}"
                sent = _meta_get(conn, key)
                if q > 0 and pct >= thr:
                    if sent is None:
                        tag = "QUOTA ÉPUISÉ" if thr >= 100 else f"quota à {thr}%"
                        pending.append((key, "1", f"⚠️ {who} : {tag} — {a['used_gb']:.2f} / {q:g} Go ({pct:.0f}%)"))
                elif sent is not None:
                    conn.execute("DELETE FROM engine_meta WHERE key = ?", (key,))  # re-arm after recharge/reset
            exp = str(a.get("expires_at") or "")[:10]
            if exp and a["status"] != "expired":
                try:
                    left = (datetime.strptime(exp, "%Y-%m-%d").date() - today).days
                except ValueError:
                    continue
                for d in expiry_days:
                    key = f"alert_e:{cid}:{d}"
                    if 0 <= left <= d and _meta_get(conn, key) != exp:
                        pending.append((key, exp, f"⏰ {who} : expire dans {left} jour(s) ({exp})"))
                        break  # only the tightest matching threshold per run
        conn.commit()
    return pending


def send_telegram(cfg: dict, text: str) -> bool:
    import urllib.parse, urllib.request
    token, ids = cfg.get("bot_token"), [cfg.get("super_admin")] + list(cfg.get("admins", []))
    ids = [i for i in ids if i]
    if not token or not ids:
        return False
    ok = False
    for chat in ids:
        try:
            data = urllib.parse.urlencode({"chat_id": chat, "text": text}).encode()
            with urllib.request.urlopen(f"https://api.telegram.org/bot{token}/sendMessage", data, timeout=10):
                ok = True
        except Exception as e:  # noqa: BLE001  never log the URL (contains the token)
            log.info("telegram send failed for chat %s: %s", chat, type(e).__name__)
    return ok


def process_alerts(eng, report: dict, send=send_telegram, settings=None) -> int:
    st = settings or load_alert_settings()
    pending = compute_alerts(eng, st["quota"], st["expiry_days"])
    sent = 0
    for key, val, msg in pending:
        if send(st["cfg"], msg):
            with _db_connection(eng.db_path) as conn:
                _meta_set(conn, key, val)
                conn.commit()
            sent += 1
        log.info("ALERT %s %s", "sent" if sent else "pending", msg)
    report["alerts_sent"] = sent
    return sent


# --------------------------------------------------------------------------
def run_collector(db_path=None) -> dict:
    _setup_log()
    eng = get_engine(db_path)
    report: dict = {"xray": 0, "sessions_cleaned": 0, "denied": [], "expired": 0, "errors": []}

    steps = (
        ("expiry", lambda: report.__setitem__("expired", mark_expired(eng))),
        ("xray_collect", lambda: apply_xray_deltas(eng, collect_xray_stats(), report)),
        ("ssh_sessions", lambda: sync_ssh(eng, report)),
        ("openvpn_sessions", lambda: collect_openvpn(eng, report)),
        ("xray_ips", lambda: sync_xray_ips(eng, report)),
        ("enforce_ssh", lambda: enforce_ssh(eng, report)),
        ("enforce_openvpn", lambda: enforce_openvpn(eng, report)),
        ("enforce_xray", lambda: enforce_xray(eng, report)),
        ("alerts", lambda: process_alerts(eng, report)),
        ("cleanup", lambda: report.__setitem__("sessions_cleaned", eng.cleanup_sessions(max_age_minutes=25))),
    )
    for name, fn in steps:
        try:
            fn()
        except Exception as e:  # noqa: BLE001  one failing step must not stop the others
            report["errors"].append(f"{name}: {e}")
            log.info("ERROR %s: %s", name, e)
    return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="TOM_TUNNEL traffic collector")
    parser.add_argument("--db", default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    r = run_collector(args.db)
    if args.json:
        print(json.dumps(r, indent=2))
    else:
        print(f"Xray accounts updated : {r['xray']}")
        print(f"Sessions denied       : {len(r['denied'])}")
        print(f"Accounts expired      : {r['expired']}")
        if r["errors"]:
            print("Errors:", r["errors"])
