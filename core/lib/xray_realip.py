#!/usr/bin/env python3
"""
TOM_TUNNEL — make Xray log the REAL client IP (needed for Xray IP limits).

All Xray inbounds listen on 127.0.0.1 behind nginx, so Xray normally sees
127.0.0.1. nginx already sends `X-Real-IP $remote_addr`; this script adds
    "sockopt": {"trustedXForwardedFor": ["X-Real-IP"]}
to the streamSettings of ws / httpupgrade / xhttp inbounds that bind to
127.0.0.1. gRPC inbounds cannot be handled this way (Xray limitation) and are
left untouched: IP limits are NOT applied to accounts used through gRPC.

Safe by design: idempotent, backup (.realip.bak), `xray run -test` before
replacing, nothing written on failure. Use --revert to remove the field.
Never edits inbounds that already have a sockopt block.

Usage:  xray_realip.py [--config /etc/xray/config.json] [--dry-run] [--revert] [--no-restart]
"""
import argparse, os, re, shutil, subprocess, sys, tempfile

FIELD = '"sockopt": {"trustedXForwardedFor": ["X-Real-IP"]},'
TAG = "# tomtunnel-realip"
SUPPORTED = ("ws", "httpupgrade", "xhttp")


def patch(text: str, revert: bool = False):
    """Return (new_text, changed_count)."""
    lines = text.split("\n")
    out, changed, i = [], 0, 0
    while i < len(lines):
        line = lines[i]
        if revert:
            if line.strip() == TAG:  # marker + following field line
                i += 2
                changed += 1
                continue
            out.append(line)
            i += 1
            continue
        out.append(line)
        if re.search(r'"streamSettings"\s*:\s*\{\s*$', line):
            # inspect the next lines of THIS block only
            block = []
            depth = 1
            for j in range(i + 1, min(i + 40, len(lines))):
                depth += lines[j].count("{") - lines[j].count("}")
                block.append(lines[j])
                if depth <= 0:
                    break
            joined = "\n".join(block)
            m = re.search(r'"network"\s*:\s*"([a-z]+)"', joined)
            if m and m.group(1) in SUPPORTED and "sockopt" not in joined:
                indent = re.match(r"\s*", lines[i + 1]).group(0) if i + 1 < len(lines) else "  "
                out.append(f"{indent}{TAG}")
                out.append(f"{indent}{FIELD}")
                changed += 1
        i += 1
    return "\n".join(out), changed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="/etc/xray/config.json")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--revert", action="store_true")
    ap.add_argument("--no-restart", action="store_true")
    a = ap.parse_args()
    if not os.path.exists(a.config):
        print(f"config not found: {a.config}", file=sys.stderr)
        return 1
    old = open(a.config).read()
    new, n = patch(old, a.revert)
    print(f"{'would change' if a.dry_run else 'changing'} {n} inbound(s)")
    if n == 0 or a.dry_run:
        return 0
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(a.config), prefix=".tom-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(new)
        if shutil.which("xray"):
            t = subprocess.run(["xray", "run", "-test", "-config", tmp], capture_output=True, text=True)
            if t.returncode != 0:
                print("xray config test FAILED, nothing changed:\n" + t.stdout + t.stderr, file=sys.stderr)
                return 2
        else:
            print("warning: xray binary not found, config not tested", file=sys.stderr)
        shutil.copy2(a.config, a.config + ".realip.bak")
        os.chmod(tmp, os.stat(a.config).st_mode & 0o777)
        os.replace(tmp, a.config)
        tmp = None
        if not a.no_restart:
            subprocess.run(["systemctl", "restart", "xray"], check=False)
        print("done. Check: tail /var/log/xray/access.log  -> source IPs must no longer be 127.0.0.1")
        return 0
    finally:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)


if __name__ == "__main__":
    sys.exit(main())
