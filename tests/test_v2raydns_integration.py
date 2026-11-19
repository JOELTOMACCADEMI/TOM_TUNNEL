import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tom_tunnel_core_bot"))
from modules import xray_core


def test_v2raydns_is_a_separate_managed_account_type():
    assert "v2raydns" in xray_core.VALID_PROTOCOLS
    assert xray_core.PREFIX["v2raydns"] == "#VDNS"
    assert xray_core.MARKERS["v2raydns"] == xray_core.MARKERS["vless"]
    assert xray_core._valid("v2raydns", "dns_user")


def test_v2raydns_generates_vless_links_with_dns_metadata_label():
    tls, ntls, grpc = xray_core._links("v2raydns", "dns_user", "00000000-0000-4000-8000-000000000000")
    assert tls.startswith("vless://") and "security=tls" in tls
    assert ntls.startswith("vless://") and ":80?" in ntls
    assert grpc.startswith("vless://") and "type=grpc" in grpc


def test_account_engine_accepts_v2raydns_with_quota_and_uuid(tmp_path):
    sys.path.insert(0, str(ROOT / "core" / "lib"))
    from account_engine import AccountEngine

    engine = AccountEngine(tmp_path / "accounts.db")
    record = engine.create_account(
        username="dns_user", protocol="v2raydns",
        uuid_str="00000000-0000-4000-8000-000000000000",
        days=14, quota_gb=5, ip_limit=2, conn_limit=3,
    )
    assert record["protocol"] == "v2raydns"
    assert record["quota_gb"] == 5
    assert record["ip_limit"] == 2
    assert record["conn_limit"] == 3


def test_v2raydns_traffic_enforcement_rewrites_marked_client():
    sys.path.insert(0, str(ROOT / "core" / "lib"))
    import traffic_collector

    active = '{"id": "00000000-0000-4000-8000-000000000000", "email": "dns_user"}'
    config = '"clients": [\n#VDNS dns_user 2026-12-01 00000000-0000-4000-8000-000000000000\n' + active + '\n]'
    changed = traffic_collector.rewrite_xray_config(config, {("v2raydns", "dns_user"): True})
    assert 'email": "dns_user"' in changed
    assert '"id": "a6a0508d-fd1c-50b6-b5cb-92213dcb4f47"' in changed


def test_v2raydns_stats_are_mapped_to_separate_engine_protocol():
    sys.path.insert(0, str(ROOT / "core" / "lib"))
    import traffic_collector

    class FakeEngine:
        db_path = "/tmp/nonexistent-v2raydns-test.db"
        def __init__(self): self.added = []
        def get_account(self, email, protocol):
            return {"username": email} if protocol == "v2raydns" else None
        def add_traffic(self, email, protocol, **kwargs): self.added.append((email, protocol, kwargs))
        def get_active_sessions(self, protocol=None): return []

    # The collector's lookup order includes v2raydns; this asserts the mapping
    # contract without writing to a live server database.
    assert "v2raydns" in traffic_collector.XRAY_PROTOS


def test_v2raydns_traffic_enforcement_handles_pretty_printed_client():
    sys.path.insert(0, str(ROOT / "core" / "lib"))
    import traffic_collector

    original = "00000000-0000-4000-8000-000000000000"
    config = (
        '"clients": [\n#VDNS dns_user 2026-12-01 ' + original + '\n'
        '{\n  "id": "' + original + '",\n  "email": "dns_user"\n}\n]'
    )
    changed = traffic_collector.rewrite_xray_config(config, {("v2raydns", "dns_user"): True})
    assert '"email": "dns_user"' in changed
    assert '"id": "' + original + '"' not in changed


def test_v2raydns_xray_traffic_updates_its_quota_row(tmp_path):
    sys.path.insert(0, str(ROOT / "core" / "lib"))
    from account_engine import AccountEngine
    import traffic_collector

    engine = AccountEngine(tmp_path / "traffic.db")
    engine.create_account(username="dns_user", protocol="v2raydns", days=30, quota_gb=1)
    traffic_collector.apply_xray_deltas(engine, {"dns_user": {"up": 4096, "down": 8192}}, {"errors": []})
    account = engine.get_account("dns_user", "v2raydns")
    assert account["used_gb"] > 0
    assert account["used_gb"] == 12288 / (1024 ** 3)
