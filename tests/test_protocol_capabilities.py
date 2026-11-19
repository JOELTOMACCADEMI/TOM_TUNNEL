"""Conservative protocol capability declarations are exposed consistently."""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core" / "lib"))
import protocol_manager as pm
from account_engine import AccountEngine


def test_capability_matrix_is_complete_and_conservative(tmp_path):
    assert set(pm.CAPABILITIES) == set(pm.REGISTRY)
    for pid, cap in pm.CAPABILITIES.items():
        assert set(("quota", "ip_limit", "conn_limit", "meter", "note")).issubset(cap)
        assert isinstance(cap["quota"], bool)
        assert isinstance(cap["ip_limit"], bool)
        assert isinstance(cap["conn_limit"], bool)
    for pid in ("slowdns", "udpcustom", "ohp"):
        assert not pm.CAPABILITIES[pid]["quota"]
        assert not pm.CAPABILITIES[pid]["ip_limit"]
        assert not pm.CAPABILITIES[pid]["conn_limit"]
    assert pm.CAPABILITIES["vless"]["quota"] is True
    assert pm.CAPABILITIES["vless"]["conn_limit"] is False
    assert pm.CAPABILITIES["zivpn"]["conn_limit"] is True
    eng = AccountEngine(tmp_path / "accounts.db")
    row = pm.status("vless", eng.db_path)
    assert row["capabilities"] == pm.CAPABILITIES["vless"]
    assert len(pm.capabilities()) == len(pm.REGISTRY)
