import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("zivpn_engine", ROOT / "core/lib/zivpn_engine.py")
z = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(z)


def test_conntrack_parser_extracts_per_port_flow_identity():
    sample = "udp 17 29 src=198.51.100.10 dst=203.0.113.2 sport=54321 dport=23456 [UNREPLIED] src=203.0.113.2 dst=198.51.100.10 sport=23456 dport=54321"
    rows = z.parse_conntrack_lines(sample, 23456)
    assert len(rows) == 1
    assert rows[0]["ip"] == "198.51.100.10"
    assert rows[0]["sport"] == "54321"
    assert rows[0]["id"].startswith("23456:")


def test_counter_delta_handles_normal_increase_and_kernel_counter_reset():
    assert z.counter_delta(1500, 1000) == 500
    assert z.counter_delta(20, 1000) == 20
    assert z.counter_delta(0, 0) == 0
