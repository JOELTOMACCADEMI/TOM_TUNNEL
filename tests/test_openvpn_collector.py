import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core" / "lib"))
import traffic_collector as tc


class OpenVPNStatusTests(unittest.TestCase):
    def test_parse_status_v1(self):
        data = "CLIENT_LIST,alice,198.51.100.7:43000,1234,5678,2026-11-19 10:00:00,alice"
        got = tc.parse_openvpn_status(data)
        self.assertEqual(got["alice"][0]["ip"], "198.51.100.7")
        self.assertEqual(got["alice"][0]["rx"], 1234)
        self.assertEqual(got["alice"][0]["tx"], 5678)

    def test_parse_status_v2(self):
        data = "CLIENT_LIST,alice,198.51.100.7:43000,10.6.0.2,,1234,5678,2026-11-19 10:00:00,2026-11-19 10:00:00"
        got = tc.parse_openvpn_status(data)
        self.assertEqual(got["alice"][0]["rx"], 1234)
        self.assertEqual(got["alice"][0]["tx"], 5678)

    def test_invalid_rows_ignored(self):
        self.assertEqual(tc.parse_openvpn_status("CLIENT_LIST,alice,not-an-address,x,y,z"), {})


if __name__ == "__main__":
    unittest.main()
