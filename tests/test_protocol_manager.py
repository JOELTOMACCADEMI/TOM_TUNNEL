"""Protocol manager tests (fake systemd — real logic, simulated services)."""
import sys, tempfile, unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core" / "lib"))
import protocol_manager as pm            # noqa: E402
import traffic_collector as tc           # noqa: E402
from account_engine import AccountEngine  # noqa: E402

U1 = "11111111-1111-4111-8111-111111111111"
U2 = "22222222-2222-4222-8222-222222222222"
CFG = ('"clients": [\n#& alice 2030-01-01 %s\n{"id": "%s", "email": "alice"}\n]\n'
       '"clients": [\n#VDNS dnsu 2030-01-01 %s\n{"id": "%s", "email": "dnsu"}\n]\n') % (U1, U1, U2, U2)


class FakeSystemd:
    def __init__(self, installed, active):
        self.installed, self.active, self.enabled, self.calls = set(installed), set(active), set(active), []
    def __call__(self, cmd, timeout=25):
        self.calls.append(cmd)
        ok = lambda out="": SimpleNamespace(returncode=0, stdout=out, stderr="")
        if cmd[0] == "ss":
            return ok("LISTEN 0 128 0.0.0.0:8181 0.0.0.0:*\n")
        if cmd[0] == "journalctl":
            return ok("line1\nline2\n")
        if cmd[0] != "systemctl":
            return None
        verb, unit = cmd[1], cmd[-1].replace(".service", "")
        if verb == "show":
            return ok("loaded" if unit in self.installed else "not-found")
        if verb == "is-active":
            return ok("active" if unit in self.active else "inactive")
        if verb == "is-enabled":
            return ok("enabled" if unit in self.enabled else "disabled")
        if unit not in self.installed:
            return SimpleNamespace(returncode=5, stdout="", stderr="not found")
        if verb == "enable":
            self.enabled.add(unit); self.active.add(unit)
        elif verb == "disable":
            self.enabled.discard(unit); self.active.discard(unit)
        elif verb == "restart":
            self.active.add(unit)
        return ok()


class ProtocolManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "t.db"
        self.eng = AccountEngine(self.db)
        self.sd = FakeSystemd({"xray", "stunnel5", "zivpn", "ssh"}, {"xray", "stunnel5", "zivpn", "ssh"})
        pm.RUN = self.sd
        self.cfg = Path(self.tmp.name) / "config.json"
        self.cfg.write_text(CFG)
        self.eng.create_account(username="alice", protocol="vless", uuid_str=U1, days=30, quota_gb=5, ip_limit=2, conn_limit=3)
        self.eng.create_account(username="dnsu", protocol="v2raydns", uuid_str=U2, days=30, quota_gb=10, ip_limit=1, conn_limit=2)

    def tearDown(self):
        pm.RUN = pm._run
        self.tmp.cleanup()

    def test_unknown_or_malicious_id_rejected(self):
        for bad in ("nope", "../etc", "vless;rm -rf /", ""):
            with self.assertRaises(KeyError):
                pm.status(bad, self.db)

    def test_service_protocol_disable_enable_and_persistence(self):
        r = pm.set_enabled("ssh-ssl", False, self.db)
        self.assertTrue(r["ok"], r)
        self.assertNotIn("stunnel5", self.sd.active)
        self.assertNotIn("stunnel5", self.sd.enabled)          # stays off after reboot
        self.assertEqual(pm.status("ssh-ssl", self.db)["state"], "disabled")
        # state survives a brand-new engine/connection (= restart of bot/panel/VPS)
        self.assertIn("ssh-ssl", pm.disabled_set(AccountEngine(self.db)))
        r = pm.set_enabled("ssh-ssl", True, self.db)
        self.assertTrue(r["ok"], r)
        self.assertIn("stunnel5", self.sd.active)
        self.assertEqual(pm.status("ssh-ssl", self.db)["state"], "running")

    def test_uninstalled_service_changes_nothing(self):
        r = pm.set_enabled("openvpn", False, self.db)
        self.assertFalse(r["ok"])
        self.assertNotIn("openvpn", pm.disabled_set(self.eng))

    def test_enable_reports_failure_if_service_does_not_start(self):
        pm.set_enabled("zivpn", False, self.db)
        self.sd.enable_fails = True
        orig = self.sd.__call__
        def broken(cmd, timeout=25):
            if cmd[:2] == ["systemctl", "enable"]:
                return SimpleNamespace(returncode=1, stdout="", stderr="boom")
            return orig(cmd, timeout)
        pm.RUN = broken
        r = pm.set_enabled("zivpn", True, self.db)
        self.assertFalse(r["ok"])

    def test_xray_protocols_are_independent_and_accounts_preserved(self):
        r_dis = pm.set_enabled("v2raydns", False, self.db)  # default config path absent in sandbox
        # enforce explicitly on our temp config (default path does not exist in the sandbox)
        rep = {"errors": []}
        tc.enforce_xray(self.eng, rep, config_path=str(self.cfg), restart=False)
        txt = self.cfg.read_text()
        self.assertNotIn('"id": "%s"' % U2, txt)   # v2raydns client id neutralised (original kept in marker line)
        self.assertIn('"id": "%s"' % U1, txt)      # vless untouched (independent)
        self.assertEqual(self.eng.get_account("dnsu", "v2raydns")["status"], "active")  # account kept
        self.assertEqual(self.eng.get_account("dnsu", "v2raydns")["quota_gb"], 10)       # quota kept
        self.assertNotIn("xray", [c[-1] for c in self.sd.calls if c[:2] == ["systemctl", "disable"]])
        pm.set_enabled("v2raydns", True, self.db)
        tc.enforce_xray(self.eng, rep, config_path=str(self.cfg), restart=False)
        self.assertEqual(self.cfg.read_text(), CFG)          # fully restored
        self.assertNotIn("v2raydns", pm.disabled_set(self.eng))

    def test_ssh_disabled_locks_users_and_enable_unlocks_only_ours(self):
        import pwd
        self.eng.create_account(username="bob", protocol="ssh", password="x", days=30)
        calls = []
        def run(cmd, timeout=15):
            calls.append(cmd); return SimpleNamespace(returncode=0, stdout="", stderr="")
        orig = pwd.getpwnam
        pwd.getpwnam = lambda u: SimpleNamespace(pw_name=u)
        try:
            pm._set_flag(self.eng, "ssh", True)
            tc.enforce_ssh(self.eng, {"errors": []}, run=run)
            self.assertIn(["usermod", "-L", "bob"], calls)
            calls.clear()
            pm._set_flag(self.eng, "ssh", False)
            tc.enforce_ssh(self.eng, {"errors": []}, run=run)
            self.assertIn(["usermod", "-U", "bob"], calls)
        finally:
            pwd.getpwnam = orig
        self.assertEqual(self.eng.get_account("bob", "ssh")["status"], "active")

    def test_list_logs_ports_and_cli_json(self):
        rows = pm.list_all(self.db)
        self.assertEqual({r["id"] for r in rows}, set(pm.REGISTRY))
        self.assertTrue(pm.ports("ssh-ssl")["ports"][0]["listening"])
        self.assertIn("line1", pm.logs("ssh-ssl", 999)["logs"])
        self.assertEqual(pm.main(["status", "vless", "--json", "--db", str(self.db)]), 0)
        self.assertEqual(pm.main(["status", "bad", "--json", "--db", str(self.db)]), 2)

    def test_restart_xray_warns_about_shared_process(self):
        r = pm.restart("vless")
        self.assertTrue(r["ok"]); self.assertIn("partagé", r["message"])


if __name__ == "__main__":
    unittest.main()
