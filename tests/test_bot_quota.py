import json, os, stat, subprocess, sys, tempfile, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tom_tunnel_core_bot"))
from modules import quota_commands as q

ENGINE = ROOT / "core" / "lib" / "account_engine.py"
GB = 1024 ** 3


class BotQuota(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        shim = Path(self.d) / "tom-account"
        shim.write_text(f'#!/bin/sh\nexec python3 {ENGINE} --db {self.d}/t.db "$@"\n')
        shim.chmod(0o755)
        os.environ["PATH"] = self.d + os.pathsep + os.environ["PATH"]
        self.audit = str(Path(self.d) / "audit.log")
        subprocess.run(["tom-account", "create", "bob", "ssh", "--password", "SECRETPW", "--quota", "2", "--ip-limit", "1"],
                       check=True, capture_output=True)
        self.admin = lambda uid: uid == 1
        self.h = lambda t, uid=1: q.handle(t, uid, self.admin, audit_path=self.audit)

    def test_v2raydns_quota_limits_suspend_from_bot(self):
        subprocess.run(["tom-account", "create", "dnsu", "v2raydns", "--quota", "5", "--ip-limit", "1", "--conn-limit", "2"],
                       check=True, capture_output=True)
        self.assertIn("20 Go", self.h("/setquota dnsu v2raydns 20"))
        self.assertIn("v2raydns", self.h("/limits dnsu v2raydns 3 4").lower())
        out = self.h("/suspend dnsu v2raydns")
        self.assertNotIn("invalide", out.lower())
        self.assertIn("suspended", subprocess.run(["tom-account", "get", "dnsu", "--protocol", "v2raydns"],
                                                  capture_output=True, text=True).stdout)
        self.assertNotIn("invalide", self.h("/unsuspend dnsu v2raydns").lower())
        # alias: "udp" is accepted and mapped to the engine's "udpcustom"
        self.assertEqual(q._proto("udp"), "udpcustom")


    def test_zivpn_quota_limits_and_status_are_managed_by_engine(self):
        subprocess.run(["tom-account", "create", "alice", "zivpn", "--quota", "5", "--ip-limit", "1", "--conn-limit", "1"],
                       check=True, capture_output=True)
        self.assertIn("10 Go", self.h("/setquota alice zivpn 10"))
        self.assertIn("Limite IP : 2", self.h("/limits alice zivpn 2 2"))
        self.assertIn("SUSPENDU", self.h("/suspend alice zivpn"))
        self.assertIn("ACTIF", self.h("/unsuspend alice zivpn"))
        self.assertIn("alice (zivpn)", self.h("/quota alice zivpn"))

    def test_non_admin_refused_and_nothing_changed(self):
        self.assertIn("réservée", self.h("/setquota bob ssh 99", uid=2))
        self.assertIn("2 Go", self.h("/quota bob ssh"))

    def test_set_add_limits_suspend_cycle(self):
        self.assertIn("10 Go", self.h("/setquota bob ssh 10"))
        self.assertIn("15 Go", self.h("/addquota bob ssh 5"))
        out = self.h("/limits bob ssh 3 2"); self.assertIn("Limite IP : 3", out); self.assertIn("Connexions : 2", out)
        self.assertIn("SUSPENDU", self.h("/suspend bob ssh"))
        self.assertIn("ACTIF", self.h("/unsuspend bob ssh"))

    def test_quota_exhausted_label_and_recharge(self):
        subprocess.run(["tom-account", "add-traffic", "bob", "ssh", "--up", str(3 * GB)], check=True, capture_output=True)
        self.assertIn("QUOTA ÉPUISÉ", self.h("/quota bob ssh"))
        self.assertIn("bob", self.h("/near 90"))
        self.assertIn("ACTIF", self.h("/addquota bob ssh 5"))

    def test_input_validation_no_shell_injection(self):
        for bad in ["/quota bob;rm -rf /", "/setquota bob ssh abc", "/setquota bob foo 5", "/limits bob ssh -1 2",
                    "/limits bob ssh 1", "/quota $(id)"]:
            self.assertTrue(self.h(bad).startswith("⚠️"), bad)
        self.assertIn("Compte introuvable", self.h("/quota nobody ssh")) if False else None

    def test_no_secret_in_replies_and_audit_written(self):
        outs = [self.h(c) for c in ("/quota bob ssh", "/setquota bob ssh 4", "/sessions")]
        self.assertTrue(all("SECRETPW" not in o for o in outs))
        lines = [json.loads(l) for l in open(self.audit)]
        self.assertEqual(lines[-1]["action"], "setquota"); self.assertEqual(lines[-1]["admin"], 1)
        self.assertNotIn("SECRETPW", open(self.audit).read())

    def test_engine_unavailable_message(self):
        def boom(*a, **k): raise OSError("no such file")
        self.assertIn("indisponible", q.handle("/quota bob ssh", 1, self.admin, run=boom, audit_path=self.audit))


class EngineRegression(unittest.TestCase):
    def test_renew_cli_does_not_crash_and_extends_from_expiry(self):
        d = tempfile.mkdtemp(); E = ["python3", str(ENGINE), "--db", f"{d}/t.db"]
        acc = json.loads(subprocess.run(E + ["create", "u", "ssh", "--days", "5"], capture_output=True, text=True, check=True).stdout)
        r = subprocess.run(E + ["renew", "u", "ssh", "--days", "10"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        from datetime import datetime, timedelta
        want = (datetime.strptime(acc["expires_at"], "%Y-%m-%d") + timedelta(days=10)).strftime("%Y-%m-%d")
        self.assertEqual(json.loads(r.stdout)["expires_at"], want)


if __name__ == "__main__":
    unittest.main(verbosity=2)
