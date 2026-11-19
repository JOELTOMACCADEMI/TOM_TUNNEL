import json, os, pwd, signal, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core" / "lib"))
import account_engine as ae
import traffic_collector as tc

GB = 1024 ** 3
CFG = '''{
 "clients": [
  {
   "id": "22f5a909-37d9-4174-aa54-1e503ad7e523"
#vless
#& alice 2030-01-01 11111111-1111-1111-1111-111111111111
},{"id": "11111111-1111-1111-1111-111111111111","email": "alice"
#& bob 2030-01-01 22222222-2222-2222-2222-222222222222
},{"id": "22222222-2222-2222-2222-222222222222","email": "bob"
  }
 ]
}
#trojanws
#! carl 2030-01-01 pw-carl
},{"password": "pw-carl","email": "carl"
'''


def fresh():
    d = tempfile.mkdtemp()
    ae._engine = None
    return ae.get_engine(os.path.join(d, "t.db"))


class T(unittest.TestCase):
    def setUp(self):
        tc._setup_log()
        self.eng = fresh()

    def test_xray_json_and_legacy_parse(self):
        j = json.dumps({"stat": [{"name": "user>>>alice>>>traffic>>>uplink", "value": "10"},
                                 {"name": "user>>>alice>>>traffic>>>downlink", "value": 20}]})
        self.assertEqual(tc.parse_xray_stats(j), {"alice": {"up": 10, "down": 20}})
        legacy = "stat: >>>> user>>>bob>>>traffic>>>downlink value: 7"
        self.assertEqual(tc.parse_xray_stats(legacy), {"bob": {"up": 0, "down": 7}})

    def test_no_double_count_and_restart(self):
        self.eng.create_account("alice", "vless", quota_gb=10)
        rep = {"xray": 0, "errors": []}
        tc.apply_xray_deltas(self.eng, {"alice": {"up": GB // 2, "down": GB // 2}}, rep)
        self.assertAlmostEqual(self.eng.get_account("alice", "vless")["used_gb"], 1.0)
        # same cumulative values again -> nothing added
        tc.apply_xray_deltas(self.eng, {"alice": {"up": GB // 2, "down": GB // 2}}, rep)
        self.assertAlmostEqual(self.eng.get_account("alice", "vless")["used_gb"], 1.0)
        # grows by 0.5 GB
        tc.apply_xray_deltas(self.eng, {"alice": {"up": GB // 2, "down": GB // 2 + GB // 2}}, rep)
        self.assertAlmostEqual(self.eng.get_account("alice", "vless")["used_gb"], 1.5)
        # xray restarted: counters back to small values
        tc.apply_xray_deltas(self.eng, {"alice": {"up": GB // 4, "down": 0}}, rep)
        self.assertAlmostEqual(self.eng.get_account("alice", "vless")["used_gb"], 1.75)

    def test_quota_exhausted_and_unlimited(self):
        self.eng.create_account("small", "vless", quota_gb=1)
        self.eng.create_account("free", "vmess", quota_gb=0)
        rep = {"xray": 0, "errors": []}
        tc.apply_xray_deltas(self.eng, {"small": {"up": GB, "down": 0}, "free": {"up": 50 * GB, "down": 0}}, rep)
        self.assertEqual(self.eng.get_account("small", "vless")["status"], "quota_exhausted")
        self.assertEqual(self.eng.get_account("free", "vmess")["status"], "active")

    def test_ssh_limits_and_kill(self):
        self.eng.create_account("u1", "ssh", password="x", conn_limit=1, ip_limit=0)
        self.eng.create_account("u2", "ssh", password="x", ip_limit=1, conn_limit=0)
        ss = (
            'ESTAB 0 0 10.0.0.1:22 1.1.1.1:5001 users:(("sshd",pid=101,fd=4))\n'
            'ESTAB 0 0 10.0.0.1:22 1.1.1.1:5002 users:(("sshd",pid=102,fd=4))\n'
            'ESTAB 0 0 10.0.0.1:22 2.2.2.2:6001 users:(("sshd",pid=201,fd=4))\n'
            'ESTAB 0 0 10.0.0.1:22 3.3.3.3:6002 users:(("sshd",pid=202,fd=4))\n'
            'ESTAB 0 0 10.0.0.1:443 9.9.9.9:1 users:(("nginx",pid=5,fd=4))\n'
        )
        owner = {101: "u1", 102: "u1", 201: "u2", 202: "u2"}
        killed = []
        rep = {"denied": [], "errors": []}
        tc.sync_ssh(self.eng, rep, ss_text=ss, user_of=lambda n, p: owner.get(p),
                    kill=lambda pid, sig: killed.append((pid, sig)))
        reasons = sorted(r for _, _, r in rep["denied"])
        self.assertEqual(reasons, ["conn_limit_reached", "ip_limit_reached"])
        self.assertEqual(len(killed), 2)
        self.assertTrue(all(s == signal.SIGKILL for _, s in killed))
        self.assertEqual(len(self.eng.get_active_sessions("u1")), 1)
        self.assertEqual(len(self.eng.get_active_sessions("u2")), 1)
        # next cycle: nothing live -> sessions removed (no ghost)
        tc.sync_ssh(self.eng, {"denied": [], "errors": []}, ss_text="", user_of=lambda n, p: None)
        self.assertEqual(self.eng.get_active_sessions(), [])

    def test_unlimited_ssh_never_denied(self):
        self.eng.create_account("u3", "ssh", password="x")
        ss = "".join(f'ESTAB 0 0 10.0.0.1:22 8.8.8.{i}:50{i} users:(("sshd",pid={300+i},fd=4))\n' for i in range(6))
        rep = {"denied": [], "errors": []}
        tc.sync_ssh(self.eng, rep, ss_text=ss, user_of=lambda n, p: "u3", kill=lambda *a: None)
        self.assertEqual(rep["denied"], [])
        self.assertEqual(len(self.eng.get_active_sessions("u3")), 6)

    def test_xray_config_block_unblock_idempotent(self):
        blocked = tc.rewrite_xray_config(CFG, {("vless", "alice"): True, ("trojan", "carl"): True})
        self.assertNotIn('"id": "11111111-1111-1111-1111-111111111111"', blocked)
        self.assertNotIn('"password": "pw-carl"', blocked)
        self.assertIn('"id": "22222222-2222-2222-2222-222222222222","email": "bob"', blocked)  # bob untouched
        self.assertEqual(tc.rewrite_xray_config(blocked, {("vless", "alice"): True, ("trojan", "carl"): True}), blocked)
        self.assertEqual(tc.rewrite_xray_config(blocked, {}), CFG)  # fully restored

    def test_enforce_xray_file(self):
        self.eng.create_account("alice", "vless", quota_gb=1)
        self.eng.set_status("alice", "vless", "quota_exhausted")
        d = tempfile.mkdtemp(); cfg = Path(d) / "config.json"; cfg.write_text(CFG)
        rep = {"errors": []}
        self.assertTrue(tc.enforce_xray(self.eng, rep, config_path=str(cfg), restart=False))
        self.assertNotIn("11111111-1111-1111-1111-111111111111", cfg.read_text().split("#& bob")[1] + cfg.read_text().split("#& bob")[0].split("#& alice")[1].split("\n")[1])
        self.assertTrue((Path(d) / "config.json.tomtunnel.bak").exists())
        self.assertFalse(tc.enforce_xray(self.eng, rep, config_path=str(cfg), restart=False))  # idempotent
        self.eng.set_status("alice", "vless", "active")  # admin recharge/reactivate
        self.assertTrue(tc.enforce_xray(self.eng, rep, config_path=str(cfg), restart=False))
        self.assertEqual(cfg.read_text(), CFG)

    def test_enforce_ssh_lock_unlock(self):
        me = pwd.getpwuid(os.getuid()).pw_name
        self.eng.create_account(me, "ssh", password="x", quota_gb=1)
        self.eng.set_status(me, "ssh", "quota_exhausted")
        calls = []
        class R:  returncode = 0
        run = lambda cmd, timeout=15: (calls.append(cmd), R())[1]
        tc.enforce_ssh(self.eng, {"errors": []}, run=run)
        tc.enforce_ssh(self.eng, {"errors": []}, run=run)  # second run must not re-lock
        self.assertEqual([c[:2] for c in calls if c[0] == "usermod"], [["usermod", "-L"]])
        self.eng.set_status(me, "ssh", "active")
        tc.enforce_ssh(self.eng, {"errors": []}, run=run)
        self.assertIn(["usermod", "-U", me], calls)

    def test_expiry(self):
        self.eng.create_account("old", "vless")
        with ae._db_connection(self.eng.db_path) as c:
            c.execute("UPDATE clients SET expires_at='2020-01-01' WHERE username='old'"); c.commit()
        self.assertEqual(tc.mark_expired(self.eng), 1)
        self.assertEqual(self.eng.get_account("old", "vless")["status"], "expired")

    def test_run_collector_survives_missing_tools(self):
        d = tempfile.mkdtemp()
        r = tc.run_collector(os.path.join(d, "x.db"))
        self.assertIsInstance(r, dict)


class AlertTests(unittest.TestCase):
    def setUp(self):
        tc._setup_log(); self.eng = fresh()
        self.sent = []
        self.send = lambda cfg, m: (self.sent.append(m), True)[1]
        self.st = {"quota": [80, 90, 100], "expiry_days": [3, 1], "cfg": {}}

    def use(self, user, gb):
        rep = {"xray": 0, "errors": []}
        key = f"xray_base:{user}:up"
        with ae._db_connection(self.eng.db_path) as c:
            base = c.execute("SELECT value FROM engine_meta WHERE key=?", (key,)).fetchone()
        cur = int(gb * GB)
        tc.apply_xray_deltas(self.eng, {user: {"up": cur, "down": 0}}, rep)

    def test_80_90_100_once_each_and_rearm(self):
        self.eng.create_account("a", "vless", quota_gb=10)
        self.use("a", 8.5); tc.process_alerts(self.eng, {}, self.send, self.st)
        self.assertEqual(len(self.sent), 1); self.assertIn("80%", self.sent[0])
        tc.process_alerts(self.eng, {}, self.send, self.st)          # same level: no repeat
        self.assertEqual(len(self.sent), 1)
        self.use("a", 9.2); tc.process_alerts(self.eng, {}, self.send, self.st)
        self.assertIn("90%", self.sent[-1])
        self.use("a", 10.5); tc.process_alerts(self.eng, {}, self.send, self.st)
        self.assertIn("QUOTA ÉPUISÉ", self.sent[-1]); self.assertEqual(len(self.sent), 3)

    def test_unlimited_no_alert_and_failed_send_stays_pending(self):
        self.eng.create_account("free", "vmess", quota_gb=0)
        self.use("free", 100); tc.process_alerts(self.eng, {}, self.send, self.st)
        self.assertEqual(self.sent, [])
        self.eng.create_account("b", "vless", quota_gb=1); self.use("b", 0.9)
        tc.process_alerts(self.eng, {}, lambda c, m: False, self.st); self.assertEqual(self.sent, [])
        tc.process_alerts(self.eng, {}, self.send, self.st); self.assertEqual(len(self.sent), 1)  # retried

    def test_expiry_alert_sent_once(self):
        self.eng.create_account("e", "vless")
        from datetime import date, timedelta
        soon = (date.today() + timedelta(days=2)).isoformat()
        with ae._db_connection(self.eng.db_path) as c:
            c.execute("UPDATE clients SET expires_at=? WHERE username='e'", (soon,)); c.commit()
        tc.process_alerts(self.eng, {}, self.send, self.st); tc.process_alerts(self.eng, {}, self.send, self.st)
        self.assertEqual(len([m for m in self.sent if "expire" in m]), 1)

    def test_settings_configurable(self):
        d = tempfile.mkdtemp(); f = Path(d) / "c.json"
        f.write_text(json.dumps({"bot_token": "T", "super_admin": 1, "alerts": {"quota": [50, 100], "expiry_days": [7]}}))
        st = tc.load_alert_settings(str(f))
        self.assertEqual((st["quota"], st["expiry_days"]), ([50, 100], [7]))
        self.assertEqual(tc.load_alert_settings("/nonexistent")["quota"], [80, 90, 100])



class SshTrafficTests(unittest.TestCase):
    def setUp(self):
        tc._setup_log(); self.eng = fresh()
        self.eng.create_account("u1", "ssh", password="x", quota_gb=10)

    def ss(self, rx, tx, port=5001):
        return (f'ESTAB 0 0 10.0.0.1:22 1.1.1.1:{port} users:(("sshd",pid=101,fd=4))\n'
                f'\t cubic wscale:7,7 bytes_sent:{tx} bytes_acked:{tx} bytes_received:{rx} segs_out:1\n')

    def run_ss(self, text):
        rep = {"denied": [], "errors": []}
        tc.sync_ssh(self.eng, rep, ss_text=text, user_of=lambda n, p: "u1", kill=lambda *a: None)
        return rep

    def test_delta_both_directions_no_double_count(self):
        self.run_ss(self.ss(GB // 2, GB // 2))
        self.assertAlmostEqual(self.eng.get_account("u1", "ssh")["used_gb"], 1.0)
        self.run_ss(self.ss(GB // 2, GB // 2))                      # unchanged -> +0
        self.assertAlmostEqual(self.eng.get_account("u1", "ssh")["used_gb"], 1.0)
        self.run_ss(self.ss(GB, GB // 2))                           # +0.5 GB uplink
        self.assertAlmostEqual(self.eng.get_account("u1", "ssh")["used_gb"], 1.5)

    def test_closed_connection_baseline_removed_and_reused_port(self):
        self.run_ss(self.ss(GB, 0))
        self.run_ss("")                                             # connection closed
        with ae._db_connection(self.eng.db_path) as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM engine_meta WHERE key LIKE 'ssh_cb:%'").fetchone()[0], 0)
        self.run_ss(self.ss(GB // 4, 0))                            # same 4-tuple reused: counted from 0
        self.assertAlmostEqual(self.eng.get_account("u1", "ssh")["used_gb"], 1.25)

    def test_quota_reached_by_ssh_traffic(self):
        self.eng.create_account("u2", "ssh", password="x", quota_gb=1)
        rep = {"denied": [], "errors": []}
        ss = f'ESTAB 0 0 10.0.0.1:22 2.2.2.2:7000 users:(("dropbear",pid=300,fd=4))\n\t bytes_acked:{GB} bytes_received:0\n'
        tc.sync_ssh(self.eng, rep, ss_text=ss, user_of=lambda n, p: "u2", kill=lambda *a: None)
        self.assertEqual(self.eng.get_account("u2", "ssh")["status"], "quota_exhausted")


class XrayIpTests(unittest.TestCase):
    NOW = tc.datetime(2026, 11, 18, 12, 0, 30)

    def setUp(self):
        tc._setup_log(); self.eng = fresh()

    def line(self, ip, email, sec=0, new=True):
        pre = "from " if new else ""
        return f"2026/11/18 12:00:{sec:02d}.123456 {pre}{ip}:5000 accepted tcp:example.com:443 [vless-ws >> direct] email: {email}"

    def test_parse_window_loopback_ipv6(self):
        txt = "\n".join([self.line("1.1.1.1", "a"), self.line("[2001:db8::1]", "a", new=False),
                         self.line("127.0.0.1", "a"), "garbage",
                         "2026/11/18 11:50:00 from 3.3.3.3:1 accepted tcp:x:1 email: a"])
        got, loop = tc.parse_xray_access(txt, now=self.NOW)
        self.assertEqual(got, {"a": {"1.1.1.1", "2001:db8::1"}}); self.assertTrue(loop)

    def test_ip_limit_ban_and_restore(self):
        self.eng.create_account("a", "vless", ip_limit=1, conn_limit=1)   # conn_limit must NOT hit Xray IPs
        self.eng.create_account("free", "vmess")
        txt = "\n".join([self.line("1.1.1.1", "a"), self.line("2.2.2.2", "a"),
                         self.line("5.5.5.5", "free"), self.line("6.6.6.6", "free")])
        rep = {"denied": [], "errors": []}
        banned = tc.sync_xray_ips(self.eng, rep, log_text=txt, now=self.NOW)
        self.assertEqual(list(banned), [("vless", "a")]); self.assertEqual(rep["denied"][0][2], "ip_limit_reached")
        self.assertEqual(len(self.eng.get_active_sessions("free")), 2)   # unlimited account untouched
        d = tempfile.mkdtemp(); cfg = Path(d) / "config.json"
        cfg.write_text(CFG.replace("alice", "a"))
        self.assertTrue(tc.enforce_xray(self.eng, {"errors": []}, config_path=str(cfg), restart=False))
        self.assertNotIn('"id": "11111111-1111-1111-1111-111111111111"', cfg.read_text())
        # cooldown over -> restored
        with ae._db_connection(self.eng.db_path) as c:
            c.execute("UPDATE engine_meta SET value='1' WHERE key LIKE 'xban:%'"); c.commit()
        self.assertTrue(tc.enforce_xray(self.eng, {"errors": []}, config_path=str(cfg), restart=False))
        self.assertEqual(cfg.read_text(), CFG.replace("alice", "a"))

    def test_only_loopback_is_reported_not_enforced(self):
        self.eng.create_account("a", "vless", ip_limit=1)
        rep = {"denied": [], "errors": []}
        tc.sync_xray_ips(self.eng, rep, log_text=self.line("127.0.0.1", "a") + "\n" + self.line("127.0.0.1", "a"), now=self.NOW)
        self.assertEqual(rep["denied"], []); self.assertFalse(rep["xray_real_ip"])


class RealIpPatchTests(unittest.TestCase):
    def test_patch_project_config(self):
        import xray_realip as x
        cfg = Path(__file__).resolve().parents[1] / "module" / "config.json"
        t = cfg.read_text()
        strip = lambda s: "\n".join(l for l in s.split("\n") if not l.lstrip().startswith("#"))
        new, n = x.patch(t)
        self.assertGreater(n, 0)
        json.loads(strip(new))                                  # still valid JSON
        self.assertEqual(x.patch(new)[1], 0)                    # idempotent
        self.assertEqual(x.patch(new, revert=True)[0], t)       # exact revert
        self.assertNotRegex(new, r'sockopt[^\n]*\n\s*"network": "grpc"')  # gRPC untouched


if __name__ == "__main__":
    unittest.main(verbosity=2)
