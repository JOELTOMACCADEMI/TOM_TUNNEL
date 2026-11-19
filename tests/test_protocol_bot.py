"""Bot protocol menu: permissions, whitelist, backend calls (fake bot, fake CLI)."""
import json, sys, types, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tom_tunnel_core_bot"))

# minimal telebot stub so the test runs without the package
if "telebot" not in sys.modules:
    tb = types.ModuleType("telebot"); tt = types.ModuleType("telebot.types")
    class _M:
        def __init__(self, *a, **k): self.rows = []
        def add(self, *b): self.rows += b
    class _B:
        def __init__(self, text, callback_data=None): self.text, self.callback_data = text, callback_data
    tt.InlineKeyboardMarkup, tt.InlineKeyboardButton = _M, _B
    tb.types = tt; sys.modules["telebot"] = tb; sys.modules["telebot.types"] = tt

from modules import protocol_core as pc  # noqa: E402


class FakeBot:
    def __init__(self): self.handlers, self.sent = [], []
    def callback_query_handler(self, func): 
        def deco(f): self.handlers.append((func, f)); return f
        return deco
    def answer_callback_query(self, *a, **k): self.sent.append(("answer", a))
    def edit_message_text(self, text, *a, **k): self.sent.append(("edit", text))
    def send_message(self, chat, text, **k): self.sent.append(("send", text))


def call(uid, data):
    return types.SimpleNamespace(id="1", data=data, from_user=types.SimpleNamespace(id=uid),
                                 message=types.SimpleNamespace(chat=types.SimpleNamespace(id=9), message_id=1))


class T(unittest.TestCase):
    def setUp(self):
        self.calls = []
        def fake_cli(args, run=None):
            self.calls.append(args)
            if args[0] == "list":
                return [{"id": "vless", "label": "VLESS", "state": "running", "accounts_active": 1, "accounts_total": 2}]
            if args[0] == "status":
                return {"id": args[1], "label": "X", "mode": "accounts", "enabled": True, "state": "running",
                        "services": [], "ports": [], "accounts_active": 1, "accounts_total": 1}
            return {"ok": True, "message": "fait", "logs": "l", "errors": "e", "ports": [], "note": "n"}
        self._orig, pc.cli = pc.cli, fake_cli
        self.bot = FakeBot()
        pc.register(self.bot, lambda u: u in (1, 2), lambda u: u == 1, lambda: "HOME")

    def tearDown(self): pc.cli = self._orig

    def dispatch(self, uid, data):
        c = call(uid, data)
        for flt, fn in self.bot.handlers:
            if flt(c): fn(c)

    def test_stranger_cannot_do_anything(self):
        for d in ("menu_protocols", "pm:off:vless", "pm:on:vless", "pm:restart:vless", "pm:logs:vless"):
            self.dispatch(99, d)
        self.assertEqual(self.calls, [])

    def test_plain_admin_can_view_but_not_change(self):
        self.dispatch(2, "pm:view:vless"); self.dispatch(2, "pm:logs:vless")
        for d in ("pm:off:vless", "pm:on:vless", "pm:restart:vless"):
            self.dispatch(2, d)
        self.assertEqual([c[0] for c in self.calls], ["status", "logs"])

    def test_super_admin_changes_reach_backend(self):
        self.dispatch(1, "pm:askoff:vless")
        self.assertEqual(self.calls, [])                     # confirmation first, nothing executed
        self.dispatch(1, "pm:off:vless"); self.dispatch(1, "pm:on:vless"); self.dispatch(1, "pm:restart:vless")
        self.assertEqual([c[:2] for c in self.calls if c[0] != "status"],
                         [["disable", "vless"], ["enable", "vless"], ["restart", "vless"]])

    def test_non_whitelisted_protocol_is_refused(self):
        for d in ("pm:off:vless;reboot", "pm:off:../x", "pm:off:", "pm:off:vless:extra"):
            self.dispatch(1, d)
        self.assertEqual(self.calls, [])

    def test_menu_lists_protocols(self):
        self.dispatch(2, "menu_protocols")
        self.assertTrue(any("PROTOCOLES" in str(s[1]) for s in self.bot.sent if s[0] == "edit"))


if __name__ == "__main__":
    unittest.main()
