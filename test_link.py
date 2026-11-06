import os, tempfile, unittest
os.environ["HIVE_LINK_HOME"] = tempfile.mkdtemp()
import hive_link as L

class T(unittest.TestCase):
    def setUp(self):
        # one identity plays both ends: we pin our own key as "h2"
        import shutil; shutil.rmtree(L.HOME, ignore_errors=True)
        self.pub = L.init("h2"); L.pin("h2", self.pub)
        self.got = []; self.t = 1000
        self.rx = L.Receiver(lambda *a: self.got.append(a), now=lambda: self.t)
    def env(self, **kw):
        return L.make(kw.pop("to", "h2"), kw.pop("text", "hi"), now=kw.pop("now", 1000), nonce=kw.pop("nonce", "n1"))
    def rej(self, e, why):
        with self.assertRaises(L.Reject) as c: self.rx.accept(e)
        self.assertIn(why, str(c.exception))
    def test_ok_and_defang(self):
        self.rx.accept(self.env(text="@new do it")); self.assertEqual(self.got[0][2], "＠new do it")
    def test_tamper(self):
        e = self.env(); e["text"] = "evil"; self.rej(e, "signature")
    def test_unknown_peer(self):
        e = self.env(); e["from_hive"] = "h9"; self.rej(e, "unknown")
    def test_wrong_target(self): self.rej(self.env(to="h3"), "not for us")
    def test_replay(self):
        e = self.env(); self.rx.accept(e); self.rej(e, "replay")
    def test_stale(self): self.rej(self.env(now=1000-400), "stale")
    def test_rate(self):
        for i in range(L.RATE): self.rx.accept(self.env(nonce=f"n{i}"))
        self.rej(self.env(nonce="x"), "rate")
    def test_size(self): self.rej(self.env(text="a" * 9000), "size")
    def test_key_change_refused(self):
        other = L.Ed25519PrivateKey.generate()
        with self.assertRaises(SystemExit): L.pin("h2", L.pub_of(other))
if __name__ == "__main__": unittest.main()
