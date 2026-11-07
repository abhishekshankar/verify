"""Run from verify/:  PYTHONPATH=src:. python3 -m unittest hosted.test_hosted -v
Against Postgres: set VERIFY_TEST_PG_DSN (a throwaway UTF8 database; its public schema is wiped per test)."""
import contextlib, hashlib, hmac, io, json, os, sqlite3, tempfile, threading, unittest, urllib.error, urllib.request
from datetime import datetime, timedelta, timezone
from hosted.store import Store, chain_hash
from hosted.server import make_server
from verify.push import push

KEY = "test-export-key"
PG = os.environ.get("VERIFY_TEST_PG_DSN")

if PG:
    from hosted.store import PostgresStore
    _SQL = open(os.path.join(os.path.dirname(__file__), "schema.postgres.sql")).read()
    def Store(_path):   # noqa: F811  fresh schema per test
        import psycopg
        with psycopg.connect(PG, autocommit=True) as c:
            c.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
            for r in ("verify_app", "verify_retention"):
                c.execute(f"DO $$BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{r}') THEN CREATE ROLE {r}; END IF; END$$;")
            c.execute(_SQL)
        return PostgresStore(PG)

def ev(run_id, type_, payload, prev, at=None):
    e = {"run_id": run_id, "type": type_, "at": at or datetime.now(timezone.utc).isoformat(), "clock_source": "system",
         "payload_json": json.dumps(payload, sort_keys=True), "evidence_hash": None, "prev_hash": prev}
    e["hash"] = chain_hash(prev, e); return e

class Hosted(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.store = Store(os.path.join(self.dir, "hosted.db"))
        self.store.add_tenant("acme", "key-acme"); self.store.add_tenant("globex", "key-globex")
        self.srv = make_server(self.store, 0, export_key=KEY)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def tearDown(self): self.srv.shutdown(); self.srv.server_close()

    def call(self, method, path, body=None, key="key-acme", raw=False):
        h = {"Content-Type": "application/json"}
        if key: h["Authorization"] = f"Bearer {key}"
        req = urllib.request.Request(self.base + path, method=method, headers=h,
                                     data=json.dumps(body).encode() if body is not None else None)
        try:
            with urllib.request.urlopen(req) as r: return r.status, (r.read() if raw else json.loads(r.read())), dict(r.headers)
        except urllib.error.HTTPError as e:
            with e: return e.code, json.loads(e.read()), None

    def post(self, events, key="key-acme", **kw): return self.call("POST", "/v1/events", {"events": events, **kw}, key)[:2]

    def test_auth_required(self):
        for k in (None, "wrong"):
            self.assertEqual(self.call("GET", "/v1/verify-chain", key=k)[0], 401)
        self.assertEqual(self.post([ev("r", "x", {}, "")], key=None)[0], 401)

    def test_access_log_and_key_rotation(self):
        self.call("GET", "/v1/verify-chain"); self.call("GET", "/v1/verdicts")
        st, body, _ = self.call("GET", "/v1/access-log")
        self.assertEqual([(r["method"], r["path"], r["status"]) for r in body["access_log"]][-2:][::-1],
                         [("GET", "/v1/verify-chain", 200), ("GET", "/v1/verdicts", 200)])
        self.assertEqual(self.call("GET", "/v1/access-log", key="key-globex")[1]["access_log"], [])   # isolated
        with self.assertRaises(Exception): self.store.q("DELETE FROM access_log")                    # append-only
        if PG: self.store.db.rollback() if not self.store.db.autocommit else None
        self.assertTrue(self.store.rotate_key("acme", "key-acme-2"))
        self.assertEqual(self.call("GET", "/v1/verify-chain")[0], 401)
        self.assertEqual(self.call("GET", "/v1/verify-chain", key="key-acme-2")[0], 200)
        self.assertFalse(self.store.rotate_key("nobody", "x"))

    def test_tenant_isolation(self):
        e = ev("r1", "action_claimed", {"secret": 1}, "")
        self.assertEqual(self.post([e], runs=[{"run_id": "r1", "contract_id": "c", "contract_version": "1", "subject_ref": "s",
                                               "actor": "a", "started_at": e["at"]}])[0], 201)
        self.assertEqual(self.call("GET", "/v1/runs/r1", key="key-globex")[0], 404)
        self.assertEqual(self.call("GET", "/v1/verify-chain", key="key-globex")[1]["events"], 0)
        self.assertEqual(self.post([ev("r9", "x", {}, "")], key="key-globex")[0], 201)   # globex chain starts at "" too
        self.assertEqual(self.call("GET", "/v1/runs/r1")[0], 200)

    def test_chain_enforcement_409(self):
        e1 = ev("r", "a", {}, ""); self.assertEqual(self.post([e1])[0], 201)
        s, body = self.post([ev("r", "b", {}, "")])                      # stale prev_hash
        self.assertEqual(s, 409); self.assertEqual(body["head"], e1["hash"])
        s, _ = self.post([ev("r", "b", {}, e1["hash"]), ev("r", "c", {}, "bogus")])   # bad 2nd event -> whole batch rolled back
        self.assertEqual(s, 409); self.assertEqual(self.call("GET", "/v1/verify-chain")[1]["events"], 1)

    def test_tamper_rejected(self):
        e = ev("r", "a", {"amount": 5000}, ""); e["payload_json"] = json.dumps({"amount": 1})   # hash no longer matches
        self.assertEqual(self.post([e])[0], 400)
        self.assertEqual(self.post([ev("r", "a", {}, "")])[0], 201)
        for sql in ("UPDATE event SET type='x'", "DELETE FROM event", "UPDATE event_payload SET payload_json='{}'",
                    "DELETE FROM event_payload"):
            with self.assertRaises(Exception, msg=sql): self.store.db.execute(sql)   # sqlite3 or psycopg error
        self.assertTrue(self.call("GET", "/v1/verify-chain")[1]["ok"])

    def test_export_signature(self):
        prev = ""
        for t in ("a", "b"):
            e = ev("r", t, {"t": t}, prev); self.post([e]); prev = e["hash"]
        s, r, h = self.call("GET", "/v1/export", raw=True)
        body = r
        self.assertEqual(h["X-Signature"], "hmac-sha256=" + hmac.new(KEY.encode(), body, hashlib.sha256).hexdigest())
        lines = [json.loads(l) for l in body.decode().splitlines()]
        self.assertEqual(lines[-1]["chain_head"], prev); self.assertEqual(len(lines), 3)

    def test_purge_keeps_chain_valid(self):
        old = (datetime.now(timezone.utc) - timedelta(days=500)).isoformat()
        e1 = ev("r", "a", {"pii": "jane@x.com"}, "", at=old); e2 = ev("r", "b", {"n": 2}, e1["hash"])
        self.assertEqual(self.post([e1, e2])[0], 201)
        self.assertEqual(self.store.purge("acme", 400), 1)
        chain = self.call("GET", "/v1/verify-chain")[1]
        self.assertEqual((chain["ok"], chain["tombstoned"], chain["head"]), (True, 1, e2["hash"]))
        self.assertNotIn(b"jane@x.com", self.call("GET", "/v1/export", raw=True)[1])
        self.assertEqual(self.post([ev("r", "c", {}, e2["hash"])])[0], 201)    # chain still appendable

    def test_client_push_demo_ledger(self):
        from verify import local
        out = os.path.join(self.dir, "demo")
        with contextlib.redirect_stdout(io.StringIO()): local.demo(out)
        led = os.path.join(out, "ledger.db")
        db = sqlite3.connect(led); local_head = db.execute("SELECT hash FROM event ORDER BY seq DESC LIMIT 1").fetchone()[0]
        n = db.execute("SELECT count(*) FROM event").fetchone()[0]
        run_ids = [r[0] for r in db.execute("SELECT run_id FROM verdict")]; db.close()
        r = push(led, self.base, "key-acme", batch=4)                     # small batches exercise chunking
        self.assertEqual((r["pushed"], r["head"]), (n, local_head))
        self.assertEqual(push(led, self.base, "key-acme")["pushed"], 0)  # resume: nothing new
        chain = self.call("GET", "/v1/verify-chain")[1]
        self.assertEqual((chain["ok"], chain["events"], chain["head"]), (True, n, local_head))
        self.assertEqual(sorted(v["verdict"] for v in self.call("GET", "/v1/verdicts?since=2000")[1]["verdicts"]),
                         ["fail", "not_observed", "pass"])
        run = self.call("GET", f"/v1/runs/{run_ids[0]}")[1]
        self.assertTrue(run["events"] and run["verdict"])

    def test_cli_push(self):
        from verify import local
        from verify.cli import main
        out = os.path.join(self.dir, "demo")
        with contextlib.redirect_stdout(io.StringIO()): local.demo(out)
        led = os.path.join(out, "ledger.db")
        with contextlib.redirect_stderr(io.StringIO()): self.assertEqual(main(["push", led, "--to", self.base]), 2)   # no key
        os.environ["VERIFY_HOSTED_KEY"] = "key-acme"
        try:
            for want in ("pushed 1", "pushed 0 events"):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf): self.assertEqual(main(["push", led, "--to", self.base]), 0)
                self.assertIn(want, buf.getvalue())
        finally: del os.environ["VERIFY_HOSTED_KEY"]

if __name__ == "__main__": unittest.main()
