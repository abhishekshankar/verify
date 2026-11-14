from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

from hosted.lightsail.migration_proxy import Gate, GateError, control, endpoint, make_control, make_proxy


class ProxyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "state.json"
        self.path.write_text(json.dumps({"version": 1, "mode": "source", "targetActivated": False}))
        self.gate = Gate(self.path, queue_seconds=1)
        self.calls = []
        self.block = threading.Event()
        self.block.set()
        calls, block = self.calls, self.block

        def backend(label):
            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):
                    body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                    calls.append((label, self.command, self.path, body, self.headers.get("Authorization")))
                    block.wait(3)
                    output = json.dumps({"backend": label}).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(output)))
                    self.send_header("X-Signature", "hmac-sha256=preserved")
                    self.end_headers()
                    self.wfile.write(output)
                do_POST = do_GET
                def log_message(self, *args):
                    pass
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            return server

        self.source, self.target = backend("source"), backend("target")
        self.proxy = make_proxy(self.gate, f"http://127.0.0.1:{self.source.server_port}",
                                f"http://127.0.0.1:{self.target.server_port}", ("127.0.0.1", 0))
        threading.Thread(target=self.proxy.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.proxy.server_port}"

    def tearDown(self):
        self.block.set()
        for server in (self.proxy, self.source, self.target):
            server.shutdown()
            server.server_close()
        self.directory.cleanup()

    def call(self, method="GET", path="/v1/verify-chain"):
        request = urllib.request.Request(self.base + path, method=method,
            data=b'{"events":[]}' if method == "POST" else None,
            headers={"Authorization": "Bearer synthetic-test-key"})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read()), response.headers
        except urllib.error.HTTPError as response:
            return response.code, json.loads(response.read()), response.headers

    def wait_for(self, predicate):
        deadline = time.monotonic() + 3
        while not predicate():
            self.assertLess(time.monotonic(), deadline)
            time.sleep(.01)

    def test_health_bypasses_gate_and_does_not_touch_any_backend(self):
        self.gate.change("drain", "source")
        self.assertEqual(self.call(path="/__migration_health")[0], 200)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.gate.status()["active"], 0)

    def test_headers_body_query_and_signature_are_preserved(self):
        status, body, headers = self.call("POST", "/v1/events?check=1")
        self.assertEqual((status, body["backend"]), (200, "source"))
        self.assertEqual(headers["X-Signature"], "hmac-sha256=preserved")
        self.assertEqual(self.calls, [("source", "POST", "/v1/events?check=1", b'{"events":[]}', "Bearer synthetic-test-key")])

    def test_get_and_post_queue_then_go_to_target_once(self):
        self.gate.change("drain", "source")
        with ThreadPoolExecutor(2) as pool:
            pending = [pool.submit(self.call, method) for method in ("GET", "POST")]
            self.wait_for(lambda: self.gate.status()["queued"] == 2)
            self.assertEqual(self.calls, [])
            self.gate.change("target", "drain")
            self.assertEqual([job.result()[1]["backend"] for job in pending], ["target", "target"])
        self.assertEqual(len(self.calls), 2)
        self.assertTrue(all(call[0] == "target" for call in self.calls))

    def test_inflight_source_must_finish_before_target_activation(self):
        self.block.clear()
        with ThreadPoolExecutor(1) as pool:
            pending = pool.submit(self.call)
            self.wait_for(lambda: self.gate.status()["active"] == 1)
            self.gate.change("drain", "source")
            with self.assertRaises(GateError):
                self.gate.change("target", "drain")
            self.block.set()
            self.assertEqual(pending.result()[1]["backend"], "source")
            self.wait_for(lambda: self.gate.status()["active"] == 0)
            self.gate.change("target", "drain")

    def test_deadline_rejects_without_any_late_backend_write(self):
        self.gate.change("drain", "source")
        status, body, headers = self.call("POST")
        self.assertEqual(status, 503)
        self.assertEqual(headers["Retry-After"], "1")
        self.gate.change("target", "drain")
        self.assertEqual(self.calls, [])
        self.assertEqual(self.gate.status()["queueTimeouts"], 1)

    def test_source_rollback_is_blocked_after_target_activation_and_restart(self):
        with self.assertRaises(GateError):
            self.gate.change("target", "source")
        self.gate.change("drain", "source")
        self.gate.change("source", "drain")
        self.gate.change("drain", "source")
        self.gate.change("target", "drain")
        self.gate.change("drain", "target")
        with self.assertRaises(GateError):
            Gate(self.path).change("source", "drain")
        self.assertTrue(Gate(self.path).status()["targetActivated"])

    def test_private_control_socket(self):
        socket_path = str(Path(self.directory.name) / "control.sock")
        try:
            admin = make_control(self.gate, socket_path)
        except PermissionError:
            self.skipTest("AF_UNIX sockets are unavailable in this execution environment; run on the target host")
        threading.Thread(target=admin.serve_forever, daemon=True).start()
        try:
            self.assertEqual(Path(socket_path).stat().st_mode & 0o777, 0o600)
            self.assertEqual(control(socket_path, {"action": "status"})["mode"], "source")
            self.assertFalse(control(socket_path, {"action": "set", "mode": "target", "expected": "source"})["ok"])
        finally:
            admin.shutdown()
            admin.server_close()
    def test_public_or_credentialed_upstream_is_rejected(self):
        for url in ("http://8.8.8.8", "https://127.0.0.1", "http://user:secret@127.0.0.1", "http://127.0.0.1/path"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                endpoint(url)


if __name__ == "__main__":
    unittest.main()
