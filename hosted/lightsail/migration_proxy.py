#!/usr/bin/env python3
"""Temporary, bounded HTTP bridge for a single-writer ledger cutover.

SOURCE forwards to the observed ECS task private address. DRAIN queues every
application request. TARGET forwards to the local replacement app. Health checks
never touch either database. A root/local-owner-only Unix socket controls modes;
changing DNS or reading an HTTP URL cannot change them. Requests are never replayed.
"""
import argparse
from contextlib import contextmanager
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import stat
import tempfile
import threading
import time
from urllib.parse import urlsplit

MAX_BODY = 5 * 1024 * 1024
HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
               "te", "trailer", "transfer-encoding", "upgrade"}


class GateError(Exception):
    pass


def endpoint(url):
    item = urlsplit(url)
    address = ipaddress.ip_address(item.hostname or "")
    if (item.scheme != "http" or not address.is_private or item.username or item.password
            or item.path not in ("", "/") or item.query or item.fragment):
        raise ValueError("Upstreams must be literal private or loopback HTTP endpoints")
    return item.hostname, item.port or 80


class Gate:
    def __init__(self, state_file, queue_seconds=20):
        self.state_file = Path(state_file)
        state = json.loads(self.state_file.read_text())
        if (state.get("version") != 1 or state.get("mode") not in ("source", "drain", "target")
                or type(state.get("targetActivated")) is not bool
                or (state["targetActivated"] and state["mode"] == "source")
                or (state["mode"] == "target" and not state["targetActivated"])):
            raise ValueError("A valid durable gate state is required")
        if not 1 <= queue_seconds <= 60:
            raise ValueError("The queue deadline must be between 1 and 60 seconds")
        self.mode, self.target_activated = state["mode"], state["targetActivated"]
        self.queue_seconds = queue_seconds
        self.condition = threading.Condition()
        self.active = self.queued = self.timed_out = 0
        self.forwarded = {"source": 0, "target": 0}

    def _persist(self, mode, activated):
        data = json.dumps({"version": 1, "mode": mode, "targetActivated": activated}) + "\n"
        fd, temporary = tempfile.mkstemp(prefix=".gate-", dir=self.state_file.parent)
        try:
            with os.fdopen(fd, "w") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.state_file)
            directory = os.open(self.state_file.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def status(self):
        with self.condition:
            return {"mode": self.mode, "targetActivated": self.target_activated,
                    "active": self.active, "queued": self.queued, "queueTimeouts": self.timed_out,
                    "forwarded": dict(self.forwarded), "queueDeadlineSeconds": self.queue_seconds}

    def change(self, mode, expected):
        with self.condition:
            if expected != self.mode:
                raise GateError("Mode changed since the operator's observation")
            if mode not in ("source", "drain", "target"):
                raise GateError("Unknown mode")
            if mode == self.mode:
                return self.status()
            if mode != "drain" and self.mode != "drain":
                raise GateError("First enter drain mode")
            if mode == "target" and self.active:
                raise GateError("First drain all in-flight requests")
            if mode == "source" and self.target_activated:
                raise GateError("Source is stale after target activation; reverse-copy data before any source rollback")
            activated = self.target_activated or mode == "target"
            self._persist(mode, activated)
            self.mode, self.target_activated = mode, activated
            self.condition.notify_all()
            return self.status()

    @contextmanager
    def destination(self):
        with self.condition:
            deadline = time.monotonic() + self.queue_seconds
            if self.mode == "drain":
                self.queued += 1
                try:
                    while self.mode == "drain":
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            self.timed_out += 1
                            raise GateError("Migration queue deadline reached")
                        self.condition.wait(remaining)
                finally:
                    self.queued -= 1
            mode = self.mode
            self.active += 1
            self.forwarded[mode] += 1
        try:
            yield mode
        finally:
            with self.condition:
                self.active -= 1
                self.condition.notify_all()


class BoundedServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, address, handler, max_workers=32):
        self.workers = threading.BoundedSemaphore(max_workers)
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        if not self.workers.acquire(blocking=False):
            try:
                request.settimeout(1)
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nRetry-After: 1\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.workers.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.workers.release()


def make_proxy(gate, source, target, address=("127.0.0.1", 8082), max_workers=32):
    upstreams = {"source": endpoint(source), "target": endpoint(target)}
    if upstreams["source"] == upstreams["target"]:
        raise ValueError("Source and target endpoints must differ")

    class Proxy(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass  # Never log tenant paths, bodies, authorization headers or signed exports.

        def reply(self, status, body, retry=False):
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            if retry:
                self.send_header("Retry-After", "1")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)
            self.close_connection = True

        def forward(self):
            self.connection.settimeout(30)
            if self.path == "/__migration_health" and self.command == "GET":
                self.reply(200, {"service": "migration-bridge", "ok": True})
                return
            lengths = self.headers.get_all("Content-Length", [])
            if (self.headers.get("Transfer-Encoding") or len(lengths) > 1
                    or not self.path.startswith("/") or self.path.startswith("//")):
                self.reply(400, {"error": "invalid request framing"})
                return
            try:
                size = int(lengths[0]) if lengths else 0
                if size < 0:
                    raise ValueError()
            except ValueError:
                self.reply(400, {"error": "invalid content length"})
                return
            if size > MAX_BODY:
                self.reply(413, {"error": "body too large"})
                return
            body = self.rfile.read(size)
            if len(body) != size:
                self.close_connection = True
                return
            started = False
            try:
                with gate.destination() as mode:
                    # A client that abandoned a queued call must not create a late write.
                    if select.select([self.connection], [], [], 0)[0] and not self.connection.recv(1, socket.MSG_PEEK):
                        self.close_connection = True
                        return
                    skip = HOP_HEADERS | {part.strip().lower() for part in self.headers.get("Connection", "").split(",")}
                    headers = {key: value for key, value in self.headers.items() if key.lower() not in skip}
                    headers["Connection"] = "close"
                    headers["Content-Length"] = str(len(body))
                    upstream = http.client.HTTPConnection(*upstreams[mode], timeout=30)
                    try:
                        upstream.request(self.command, self.path, body=body, headers=headers)
                        response = upstream.getresponse()
                        self.send_response_only(response.status, response.reason)
                        for key, value in response.getheaders():
                            if key.lower() not in HOP_HEADERS:
                                self.send_header(key, value)
                        self.send_header("Connection", "close")
                        self.end_headers()
                        started = True
                        if self.command != "HEAD":
                            while chunk := response.read(65536):
                                self.wfile.write(chunk)
                    finally:
                        upstream.close()
            except GateError:
                if not started:
                    self.reply(503, {"error": "migration queue deadline reached"}, retry=True)
            except (OSError, http.client.HTTPException):
                # No retry: an upstream may have committed a POST before disconnecting.
                if not started:
                    self.reply(502, {"error": "upstream unavailable"})
            finally:
                self.close_connection = True

        do_GET = do_POST = do_HEAD = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = forward

    return BoundedServer(address, Proxy, max_workers=max_workers)


def make_control(gate, socket_path):
    path = Path(socket_path)
    if path.exists():
        if not stat.S_ISSOCK(path.stat().st_mode) or path.stat().st_uid != os.getuid():
            raise ValueError("Refusing to replace a nonowned control path")
        probe = socket.socket(socket.AF_UNIX)
        try:
            probe.connect(str(path))
        except ConnectionRefusedError:
            path.unlink()
        else:
            raise ValueError("Control socket already serves a live process")
        finally:
            probe.close()

    class Control(socketserver.StreamRequestHandler):
        def handle(self):
            self.connection.settimeout(3)
            try:
                data = self.rfile.readline(4097)
                if len(data) > 4096 or not data.endswith(b"\n"):
                    raise GateError("Invalid control message")
                request = json.loads(data)
                if not isinstance(request, dict):
                    raise GateError("Invalid control object")
                if request.get("action") == "status":
                    result = gate.status()
                elif request.get("action") == "set":
                    result = gate.change(request.get("mode"), request.get("expected"))
                else:
                    raise GateError("Unknown control action")
                response = {"ok": True, **result}
            except (ValueError, GateError, OSError) as exc:
                response = {"ok": False, "error": str(exc) if isinstance(exc, GateError) else "Control operation failed"}
            self.wfile.write((json.dumps(response) + "\n").encode())

    server = socketserver.UnixStreamServer(str(path), Control)
    os.chmod(path, 0o600)
    return server


def control(socket_path, request, timeout=5):
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(timeout)
        connection.connect(socket_path)
        connection.sendall((json.dumps(request) + "\n").encode())
        with connection.makefile("rb") as stream:
            result = json.loads(stream.readline(8192))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", default="/run/verify-migration/control.sock")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("serve")
    run.add_argument("--state", default="/var/lib/verify-migration/state.json")
    run.add_argument("--source", required=True)
    run.add_argument("--target", default="http://127.0.0.1:8080")
    run.add_argument("--bind", default="0.0.0.0")
    run.add_argument("--port", default=8082, type=int)
    run.add_argument("--queue-seconds", default=20, type=float)
    commands.add_parser("status")
    change = commands.add_parser("set")
    change.add_argument("mode", choices=("source", "drain", "target"))
    change.add_argument("--expected", choices=("source", "drain", "target"), required=True)
    args = parser.parse_args()
    if args.command != "serve":
        request = {"action": "status"} if args.command == "status" else {"action": "set", "mode": args.mode, "expected": args.expected}
        result = control(args.socket, request)
        print(json.dumps(result))
        return 0 if result["ok"] else 2
    gate = Gate(args.state, args.queue_seconds)
    proxy = make_proxy(gate, args.source, args.target, (args.bind, args.port))
    admin = make_control(gate, args.socket)
    threading.Thread(target=admin.serve_forever, daemon=True).start()
    try:
        proxy.serve_forever()
    finally:
        admin.shutdown()
        admin.server_close()
        proxy.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
