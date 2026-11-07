"""Hosted ledger HTTP API v0 (stdlib only).

Routing is a plain function `handle(store, method, path, query, headers, body) -> (status, headers, body)`,
so moving to FastAPI/Starlette later means wrapping `handle`, not rewriting it.

Env: VERIFY_EXPORT_KEY (HMAC key for signed exports, required), VERIFY_DATABASE_URL (postgres://... or sqlite path).
Admin:  python -m hosted.server add-tenant <id>       (prints a new API key once; only its sha256 is stored)
        python -m hosted.server rotate-key <id>       (new key printed once; old key stops working)
        python -m hosted.server purge <id> <days>
        python -m hosted.server serve [port]
"""
import hashlib, hmac, json, os, secrets, sys, re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs
from .store import Conflict, Invalid, open_store

MAX_BODY = 5 * 1024 * 1024

def _json(status, obj): return status, {"Content-Type": "application/json"}, json.dumps(obj).encode()

def sign(key, body): return hmac.new(key.encode(), body, hashlib.sha256).hexdigest()

def export(store, tenant, key):
    lines = [json.dumps(e, sort_keys=True) for e in store.events(tenant)]
    lines.append(json.dumps({"chain_head": store.head(tenant)[1], "tenant": tenant}, sort_keys=True))
    body = ("\n".join(lines) + "\n").encode()
    return 200, {"Content-Type": "application/x-ndjson", "X-Signature": "hmac-sha256=" + sign(key, body),
                 "X-Chain-Head": store.head(tenant)[1]}, body

def handle(store, method, path, query, headers, body, export_key):
    auth = headers.get("Authorization", "")
    tenant = store.tenant_for_key(auth[7:]) if auth.startswith("Bearer ") and len(auth) > 7 else None
    if not tenant: return _json(401, {"error": "missing or invalid API key"})
    res = _route(store, tenant, method, path, query, body, export_key)
    store.log_access(tenant, method, path, res[0])
    return res

def _route(store, tenant, method, path, query, body, export_key):
    if method == "POST" and path == "/v1/events":
        try:
            req = json.loads(body or b"{}")
            return _json(201, store.append(tenant, req.get("events", []), req.get("runs", []), req.get("verdicts", [])))
        except Conflict as e: return _json(409, {"error": str(e), "head": store.head(tenant)[1]})
        except (Invalid, ValueError, KeyError, TypeError, AttributeError) as e: return _json(400, {"error": f"invalid batch: {e}"})
        except Exception as e:   # constraint violations (duplicate run, bad verdict enum)
            return _json(400, {"error": f"rejected: {type(e).__name__}: {e}"})
    if method != "GET": return _json(405, {"error": "method not allowed"})
    if m := re.fullmatch(r"/v1/runs/([\w.:-]+)", path):
        r = store.run(tenant, m[1])
        return _json(200, r) if r else _json(404, {"error": "run not found"})
    if path == "/v1/verdicts": return _json(200, {"verdicts": store.verdicts(tenant, query.get("since", [""])[0])})
    if path == "/v1/verify-chain": return _json(200, store.verify_chain(tenant))
    if path == "/v1/export": return export(store, tenant, export_key)
    if path == "/v1/access-log": return _json(200, {"access_log": store.access_log(tenant)})
    return _json(404, {"error": "not found"})

def make_server(store, port=0, export_key=None, host="127.0.0.1"):
    key = export_key or os.environ.get("VERIFY_EXPORT_KEY")
    if not key: raise RuntimeError("VERIFY_EXPORT_KEY must be set")

    class H(BaseHTTPRequestHandler):
        def _go(self, method):
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY: s, h, b = _json(413, {"error": "body too large"})
            else:
                u = urlsplit(self.path)
                s, h, b = handle(store, method, u.path, parse_qs(u.query), self.headers, self.rfile.read(n), key)
            self.send_response(s)
            for k, v in {**h, "Content-Length": str(len(b))}.items(): self.send_header(k, v)
            self.end_headers(); self.wfile.write(b)
        def do_GET(self): self._go("GET")
        def do_POST(self): self._go("POST")
        def log_message(self, *a): pass

    return ThreadingHTTPServer((host, port), H)

if __name__ == "__main__":
    cmd, args, st = (sys.argv[1:2] or ["serve"])[0], sys.argv[2:], open_store()
    if cmd == "add-tenant":
        k = "vk_" + secrets.token_urlsafe(32); st.add_tenant(args[0], k); print(k)
    elif cmd == "rotate-key":
        k = "vk_" + secrets.token_urlsafe(32)
        print(k if st.rotate_key(args[0], k) else f"no tenant {args[0]!r}")
    elif cmd == "purge":
        print(st.purge(args[0], int(args[1])), "payloads tombstoned")
    else:
        srv = make_server(st, int(args[0]) if args else 8080, host=os.environ.get("VERIFY_BIND", "0.0.0.0"))
        print("listening on", srv.server_address); srv.serve_forever()
