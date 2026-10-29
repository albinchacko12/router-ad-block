"""Web control panel and JSON API."""

import base64
import hmac
import json
import logging
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

log = logging.getLogger(__name__)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
ENTRY_KINDS = {"/api/allowlist": "allowlist", "/api/blocklist": "blocklist",
               "/api/bypass": "bypass_clients"}


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def make_handler(filter_, admin_password):
    class Handler(BaseHTTPRequestHandler):
        server_version = "router-ad-block"

        def log_message(self, fmt, *args):
            log.debug("%s %s", self.address_string(), fmt % args)

        # ---- plumbing ------------------------------------------------

        def _authorized(self):
            if not admin_password:
                return True
            header = self.headers.get("Authorization", "")
            if not header.startswith("Basic "):
                return False
            try:
                _, _, password = base64.b64decode(header[6:]).decode().partition(":")
            except ValueError:
                return False
            return hmac.compare_digest(password.encode(), admin_password.encode())

        def _send(self, status, body, content_type="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(data)

        def _body(self):
            # Requiring a JSON content type forces a CORS preflight, which blocks
            # other websites from silently changing settings via the browser.
            if not self.headers.get("Content-Type", "").startswith("application/json"):
                raise ApiError(415, "Content-Type must be application/json")
            length = int(self.headers.get("Content-Length") or 0)
            if length > 64 * 1024:
                raise ApiError(413, "request too large")
            try:
                return json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                raise ApiError(400, "invalid JSON") from None

        def _dispatch(self, method):
            if not self._authorized():
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="router-ad-block"')
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            url = urlparse(self.path)
            try:
                result = self._route(method, url.path, parse_qs(url.query))
            except ApiError as exc:
                return self._send(exc.status, {"error": str(exc)})
            except ValueError as exc:
                return self._send(400, {"error": str(exc)})
            if result is None:
                return self._send(404, {"error": "not found"})
            if isinstance(result, tuple):
                return self._send(200, *result)
            self._send(200, result)

        do_GET = lambda self: self._dispatch("GET")
        do_POST = lambda self: self._dispatch("POST")
        do_DELETE = lambda self: self._dispatch("DELETE")

        # ---- routes --------------------------------------------------

        def _route(self, method, path, query):
            f = filter_
            if method == "GET":
                if path in ("/", "/index.html"):
                    with open(os.path.join(STATIC_DIR, "index.html"), "rb") as fh:
                        return fh.read(), "text/html; charset=utf-8"
                if path == "/api/status":
                    return f.status()
                if path == "/api/settings":
                    return f.settings()
                if path == "/api/queries":
                    limit = min(int(query.get("limit", ["200"])[0]), 1000)
                    blocked_only = query.get("blocked", ["0"])[0] == "1"
                    return f.recent_queries(limit, blocked_only)
                if path == "/api/check":
                    domain = query.get("domain", [""])[0]
                    blocked, reason = f.check(domain, query.get("client", [None])[0])
                    return {"domain": domain, "blocked": blocked, "reason": reason}
                return None

            body = self._body()
            if method == "POST" and path == "/api/enabled":
                f.set_enabled(body.get("enabled", True))
                return f.status()
            if method == "POST" and path == "/api/pause":
                f.pause(float(body.get("minutes", 0)))
                return f.status()
            if path in ENTRY_KINDS:
                kind = ENTRY_KINDS[path]
                if method == "POST":
                    f.add_entry(kind, body.get("value"))
                else:
                    f.remove_entry(kind, body.get("value"))
                return f.settings()
            if path == "/api/lists":
                url = (body.get("url") or "").strip()
                if method == "POST":
                    if "enabled" in body:
                        f.set_list_enabled(url, body["enabled"])
                    else:
                        f.add_list(url)
                    threading.Thread(target=f.refresh_lists, daemon=True).start()
                else:
                    f.remove_list(url)
                return f.settings()
            if method == "POST" and path == "/api/lists/refresh":
                threading.Thread(target=f.refresh_lists, kwargs={"force": True}, daemon=True).start()
                return {"ok": True}
            return None

    return Handler


def start_web(filter_, config):
    server = ThreadingHTTPServer((config.web_addr, config.web_port),
                                 make_handler(filter_, config.admin_password))
    threading.Thread(target=server.serve_forever, name="web", daemon=True).start()
    if not config.admin_password:
        log.warning("ADMIN_PASSWORD is not set: anyone on your network can change settings")
    log.info("web UI on http://%s:%d", config.web_addr, config.web_port)
    return server
