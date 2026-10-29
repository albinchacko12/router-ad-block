"""Blocking rules, persistent settings and blocklist downloads."""

import collections
import hashlib
import ipaddress
import json
import logging
import os
import re
import threading
import time
import urllib.request

from .config import DEFAULT_LISTS

log = logging.getLogger(__name__)

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_-]{1,63}$")
IGNORED_HOSTS = {"localhost", "localhost.localdomain", "local", "broadcasthost",
                 "ip6-localhost", "ip6-loopback", "0.0.0.0"}


def normalize_domain(value):
    domain = (value or "").strip().lower().rstrip(".")
    if domain.startswith("*."):
        domain = domain[2:]
    if not DOMAIN_RE.match(domain):
        raise ValueError(f"invalid domain: {value!r}")
    return domain


def normalize_ip(value):
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError:
        raise ValueError(f"invalid IP address: {value!r}") from None


def parse_list(text):
    """Parse hosts-file or simple adblock (||domain^) syntax into a set of domains."""
    domains = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("!") or line.startswith("@@"):
            continue
        if line.startswith("||"):
            line = line[2:].split("^", 1)[0]
            if "/" in line or "*" in line:
                continue
            candidates = [line]
        else:
            parts = line.split()
            try:
                ipaddress.ip_address(parts[0])
                candidates = parts[1:]
            except ValueError:
                candidates = parts[:1]
        for candidate in candidates:
            candidate = candidate.lower().rstrip(".")
            if candidate in IGNORED_HOSTS or not DOMAIN_RE.match(candidate):
                continue
            domains.add(candidate)
    return domains


def _suffixes(domain):
    labels = domain.split(".")
    return (".".join(labels[i:]) for i in range(len(labels)))


class Filter:
    """Holds all settings, decides whether a query is blocked, and records stats."""

    def __init__(self, data_dir, list_refresh_hours=24.0):
        self.data_dir = data_dir
        self.lists_dir = os.path.join(data_dir, "lists")
        self.state_path = os.path.join(data_dir, "state.json")
        self.list_refresh_seconds = list_refresh_hours * 3600
        os.makedirs(self.lists_dir, exist_ok=True)

        self._lock = threading.RLock()
        self.enabled = True
        self.paused_until = 0.0
        self.allowlist = set()
        self.blocklist = set()
        self.bypass_clients = set()
        self.lists = [{"url": url, "enabled": True} for url in DEFAULT_LISTS]
        self.list_status = {}
        self._list_domains = frozenset()

        self.queries = collections.deque(maxlen=1000)
        self.total_queries = 0
        self.blocked_queries = 0
        self.top_blocked = collections.Counter()
        self.started_at = time.time()

        self._load_state()
        self._rebuild_from_cache()

    # ---- persistence -------------------------------------------------

    def _load_state(self):
        try:
            with open(self.state_path) as f:
                state = json.load(f)
        except FileNotFoundError:
            return
        except (OSError, ValueError) as exc:
            log.warning("could not read %s: %s", self.state_path, exc)
            return
        self.enabled = state.get("enabled", True)
        self.paused_until = state.get("paused_until", 0.0)
        self.allowlist = set(state.get("allowlist", []))
        self.blocklist = set(state.get("blocklist", []))
        self.bypass_clients = set(state.get("bypass_clients", []))
        self.lists = state.get("lists", self.lists)

    def _save_state(self):
        state = {
            "enabled": self.enabled,
            "paused_until": self.paused_until,
            "allowlist": sorted(self.allowlist),
            "blocklist": sorted(self.blocklist),
            "bypass_clients": sorted(self.bypass_clients),
            "lists": self.lists,
        }
        tmp = self.state_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(state, f, indent=2)
        os.replace(tmp, self.state_path)

    def _cache_path(self, url):
        return os.path.join(self.lists_dir, hashlib.sha256(url.encode()).hexdigest()[:16] + ".txt")

    # ---- blocklists --------------------------------------------------

    def _rebuild_from_cache(self):
        domains = set()
        for entry in self.lists:
            path = self._cache_path(entry["url"])
            if not entry.get("enabled", True) or not os.path.exists(path):
                continue
            with open(path, encoding="utf-8", errors="replace") as f:
                parsed = parse_list(f.read())
            self.list_status.setdefault(entry["url"], {})["domains"] = len(parsed)
            self.list_status[entry["url"]].setdefault("updated", os.path.getmtime(path))
            domains |= parsed
        self._list_domains = frozenset(domains)
        log.info("loaded %d domains from blocklists", len(domains))

    def refresh_lists(self, force=False):
        """Download blocklists that are missing or stale, then rebuild the domain set."""
        with self._lock:
            entries = [dict(e) for e in self.lists]
        for entry in entries:
            url, path = entry["url"], self._cache_path(entry["url"])
            if not entry.get("enabled", True):
                continue
            fresh = os.path.exists(path) and time.time() - os.path.getmtime(path) < self.list_refresh_seconds
            if fresh and not force:
                continue
            status = self.list_status.setdefault(url, {})
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "router-ad-block/1.0"})
                with urllib.request.urlopen(req, timeout=60) as resp:
                    body = resp.read()
                with open(path + ".tmp", "wb") as f:
                    f.write(body)
                os.replace(path + ".tmp", path)
                status.update(updated=time.time(), error=None)
                log.info("downloaded %s (%d bytes)", url, len(body))
            except Exception as exc:  # network errors must not kill the refresher
                status["error"] = str(exc)
                log.warning("failed to download %s: %s", url, exc)
        with self._lock:
            self._rebuild_from_cache()

    def add_list(self, url):
        if not re.match(r"^https?://", url or ""):
            raise ValueError("list URL must start with http:// or https://")
        with self._lock:
            if any(e["url"] == url for e in self.lists):
                return
            self.lists.append({"url": url, "enabled": True})
            self._save_state()

    def remove_list(self, url):
        with self._lock:
            self.lists = [e for e in self.lists if e["url"] != url]
            self.list_status.pop(url, None)
            self._save_state()
            try:
                os.remove(self._cache_path(url))
            except FileNotFoundError:
                pass
            self._rebuild_from_cache()

    def set_list_enabled(self, url, enabled):
        with self._lock:
            for entry in self.lists:
                if entry["url"] == url:
                    entry["enabled"] = bool(enabled)
            self._save_state()
            self._rebuild_from_cache()

    # ---- settings ----------------------------------------------------

    def set_enabled(self, enabled):
        with self._lock:
            self.enabled = bool(enabled)
            self.paused_until = 0.0
            self._save_state()

    def pause(self, minutes):
        with self._lock:
            self.paused_until = time.time() + minutes * 60 if minutes > 0 else 0.0
            self._save_state()

    def is_active(self):
        return self.enabled and time.time() >= self.paused_until

    def _set_for(self, kind):
        return {"allowlist": self.allowlist, "blocklist": self.blocklist,
                "bypass_clients": self.bypass_clients}[kind]

    def add_entry(self, kind, value):
        value = normalize_ip(value) if kind == "bypass_clients" else normalize_domain(value)
        with self._lock:
            self._set_for(kind).add(value)
            if kind == "allowlist":
                self.blocklist.discard(value)
            elif kind == "blocklist":
                self.allowlist.discard(value)
            self._save_state()
        return value

    def remove_entry(self, kind, value):
        with self._lock:
            self._set_for(kind).discard((value or "").strip().lower())
            self._save_state()

    # ---- decisions ---------------------------------------------------

    def check(self, domain, client_ip=None):
        """Return (blocked, reason) for a query."""
        domain = domain.lower().rstrip(".")
        if not self.is_active():
            return False, "blocking disabled"
        if client_ip and client_ip in self.bypass_clients:
            return False, "client bypass"
        suffixes = list(_suffixes(domain))
        for s in suffixes:
            if s in self.allowlist:
                return False, f"allowlisted ({s})"
        for s in suffixes:
            if s in self.blocklist:
                return True, f"custom block ({s})"
        list_domains = self._list_domains
        for s in suffixes:
            if s in list_domains:
                return True, f"blocklist ({s})"
        return False, ""

    def record(self, domain, client_ip, qtype, blocked, reason):
        with self._lock:
            self.total_queries += 1
            if blocked:
                self.blocked_queries += 1
                self.top_blocked[domain] += 1
            self.queries.append({"time": time.time(), "domain": domain, "client": client_ip,
                                 "type": qtype, "blocked": blocked, "reason": reason})

    def status(self):
        with self._lock:
            return {
                "enabled": self.enabled,
                "active": self.is_active(),
                "paused_until": self.paused_until if self.paused_until > time.time() else 0,
                "total_queries": self.total_queries,
                "blocked_queries": self.blocked_queries,
                "blocklist_domains": len(self._list_domains),
                "top_blocked": self.top_blocked.most_common(10),
                "uptime": time.time() - self.started_at,
            }

    def settings(self):
        with self._lock:
            return {
                "allowlist": sorted(self.allowlist),
                "blocklist": sorted(self.blocklist),
                "bypass_clients": sorted(self.bypass_clients),
                "lists": [dict(e, **self.list_status.get(e["url"], {})) for e in self.lists],
            }

    def recent_queries(self, limit=200, blocked_only=False):
        with self._lock:
            items = [q for q in self.queries if q["blocked"] or not blocked_only]
        return items[-limit:][::-1]

    def start_refresher(self):
        def loop():
            while True:
                self.refresh_lists()
                time.sleep(min(self.list_refresh_seconds, 3600))
        threading.Thread(target=loop, name="list-refresher", daemon=True).start()
