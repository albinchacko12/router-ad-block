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
import urllib.parse
import urllib.request

from .config import DEFAULT_LISTS, LEGACY_DEFAULT_LISTS

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


# ||host^ or ||host^$options, with no path or wildcard: the only network rules
# that mean "block this whole hostname", which is all a DNS server can do.
HOST_RULE_RE = re.compile(r"^(@@)?\|\|([^/^$*|]+)(?:\^\|?)?(?:\$(.+))?$")
OPTION_ALIASES = {"third-party": "3p", "~first-party": "3p", "first-party": "1p",
                  "~third-party": "1p", "document": "doc"}
# Options that still mean "block every request to this host". Rules with any other
# option (script, image, popup, domain=, redirect=, ...) only block some requests
# in a browser, so blocking the whole host over DNS would break things.
BLOCK_OPTIONS = {"3p", "doc", "all", "important"}
ALLOW_OPTIONS = {"all"}
IGNORED_OPTIONS = {"reason"}
INCLUDE_RE = re.compile(r"^!#include\s+(\S+)")
MAX_INCLUDE_DEPTH = 3


class ParsedList:
    def __init__(self):
        self.block = {}          # host -> set of option keys it is blocked with
        self.allow = set()       # hosts with an unconditional @@ exception
        self.badfilter = set()   # (host, option key) pairs cancelled by $badfilter

    def __len__(self):
        return len(self.block)


def _condition(expr):
    """Evaluate a !#if expression. A DNS server is none of the browser environments
    uBlock Origin tests for, so every token except `true` is false."""
    py = re.sub(r"[A-Za-z_][A-Za-z0-9_]*",
                lambda m: "True" if m.group() == "true" else "False", expr)
    py = py.replace("&&", " and ").replace("||", " or ").replace("!", " not ")
    if not re.fullmatch(r"(\s|\(|\)|True|False|and|or|not)*", py):
        return False
    try:
        return bool(eval(py, {"__builtins__": {}}))  # only booleans and operators remain
    except SyntaxError:
        return False


def _valid_host(host):
    if "." not in host or host in IGNORED_HOSTS or not DOMAIN_RE.match(host):
        return False
    try:
        ipaddress.ip_address(host)
        return False  # clients never look up IP addresses over DNS
    except ValueError:
        return True


def _host_rule(parsed, match):
    exception, host, options = match.groups()
    host = host.lower().rstrip(".")
    if not _valid_host(host):
        return
    key = set()
    for option in (options or "").split(","):
        name = option.split("=", 1)[0].strip().lower()
        if name and name not in IGNORED_OPTIONS:
            key.add(OPTION_ALIASES.get(name, name))
    if "badfilter" in key:
        if not exception:
            parsed.badfilter.add((host, frozenset(key - {"badfilter"})))
    elif exception:
        if key <= ALLOW_OPTIONS:
            parsed.allow.add(host)
    elif key <= BLOCK_OPTIONS:
        parsed.block.setdefault(host, set()).add(frozenset(key))


def _add_host(parsed, host):
    host = host.lower().rstrip(".")
    if _valid_host(host):
        parsed.block.setdefault(host, set()).add(frozenset())


def parse_list(text):
    """Parse a uBlock Origin / Adblock Plus filter list or a hosts file.

    Keeps only rules that apply to whole hostnames; cosmetic, scriptlet and
    path/resource-specific rules have no meaning at the DNS level.
    """
    parsed = ParsedList()
    active, stack = True, []
    # In filter-list syntax a bare line is a URL substring, not a hostname, so bare
    # lines only count if the file turns out to be a plain domain list.
    adblock_syntax, bare_hosts = False, []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith(("!", "[Adblock")):
            adblock_syntax = True
        if line.startswith("!#if"):
            cond = _condition(line[4:])
            stack.append((active, cond))
            active = active and cond
            continue
        if line.startswith("!#else") and stack:
            parent, cond = stack[-1]
            active = parent and not cond
            continue
        if line.startswith("!#endif") and stack:
            active = stack.pop()[0]
            continue
        if not active or not line or line[0] in "![":
            continue
        # Hosts-file comments start a line or follow whitespace; "##" etc. glued to
        # a hostname is a cosmetic filter and is dropped by the "#" check below.
        line = re.sub(r"(^|\s)#.*$", "", line).strip()
        if not line or "#" in line:
            continue
        match = HOST_RULE_RE.match(line)
        if match:
            adblock_syntax = True
            _host_rule(parsed, match)
            continue
        parts = line.split()
        try:
            ipaddress.ip_address(parts[0])
        except ValueError:
            bare_hosts.append(parts[0])
            continue
        for host in parts[1:]:  # hosts file: "0.0.0.0 host [host...]"
            _add_host(parsed, host)
    if not adblock_syntax:
        for host in bare_hosts:
            _add_host(parsed, host)
    return parsed


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
        self.lists = [dict(entry, enabled=True) for entry in DEFAULT_LISTS]
        self.list_status = {}
        self._parsed = {}                 # url -> (cache mtime, ParsedList)
        # (block, allow, important), swapped as one tuple so lookups see a consistent set:
        #   block: host -> name of a list that blocks it
        #   allow: hosts unblocked by @@ exceptions in lists
        #   important: hosts blocked with $important, which beats exceptions
        self._index = ({}, frozenset(), frozenset())

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
        saved_lists = state.get("lists")
        if saved_lists and [e["url"] for e in saved_lists] not in LEGACY_DEFAULT_LISTS:
            self.lists = saved_lists

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

    def _parse_cached(self, url):
        path = self._cache_path(url)
        mtime = os.path.getmtime(path)
        cached = self._parsed.get(url)
        if cached and cached[0] == mtime:
            return cached[1]
        with open(path, encoding="utf-8", errors="replace") as f:
            parsed = parse_list(f.read())
        self._parsed[url] = (mtime, parsed)
        status = self.list_status.setdefault(url, {})
        status["domains"] = len(parsed)
        status.setdefault("updated", mtime)
        return parsed

    def _rebuild_from_cache(self):
        rules = {}   # host -> {option key: list name}
        allow, badfilter = set(), set()
        for entry in self.lists:
            url = entry["url"]
            if not entry.get("enabled", True) or not os.path.exists(self._cache_path(url)):
                continue
            parsed = self._parse_cached(url)
            name = entry.get("name") or url
            for host, keys in parsed.block.items():
                by_key = rules.setdefault(host, {})
                for key in keys:
                    by_key.setdefault(key, name)
            allow |= parsed.allow
            badfilter |= parsed.badfilter

        # $badfilter cancels the identical rule in any list (uBO's Unbreak and
        # Quick fixes lists use this to switch off rules from EasyList etc.).
        block, important = {}, set()
        for host, by_key in rules.items():
            live = [(key, name) for key, name in by_key.items() if (host, key) not in badfilter]
            if not live:
                continue
            block[host] = live[0][1]
            if any("important" in key for key, _ in live):
                important.add(host)
        self._index = (block, frozenset(allow), frozenset(important))
        log.info("loaded %d blocked hosts (%d exceptions) from blocklists", len(block), len(allow))

    def _fetch(self, url, depth=0):
        req = urllib.request.Request(url, headers={"User-Agent": "router-ad-block/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            text = resp.read().decode("utf-8", errors="replace")
        if depth >= MAX_INCLUDE_DEPTH or "!#include" not in text:
            return text
        # Inline uBO "!#include file.txt" sub-lists in place, so any surrounding
        # !#if blocks still apply. Like uBO, only files next to the list are allowed.
        base = urllib.parse.urlsplit(url)
        base_dir = base.path.rsplit("/", 1)[0] + "/"
        lines = []
        for line in text.splitlines():
            match = INCLUDE_RE.match(line.strip())
            if not match:
                lines.append(line)
                continue
            target = urllib.parse.urlsplit(urllib.parse.urljoin(url, match.group(1)))
            if target.netloc != base.netloc or not target.path.startswith(base_dir):
                log.warning("ignoring include outside list directory: %s", match.group(1))
                continue
            lines.append(self._fetch(urllib.parse.urlunsplit(target), depth + 1))
        return "\n".join(lines)

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
                body = self._fetch(url)
                with open(path + ".tmp", "w", encoding="utf-8") as f:
                    f.write(body)
                os.replace(path + ".tmp", path)
                status.update(updated=time.time(), error=None)
                log.info("downloaded %s (%d bytes)", url, len(body))
            except Exception as exc:  # network errors must not kill the refresher
                status["error"] = str(exc)
                log.warning("failed to download %s: %s", url, exc)
        with self._lock:
            self._rebuild_from_cache()

    def add_list(self, url, name=""):
        if not re.match(r"^https?://", url or ""):
            raise ValueError("list URL must start with http:// or https://")
        with self._lock:
            if any(e["url"] == url for e in self.lists):
                return
            self.lists.append({"name": (name or "").strip() or url, "url": url, "enabled": True})
            self._save_state()

    def remove_list(self, url):
        with self._lock:
            self.lists = [e for e in self.lists if e["url"] != url]
            self.list_status.pop(url, None)
            self._parsed.pop(url, None)
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
        list_block, list_allow, list_important = self._index
        for s in suffixes:
            if s in list_important:
                return True, f"{list_block[s]} ({s}, important)"
        for s in suffixes:
            if s in list_allow:
                return False, f"list exception ({s})"
        for s in suffixes:
            if s in list_block:
                return True, f"{list_block[s]} ({s})"
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
                "blocklist_domains": len(self._index[0]),
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
