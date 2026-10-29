import os
from dataclasses import dataclass, field

# The lists uBlock Origin enables out of the box (see uBlock's assets/assets.json),
# using the pre-assembled CDN builds where uBO publishes them.
UBO_CDN = "https://ublockorigin.github.io/uAssetsCDN"
DEFAULT_LISTS = [
    {"name": "uBlock filters – Ads", "url": f"{UBO_CDN}/filters/filters.min.txt"},
    {"name": "uBlock filters – Badware risks", "url": f"{UBO_CDN}/filters/badware.min.txt"},
    {"name": "uBlock filters – Privacy", "url": f"{UBO_CDN}/filters/privacy.min.txt"},
    {"name": "uBlock filters – Unbreak", "url": f"{UBO_CDN}/filters/unbreak.min.txt"},
    {"name": "uBlock filters – Quick fixes", "url": f"{UBO_CDN}/filters/quick-fixes.min.txt"},
    {"name": "EasyList", "url": f"{UBO_CDN}/thirdparties/easylist.txt"},
    {"name": "EasyPrivacy", "url": f"{UBO_CDN}/thirdparties/easyprivacy.txt"},
    {"name": "Online Malicious URL Blocklist",
     "url": "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh-online.txt"},
    {"name": "Peter Lowe’s Ad and tracking server list",
     "url": "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"},
]

# Defaults shipped by earlier versions; saved settings that still match are upgraded.
LEGACY_DEFAULT_LISTS = [
    ["https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"],
]


def _parse_upstreams(raw):
    servers = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        host, _, port = item.rpartition(":") if item.count(":") == 1 else (item, "", "")
        servers.append((host, int(port) if port else 53))
    return servers


@dataclass
class Config:
    dns_addr: str = "0.0.0.0"
    dns_port: int = 53
    web_addr: str = "0.0.0.0"
    web_port: int = 8080
    upstreams: list = field(default_factory=lambda: [("1.1.1.1", 53), ("9.9.9.9", 53)])
    data_dir: str = "data"
    admin_password: str = ""
    list_refresh_hours: float = 24.0
    upstream_timeout: float = 3.0

    @classmethod
    def from_env(cls):
        env = os.environ.get
        return cls(
            dns_addr=env("DNS_ADDR", "0.0.0.0"),
            dns_port=int(env("DNS_PORT", "53")),
            web_addr=env("WEB_ADDR", "0.0.0.0"),
            web_port=int(env("WEB_PORT", "8080")),
            upstreams=_parse_upstreams(env("UPSTREAM_DNS", "1.1.1.1,9.9.9.9")),
            data_dir=env("DATA_DIR", "data"),
            admin_password=env("ADMIN_PASSWORD", ""),
            list_refresh_hours=float(env("LIST_REFRESH_HOURS", "24")),
            upstream_timeout=float(env("UPSTREAM_TIMEOUT", "3")),
        )
