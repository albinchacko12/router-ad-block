import os
from dataclasses import dataclass, field

DEFAULT_LISTS = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
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
