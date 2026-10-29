# router-ad-block

A network-wide ad blocker with a web control panel. It runs as a DNS server on
your LAN: every device that uses it gets ads and trackers blocked, with no
software installed on the device.

## How it works

```
 phone / laptop / TV ──DNS query──▶ router-ad-block ──▶ upstream DNS (1.1.1.1, 9.9.9.9)
                                         │
                       on a blocklist? ──┴──▶ answer 0.0.0.0 (ad never loads)
```

1. Your router's DHCP tells every device to use this machine as its DNS server.
2. For each lookup, the blocker checks the name (and its parent domains) against
   downloaded blocklists plus your own rules.
3. Blocked names get `0.0.0.0` / `::`; everything else is forwarded upstream.

Decision order for each query:

1. Blocking turned off or paused → allow
2. Device is on the bypass list → allow
3. Domain (or a parent) is in **Allowed exceptions** → allow
4. Domain (or a parent) is in **Custom blocks** or a blocklist → block

## Web interface

Open `http://<server-ip>:8080`. From there you can:

- turn blocking **off/on**, or **pause** it for 5 min / 30 min / 1 hour
- add **allowed exceptions** (e.g. a shopping site whose links break)
- let specific **devices bypass** blocking entirely, by IP
- add **custom blocks**
- watch **recent queries** and click *Allow* / *Block* on any of them
- add, disable, remove and refresh **blocklists** (hosts-file or `||domain^` format)
- **check** whether a domain would be blocked and why

Settings are saved to `data/state.json` and survive restarts.

## Setup

You need an always-on machine on your network: a Raspberry Pi, a NAS, a home
server, or an OpenWrt router with enough storage to run Python.

### 1. Run it

**Docker (recommended):**

```sh
git clone https://github.com/albinchacko12/router-ad-block.git
cd router-ad-block
# edit ADMIN_PASSWORD in docker-compose.yml
docker compose up -d
```

**Without Docker:**

```sh
sudo git clone https://github.com/albinchacko12/router-ad-block.git /opt/router-ad-block
cd /opt/router-ad-block
sudo python3 -m venv .venv && sudo .venv/bin/pip install -r requirements.txt
sudo cp deploy/router-ad-block.service /etc/systemd/system/
sudo systemctl edit --full router-ad-block   # set ADMIN_PASSWORD
sudo systemctl enable --now router-ad-block
```

> **Port 53 already in use?** On Ubuntu/Debian, `systemd-resolved` holds it.
> Set `DNSStubListener=no` in `/etc/systemd/resolved.conf` and run
> `sudo systemctl restart systemd-resolved`.

Test it from another machine:

```sh
nslookup doubleclick.net <server-ip>   # → 0.0.0.0
nslookup example.com <server-ip>       # → real address
```

### 2. Point your network at it

1. Give the blocker machine a **static IP** (DHCP reservation in the router).
2. In the router's **DHCP / LAN settings**, set the primary DNS server to that IP.
   Leave the secondary DNS empty, or devices will quietly skip the blocker.
3. Reconnect devices (or wait for their DHCP lease to renew).

If your router doesn't let you change the DHCP DNS server, turn off its DHCP
server and run one on the blocker machine instead (e.g. `dnsmasq`), or set DNS
manually on each device.

### 3. (Optional) Stop devices that bypass it

Some devices hard-code `8.8.8.8`. On routers with firewall rules (OpenWrt,
pfSense, OPNsense, UniFi), redirect outbound port 53 from the LAN to the blocker:

```sh
# OpenWrt example: /etc/config/firewall
config redirect
    option name 'Force DNS'
    option src 'lan'
    option proto 'tcp udp'
    option src_dport '53'
    option dest_ip '192.168.1.2'      # blocker IP
    option dest_port '53'
    option target 'DNAT'
    option src_ip '!192.168.1.2'      # don't loop the blocker's own queries
```

## Configuration

Environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `ADMIN_PASSWORD` | *(empty)* | Password for the web UI (any username). **Set this.** |
| `UPSTREAM_DNS` | `1.1.1.1,9.9.9.9` | Upstream resolvers, comma-separated, optional `:port` |
| `DNS_ADDR` / `DNS_PORT` | `0.0.0.0` / `53` | DNS listen address |
| `WEB_ADDR` / `WEB_PORT` | `0.0.0.0` / `8080` | Web UI listen address |
| `DATA_DIR` | `data` | Where settings and downloaded lists are stored |
| `LIST_REFRESH_HOURS` | `24` | How often blocklists are re-downloaded |
| `UPSTREAM_TIMEOUT` | `3` | Seconds to wait for an upstream before trying the next |

## Limitations

DNS blocking stops ads served from separate ad domains. It cannot block:

- ads served from the same domain as the content (**YouTube**, Facebook, Instagram ads)
- devices or browsers using **DNS-over-HTTPS** (Firefox and Chrome may enable it;
  turn it off in the browser, or block known DoH endpoints with a custom block)

For those, pair this with a browser extension such as uBlock Origin.

## Development

```sh
pip install -r requirements.txt
python -m unittest                                   # tests
DNS_PORT=5353 WEB_PORT=8080 python -m adblock        # run on unprivileged ports
dig @127.0.0.1 -p 5353 doubleclick.net
```

## Off-the-shelf alternatives

If you'd rather not run your own code, [Pi-hole](https://pi-hole.net) and
[AdGuard Home](https://adguard.com/adguard-home.html) do the same job with more
features (DHCP server, DoH upstreams, group policies) and are well maintained.
