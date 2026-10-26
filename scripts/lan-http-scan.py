#!/usr/bin/env python3
"""Find HTTP services on the local network — the fallback check when raemote
won't connect.

Scans the LAN this machine sits on for open ports, then asks each one for `/`
and reports what answered (status, `Server:` header, page title). The point is
to answer one question fast: *is the app itself reachable, or is only the
raemote tunnel broken?* Open one of the printed URLs on the device that can't
connect; if the page loads, the app and the network are fine and the problem is
in the tunnel (see `raemote status`, `raemote doctor`, and the app's Connection
Logs screen).

    scripts/lan-http-scan.py                    # auto-detect LAN(s), common ports
    scripts/lan-http-scan.py --cidr 192.168.1.0/24
    scripts/lan-http-scan.py --ports 80,8080,3000-3010
    scripts/lan-http-scan.py --json             # machine-readable
    scripts/lan-http-scan.py -q                 # URLs only

Notes:
  - A scan from this machine sees only services bound to a LAN address or to
    0.0.0.0. Apps bound to 127.0.0.1 (the common case) are invisible here — the
    daemon's own discovery sees those: `raemote discover --verbose`.
  - tcp connect only: nothing is exploited or brute-forced, and no traffic is
    sent beyond one `GET /` per open port.
  - macOS 15+: the terminal app needs "Local Network" permission, or every host
    will look dead. Check System Settings → Privacy & Security → Local Network.
  - Only private (RFC1918/CGNAT) ranges are scanned unless --allow-public.

Exit status: 0 if at least one HTTP service was found, 1 if none, 2 on error.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import re
import socket
import ssl
import subprocess
import sys
import time
import unicodedata

# Ports worth trying: web front ends, dev servers, NAS/admin UIs, Jupyter,
# Home Assistant, media servers. Override with --ports.
DEFAULT_PORTS = [
    80, 443, 3000, 3001, 4000, 5000, 5001, 5173, 5601, 7000, 7860, 8000, 8008,
    8009, 8080, 8081, 8088, 8090, 8096, 8123, 8181, 8443, 8888, 8983, 9000,
    9090, 9091, 9443, 10000, 18080,
]

CGNAT = ipaddress.ip_network("100.64.0.0/10")
REQUEST = (
    "GET / HTTP/1.1\r\n"
    "Host: {host}:{port}\r\n"
    "User-Agent: raemote-lan-scan\r\n"
    "Accept: text/html,*/*\r\n"
    "Connection: close\r\n\r\n"
)
TITLE_RE = re.compile(r"(?is)<title[^>]*>(.*?)</title>")
WS_RE = re.compile(r"\s+")
CHARSET_RE = re.compile(r"charset=([\w-]+)", re.I)
# Ports where a plaintext request usually means "you wanted TLS".
TLS_PORTS = {443, 4443, 7443, 8443, 9443, 10443}


# ---------------------------------------------------------------------------
# Local networks
# ---------------------------------------------------------------------------

def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=5, check=False
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _skip_interface(name: str) -> bool:
    """Interfaces that never carry a LAN worth scanning."""
    return name.startswith(("lo", "utun", "ipsec", "awdl", "llw", "anpi", "gif", "stf"))


def _prefix_from_mask(mask: str) -> int | None:
    try:
        if mask.startswith("0x"):
            return bin(int(mask, 16)).count("1")
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return None


def _darwin_networks() -> list[ipaddress.IPv4Network]:
    nets: list[ipaddress.IPv4Network] = []
    iface = ""
    for line in _run(["ifconfig"]).splitlines():
        if line and not line[0].isspace() and ":" in line:
            iface = line.split(":", 1)[0]
            continue
        fields = line.split()
        if len(fields) < 2 or fields[0] != "inet" or _skip_interface(iface):
            continue
        try:
            addr = ipaddress.IPv4Address(fields[1])
        except ValueError:
            continue
        prefix = 24
        for i, field in enumerate(fields):
            if field == "netmask" and i + 1 < len(fields):
                prefix = _prefix_from_mask(fields[i + 1]) or 24
                break
        nets.append(ipaddress.IPv4Network(f"{addr}/{prefix}", strict=False))
    return nets


def _linux_networks() -> list[ipaddress.IPv4Network]:
    nets: list[ipaddress.IPv4Network] = []
    for line in _run(["ip", "-o", "-4", "addr", "show"]).splitlines():
        fields = line.split()
        if len(fields) < 4 or _skip_interface(fields[1]):
            continue
        if fields[2] != "inet":
            continue
        try:
            nets.append(ipaddress.IPv4Network(fields[3], strict=False))
        except ValueError:
            continue
    return nets


def local_networks() -> list[ipaddress.IPv4Network]:
    nets = _darwin_networks() if sys.platform == "darwin" else _linux_networks()
    if not nets:
        # Last resort: the address that would be used to reach the Internet,
        # assumed to be on a /24.
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.connect(("192.0.2.1", 9))
            addr = probe.getsockname()[0]
            probe.close()
            nets = [ipaddress.IPv4Network(f"{addr}/24", strict=False)]
        except OSError:
            nets = []

    kept: list[ipaddress.IPv4Network] = []
    for net in nets:
        if net.is_loopback or net.is_link_local or net in kept:
            continue
        kept.append(net)
    return kept


def local_ip() -> str | None:
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("192.0.2.1", 9))
        addr = probe.getsockname()[0]
        probe.close()
        return addr
    except OSError:
        return None


def is_private(net: ipaddress.IPv4Network) -> bool:
    return net.is_private or net.subnet_of(CGNAT)


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def port_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout):
            return True
    except OSError:
        return False


def _read_head(sock: socket.socket, limit: int = 16384) -> bytes:
    raw = b""
    while len(raw) < limit:
        try:
            chunk = sock.recv(4096)
        except (socket.timeout, ssl.SSLError, OSError):
            break
        if not chunk:
            break
        raw += chunk
        if b"\r\n\r\n" in raw and (TITLE_RE.search(raw.decode("latin-1", "replace")) or len(raw) > 2048):
            break
    return raw


def _request(host: str, port: int, timeout: float, tls: bool) -> bytes:
    sock = socket.create_connection((host, port), timeout)
    try:
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock)
        sock.settimeout(timeout)
        sock.sendall(REQUEST.format(host=host, port=port).encode())
        return _read_head(sock)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _decode_body(raw: bytes, content_type: str) -> str:
    """Decode a response body for the page title.

    Latin-1 would turn every UTF-8/GBK title into mojibake, so try the declared
    charset, then UTF-8, then the two encodings most Chinese routers/NAS UIs use.
    """
    declared = CHARSET_RE.search(content_type or "")
    for encoding in (declared.group(1) if declared else "", "utf-8", "gb18030", "cp950"):
        if not encoding:
            continue
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("latin-1", "replace")


def _parse(raw: bytes, host: str, port: int, tls: bool) -> dict:
    head_bytes, _, body_bytes = raw.partition(b"\r\n\r\n")
    lines = head_bytes.decode("latin-1", "replace").splitlines()
    status_line = lines[0].strip() if lines else ""
    match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})\s*(.*)", status_line)
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if sep:
            headers[name.strip().lower()] = value.strip()
    content_type = headers.get("content-type", "")
    text = _decode_body(body_bytes, content_type)
    title = ""
    found = TITLE_RE.search(text)
    if found:
        title = WS_RE.sub(" ", found.group(1)).strip()
    scheme = "https" if tls else "http"
    return {
        "ip": host,
        "port": port,
        "scheme": scheme,
        "url": f"{scheme}://{host}:{port}/",
        "status": int(match.group(1)) if match else None,
        "reason": (match.group(2) or "").strip() if match else "",
        "server": headers.get("server", ""),
        "content_type": content_type,
        "redirect": headers.get("location", ""),
        "title": title,
        "not_http": "",
        "_plain_on_tls": (not tls)
        and (int(match.group(1)) if match else 0) == 400
        and "plain http request" in text.lower(),
        "_body": text,
    }


def probe(host: str, port: int, timeout: float) -> dict:
    """Return what this port serves: parsed HTTP(S), or a `not_http` note."""
    try:
        raw = _request(host, port, timeout, tls=False)
    except OSError as e:
        return {"ip": host, "port": port, "not_http": f"connect failed: {e}", "status": None,
                "server": "", "title": "", "url": "", "scheme": "", "reason": "",
                "content_type": "", "redirect": ""}

    if raw.startswith(b"HTTP/"):
        parsed = _parse(raw, host, port, tls=False)
        # nginx (and friends) answer a plaintext request on an HTTPS port with a
        # 400 "plain HTTP request was sent to HTTPS port" page; the TLS result is
        # the one worth reporting.
        if parsed["_plain_on_tls"] or (port in TLS_PORTS and parsed.get("status") == 400):
            try:
                raw_tls = _request(host, port, timeout, tls=True)
            except (OSError, ssl.SSLError):
                raw_tls = b""
            if raw_tls.startswith(b"HTTP/"):
                tls_parsed = _parse(raw_tls, host, port, tls=True)
                if tls_parsed["status"] not in (None, 400):
                    return tls_parsed
        return parsed

    # A TLS server answers a plaintext request with an alert or nothing at all;
    # a plaintext non-HTTP service (SSH, for instance) answers with a banner.
    worth_tls = not raw or raw[0] in (0x15, 0x16)
    if worth_tls:
        try:
            raw_tls = _request(host, port, timeout, tls=True)
        except (OSError, ssl.SSLError):
            raw_tls = b""
        if raw_tls.startswith(b"HTTP/"):
            return _parse(raw_tls, host, port, tls=True)

    banner = WS_RE.sub(" ", raw[:60].decode("latin-1", "replace")).strip()
    note = f"not HTTP: {banner}" if banner else "open, but sent no HTTP response"
    return {"ip": host, "port": port, "not_http": note, "status": None, "server": "",
            "title": "", "url": "", "scheme": "", "reason": "", "content_type": "",
            "redirect": ""}


def scan(hosts: list[str], ports: list[int], timeout: float, workers: int) -> tuple[list[dict], int]:
    open_ports: list[tuple[str, int]] = []
    done = 0
    total = len(hosts) * len(ports)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(port_open, host, port, timeout): (host, port)
            for host in hosts
            for port in ports
        }
        for future in concurrent.futures.as_completed(futures):
            done += 1
            if future.result():
                open_ports.append(futures[future])
            if done % 512 == 0 and sys.stderr.isatty():
                print(f"\r  {done}/{total} probes, {len(open_ports)} open…", end="", file=sys.stderr)
    if sys.stderr.isatty() and total >= 512:
        print("\r" + " " * 48 + "\r", end="", file=sys.stderr)

    results: list[dict] = []
    if not open_ports:
        return results, 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(open_ports))) as pool:
        results = list(pool.map(lambda hp: probe(hp[0], hp[1], timeout), open_ports))
    return results, len(open_ports)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def parse_ports(spec: str) -> list[int]:
    ports: list[int] = []
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        if "-" in item:
            low, high = item.split("-", 1)
            ports.extend(range(int(low), int(high) + 1))
        else:
            ports.append(int(item))
    bad = [p for p in ports if not 0 < p < 65536]
    if bad:
        raise ValueError(f"invalid port(s): {bad}")
    return sorted(set(ports))


def _public(row: dict) -> dict:
    return {k: v for k, v in row.items() if not k.startswith("_")}


def _width(text: str) -> int:
    """Terminal columns a string occupies (CJK and emoji are double width)."""
    total = 0
    for ch in text:
        total += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return total


def _clip(text: str, limit: int) -> str:
    if _width(text) <= limit:
        return text
    out = ""
    used = 0
    for ch in text:
        w = 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
        if used + w > limit - 1:
            break
        out += ch
        used += w
    return out + "…"


def _pad(text: str, width: int) -> str:
    return text + " " * max(0, width - _width(text))


def fmt_table(rows: list[dict], mine: str | None, show_all: bool) -> str:
    shown = [r for r in rows if r["status"] is not None or show_all]
    if not shown:
        return ""
    head = ["IP", "PORT", "SCHEME", "STATUS", "SERVER", "TITLE"]
    table = [head]
    for r in shown:
        ip = r["ip"] + (" *" if mine and r["ip"] == mine else "")
        if r["status"] is None:
            table.append([ip, str(r["port"]), "-", "-", "-", _clip(r["not_http"], 70)])
        else:
            detail = r["title"] or r["redirect"] or r["reason"] or r["content_type"]
            table.append([ip, str(r["port"]), r["scheme"], str(r["status"]),
                          _clip(r["server"], 26), _clip(detail, 70)])
    widths = [max(_width(row[i]) for row in table) for i in range(len(head))]
    lines = []
    for index, row in enumerate(table):
        lines.append("  ".join(_pad(row[i], widths[i]) for i in range(len(head))).rstrip())
        if index == 0:
            lines.append("  ".join("-" * w for w in widths))
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan the local network for HTTP services (a raemote fallback check).",
        epilog="Examples: %(prog)s --cidr 192.168.1.0/24 --ports 80,8080",
    )
    parser.add_argument("--cidr", action="append", default=[], metavar="CIDR",
                        help="network to scan (repeatable; default: every LAN this machine is on)")
    parser.add_argument("--ports", metavar="LIST", default="",
                        help="ports, comma separated with optional ranges (default: common web ports)")
    parser.add_argument("--timeout", type=float, default=0.35, metavar="SECS",
                        help="per-connection timeout (default: 0.35)")
    parser.add_argument("--workers", type=int, default=256, metavar="N",
                        help="parallel probes (default: 256)")
    parser.add_argument("--max-hosts", type=int, default=1024, metavar="N",
                        help="skip networks larger than this many hosts (default: 1024)")
    parser.add_argument("--allow-public", action="store_true",
                        help="also scan non-private ranges (default: refuse)")
    parser.add_argument("--all", action="store_true",
                        help="also list open ports that did not answer HTTP")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("-q", "--quiet", action="store_true", help="print URLs only")
    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports) if args.ports else DEFAULT_PORTS
    except ValueError as e:
        print(f"raemote lan-scan: {e}", file=sys.stderr)
        return 2

    try:
        networks = [ipaddress.IPv4Network(c, strict=False) for c in args.cidr] or local_networks()
    except ValueError as e:
        print(f"raemote lan-scan: {e}", file=sys.stderr)
        return 2
    if not networks:
        print("raemote lan-scan: no LAN found; pass --cidr 192.168.1.0/24", file=sys.stderr)
        return 2

    hosts: list[str] = []
    for net in networks:
        if not is_private(net) and not args.allow_public:
            print(f"raemote lan-scan: skipping {net} (not a private range; use --allow-public)",
                  file=sys.stderr)
            continue
        count = net.num_addresses if net.prefixlen >= 31 else net.num_addresses - 2
        if count > args.max_hosts:
            print(f"raemote lan-scan: skipping {net} ({count} hosts > {args.max_hosts}); "
                  f"pass --cidr {net.network_address}/{net.prefixlen + 8} or raise --max-hosts",
                  file=sys.stderr)
            continue
        hosts.extend(str(h) for h in net.hosts())
    if not hosts:
        print("raemote lan-scan: nothing to scan", file=sys.stderr)
        return 2

    mine = local_ip()
    if not args.quiet and not args.json:
        print(f"raemote lan-scan: {len(hosts)} host(s) × {len(ports)} port(s) "
              f"on {', '.join(str(n) for n in networks)}", file=sys.stderr)

    started = time.time()
    results, open_count = scan(hosts, ports, args.timeout, max(1, args.workers))
    elapsed = time.time() - started
    http = sorted(
        [r for r in results if r["status"] is not None],
        key=lambda r: (ipaddress.IPv4Address(r["ip"]), r["port"]),
    )
    not_http = sorted(
        [r for r in results if r["status"] is None],
        key=lambda r: (ipaddress.IPv4Address(r["ip"]), r["port"]),
    )

    if args.json:
        print(json.dumps({
            "networks": [str(n) for n in networks],
            "local_ip": mine,
            "elapsed_secs": round(elapsed, 2),
            "open_ports": open_count,
            "http": [_public(r) for r in http],
            "other": [_public(r) for r in not_http],
        }, indent=2))
        return 0 if http else 1

    if args.quiet:
        for row in http:
            print(row["url"])
        return 0 if http else 1

    table = fmt_table(results, mine, args.all)
    if table:
        print(table)
        print()
    if http:
        print(f"{len(http)} HTTP service(s) on {len({r['ip'] for r in http})} host(s):")
        for row in http:
            detail = row["title"] or row["redirect"] or row["reason"]
            print(f"  {row['url']}" + (f"   {detail}" if detail else ""))
        print()
    else:
        print("no HTTP services found")
    if not_http and not args.all:
        print(f"({len(not_http)} other open port(s) skipped; add --all to see them)")
        print()

    print(f"scanned {len(hosts)} host(s) × {len(ports)} port(s) in {elapsed:.1f}s"
          + (f"; * = this machine ({mine})" if mine else ""), file=sys.stderr)
    print("""
If these URLs open from the device that can't connect, the app and the network
are fine and the tunnel is the problem: `raemote status`, `raemote doctor`, and
the app's Connection Logs. Apps bound to 127.0.0.1 never appear here — use
`raemote discover --verbose` on the machine itself for those.""".strip(),
          file=sys.stderr)
    return 0 if http else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)
