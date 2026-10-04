#!/usr/bin/env python3
"""Edge bridge for cloudflared in locked-down sandboxes.

Why this exists: in Muse-style sandboxes the only egress is a shared
HTTP(S) proxy, system DNS hands out fake IPs (198.18.0.0/15) for the
Cloudflare edge hostnames, and cloudflared's own edge dialer does not
support outbound proxies. Direct `cloudflared tunnel run` therefore
never registers (QUIC + HTTP/2 prechecks both fail).

Run cloudflared with TUNNEL_EDGE=<this bridge> and the bridge splices
the raw TCP stream through the HTTP proxy's CONNECT method to a real
edge IP:7844. TLS stays end-to-end between cloudflared and the edge;
the bridge never decrypts, never sees credentials, and only reads the
proxy address from the environment (HTTPS_PROXY / https_proxy). Proxy
credentials are used for the CONNECT handshake and never logged.

Real edge IPs are discovered over DoH (cloudflare-dns.com, which
bypasses the poisoned system resolver); a built-in fallback list is
used when DoH fails. Candidates are raced in parallel: sequentially
trying them lets one dead edge eat cloudflared's ~15s TLS handshake
budget and the tunnel never comes up.

Usage:
    python3 edge_bridge.py [--listen 127.0.0.1:17844] [--race 8]
                           [--connect-timeout 8] [--race-timeout 12]
Environment:
    HTTPS_PROXY / https_proxy   required; the sandbox egress proxy.
    CF_EDGE_BRIDGE_LISTEN       alternative to --listen.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import select
import socket
import sys
import threading
import urllib.parse
import urllib.request

EDGE_PORT = 7844
EDGE_SRV_NAMES = ("region1.v2.argotunnel.com", "region2.v2.argotunnel.com")
DOH_URL = "https://cloudflare-dns.com/dns-query"

# Fallback edge IPs (anycast ranges used by Cloudflare Tunnel). DoH is
# authoritative; this list only matters when DoH itself is unreachable.
FALLBACK_EDGES = [
    "198.41.192.7", "198.41.192.27", "198.41.192.37", "198.41.192.47",
    "198.41.192.57", "198.41.192.67", "198.41.192.77",
    "198.41.200.7", "198.41.200.27", "198.41.200.37",
]


def log(msg: str) -> None:
    print(f"[edge-bridge] {msg}", flush=True)


def doh_query(name: str, qtype: str) -> list[dict]:
    url = f"{DOH_URL}?name={urllib.parse.quote(name)}&type={qtype}"
    req = urllib.request.Request(url, headers={"accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.load(resp).get("Answer", [])


def fetch_edge_ips() -> list[str]:
    """Real edge IPs via DoH; SRV gives the port, A gives addresses."""
    ips: list[str] = []
    for name in EDGE_SRV_NAMES:
        try:
            for ans in doh_query(name, "A"):
                ip = str(ans.get("data", ""))
                if ip.count(".") == 3 and ip not in ips:
                    ips.append(ip)
        except Exception as e:  # noqa: BLE001 - fall through to fallback list
            log(f"DoH lookup failed for {name}: {e}")
    return ips or list(FALLBACK_EDGES)


def proxy_target() -> tuple[str, int, str | None]:
    raw = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or ""
    u = urllib.parse.urlparse(raw)
    if not u.hostname or not u.port:
        raise RuntimeError("no usable HTTP proxy in environment (HTTPS_PROXY)")
    auth = None
    if u.username:
        user = urllib.parse.unquote(u.username)
        pw = urllib.parse.unquote(u.password or "")
        auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
    return u.hostname, u.port, auth


def connect_via_proxy(edge_ip: str, timeout: float, proxy: tuple[str, int, str | None]) -> socket.socket | None:
    host, port, auth = proxy
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        log(f"proxy connect failed: {e}")
        return None
    req = f"CONNECT {edge_ip}:{EDGE_PORT} HTTP/1.1\r\nHost: {edge_ip}:{EDGE_PORT}\r\n"
    if auth:
        req += f"Proxy-Authorization: Basic {auth}\r\n"
    req += "\r\n"
    try:
        s.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                log(f"CONNECT {edge_ip}: proxy closed early")
                s.close()
                return None
            buf += chunk
            if len(buf) > 65536:
                break
        status = buf.split(b"\r\n", 1)[0].decode("latin1", "replace")
        if " 200 " not in status:
            log(f"CONNECT {edge_ip}: {status}")
            s.close()
            return None
        # Bytes after the header terminator already belong to the tunnel.
        rest = buf.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in buf else b""
        if rest:
            s._prefix = rest  # type: ignore[attr-defined]
        return s
    except OSError as e:
        log(f"CONNECT {edge_ip} failed: {e}")
        try:
            s.close()
        except OSError:
            pass
        return None


def splice(a: socket.socket, b: socket.socket) -> None:
    prefix = getattr(b, "_prefix", b"")
    if prefix:
        try:
            a.sendall(prefix)
        except OSError:
            pass
    a.setblocking(False)
    b.setblocking(False)
    sockets = [a, b]
    try:
        while True:
            r, _, x = select.select(sockets, [], sockets, 60)
            if x:
                break
            if not r:
                continue
            for s in r:
                try:
                    data = s.recv(65536)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    return
                if not data:
                    return
                other = b if s is a else a
                try:
                    other.sendall(data)
                except OSError:
                    return
    finally:
        for s in sockets:
            try:
                s.close()
            except OSError:
                pass


class EdgeBridge:
    def __init__(self, race: int = 8, connect_timeout: float = 8, race_timeout: float = 12):
        self.race = race
        self.connect_timeout = connect_timeout
        self.race_timeout = race_timeout
        self.proxy = proxy_target()
        self.edge_ips = fetch_edge_ips()
        log(f"edge candidates: {len(self.edge_ips)}")

    def race_edges(self) -> tuple[str, socket.socket] | None:
        """Race several edge IPs; first CONNECT 200 wins.

        Sequential trying is too slow: one dead edge holds the CONNECT
        for the full timeout and starves cloudflared's TLS budget.
        """
        results: list[tuple[str, socket.socket]] = []
        lock = threading.Lock()
        done = threading.Event()

        def attempt(ip: str) -> None:
            s = connect_via_proxy(ip, timeout=self.connect_timeout, proxy=self.proxy)
            if s is not None:
                with lock:
                    results.append((ip, s))
                done.set()

        threads = [
            threading.Thread(target=attempt, args=(ip,), daemon=True)
            for ip in self.edge_ips[: self.race]
        ]
        for t in threads:
            t.start()
        done.wait(timeout=self.race_timeout)
        if not results:
            return None
        ip, winner = results[0]
        for _, s in results[1:]:
            try:
                s.close()
            except OSError:
                pass
        return ip, winner

    def handle(self, client: socket.socket) -> None:
        raced = self.race_edges()
        if raced is not None:
            ip, upstream = raced
            log(f"bridged via edge {ip}")
            try:
                splice(client, upstream)
            finally:
                log(f"bridge closed (edge {ip})")
            return
        log("all edge candidates failed")
        try:
            client.close()
        except OSError:
            pass

    def serve(self, listen_host: str, listen_port: int) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((listen_host, listen_port))
        srv.listen(64)
        log(f"listening on {listen_host}:{listen_port}")
        while True:
            client, _ = srv.accept()
            threading.Thread(target=self.handle, args=(client,), daemon=True).start()


def parse_listen(value: str) -> tuple[str, int]:
    host, _, port = value.rpartition(":")
    return (host or "127.0.0.1"), int(port)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="cloudflared edge bridge for proxied sandboxes")
    ap.add_argument("--listen", default=os.environ.get("CF_EDGE_BRIDGE_LISTEN", "127.0.0.1:17844"))
    ap.add_argument("--race", type=int, default=8, help="edge candidates raced in parallel")
    ap.add_argument("--connect-timeout", type=float, default=8)
    ap.add_argument("--race-timeout", type=float, default=12)
    args = ap.parse_args(argv)
    host, port = parse_listen(args.listen)
    try:
        bridge = EdgeBridge(race=args.race, connect_timeout=args.connect_timeout, race_timeout=args.race_timeout)
    except RuntimeError as e:
        log(f"fatal: {e}")
        return 1
    bridge.serve(host, port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
