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
budget and the tunnel never comes up. A total race failure triggers a
fresh DoH round (the anycast set does rotate) before the client is
dropped.

Usage:
    python3 edge_bridge.py [--listen 127.0.0.1:17844] [--race 8]
                           [--connect-timeout 8] [--race-timeout 12]
                           [--idle-timeout 300]
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
import time
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

# Re-resolve over DoH when a whole race round comes up empty. The anycast
# set does rotate, so a cached list can go stale under a long-lived unit.
DOH_REFRESH_MIN_INTERVAL = 60.0
IDLE_TIMEOUT_DEFAULT = 300.0


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


def connect_via_proxy(edge_ip: str, timeout: float,
                      proxy: tuple[str, int, str | None]) -> tuple[socket.socket, bytes] | None:
    """CONNECT to the edge through the proxy.

    Returns (socket, prefix) where prefix holds any bytes of tunnel data
    that arrived in the same read as the CONNECT response and therefore
    must be handed to the client before the splice starts. A tuple is
    used rather than an attribute on the socket: CPython's socket
    objects define __slots__, so stashing state on them raises
    AttributeError.
    """
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
                log(f"CONNECT {edge_ip}: oversized response header")
                s.close()
                return None
        status = buf.split(b"\r\n", 1)[0].decode("latin1", "replace")
        if " 200 " not in status:
            log(f"CONNECT {edge_ip}: {status}")
            s.close()
            return None
        # Bytes after the header terminator already belong to the tunnel.
        rest = buf.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in buf else b""
        return s, rest
    except OSError as e:
        log(f"CONNECT {edge_ip} failed: {e}")
        try:
            s.close()
        except OSError:
            pass
        return None


def _shutdown_write(sock: socket.socket) -> None:
    try:
        sock.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def splice(a: socket.socket, b: socket.socket, prefix: bytes = b"",
           idle_timeout: float = IDLE_TIMEOUT_DEFAULT) -> None:
    """Splice two sockets byte-for-byte until both directions are done.

    Both sockets are non-blocking and driven by select(), with a pending
    buffer per direction. A bare ``sendall`` would be wrong here: on a
    non-blocking socket it raises BlockingIOError as soon as the send
    buffer fills, which under real traffic silently tears down healthy
    tunnels. Backpressure is expressed by pausing reads on a socket
    while its peer still has unflushed bytes.

    `prefix` is data already read from `b` (bytes that arrived with the
    CONNECT response) and is handed to `a` first.
    """
    peers = {a: b, b: a}
    pending = {a: bytearray(), b: bytearray()}  # key = source socket, value = bytes owed to its peer
    eof = {a: False, b: False}                  # read side saw FIN/EOF
    for s in (a, b):
        s.setblocking(False)
    try:
        if prefix:
            pending[b].extend(prefix)
        last_progress = time.monotonic()
        while True:
            rlist = [s for s in (a, b) if not eof[s] and not pending[s]]
            wlist = [s for s in (a, b) if pending[peers[s]]]
            if not rlist and not wlist:
                break  # both directions finished
            try:
                r, w, x = select.select(rlist, wlist, [a, b], 5.0)
            except ValueError:
                # select() raises ValueError (not OSError) for a closed
                # descriptor; either way the pair is unusable now.
                return
            except OSError:
                return
            if x:
                break
            for s in r:
                try:
                    data = s.recv(65536)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    return
                if data:
                    pending[s].extend(data)
                    last_progress = time.monotonic()
                else:
                    eof[s] = True
                    if not pending[s]:
                        _shutdown_write(peers[s])
            for s in w:
                src = peers[s]          # bytes read from src are owed to s
                buf = pending[src]
                if not buf:
                    continue
                try:
                    n = s.send(buf)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    return
                if n:
                    del buf[:n]
                    last_progress = time.monotonic()
                if not buf and eof[src]:
                    _shutdown_write(s)
            # Idle/never-progress watchdog: also catches a select() that
            # keeps reporting readiness while nothing actually moves.
            if time.monotonic() - last_progress > idle_timeout:
                log("splice idle timeout; closing")
                break
    finally:
        for s in (a, b):
            try:
                s.close()
            except OSError:
                pass


class EdgeBridge:
    def __init__(self, race: int = 8, connect_timeout: float = 8, race_timeout: float = 12,
                 idle_timeout: float = IDLE_TIMEOUT_DEFAULT):
        self.race = race
        self.connect_timeout = connect_timeout
        self.race_timeout = race_timeout
        self.idle_timeout = idle_timeout
        self.proxy = proxy_target()
        self._lock = threading.Lock()
        self.edge_ips = fetch_edge_ips()
        self._last_doh = time.monotonic()
        log(f"edge candidates: {len(self.edge_ips)}")

    def _refresh_edges(self) -> None:
        with self._lock:
            if time.monotonic() - self._last_doh < DOH_REFRESH_MIN_INTERVAL:
                return
            self._last_doh = time.monotonic()
        ips = fetch_edge_ips()
        if ips and ips != self.edge_ips:
            self.edge_ips = ips
            log(f"edge candidates refreshed via DoH: {len(ips)}")

    def race_edges(self) -> tuple[str, socket.socket, bytes] | None:
        """Race several edge IPs; first CONNECT 200 wins.

        Sequential trying is too slow: one dead edge holds the CONNECT
        for the full timeout and starves cloudflared's TLS budget.
        """
        results: list[tuple[str, socket.socket, bytes]] = []
        lock = threading.Lock()
        done = threading.Event()

        def attempt(ip: str) -> None:
            got = connect_via_proxy(ip, timeout=self.connect_timeout, proxy=self.proxy)
            if got is None:
                return
            s, prefix = got
            with lock:
                winner = done.is_set()
                if not winner:
                    results.append((ip, s, prefix))
                    done.set()
            if winner:
                # A loser finishing after the winner must not leak its fd.
                try:
                    s.close()
                except OSError:
                    pass

        threads = [
            threading.Thread(target=attempt, args=(ip,), daemon=True)
            for ip in list(self.edge_ips[: self.race])
        ]
        for t in threads:
            t.start()
        done.wait(timeout=self.race_timeout)
        with lock:
            picked = list(results)
        if not picked:
            return None
        ip, winner, prefix = picked[0]
        for _, s, _ in picked[1:]:
            try:
                s.close()
            except OSError:
                pass
        return ip, winner, prefix

    def handle(self, client: socket.socket) -> None:
        try:
            raced = self.race_edges()
            if raced is None:
                self._refresh_edges()
                raced = self.race_edges()
            if raced is None:
                log("all edge candidates failed")
                client.close()
                return
            ip, upstream, prefix = raced
            log(f"bridged via edge {ip}")
            try:
                splice(client, upstream, prefix, idle_timeout=self.idle_timeout)
            finally:
                log(f"bridge closed (edge {ip})")
        except Exception as e:  # noqa: BLE001 - never kill the listener thread
            log(f"connection handler error: {type(e).__name__}: {e}")
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
            try:
                client, _ = srv.accept()
            except OSError as e:
                log(f"accept failed: {e}")
                time.sleep(1)
                continue
            threading.Thread(target=self.handle, args=(client,), daemon=True).start()


def parse_listen(value: str) -> tuple[str, int]:
    host, _, port = value.rpartition(":")
    try:
        port_num = int(port)
    except ValueError:
        raise SystemExit(f"bad --listen value: {value!r} (want host:port)")
    if not 1 <= port_num <= 65535:
        raise SystemExit(f"bad --listen port: {port_num}")
    return (host or "127.0.0.1"), port_num


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="cloudflared edge bridge for proxied sandboxes")
    ap.add_argument("--listen", default=os.environ.get("CF_EDGE_BRIDGE_LISTEN", "127.0.0.1:17844"))
    ap.add_argument("--race", type=int, default=8, help="edge candidates raced in parallel")
    ap.add_argument("--connect-timeout", type=float, default=8)
    ap.add_argument("--race-timeout", type=float, default=12)
    ap.add_argument("--idle-timeout", type=float, default=IDLE_TIMEOUT_DEFAULT,
                    help="drop a spliced pair after this many idle seconds")
    args = ap.parse_args(argv)
    host, port = parse_listen(args.listen)
    try:
        bridge = EdgeBridge(race=args.race, connect_timeout=args.connect_timeout,
                            race_timeout=args.race_timeout, idle_timeout=args.idle_timeout)
    except RuntimeError as e:
        log(f"fatal: {e}")
        return 1
    bridge.serve(host, port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
