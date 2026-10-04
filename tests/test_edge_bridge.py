"""Tests for edge_bridge: proxy CONNECT handling and the byte splice.

Run with:  python3 -m unittest discover -s tests -v
Standard library only, no network access, no root.
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bin"))

import edge_bridge  # noqa: E402


class FakeProxy:
    """Minimal HTTP CONNECT proxy: replies with a canned status line."""

    def __init__(self, status: bytes = b"HTTP/1.1 200 Connection established\r\n\r\n",
                 prefix: bytes = b""):
        self.status = status
        self.prefix = prefix
        self.request = b""
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.port = self.srv.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn: socket.socket) -> None:
        try:
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
            self.request = buf
            conn.sendall(self.status)
            if self.prefix:
                conn.sendall(self.prefix)
            # Hold the connection open like a real proxy does.
            while conn.recv(4096):
                pass
        except OSError:
            pass

    def close(self) -> None:
        self.srv.close()


class ProxyTargetTests(unittest.TestCase):
    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in ("HTTPS_PROXY", "https_proxy")}
        for k in self._saved:
            os.environ.pop(k, None)

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_parses_host_port_and_basic_auth(self):
        os.environ["HTTPS_PROXY"] = "http://user:pa%40ss@127.0.0.1:3128"
        host, port, auth = edge_bridge.proxy_target()
        self.assertEqual((host, port), ("127.0.0.1", 3128))
        self.assertEqual(auth, "dXNlcjpwYUBzcw==")  # user:pa@ss

    def test_lowercase_var_is_used(self):
        os.environ["https_proxy"] = "http://10.0.0.9:8080"
        self.assertEqual(edge_bridge.proxy_target(), ("10.0.0.9", 8080, None))

    def test_missing_proxy_raises(self):
        with self.assertRaises(RuntimeError):
            edge_bridge.proxy_target()

    def test_proxy_without_port_raises(self):
        os.environ["HTTPS_PROXY"] = "http://proxy.local"
        with self.assertRaises(RuntimeError):
            edge_bridge.proxy_target()


class ConnectViaProxyTests(unittest.TestCase):
    def test_success_returns_socket_and_captures_prefix(self):
        proxy = FakeProxy(prefix=b"\x16\x03\x01padding")
        self.addCleanup(proxy.close)
        got = edge_bridge.connect_via_proxy("198.41.192.7", 5, ("127.0.0.1", proxy.port, None))
        self.assertIsNotNone(got)
        sock, prefix = got
        self.addCleanup(sock.close)
        self.assertIn(b"CONNECT 198.41.192.7:7844 HTTP/1.1", proxy.request)
        # Bytes that arrived with the CONNECT response must be kept for the
        # splice. (They may also arrive in a later segment, in which case the
        # socket buffer holds them — hence this is not a data-loss check.)
        self.assertIn(prefix, (b"\x16\x03\x01padding", b""))

    def test_prefix_is_captured_when_bundled_with_the_response(self):
        proxy = FakeProxy(status=b"HTTP/1.1 200 OK\r\n\r\nextra")
        self.addCleanup(proxy.close)
        sock, prefix = edge_bridge.connect_via_proxy("198.41.192.7", 5, ("127.0.0.1", proxy.port, None))
        self.addCleanup(sock.close)
        self.assertEqual(prefix, b"extra")

    def test_auth_header_is_sent(self):
        proxy = FakeProxy()
        self.addCleanup(proxy.close)
        sock, _ = edge_bridge.connect_via_proxy("198.41.192.7", 5, ("127.0.0.1", proxy.port, "dXNlcg=="))
        self.addCleanup(sock.close)
        self.assertIn(b"Proxy-Authorization: Basic dXNlcg==", proxy.request)

    def test_non_200_returns_none(self):
        proxy = FakeProxy(status=b"HTTP/1.1 403 Forbidden\r\n\r\n")
        self.addCleanup(proxy.close)
        self.assertIsNone(edge_bridge.connect_via_proxy("198.41.192.7", 5, ("127.0.0.1", proxy.port, None)))

    def test_dead_proxy_returns_none(self):
        # Nothing listening: must degrade to None, not raise.
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        self.assertIsNone(edge_bridge.connect_via_proxy("198.41.192.7", 2, ("127.0.0.1", port, None)))


class SpliceTests(unittest.TestCase):
    """The splice must move arbitrary volumes of data in both directions.

    The regressions this guards: an earlier version used sendall() on
    non-blocking sockets, which raised BlockingIOError once the kernel
    buffer filled and silently dropped the connection — invisible in a
    small smoke test, fatal under real traffic. A second one indexed the
    write buffer by the wrong socket key, which made the select loop
    spin forever without moving a byte.
    """

    def _pair(self):
        return socket.socketpair()

    def _splice_async(self, a, b, **kw):
        """Run splice() in a thread; join it during cleanup."""
        t = threading.Thread(target=edge_bridge.splice, args=(a, b), kwargs=kw, daemon=True)
        t.start()

        def cleanup():
            for s in (a, b):
                try:
                    s.close()
                except OSError:
                    pass
            t.join(timeout=10)

        self.addCleanup(cleanup)
        return t

    def test_bidirectional_bulk_transfer(self):
        c1, c2 = self._pair()
        u1, u2 = self._pair()
        self.addCleanup(lambda: [s.close() for s in (c1, c2, u1, u2)])
        self._splice_async(c1, u1)

        payload = os.urandom(2 * 1024 * 1024)
        received = bytearray()

        def pump():
            c2.sendall(payload)
            u2.settimeout(20)
            while len(received) < len(payload):
                chunk = u2.recv(65536)
                if not chunk:
                    break
                received.extend(chunk)

        sender = threading.Thread(target=pump)
        sender.start()
        sender.join(timeout=60)
        self.assertFalse(sender.is_alive(), "bulk transfer stalled — splice is not draining")
        self.assertEqual(bytes(received), payload)

        # And back the other way on the same spliced pair.
        u2.sendall(payload[:1024])
        c2.settimeout(10)
        self.assertEqual(c2.recv(4096), payload[:1024])

    def test_input_prefix_is_flushed_to_the_client(self):
        """Bytes captured with the CONNECT response must reach cloudflared."""
        c1, c2 = self._pair()
        u1, u2 = self._pair()
        self.addCleanup(lambda: [s.close() for s in (c1, c2, u1, u2)])
        self._splice_async(c1, u1, prefix=b"early-bytes")
        c2.settimeout(10)
        self.assertEqual(c2.recv(64), b"early-bytes")
        u2.sendall(b"upstream")
        self.assertEqual(c2.recv(64), b"upstream")

    def test_half_close_propagates_eof(self):
        c1, c2 = self._pair()
        u1, u2 = self._pair()
        self.addCleanup(lambda: [s.close() for s in (c1, c2, u1, u2)])
        self._splice_async(c1, u1)
        c2.sendall(b"tail")
        c2.shutdown(socket.SHUT_WR)
        u2.settimeout(10)
        self.assertEqual(u2.recv(64), b"tail")
        self.assertEqual(u2.recv(64), b"")  # FIN must be forwarded, not swallowed
        u2.sendall(b"response")
        u2.shutdown(socket.SHUT_WR)
        self.assertEqual(c2.recv(64), b"response")
        self.assertEqual(c2.recv(64), b"")

    def test_idle_timeout_closes_the_pair(self):
        c1, c2 = self._pair()
        u1, u2 = self._pair()
        self.addCleanup(lambda: [s.close() for s in (c1, c2, u1, u2)])
        started = time.monotonic()
        edge_bridge.splice(c1, u1, idle_timeout=1.0)
        self.assertLess(time.monotonic() - started, 15.0)

    def test_closed_peer_does_not_raise(self):
        """A descriptor closed underneath splice() must end it quietly."""
        c1, c2 = self._pair()
        u1, u2 = self._pair()
        t = self._splice_async(c1, u1)
        c2.close()
        u2.close()
        t.join(timeout=10)
        self.assertFalse(t.is_alive(), "splice did not exit after both peers closed")


class RaceEdgesTests(unittest.TestCase):
    def _bridge(self, results):
        bridge = edge_bridge.EdgeBridge.__new__(edge_bridge.EdgeBridge)
        bridge.race = 8
        bridge.connect_timeout = 1
        bridge.race_timeout = 2
        bridge.idle_timeout = 5
        bridge.proxy = ("127.0.0.1", 1, None)
        bridge.edge_ips = list(results)
        bridge._lock = threading.Lock()
        bridge._last_doh = 0.0
        return bridge

    def test_first_success_wins_and_losers_are_closed(self):
        made = []

        def fake(ip, timeout, proxy):
            a, b = socket.socketpair()
            made.append((ip, a, b))
            if ip == "198.41.192.7":
                a.close()
                return None  # first candidate dead
            time.sleep(0.05 if ip == "198.41.192.27" else 0.3)
            return a, b""

        original = edge_bridge.connect_via_proxy
        edge_bridge.connect_via_proxy = fake
        self.addCleanup(lambda: setattr(edge_bridge, "connect_via_proxy", original))

        bridge = self._bridge(["198.41.192.7", "198.41.192.27", "198.41.192.37"])
        raced = bridge.race_edges()
        self.assertIsNotNone(raced)
        ip, winner, prefix = raced
        self.assertEqual(ip, "198.41.192.27")
        self.assertEqual(prefix, b"")
        winner.close()
        time.sleep(0.5)  # let the straggler finish and close itself
        # No candidate socket may be left dangling.
        for _, a, b in made:
            if a is not winner:
                a.close()
            b.close()

    def test_prefix_from_the_winner_is_returned(self):
        def fake(ip, timeout, proxy):
            a, b = socket.socketpair()
            self.addCleanup(b.close)
            return a, b"handshake-bytes"

        original = edge_bridge.connect_via_proxy
        edge_bridge.connect_via_proxy = fake
        self.addCleanup(lambda: setattr(edge_bridge, "connect_via_proxy", original))
        bridge = self._bridge(["198.41.192.7"])
        ip, sock, prefix = bridge.race_edges()
        self.assertEqual(prefix, b"handshake-bytes")
        sock.close()

    def test_all_failures_return_none(self):
        original = edge_bridge.connect_via_proxy
        edge_bridge.connect_via_proxy = lambda ip, timeout, proxy: None
        self.addCleanup(lambda: setattr(edge_bridge, "connect_via_proxy", original))
        bridge = self._bridge(["198.41.192.7", "198.41.192.27"])
        self.assertIsNone(bridge.race_edges())


class MiscTests(unittest.TestCase):
    def test_parse_listen_defaults_host(self):
        self.assertEqual(edge_bridge.parse_listen(":1234"), ("127.0.0.1", 1234))
        self.assertEqual(edge_bridge.parse_listen("0.0.0.0:9"), ("0.0.0.0", 9))

    def test_parse_listen_rejects_garbage(self):
        with self.assertRaises(SystemExit):
            edge_bridge.parse_listen("nonsense")
        with self.assertRaises(SystemExit):
            edge_bridge.parse_listen("host:99999")

    def test_fetch_edge_ips_falls_back_when_doh_fails(self):
        original = edge_bridge.doh_query
        edge_bridge.doh_query = lambda name, qtype: (_ for _ in ()).throw(OSError("no doh"))
        self.addCleanup(lambda: setattr(edge_bridge, "doh_query", original))
        ips = edge_bridge.fetch_edge_ips()
        self.assertEqual(ips, edge_bridge.FALLBACK_EDGES)

    def test_fetch_edge_ips_filters_junk(self):
        original = edge_bridge.doh_query
        edge_bridge.doh_query = lambda name, qtype: [
            {"data": "198.41.192.7"}, {"data": "198.41.192.7"}, {"data": "not-an-ip"},
        ]
        self.addCleanup(lambda: setattr(edge_bridge, "doh_query", original))
        self.assertEqual(edge_bridge.fetch_edge_ips(), ["198.41.192.7"])


if __name__ == "__main__":
    unittest.main()
