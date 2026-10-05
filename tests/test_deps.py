"""Dependency self-check / self-heal tests.

The behaviour under test is the one that used to be missing: cfbridge
must find out whether its runtime dependencies *work* — not whether an
environment variable exists — and repair the ones it owns instead of
letting `up` start a stack that can only fail.

Everything here is hermetic: a throwaway TCP listener stands in for the
sandbox egress proxy, and no test touches the network, /etc, or root.
"""
import base64
import contextlib
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin"))
import cfbridge  # noqa: E402

PROXY_VARS = ("CFBRIDGE_PROXY", "HTTPS_PROXY", "https_proxy",
              "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class LiveProxy:
    """A TCP listener that answers like an HTTP CONNECT proxy."""

    def __init__(self, fail_connect: bool = False):
        self.fail_connect = fail_connect
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._accept_loop, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def _accept_loop(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            conn.settimeout(10)
            conn.recv(4096)
            if self.fail_connect:
                conn.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            else:
                conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            conn.recv(1)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


@contextlib.contextmanager
def fake_root():
    """collect_deps reads euid through getattr(os, "geteuid", None)."""
    had = hasattr(os, "geteuid")
    old = getattr(os, "geteuid", None)
    os.geteuid = lambda: 0
    try:
        yield
    finally:
        if had:
            os.geteuid = old
        else:
            delattr(os, "geteuid")


@contextlib.contextmanager
def patched(**replacements):
    """Patch module-level names on cfbridge and restore them after."""
    saved = {k: getattr(cfbridge, k) for k in replacements}
    for k, v in replacements.items():
        setattr(cfbridge, k, v)
    try:
        yield
    finally:
        for k, v in saved.items():
            setattr(cfbridge, k, v)


@contextlib.contextmanager
def no_sleep():
    """Drop the probe's between-round pause; the retry is what is under test."""
    old = cfbridge.time.sleep
    cfbridge.time.sleep = lambda _seconds: None
    try:
        yield
    finally:
        cfbridge.time.sleep = old


@contextlib.contextmanager
def fake_edge_ips(ips=("198.41.192.7", "198.41.192.27")):
    """collect_deps resolves edge candidates over the network; don't."""
    saved = cfbridge.edge_bridge.fetch_edge_ips
    cfbridge.edge_bridge.fetch_edge_ips = lambda: list(ips)
    try:
        yield
    finally:
        cfbridge.edge_bridge.fetch_edge_ips = saved


class ProxyEnvGuard(unittest.TestCase):
    """No test inherits a proxy from the shell that runs it."""

    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in PROXY_VARS}
        for k in PROXY_VARS:
            os.environ.pop(k, None)
        self.addCleanup(self._restore_env)

    def _restore_env(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


class ParseProxyTests(ProxyEnvGuard):
    def test_credentials_become_a_basic_auth_header(self):
        host, port, auth = cfbridge.parse_proxy("http://user:pw@proxy.internal:3128")
        self.assertEqual((host, port), ("proxy.internal", 3128))
        self.assertEqual(base64.b64decode(auth).decode(), "user:pw")

    def test_scheme_and_port_defaults(self):
        self.assertEqual(cfbridge.parse_proxy("http://h")[1], 80)
        self.assertEqual(cfbridge.parse_proxy("https://h")[1], 443)

    def test_bare_host_port_is_accepted(self):
        self.assertEqual(cfbridge.parse_proxy("10.0.0.1:8080"), ("10.0.0.1", 8080, None))

    def test_socks_urls_still_parse(self):
        host, port, auth = cfbridge.parse_proxy("socks5h://u:p@nas.example:1186")
        self.assertEqual((host, port), ("nas.example", 1186))
        self.assertIsNotNone(auth)

    def test_garbage_is_rejected(self):
        for bad in ("", "   ", "http://", "://nope", "http://h:not-a-port"):
            self.assertIsNone(cfbridge.parse_proxy(bad), bad)

    def test_redact_never_leaks_the_password(self):
        shown = cfbridge.redact_proxy("http://zhumao:s3cr3tPW@nas.021800.xyz:1186")
        self.assertNotIn("s3cr3tPW", shown)
        self.assertNotIn("zhumao", shown)
        self.assertIn("nas.021800.xyz:1186", shown)
        self.assertTrue(shown.startswith("http://***@"))

    def test_redact_of_garbage_is_a_placeholder(self):
        self.assertEqual(cfbridge.redact_proxy("not a url"),
                         "<unparseable proxy URL>")  # hostname-less -> None target


class ProbeProxyTests(ProxyEnvGuard):
    def test_live_proxy_is_accepted(self):
        proxy = LiveProxy()
        self.addCleanup(proxy.close)
        ok, detail = cfbridge.probe_proxy_endpoint(proxy.url)
        self.assertTrue(ok, detail)

    def test_closed_port_is_reported_unreachable(self):
        ok, detail = cfbridge.probe_proxy_endpoint(f"http://127.0.0.1:{free_port()}", timeout=2)
        self.assertFalse(ok)
        self.assertIn("unreachable", detail)

    def test_socks_scheme_is_rejected_with_a_reason(self):
        # The bridge speaks HTTP CONNECT; a SOCKS listener cannot carry it.
        ok, detail = cfbridge.probe_proxy_endpoint("socks5h://127.0.0.1:1080")
        self.assertFalse(ok)
        self.assertIn("CONNECT", detail)

    def test_unparseable_is_rejected(self):
        ok, detail = cfbridge.probe_proxy_endpoint("http://")
        self.assertFalse(ok)
        self.assertIn("unparseable", detail)


class ProxySourceTests(ProxyEnvGuard):
    def test_env_wins_over_the_project_file(self):
        with tempfile.TemporaryDirectory() as proj:
            os.makedirs(os.path.join(proj, "secrets"))
            with open(os.path.join(proj, "secrets", "proxy.env"), "w", encoding="utf-8") as f:
                f.write("HTTPS_PROXY=http://from-file:1\n")
            os.environ["HTTPS_PROXY"] = "http://from-env:2"
            self.assertEqual(cfbridge.proxy_from_env(), "http://from-env:2")
            self.assertEqual(cfbridge.proxy_from_project(proj), "http://from-file:1")

    def test_cfbridge_proxy_overrides_the_usual_variables(self):
        os.environ["HTTPS_PROXY"] = "http://usual:1"
        os.environ["CFBRIDGE_PROXY"] = "http://pinned:2"
        self.assertEqual(cfbridge.proxy_from_env(), "http://pinned:2")

    def test_project_file_reader_handles_lowercase_keys(self):
        with tempfile.TemporaryDirectory() as proj:
            os.makedirs(os.path.join(proj, "secrets"))
            with open(os.path.join(proj, "secrets", "proxy.env"), "w", encoding="utf-8") as f:
                f.write("no_proxy=localhost\nhttps_proxy=http://lower:9\n")
            self.assertEqual(cfbridge.proxy_from_project(proj), "http://lower:9")

    def test_project_file_reader_without_a_file(self):
        with tempfile.TemporaryDirectory() as proj:
            self.assertEqual(cfbridge.proxy_from_project(proj), "")

    def test_resolve_prefers_a_live_candidate_over_a_dead_environment_one(self):
        proxy = LiveProxy()
        self.addCleanup(proxy.close)
        with tempfile.TemporaryDirectory() as proj:
            os.makedirs(os.path.join(proj, "secrets"))
            with open(os.path.join(proj, "secrets", "proxy.env"), "w", encoding="utf-8") as f:
                f.write(f"HTTPS_PROXY={proxy.url}\n")
            # The environment still points at a proxy that rotated away.
            os.environ["HTTPS_PROXY"] = f"http://127.0.0.1:{free_port()}"
            url, source, ok, detail = cfbridge.resolve_proxy(proj, timeout=2)
            self.assertTrue(ok, detail)
            self.assertEqual((url, source), (proxy.url, "secrets/proxy.env"))

    def test_resolve_reports_no_candidate(self):
        with tempfile.TemporaryDirectory() as proj:
            url, source, ok, detail = cfbridge.resolve_proxy(proj)
            self.assertEqual((url, source, ok), ("", "unset", False))
            self.assertIn("no proxy URL", detail)

    def test_resolve_reports_every_candidate_failing(self):
        with tempfile.TemporaryDirectory() as proj:
            os.environ["HTTPS_PROXY"] = f"http://127.0.0.1:{free_port()}"
            url, source, ok, detail = cfbridge.resolve_proxy(proj, timeout=2)
            self.assertFalse(ok)
            self.assertEqual(source, "env")
            self.assertIn("env", detail)

    def test_adopt_project_proxy_only_when_the_environment_is_empty(self):
        proxy = LiveProxy()
        self.addCleanup(proxy.close)
        with tempfile.TemporaryDirectory() as proj:
            os.makedirs(os.path.join(proj, "secrets"))
            with open(os.path.join(proj, "secrets", "proxy.env"), "w", encoding="utf-8") as f:
                f.write(f"https_proxy={proxy.url}\n")
            self.assertEqual(cfbridge.adopt_project_proxy(proj), proxy.url)
            self.assertEqual(os.environ["HTTPS_PROXY"], proxy.url)
            os.environ["HTTP_PROXY"] = "http://already-here:1"
            self.assertEqual(cfbridge.adopt_project_proxy(proj), "")

    def test_refresh_proxy_env_writes_then_reports_no_change(self):
        os.environ["HTTPS_PROXY"] = "http://p:3128"
        with tempfile.TemporaryDirectory() as proj:
            self.assertTrue(cfbridge.refresh_proxy_env(proj))
            self.assertFalse(cfbridge.refresh_proxy_env(proj))  # idempotent


class ProbeEdgeViaProxyTests(ProxyEnvGuard):
    def test_connect_200_through_the_proxy_counts_as_ok(self):
        proxy = LiveProxy()
        self.addCleanup(proxy.close)
        target = cfbridge.parse_proxy(proxy.url)
        ok, detail = cfbridge.probe_edge_via_proxy(target, ["198.41.192.7"], timeout=5)
        self.assertTrue(ok, detail)
        self.assertIn("198.41.192.7", detail)

    def test_connect_403_is_a_dependency_failure(self):
        proxy = LiveProxy(fail_connect=True)
        self.addCleanup(proxy.close)
        target = cfbridge.parse_proxy(proxy.url)
        with no_sleep():
            ok, detail = cfbridge.probe_edge_via_proxy(target, ["198.41.192.7"], timeout=5)
        self.assertFalse(ok)
        self.assertIn("CONNECT failed", detail)


class ProbeEdgeRacingTests(unittest.TestCase):
    """The probe must race like the bridge, and must not cry wolf.

    Reported live: the first `doctor` said `edge via proxy MISSING` and
    told the user to inspect the proxy's CONNECT policy, while a direct
    re-test with the bridge's own connect_via_proxy reached every
    candidate in 0.2s. The probe was walking the candidates one at a
    time with an 8s timeout each, so one transient hiccup on the shared
    egress produced a confident verdict about a healthy proxy.
    """

    def setUp(self):
        self.original = cfbridge.edge_bridge.race_connect
        self.addCleanup(lambda: setattr(cfbridge.edge_bridge, "race_connect", self.original))

    def test_races_all_candidates_in_one_call(self):
        seen = {}

        def fake_race(candidates, proxy, **kwargs):
            seen["candidates"] = list(candidates)
            seen["kwargs"] = kwargs
            return None

        cfbridge.edge_bridge.race_connect = fake_race
        ips = [f"198.41.192.{i}" for i in range(1, 6)]
        with no_sleep():
            ok, detail = cfbridge.probe_edge_via_proxy(("127.0.0.1", 1, None), ips,
                                                       timeout=5, rounds=1)
        self.assertFalse(ok)
        # One call carrying every candidate — never one CONNECT per candidate.
        self.assertEqual(seen["candidates"], ips)
        self.assertEqual(seen["kwargs"]["connect_timeout"], 5)
        self.assertEqual(seen["kwargs"]["race_timeout"], 9)
        self.assertIn("CONNECT failed", detail)

    def test_candidate_count_is_capped_at_the_bridge_race_width(self):
        seen = {}

        def fake_race(candidates, proxy, **kwargs):
            seen["candidates"] = list(candidates)
            return None

        cfbridge.edge_bridge.race_connect = fake_race
        with no_sleep():
            cfbridge.probe_edge_via_proxy(("127.0.0.1", 1, None),
                                          [f"ip{i}" for i in range(30)], rounds=1)
        self.assertEqual(len(seen["candidates"]), cfbridge.edge_bridge.RACE_WIDTH_DEFAULT)

    def test_a_transient_first_round_is_retried_before_reporting(self):
        calls = []

        def flaky(candidates, proxy, **kwargs):
            calls.append(1)
            if len(calls) == 1:
                return None
            return "198.41.192.7", socket.socket(), b""

        cfbridge.edge_bridge.race_connect = flaky
        with no_sleep():
            ok, detail = cfbridge.probe_edge_via_proxy(("127.0.0.1", 1, None),
                                                       ["198.41.192.7"], timeout=5)
        self.assertTrue(ok, detail)
        self.assertEqual(len(calls), 2)
        self.assertIn("attempt 2 of 2", detail)

    def test_failure_is_reported_only_after_every_attempt(self):
        calls = []

        def always_fail(candidates, proxy, **kwargs):
            calls.append(1)
            return None

        cfbridge.edge_bridge.race_connect = always_fail
        with no_sleep():
            ok, detail = cfbridge.probe_edge_via_proxy(("127.0.0.1", 1, None),
                                                       ["198.41.192.7"], timeout=5)
        self.assertFalse(ok)
        self.assertEqual(len(calls), cfbridge.EDGE_PROBE_ROUNDS)
        self.assertIn("over 2 attempt(s)", detail)

    def test_no_candidates_is_reported_clearly(self):
        ok, detail = cfbridge.probe_edge_via_proxy(("127.0.0.1", 1, None), [])
        self.assertFalse(ok)
        self.assertIn("no edge candidates", detail)

    def test_the_winning_socket_is_closed(self):
        opened = []

        def race(candidates, proxy, **kwargs):
            sock = socket.socket()
            opened.append(sock)
            return "198.41.192.7", sock, b""

        cfbridge.edge_bridge.race_connect = race
        ok, _ = cfbridge.probe_edge_via_proxy(("127.0.0.1", 1, None), ["198.41.192.7"])
        self.assertTrue(ok)
        # A probe that forgets to close leaks one fd per doctor run.
        self.assertEqual(opened[0].fileno(), -1)


class DirectEdgeProbeTests(unittest.TestCase):
    """Same defect class as the bridge probe: never block on one IP."""

    def setUp(self):
        self.original = cfbridge._verified_edge_tls
        self.addCleanup(lambda: setattr(cfbridge, "_verified_edge_tls", self.original))

    def test_a_slow_candidate_does_not_delay_a_working_one(self):
        def fake(ip, timeout):
            if ip == "198.41.192.7":
                time.sleep(5)          # sequential code would wait this out
                return False
            return True

        cfbridge._verified_edge_tls = fake
        started = time.monotonic()
        self.assertTrue(cfbridge.direct_edge_ok(["198.41.192.7", "198.41.192.27"], timeout=1))
        self.assertLess(time.monotonic() - started, 3.0)

    def test_all_candidates_failing_is_false(self):
        cfbridge._verified_edge_tls = lambda ip, timeout: False
        self.assertFalse(cfbridge.direct_edge_ok(["198.41.192.7", "198.41.192.27"], timeout=1))

    def test_a_single_candidate_skips_the_thread_dance(self):
        calls = []

        def fake(ip, timeout):
            calls.append(ip)
            return True

        cfbridge._verified_edge_tls = fake
        self.assertTrue(cfbridge.direct_edge_ok(["198.41.192.7"], timeout=1))
        self.assertEqual(calls, ["198.41.192.7"])

    def test_no_candidates_is_false(self):
        self.assertFalse(cfbridge.direct_edge_ok([]))


class DepModelTests(unittest.TestCase):
    def test_missing_counts_only_required_failures(self):
        deps = [cfbridge.dep("a", True, ""), cfbridge.dep("b", False, ""),
                cfbridge.dep("c", False, "", required=False)]
        self.assertEqual([d["name"] for d in cfbridge.dep_missing(deps)], ["b"])


class CollectDepsTests(ProxyEnvGuard):
    """collect_deps is the read-only half: it must never touch the
    network, so every probe it reaches for is replaced."""

    def _collector(self, **overrides):
        base = dict(
            systemctl_path=lambda: "/usr/bin/systemctl",
            find_python_bin=lambda: "/usr/bin/python3",
            cloudflared_version=lambda path: "cloudflared version test",
            resolve_proxy=lambda proj, timeout=6: ("http://127.0.0.1:3128", "env", True, "accepts TCP"),
            bridge_port_free=lambda port: True,
            probe_edge_via_proxy=lambda target, ips, timeout=8: (True, "CONNECT ok"),
            direct_edge_ok=lambda ips, timeout=5: True,
        )
        base.update(overrides)
        return patched(**base)

    def _prepare(self, proj, with_proxy_env=True):
        cfbridge.ensure_project_layout(proj)
        cfbridge.write_secret(proj, "bridge-key.txt", "k")
        # collect_deps only asks cloudflared_version() about a binary it
        # can see, so the file has to exist even though the probe is faked.
        with open(os.path.join(proj, "bin", "cloudflared"), "w", encoding="utf-8") as f:
            f.write("")
        if with_proxy_env:
            with open(os.path.join(proj, "secrets", "proxy.env"), "w", encoding="utf-8") as f:
                f.write("HTTPS_PROXY=http://127.0.0.1:3128\n")

    def test_bridge_mode_all_required_dependencies_ok(self):
        with tempfile.TemporaryDirectory() as proj:
            self._prepare(proj)
            cfg = {"zone": "example.com", "tunnel_name": "t", "bridge_port": 17844, "services": []}
            with fake_root(), fake_edge_ips(), self._collector():
                deps = cfbridge.collect_deps(proj, cfg, "bridge")
            self.assertEqual(cfbridge.dep_missing(deps), [])
            names = [d["name"] for d in deps]
            for expected in ("root", "systemd", "python3", "cloudflared", "proxy",
                             "secrets/proxy.env", "edge via proxy", "bridge port"):
                self.assertIn(expected, names)

    def test_direct_mode_checks_the_direct_edge_instead(self):
        with tempfile.TemporaryDirectory() as proj:
            self._prepare(proj, with_proxy_env=False)
            cfg = {"zone": "example.com", "tunnel_name": "t", "services": []}
            with fake_root(), fake_edge_ips(), self._collector():
                deps = cfbridge.collect_deps(proj, cfg, "direct")
            names = [d["name"] for d in deps]
            self.assertIn("direct edge", names)
            self.assertNotIn("edge via proxy", names)
            self.assertNotIn("secrets/proxy.env", names)

    def test_a_dead_proxy_is_a_required_miss(self):
        with tempfile.TemporaryDirectory() as proj:
            self._prepare(proj)
            cfg = {"zone": "example.com", "tunnel_name": "t", "services": []}
            dead = lambda proj_, timeout=6: ("http://127.0.0.1:1", "env", False, "unreachable")
            dead_edge = lambda target, ips, timeout=8: (False, "CONNECT failed")
            with fake_root(), fake_edge_ips(), \
                    self._collector(resolve_proxy=dead, probe_edge_via_proxy=dead_edge):
                deps = cfbridge.collect_deps(proj, cfg, "bridge")
            missing = {d["name"] for d in cfbridge.dep_missing(deps)}
            self.assertIn("proxy", missing)
            self.assertIn("edge via proxy", missing)

    def test_jq_is_optional_not_a_failure(self):
        with tempfile.TemporaryDirectory() as proj:
            self._prepare(proj, with_proxy_env=False)
            cfg = {"zone": "example.com", "tunnel_name": "t", "services": []}
            with fake_root(), fake_edge_ips(), self._collector():
                deps = cfbridge.collect_deps(proj, cfg, "direct")
            jq = [d for d in deps if d["name"] == "jq"][0]
            self.assertFalse(jq["required"])

    def test_venv_is_only_a_dependency_when_a_service_needs_it(self):
        with tempfile.TemporaryDirectory() as proj:
            self._prepare(proj, with_proxy_env=False)
            cfg = {"zone": "example.com", "tunnel_name": "t", "services": [
                {"name": "demo", "hostname": "d.example.com", "port": 18099,
                 "start_cmd": f"{cfbridge.venv_python(proj)} app.py"}]}
            with fake_root(), fake_edge_ips(), self._collector():
                deps = cfbridge.collect_deps(proj, cfg, "direct")
            venv = [d for d in deps if d["name"] == "service venv"]
            self.assertEqual(len(venv), 1)
            self.assertFalse(venv[0]["ok"])
            self.assertIn("service venv", {d["name"] for d in cfbridge.dep_missing(deps)})


class ServicesNeedingVenvTests(unittest.TestCase):
    def test_only_commands_using_the_project_venv_count(self):
        proj = os.path.join(tempfile.gettempdir(), "muse-proj")
        py = cfbridge.venv_python(proj)
        cfg = {"services": [
            {"name": "a", "start_cmd": f"{py} a.py"},
            {"name": "b", "start_cmd": "/usr/bin/python3 b.py"},
            {"name": "c"},
        ]}
        self.assertEqual(cfbridge.services_needing_venv(proj, cfg), ["a"])


class HealDepsTests(ProxyEnvGuard):
    def test_creates_layout_key_and_adopts_the_remembered_proxy(self):
        proxy = LiveProxy()
        self.addCleanup(proxy.close)
        with tempfile.TemporaryDirectory() as proj:
            os.makedirs(os.path.join(proj, "secrets"))
            with open(os.path.join(proj, "secrets", "proxy.env"), "w", encoding="utf-8") as f:
                f.write(f"HTTPS_PROXY={proxy.url}\n")
            cfg = {"zone": "example.com", "tunnel_name": "t", "services": []}
            with patched(cloudflared_version=lambda path: "cloudflared version test"):
                lines = cfbridge.heal_deps(proj, cfg, "direct")
            for d in cfbridge.PROJECT_LAYOUT:
                self.assertTrue(os.path.isdir(os.path.join(proj, d)), d)
            self.assertTrue(os.path.exists(os.path.join(proj, "secrets", "bridge-key.txt")))
            self.assertEqual(os.environ.get("HTTPS_PROXY"), proxy.url)
            self.assertTrue(any("adopted the working proxy" in l for l in lines), lines)

    def test_installs_a_cloudflared_the_project_is_missing(self):
        installed = []

        def fake_ensure(proj):
            installed.append(proj)
            return os.path.join(proj, "bin", "cloudflared")

        with tempfile.TemporaryDirectory() as proj:
            cfbridge.ensure_project_layout(proj)
            cfg = {"services": []}
            with patched(cloudflared_version=lambda path: None,
                         ensure_cloudflared=fake_ensure,
                         resolve_proxy=lambda proj_, timeout=6: ("", "unset", False, "none")):
                lines = cfbridge.heal_deps(proj, cfg, "direct")
            self.assertEqual(installed, [proj])
            self.assertTrue(any("cloudflared" in l for l in lines), lines)

    def test_moves_a_bridge_port_someone_else_holds(self):
        holder = LiveProxy()
        self.addCleanup(holder.close)
        with tempfile.TemporaryDirectory() as proj:
            cfg = {"zone": "example.com", "tunnel_name": "t",
                   "bridge_port": holder.port, "services": []}
            with patched(cloudflared_version=lambda path: "v",
                         resolve_proxy=lambda proj_, timeout=6: ("", "unset", False, "none")):
                cfbridge.heal_deps(proj, cfg, "bridge")
            self.assertNotEqual(cfg["bridge_port"], holder.port)
            self.assertTrue(cfbridge.bridge_port_free(cfg["bridge_port"]))

    def test_rebuilds_a_service_venv_that_was_lost(self):
        built = []
        with tempfile.TemporaryDirectory() as proj:
            cfg = {"services": [{"name": "demo", "start_cmd": f"{cfbridge.venv_python(proj)} app.py"}]}
            with patched(cloudflared_version=lambda path: "v",
                         resolve_proxy=lambda proj_, timeout=6: ("", "unset", False, "none"),
                         ensure_venv=lambda proj_: built.append(proj_) or cfbridge.venv_python(proj_)):
                lines = cfbridge.heal_deps(proj, cfg, "direct")
            self.assertEqual(built, [proj])
            self.assertTrue(any("venv" in l for l in lines), lines)


class HealStackTests(unittest.TestCase):
    def test_reinstalls_units_wiped_from_etc(self):
        calls = []
        with tempfile.TemporaryDirectory() as proj:
            cfg = {"zone": "example.com", "tunnel_name": "t", "bridge_port": 17844,
                   "services": [{"name": "demo", "hostname": "d.example.com", "port": 18099,
                                 "start_cmd": "/bin/true"}]}
            with fake_root(), patched(
                    units_missing_from_etc=lambda proj_: ["cfb-x-cloudflared"],
                    render_units=lambda proj_, cfg_, mode: ["cfb-x-cloudflared"],
                    install_units=lambda proj_, units: calls.append(list(units)),
                    start_stack=lambda proj_, cfg_, mode, restart=True: [],
                    systemctl=lambda *a, **k: subprocess.CompletedProcess(list(a), 0, "inactive", ""),
                    tunnel_registered_tail=lambda proj_: True):
                lines = cfbridge.heal_stack(proj, cfg, "direct")
            self.assertEqual(calls, [["cfb-x-cloudflared"]])
            self.assertTrue(any("reinstalled" in l for l in lines), lines)

    def test_restarts_a_cloudflared_that_is_up_but_unregistered(self):
        seen = []

        def fake_systemctl(*args, **kwargs):
            seen.append(args)
            out = "active" if args[:1] == ("is-active",) else ""
            return subprocess.CompletedProcess(list(args), 0, out, "")

        with tempfile.TemporaryDirectory() as proj:
            cfg = {"zone": "example.com", "tunnel_name": "t", "services":
                   [{"name": "demo", "hostname": "d.example.com", "port": 18099}]}
            with patched(units_missing_from_etc=lambda proj_: [],
                         start_stack=lambda proj_, cfg_, mode, restart=True: [],
                         systemctl=fake_systemctl,
                         tunnel_registered_tail=lambda proj_: False,
                         wait_tunnel_registered=lambda proj_, offset=0, timeout=45: True):
                lines = cfbridge.heal_stack(proj, cfg, "direct")
            restarts = [a for a in seen if a[:1] == ("restart",)]
            self.assertEqual(len(restarts), 1)
            self.assertTrue(restarts[0][1].endswith("-cloudflared"), restarts)
            self.assertTrue(any("no longer registered" in l for l in lines), lines)

    def test_no_services_means_nothing_to_heal(self):
        with tempfile.TemporaryDirectory() as proj:
            self.assertEqual(cfbridge.heal_stack(proj, {"services": []}, "bridge"), [])


class StartOrderTests(unittest.TestCase):
    def test_dependents_come_last(self):
        names = {"cloudflared": "cfb-x-cf", "bridge": "cfb-x-bridge",
                 "svc:b": "cfb-x-svc-b", "svc:a": "cfb-x-svc-a"}
        self.assertEqual(cfbridge.start_order(names),
                         ["cfb-x-bridge", "cfb-x-svc-a", "cfb-x-svc-b", "cfb-x-cf"])

    def test_direct_mode_starts_services_then_cloudflared(self):
        names = {"cloudflared": "cfb-x-cf", "svc:a": "cfb-x-svc-a"}
        self.assertEqual(cfbridge.start_order(names), ["cfb-x-svc-a", "cfb-x-cf"])


class ReadinessTests(unittest.TestCase):
    def test_wait_port_listening_sees_a_real_listener(self):
        proxy = LiveProxy()
        self.addCleanup(proxy.close)
        self.assertTrue(cfbridge.wait_port_listening("127.0.0.1", proxy.port, timeout=5))

    def test_wait_port_listening_gives_up_on_a_closed_port(self):
        self.assertFalse(cfbridge.wait_port_listening("127.0.0.1", free_port(), timeout=1))

    def test_log_offset_of_a_missing_file_is_zero(self):
        with tempfile.TemporaryDirectory() as proj:
            self.assertEqual(cfbridge.log_offset(os.path.join(proj, "nope.log")), 0)

    def test_registration_must_be_after_the_offset(self):
        with tempfile.TemporaryDirectory() as proj:
            logs = os.path.join(proj, "logs")
            os.makedirs(logs)
            path = os.path.join(logs, "cloudflared.log")
            with open(path, "w", encoding="utf-8") as f:
                f.write("INF " + cfbridge.CF_REGISTERED_MARK + "\n")
            offset = os.path.getsize(path)
            # An old registration must not make a just-restarted unit look ready.
            self.assertFalse(cfbridge.wait_tunnel_registered(proj, offset, timeout=0.3))
            with open(path, "a", encoding="utf-8") as f:
                f.write("INF " + cfbridge.CF_REGISTERED_MARK + "\n")
            self.assertTrue(cfbridge.wait_tunnel_registered(proj, offset, timeout=5))

    def test_tail_check_reads_the_end_of_the_file(self):
        with tempfile.TemporaryDirectory() as proj:
            logs = os.path.join(proj, "logs")
            os.makedirs(logs)
            path = os.path.join(logs, "cloudflared.log")
            with open(path, "w", encoding="utf-8") as f:
                f.write("x" * 20000)
                f.write(cfbridge.CF_REGISTERED_MARK + "\n")
            self.assertTrue(cfbridge.tunnel_registered_tail(proj))
            with open(path, "a", encoding="utf-8") as f:
                f.write("y" * 20000)  # pushes the marker out of the window
            self.assertFalse(cfbridge.tunnel_registered_tail(proj))


if __name__ == "__main__":
    unittest.main()
