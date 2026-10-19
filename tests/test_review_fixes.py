"""Regression tests for the 1bfa0f3 code review (H1-H2, M1-M8, L1-L8).

Hermetic like the rest of the suite: no network, no Cloudflare API, no
real systemd. The keepalive hook is rendered for real and run under
bash against a fake `systemctl` on PATH and a stub hook runtime.
"""
from __future__ import annotations

import contextlib
import http.server
import importlib.util
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bin"))

import cfbridge  # noqa: E402
import edge_bridge  # noqa: E402

PROXY_VARS = ("CFBRIDGE_PROXY", "HTTPS_PROXY", "https_proxy",
              "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@contextlib.contextmanager
def patched(module=cfbridge, **replacements):
    saved = {k: getattr(module, k) for k in replacements}
    for k, v in replacements.items():
        setattr(module, k, v)
    try:
        yield
    finally:
        for k, v in saved.items():
            setattr(module, k, v)


@contextlib.contextmanager
def euid(value):
    had = hasattr(os, "geteuid")
    old = getattr(os, "geteuid", None)
    os.geteuid = lambda: value
    try:
        yield
    finally:
        if had:
            os.geteuid = old
        else:
            delattr(os, "geteuid")


@contextlib.contextmanager
def captured():
    out = io.StringIO()
    old = sys.stdout
    sys.stdout = out
    try:
        yield out
    finally:
        sys.stdout = old


class HealthServer:
    """Loopback HTTP server; `healthy` decides 200 vs 500."""

    def __init__(self, healthy=lambda: True):
        check = healthy

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                code = 200 if check() else 500
                self.send_response(code)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *a):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class LiveProxy:
    """Accepts TCP; enough for probe_proxy_endpoint()."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def _loop(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            c.close()

    def close(self):
        self.sock.close()


class EnvGuard(unittest.TestCase):
    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in PROXY_VARS}
        for k in PROXY_VARS:
            os.environ.pop(k, None)
        self.addCleanup(self._restore)

    def _restore(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def svc(**over):
    base = {"name": "web", "hostname": "web.example.com", "port": 8080,
            "health": "/health", "auth": "key", "public_confirmed": False,
            "origin": "", "start_cmd": "", "workdir": "", "env_proxy": False}
    base.update(over)
    return base


# ---------------------------------------------------------------- H1

class H1LocalProbeBypassesProxy(EnvGuard):
    def test_local_probe_ignores_a_dead_proxy(self):
        srv = HealthServer()
        self.addCleanup(srv.close)
        dead = f"http://127.0.0.1:{free_port()}"
        for k in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
            os.environ[k] = dead
        os.environ["NO_PROXY"] = os.environ["no_proxy"] = ""
        status, body = cfbridge.local_get(srv.port, "/health", timeout=3)
        self.assertEqual((status, body), (200, "ok"))
        status, _ = cfbridge.http_get(f"http://127.0.0.1:{srv.port}/x", timeout=3, direct=True)
        self.assertEqual(status, 200)

    def test_status_and_wait_use_the_direct_probe(self):
        seen = []

        def fake_local(port, path, timeout=4):
            seen.append((port, path))
            return 200, "ok"

        cfg = {"zone": "example.com", "services": [svc(port=9)]}
        with patched(local_get=fake_local):
            cfbridge.wait_local_health(cfg, timeout=2)
        self.assertEqual(seen, [(9, "/health")])

    def test_hook_curl_bypasses_proxies(self):
        text = (ROOT / "templates" / "keepalive-hook.sh.tmpl").read_text(encoding="utf-8")
        self.assertIn("curl --noproxy '*'", text)
        self.assertIn("ProxyHandler({})", text)


# ---------------------------------------------------------------- H2

class H2StoppedMarker(unittest.TestCase):
    def test_down_writes_the_marker(self):
        with tempfile.TemporaryDirectory() as proj:
            os.makedirs(os.path.join(proj, "run"))
            Path(proj, "run", "managed-units.txt").write_text("cfb-x-cloudflared\n")
            calls = []
            fake = lambda *a, **k: calls.append(a) or subprocess.CompletedProcess(list(a), 0, "", "")
            with patched(require_root=lambda action: None, systemctl=fake), captured():
                cfbridge.cmd_down(types.SimpleNamespace(project=proj))
            self.assertTrue(cfbridge.is_stopped(proj))
            self.assertIn(("stop", "cfb-x-cloudflared"), calls)

    def test_up_clears_the_marker(self):
        class Stop(Exception):
            pass

        def boom(_svc):
            raise Stop()

        with tempfile.TemporaryDirectory() as proj:
            cfbridge.save_config(proj, {"zone": "example.com", "tunnel_name": "t",
                                        "services": [svc()]})
            cfbridge.mark_stopped(proj)
            with patched(require_root=lambda action: None, normalize_origin=boom), captured():
                with self.assertRaises(Stop):
                    cfbridge.cmd_up(types.SimpleNamespace(project=proj, force_dns=False))
            self.assertFalse(cfbridge.is_stopped(proj))

    def test_heal_stack_leaves_a_stopped_stack_alone(self):
        calls = []
        with tempfile.TemporaryDirectory() as proj:
            cfbridge.mark_stopped(proj)
            cfg = {"services": [svc(start_cmd="/bin/true")]}
            with euid(0), patched(systemctl_path=lambda: "/usr/bin/systemctl",
                                  start_stack=lambda *a, **k: calls.append(a) or [],
                                  install_units=lambda *a: calls.append(a)):
                lines = cfbridge.heal_stack(proj, cfg, "bridge")
        self.assertEqual(calls, [])
        self.assertTrue(any("cfbridge down" in l for l in lines), lines)

    def test_heal_deps_does_not_rerender_a_stopped_stack(self):
        with tempfile.TemporaryDirectory() as proj:
            holder = socket.socket()
            holder.bind(("127.0.0.1", 0))
            holder.listen(1)
            self.addCleanup(holder.close)
            cfbridge.ensure_project_layout(proj)
            Path(proj, "run", "managed-units.txt").write_text("cfb-x-bridge\n")
            cfbridge.mark_stopped(proj)
            cfg = {"zone": "example.com", "tunnel_name": "t",
                   "bridge_port": holder.getsockname()[1], "services": [svc()]}
            installed = []
            with euid(0), patched(cloudflared_version=lambda p: "v",
                                  resolve_proxy=lambda p, timeout=6: ("", "unset", False, ""),
                                  systemctl_path=lambda: "",
                                  install_units=lambda *a: installed.append(a)):
                cfbridge.heal_deps(proj, cfg, "bridge")
            self.assertEqual(installed, [])

    def test_teardown_forgets_units_and_copies(self):
        with tempfile.TemporaryDirectory() as proj:
            cfbridge.ensure_project_layout(proj)
            cfbridge.save_config(proj, {"zone": "example.com", "tunnel_name": "t", "services": []})
            Path(proj, "run", "managed-units.txt").write_text("cfb-x-cloudflared\ncfb-x-bridge\n")
            for u in ("cfb-x-cloudflared", "cfb-x-bridge"):
                Path(proj, "systemd", u + ".service").write_text("[Unit]\n")
            Path(proj, "systemd", "unrelated.txt").write_text("keep")
            ok = lambda *a, **k: subprocess.CompletedProcess(list(a), 0, "", "")
            with patched(require_root=lambda action: None, systemctl=ok), captured() as out:
                cfbridge.cmd_teardown(types.SimpleNamespace(project=proj, purge_project=False))
            self.assertFalse(os.path.exists(os.path.join(proj, "run", "managed-units.txt")))
            self.assertFalse(os.path.exists(os.path.join(proj, "systemd", "cfb-x-bridge.service")))
            self.assertTrue(os.path.exists(os.path.join(proj, "systemd", "unrelated.txt")))
            self.assertTrue(cfbridge.is_stopped(proj))
            self.assertIn("hooks.remove", out.getvalue())


# ---------------------------------------------------------------- hook harness

FAKE_SYSTEMCTL = r"""#!/usr/bin/env bash
echo "$*" >> "$FAKE_STATE/calls"
verb="$1"; shift || true
case "$verb" in
  is-active)
    [[ "${1:-}" == "--quiet" ]] && shift
    if [[ "$(cat "$FAKE_STATE/unit-$1" 2>/dev/null)" == "active" ]]; then echo active; exit 0; fi
    echo inactive; exit 3 ;;
  start|restart)
    for u in "$@"; do echo active > "$FAKE_STATE/unit-$u"; touch "$FAKE_STATE/fixed-$u"; done
    exit 0 ;;
  *) exit 0 ;;
esac
"""

RUNTIME = r"""
log() { echo "LOG: $1"; }
silent() { echo "SILENT: $1"; exit 0; }
wake() { echo "WAKE: $1"; exit 0; }
hook_state_get() { echo '{}'; }
hook_state_set() { :; }
"""


@unittest.skipUnless(shutil.which("bash"), "bash required")
class HookHarness(EnvGuard):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.mkdtemp(prefix="cfbhook")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.proj = os.path.join(self.tmp, "proj")
        self.state = os.path.join(self.tmp, "state")
        self.bindir = os.path.join(self.tmp, "bin")
        self.etc = os.path.join(self.tmp, "etc")
        for d in (self.state, self.bindir, self.etc):
            os.makedirs(d)
        cfbridge.ensure_project_layout(self.proj)
        sctl = os.path.join(self.bindir, "systemctl")
        Path(sctl).write_text(FAKE_SYSTEMCTL)
        os.chmod(sctl, 0o755)
        Path(self.tmp, "runtime.sh").write_text(RUNTIME)
        slug = cfbridge.project_slug(self.proj)
        self.prefix = f"cfb-{slug}-"
        self.units = [self.prefix + "bridge", self.prefix + "svc-web", self.prefix + "cloudflared"]
        Path(self.proj, "run", "managed-units.txt").write_text("\n".join(self.units) + "\n")
        for u in self.units:
            Path(self.proj, "systemd", u + ".service").write_text("[Unit]\n")
            Path(self.etc, u + ".service").write_text("[Unit]\n")
        text = cfbridge.render(cfbridge.read_template("keepalive-hook.sh.tmpl"),
                               {"PROJECT_DIR": self.proj, "SKILL_BIN": cfbridge.HERE})
        self.script = os.path.join(self.tmp, "hook.sh")
        Path(self.script).write_text(text)

    def config(self, services):
        cfbridge.save_config(self.proj, {"zone": "example.com", "tunnel_name": "t",
                                         "log_retention_hours": 0, "services": services})

    def set_active(self, *units):
        for u in units:
            Path(self.state, "unit-" + u).write_text("active")

    def calls(self):
        p = Path(self.state, "calls")
        return p.read_text().splitlines() if p.exists() else []

    def run_hook(self, extra_env=None, timeout=90):
        env = {k: v for k, v in os.environ.items() if k not in PROXY_VARS}
        env.update({"PATH": self.bindir + os.pathsep + env.get("PATH", ""),
                    "HATCH_HOOK_RUNTIME": os.path.join(self.tmp, "runtime.sh"),
                    "FAKE_STATE": self.state, "CFB_SYSTEMD_UNIT_DIR": self.etc})
        env.update(extra_env or {})
        r = subprocess.run(["bash", self.script], capture_output=True, text=True,
                           env=env, timeout=timeout)
        return r.stdout + r.stderr

    # H2
    def test_h2_stopped_marker_silences_the_hook(self):
        self.config([svc(start_cmd="/bin/true", port=free_port())])
        cfbridge.mark_stopped(self.proj)
        out = self.run_hook()
        self.assertIn("intentionally stopped", out)
        self.assertEqual(self.calls(), [])

    # H1
    def test_h1_healthy_stack_stays_silent_behind_a_dead_proxy(self):
        srv = HealthServer()
        self.addCleanup(srv.close)
        self.config([svc(start_cmd="/bin/true", port=srv.port)])
        self.set_active(*self.units)
        dead = f"http://127.0.0.1:{free_port()}"
        out = self.run_hook({"http_proxy": dead, "HTTP_PROXY": dead})
        self.assertIn("SILENT: cf tunnel stack healthy", out)
        self.assertFalse([c for c in self.calls() if c.startswith(("restart", "start"))])

    # M6
    def test_m6_only_the_unhealthy_service_unit_is_restarted(self):
        web_unit = self.prefix + "svc-web"
        srv = HealthServer(lambda: os.path.exists(os.path.join(self.state, "fixed-" + web_unit)))
        self.addCleanup(srv.close)
        self.config([svc(start_cmd="/bin/true", port=srv.port)])
        self.set_active(*self.units)
        out = self.run_hook()
        self.assertIn("healthy now", out)
        acts = [c for c in self.calls() if c.startswith(("restart", "start"))]
        self.assertEqual(acts, [f"restart {web_unit}"])

    def test_m6_down_units_start_in_dependency_order_and_active_ones_are_left_alone(self):
        srv = HealthServer()
        self.addCleanup(srv.close)
        self.config([svc(start_cmd="/bin/true", port=srv.port)])
        self.set_active(self.prefix + "svc-web")
        out = self.run_hook()
        self.assertIn("healthy now", out)
        acts = [c for c in self.calls() if c.startswith(("restart", "start"))]
        self.assertEqual(acts, [f"start {self.prefix}bridge", f"start {self.prefix}cloudflared"])

    def test_m6_route_only_failure_restarts_nothing_and_skips_doctor(self):
        srv = HealthServer(lambda: False)
        self.addCleanup(srv.close)
        self.config([svc(name="ext", port=srv.port)])  # no start_cmd: user-run process
        self.set_active(*self.units)
        out = self.run_hook()
        self.assertIn("WAKE:", out)
        self.assertFalse([c for c in self.calls() if c.startswith(("restart", "start"))])
        self.assertFalse(os.path.exists(os.path.join(self.proj, "logs", "last-doctor-fix.log")))

    def test_m6_repairs_are_throttled(self):
        srv = HealthServer()
        self.addCleanup(srv.close)
        self.config([svc(start_cmd="/bin/true", port=srv.port)])
        Path(self.proj, "run", "hook-last-repair").write_text(str(int(time.time())))
        out = self.run_hook()
        self.assertIn("throttled", out)
        self.assertFalse([c for c in self.calls() if c.startswith(("restart", "start"))])

    # M2
    def test_m2_hook_does_not_overwrite_a_working_proxy_env_with_a_dead_value(self):
        live = LiveProxy()
        self.addCleanup(live.close)
        srv = HealthServer()
        self.addCleanup(srv.close)
        self.config([svc(start_cmd="/bin/true", port=srv.port)])
        self.set_active(*self.units)
        env_file = Path(self.proj, "secrets", "proxy.env")
        env_file.write_text(f"HTTPS_PROXY={live.url}\nhttps_proxy={live.url}\n")
        dead = f"http://127.0.0.1:{free_port()}"
        self.run_hook({"HTTPS_PROXY": dead, "https_proxy": dead})
        self.assertIn(live.url, env_file.read_text())
        self.assertNotIn(dead, env_file.read_text())

    def test_m2_hook_writes_a_live_environment_proxy(self):
        live = LiveProxy()
        self.addCleanup(live.close)
        srv = HealthServer()
        self.addCleanup(srv.close)
        self.config([svc(start_cmd="/bin/true", port=srv.port)])
        self.set_active(*self.units)
        out = self.run_hook({"HTTPS_PROXY": live.url})
        self.assertIn("proxy.env refreshed", out)
        self.assertIn(live.url, Path(self.proj, "secrets", "proxy.env").read_text())


# ---------------------------------------------------------------- M1

class M1PathInjection(unittest.TestCase):
    def test_unsafe_paths_are_refused(self):
        for bad in ('/tmp/p"$(touch /tmp/PWNED)"x', "/tmp/a b", "/tmp/`id`", "/tmp/50%", "/tmp/a$b"):
            with self.assertRaises(SystemExit, msg=bad):
                cfbridge.require_safe_path("project path", bad)
        for good in ("/home/hatch/workspace/projects/my-bridge", "/root/p_1.2+x", "/h/a@b:c=d,e~f"):
            self.assertEqual(cfbridge.require_safe_path("project path", good), good)

    def test_install_autostart_refuses_an_injecting_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "PWNED")
            proj = os.path.join(tmp, f'p"$(touch {marker})"x')
            os.makedirs(proj)
            with captured(), self.assertRaises(SystemExit):
                cfbridge.cmd_install_autostart(types.SimpleNamespace(project=proj))
            self.assertFalse(os.path.exists(marker))

    def test_render_units_refuses_an_unsafe_project_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            proj = os.path.join(tmp, "with space")
            os.makedirs(proj)
            cfg = {"zone": "example.com", "tunnel_name": "t", "services": []}
            with self.assertRaises(SystemExit):
                cfbridge.render_units(proj, cfg, "direct")


# ---------------------------------------------------------------- M2

class M2VerifiedProxyOnly(EnvGuard):
    def test_dead_cfbridge_proxy_does_not_clobber_the_working_file_value(self):
        live = LiveProxy()
        self.addCleanup(live.close)
        dead = f"http://127.0.0.1:{free_port()}"
        os.environ["CFBRIDGE_PROXY"] = dead
        with tempfile.TemporaryDirectory() as proj:
            cfbridge.ensure_project_layout(proj)
            env_file = Path(proj, "secrets", "proxy.env")
            env_file.write_text(f"HTTPS_PROXY={live.url}\nNO_PROXY=internal\n")
            with patched(cloudflared_version=lambda p: "v"):
                lines = cfbridge.heal_deps(proj, {"services": []}, "direct")
            text = env_file.read_text()
            self.assertIn(live.url, text)
            self.assertNotIn(dead, text)
            self.assertIn("NO_PROXY=internal", text)  # companions kept from the file
            self.assertEqual(cfbridge.proxy_from_env(), live.url)
            self.assertTrue(any("adopted" in l for l in lines), lines)

    def test_refresh_with_explicit_url(self):
        with tempfile.TemporaryDirectory() as proj:
            self.assertTrue(cfbridge.refresh_proxy_env(proj, "http://10.0.0.1:3128"))
            self.assertIn("HTTPS_PROXY=http://10.0.0.1:3128",
                          Path(proj, "secrets", "proxy.env").read_text())
            self.assertFalse(cfbridge.refresh_proxy_env(proj, "http://10.0.0.1:3128"))

    def test_sync_proxy_leaves_the_file_when_nothing_answers(self):
        dead = f"http://127.0.0.1:{free_port()}"
        os.environ["HTTPS_PROXY"] = dead
        with tempfile.TemporaryDirectory() as proj:
            cfbridge.ensure_project_layout(proj)
            env_file = Path(proj, "secrets", "proxy.env")
            env_file.write_text("HTTPS_PROXY=http://kept:1\n")
            with captured(), self.assertRaises(SystemExit):
                cfbridge.cmd_sync_proxy(types.SimpleNamespace(project=proj, timeout=1, quiet=True))
            self.assertEqual(env_file.read_text(), "HTTPS_PROXY=http://kept:1\n")


# ---------------------------------------------------------------- M4

class M4AuthKeyIsOriginEnforced(unittest.TestCase):
    def test_add_service_says_key_auth_is_the_origins_job(self):
        with tempfile.TemporaryDirectory() as proj:
            cfbridge.save_config(proj, {"zone": "example.com", "tunnel_name": "t", "services": []})
            with captured() as out:
                cfbridge.main(["--project", proj, "add-service", "--name", "web",
                               "--hostname", "web.example.com", "--port", "8080"])
            self.assertIn("enforced by YOUR origin", out.getvalue())

    def test_verify_without_ws_flags_unchecked_auth(self):
        with tempfile.TemporaryDirectory() as proj:
            cfbridge.save_config(proj, {"zone": "example.com", "tunnel_name": "t",
                                        "services": [svc()]})
            with patched(http_get=lambda url, timeout=10, direct=False: (200, "ok")), \
                    captured() as out:
                cfbridge.cmd_verify(types.SimpleNamespace(project=proj, ws=False))
            self.assertIn("auth NOT verified for web", out.getvalue())


# ---------------------------------------------------------------- M5

class M5StartCmd(unittest.TestCase):
    cfg = {"zone": "example.com", "services": []}

    def test_tilde_is_expanded(self):
        home = os.path.expanduser("~")
        self.assertEqual(cfbridge.expand_start_cmd("~/venv/bin/python app.py --data ~/d"),
                         f"{home}/venv/bin/python app.py --data {home}/d")
        self.assertEqual(cfbridge.expand_start_cmd("/bin/echo a~b"), "/bin/echo a~b")

    def test_relative_executable_with_a_slash_is_rejected(self):
        with self.assertRaises(SystemExit):
            cfbridge.validate_service(self.cfg, svc(start_cmd="venv/bin/python app.py"), False)
        cfbridge.validate_service(self.cfg, svc(start_cmd="~/venv/bin/python app.py"), False)
        cfbridge.validate_service(self.cfg, svc(start_cmd="-/usr/bin/python3 app.py"), False)

    def test_percent_is_escaped_in_the_unit(self):
        with tempfile.TemporaryDirectory() as proj:
            cfg = {"zone": "example.com", "tunnel_name": "t", "services": [
                svc(start_cmd="/bin/sh -c 'echo $(date +%s)'", workdir="~/w%d")]}
            cfbridge.render_units(proj, cfg, "direct")
            name = cfbridge.unit_names(proj, cfg, "direct")["svc:web"]
            text = Path(proj, "systemd", name + ".service").read_text()
            self.assertIn("date +%%s", text)
            self.assertIn(f"WorkingDirectory={os.path.expanduser('~')}/w%%d", text)

    def test_add_service_stores_the_expanded_command(self):
        with tempfile.TemporaryDirectory() as proj:
            cfbridge.save_config(proj, {"zone": "example.com", "tunnel_name": "t", "services": []})
            with captured():
                cfbridge.main(["--project", proj, "add-service", "--name", "web",
                               "--hostname", "web.example.com", "--port", "8080",
                               "--start-cmd", "~/venv/bin/python app.py"])
            stored = cfbridge.load_config(proj)["services"][0]["start_cmd"]
            self.assertTrue(os.path.isabs(stored.split()[0]), stored)

    def test_tilde_venv_counts_for_the_venv_self_heal(self):
        home = os.path.expanduser("~")
        proj = os.path.join(home, "workspace", "projects", "p")
        cfg = {"services": [{"name": "a", "start_cmd": "~/workspace/projects/p/venv/bin/python a.py"}]}
        self.assertEqual(cfbridge.services_needing_venv(proj, cfg), ["a"])


# ---------------------------------------------------------------- M7

class M7RegistrationState(unittest.TestCase):
    def _log(self, proj, text):
        os.makedirs(os.path.join(proj, "logs"), exist_ok=True)
        Path(proj, "logs", "cloudflared.log").write_text(text)

    def test_long_running_tunnel_is_still_registered(self):
        with tempfile.TemporaryDirectory() as proj:
            self._log(proj, "INF Starting tunnel\nINF Registered tunnel connection\n" + "noise\n" * 5000)
            self.assertFalse(cfbridge.tunnel_registered_tail(proj))  # the old check misfired here
            self.assertEqual(cfbridge.tunnel_registration_state(proj), "registered")

    def test_a_start_without_registration_is_unregistered(self):
        with tempfile.TemporaryDirectory() as proj:
            self._log(proj, "INF Starting tunnel\nINF Registered tunnel connection\n"
                            "INF Starting tunnel\nERR failed to dial\n")
            self.assertEqual(cfbridge.tunnel_registration_state(proj), "unregistered")

    def test_rotated_log_is_unknown_and_not_bounced(self):
        with tempfile.TemporaryDirectory() as proj:
            self._log(proj, "noise\n" * 100)
            self.assertEqual(cfbridge.tunnel_registration_state(proj), "unknown")
            restarts = []

            def fake(*a, **k):
                if a[:1] == ("restart",):
                    restarts.append(a)
                return subprocess.CompletedProcess(list(a), 0, "active", "")

            cfg = {"services": [svc()]}
            with euid(0), patched(systemctl_path=lambda: "/usr/bin/systemctl",
                                  units_missing_from_etc=lambda p: [],
                                  start_stack=lambda *a, **k: [], systemctl=fake):
                cfbridge.heal_stack(proj, cfg, "direct")
            self.assertEqual(restarts, [])


# ---------------------------------------------------------------- M8

class M8DoctorFixDegrades(unittest.TestCase):
    def test_non_root_is_skipped_not_fatal(self):
        with tempfile.TemporaryDirectory() as proj, euid(1000), \
                patched(systemctl_path=lambda: "/usr/bin/systemctl"):
            lines = cfbridge.heal_stack(proj, {"services": [svc(start_cmd="/bin/true")]}, "direct")
        self.assertTrue(any(l.startswith("SKIPPED") and "root" in l for l in lines), lines)

    def test_no_systemd_is_skipped_not_fatal(self):
        with tempfile.TemporaryDirectory() as proj, euid(0), patched(systemctl_path=lambda: ""):
            lines = cfbridge.heal_stack(proj, {"services": [svc()]}, "direct")
        self.assertTrue(any("systemctl not on PATH" in l for l in lines), lines)

    def test_a_unit_that_fails_to_start_is_reported(self):
        def fake(*a, check=False, **k):
            if a[:1] == ("start",):
                if check:
                    raise AssertionError("start_stack must not die from heal_stack")
                return subprocess.CompletedProcess(list(a), 5, "", "Unit not found")
            return subprocess.CompletedProcess(list(a), 3, "inactive", "")

        with tempfile.TemporaryDirectory() as proj, euid(0), \
                patched(systemctl_path=lambda: "/usr/bin/systemctl",
                        units_missing_from_etc=lambda p: [], systemctl=fake,
                        tunnel_registration_state=lambda p: "unknown"):
            cfg = {"services": [svc(start_cmd="/bin/true")]}
            lines = cfbridge.heal_stack(proj, cfg, "direct")
        self.assertTrue(any(l.startswith("FAILED to start") for l in lines), lines)

    def test_broken_cloudflared_copy_is_replaced(self):
        with tempfile.TemporaryDirectory() as proj:
            os.makedirs(os.path.join(proj, "bin"))
            dst = os.path.join(proj, "bin", "cloudflared")
            Path(dst).write_text("truncated")
            downloads = []

            def fake_download(path):
                downloads.append(path)
                Path(path).write_text("fresh")
                return path

            version = lambda p: "cloudflared 1" if Path(p).read_text() == "fresh" else None
            with patched(cloudflared_version=version, download_cloudflared=fake_download), \
                    patched(module=cfbridge.shutil, which=lambda name: None), captured():
                cfbridge.ensure_cloudflared(proj)
            self.assertEqual(downloads, [dst])
            self.assertEqual(Path(dst + ".broken").read_text(), "truncated")


# ---------------------------------------------------------------- L1-L8

class LowFindings(EnvGuard):
    def test_l1_latest_uses_githubs_latest_download_path(self):
        os.environ.pop("CFBRIDGE_CLOUDFLARED_URL", None)
        old = os.environ.get("CFBRIDGE_CLOUDFLARED_VERSION")
        self.addCleanup(lambda: os.environ.__setitem__("CFBRIDGE_CLOUDFLARED_VERSION", old)
                        if old is not None else os.environ.pop("CFBRIDGE_CLOUDFLARED_VERSION", None))
        os.environ["CFBRIDGE_CLOUDFLARED_VERSION"] = "latest"
        with patched(cloudflared_asset=lambda: "cloudflared-linux-amd64"):
            self.assertEqual(cfbridge.cloudflared_download_url(),
                             "https://github.com/cloudflare/cloudflared/releases/latest/download/"
                             "cloudflared-linux-amd64")
            os.environ["CFBRIDGE_CLOUDFLARED_VERSION"] = "2026.9.3"
            self.assertIn("/releases/download/2026.9.3/", cfbridge.cloudflared_download_url())

    def test_l2_time_wait_after_a_bridge_restart_is_not_busy(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        cli = socket.create_connection(("127.0.0.1", port))
        conn, _ = srv.accept()
        conn.close()  # server side closes first -> TIME_WAIT on the listener's port
        time.sleep(0.1)
        cli.close()
        srv.close()
        self.assertTrue(cfbridge.bridge_port_free(port))

    def test_l2_activating_own_bridge_counts_as_ours(self):
        fake = lambda *a, **k: subprocess.CompletedProcess(list(a), 3, "activating\n", "")
        with patched(systemctl_path=lambda: "/usr/bin/systemctl", systemctl=fake):
            self.assertTrue(cfbridge.own_bridge_holds_port("/home/x/p", {"services": []}))

    def test_l4_regions_are_interleaved(self):
        answers = {"region1.v2.argotunnel.com": [f"1.0.0.{i}" for i in range(10)],
                   "region2.v2.argotunnel.com": [f"2.0.0.{i}" for i in range(10)]}
        with patched(module=edge_bridge,
                     doh_query=lambda name, qtype: [{"data": ip} for ip in answers[name]]):
            ips = edge_bridge.fetch_edge_ips()
        self.assertEqual(ips[:4], ["1.0.0.0", "2.0.0.0", "1.0.0.1", "2.0.0.1"])
        self.assertEqual(len(ips), 20)

    def test_l4_failed_rounds_move_to_the_next_candidates(self):
        seen = []

        def fake_race(candidates, proxy, race=8, **kw):
            seen.append(list(candidates)[:race])
            return None

        bridge = edge_bridge.EdgeBridge.__new__(edge_bridge.EdgeBridge)
        bridge.race, bridge.connect_timeout, bridge.race_timeout = 2, 1, 1
        bridge.proxy = ("127.0.0.1", 1, None)
        bridge.edge_ips = ["a", "b", "c", "d", "e"]
        with patched(module=edge_bridge, race_connect=fake_race):
            bridge.race_edges()
            bridge.race_edges()
            bridge.race_edges()
        self.assertEqual(seen, [["a", "b"], ["c", "d"], ["e", "a"]])
        self.assertEqual(edge_bridge.rotate([], 3), [])

    def test_l4_probe_retry_round_uses_the_next_slice(self):
        seen = []
        with patched(module=edge_bridge,
                     race_connect=lambda c, p, **kw: seen.append(list(c)) or None), \
                patched(module=cfbridge.time, sleep=lambda s: None):
            cfbridge.probe_edge_via_proxy(("127.0.0.1", 1, None), [f"ip{i}" for i in range(16)])
        self.assertEqual(seen[0], [f"ip{i}" for i in range(8)])
        self.assertEqual(seen[1], [f"ip{i}" for i in range(8, 16)])

    def test_l5_demo_accepts_the_header_only(self):
        fake_ws = types.ModuleType("websockets")
        ds = types.ModuleType("websockets.datastructures")
        ds.Headers = dict
        h11 = types.ModuleType("websockets.http11")
        h11.Response = object
        saved = {k: sys.modules.get(k) for k in ("websockets", "websockets.datastructures",
                                                 "websockets.http11")}
        sys.modules.update({"websockets": fake_ws, "websockets.datastructures": ds,
                            "websockets.http11": h11})
        # No .pyc under templates/: CI's placeholder check reads every file there as UTF-8.
        saved_dwb, sys.dont_write_bytecode = sys.dont_write_bytecode, True
        try:
            spec = importlib.util.spec_from_file_location(
                "demo_origin_under_test", ROOT / "templates" / "demo_origin.py")
            demo = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(demo)
        finally:
            sys.dont_write_bytecode = saved_dwb
            for k, v in saved.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v
        demo.KEY = "s3cret"
        req = lambda headers, path="/ws": types.SimpleNamespace(headers=headers, path=path)
        self.assertTrue(demo.key_ok(req({"X-Bridge-Key": "s3cret"})))
        self.assertFalse(demo.key_ok(req({}, "/ws?key=s3cret")))
        self.assertFalse(demo.key_ok(req({"X-Bridge-Key": "wrong"})))
        demo.KEY = ""
        self.assertFalse(demo.key_ok(req({"X-Bridge-Key": ""})))
        self.assertIn("compare_digest", (ROOT / "templates" / "demo_origin.py").read_text())

    def test_l6_websockets_floor_matches_the_demo_api(self):
        self.assertEqual(cfbridge.WEBSOCKETS_REQ, "websockets>=14,<16")

    def test_l8_home_check_is_a_path_check(self):
        self.assertTrue(cfbridge.under_home("/root/p", "/root"))
        self.assertTrue(cfbridge.under_home("/root", "/root"))
        self.assertFalse(cfbridge.under_home("/root2/p", "/root"))
        self.assertFalse(cfbridge.under_home("/home/hatchery", "/home/hatch"))

    def test_l8_purge_refuses_a_lookalike_of_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = os.path.join(tmp, "home")
            proj = home + "2"
            os.makedirs(home)
            os.makedirs(proj)
            cfbridge.save_config(proj, {"zone": "example.com", "tunnel_name": "t", "services": []})
            old_home = os.environ.get("HOME")
            os.environ["HOME"] = home
            self.addCleanup(lambda: os.environ.__setitem__("HOME", old_home)
                            if old_home is not None else os.environ.pop("HOME", None))
            with captured(), self.assertRaises(SystemExit):
                cfbridge.cmd_teardown(types.SimpleNamespace(project=proj, purge_project=True))
            self.assertTrue(os.path.isdir(proj))


if __name__ == "__main__":
    unittest.main()
