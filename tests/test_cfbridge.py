"""Tests for cfbridge: input validation, unit rendering, secrets hygiene.

Run with:  python3 -m unittest discover -s tests -v
Standard library only; nothing here touches systemd or the network.
"""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bin"))

import cfbridge  # noqa: E402


def svc(**over):
    base = {"name": "files", "hostname": "files.example.com", "port": 8080,
            "health": "/health", "auth": "key", "public_confirmed": False,
            "origin": "", "start_cmd": "", "workdir": "", "env_proxy": False}
    base.update(over)
    return base


class HelperTests(unittest.TestCase):
    def test_fake_ip_range(self):
        for ip in ("198.18.0.1", "198.19.255.255"):
            self.assertTrue(cfbridge.is_fake_ip(ip), ip)
        for ip in ("198.20.0.1", "198.41.192.7", "1.1.1.1"):
            self.assertFalse(cfbridge.is_fake_ip(ip), ip)

    def test_fake_ip_garbage_is_false(self):
        self.assertFalse(cfbridge.is_fake_ip("not-an-ip"))
        self.assertFalse(cfbridge.is_fake_ip(""))

    def test_slugify(self):
        self.assertEqual(cfbridge.slugify("My Bridge!"), "my-bridge")
        self.assertEqual(cfbridge.slugify("---"), "project")
        self.assertEqual(cfbridge.slugify("Ünïcode Name"), "n-code-name")

    def test_project_slug_is_stable_and_path_specific(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = os.path.join(tmp, "a", "bridge")
            b = os.path.join(tmp, "b", "bridge")
            self.assertEqual(cfbridge.project_slug(a), cfbridge.project_slug(a))
            # Same basename, different path: units must not collide.
            self.assertNotEqual(cfbridge.project_slug(a), cfbridge.project_slug(b))
            self.assertTrue(cfbridge.project_slug(a).startswith("bridge-"))

    def test_unit_names_are_unique_per_project(self):
        cfg = {"services": [svc(start_cmd="run-it")]}
        with tempfile.TemporaryDirectory() as tmp:
            a = cfbridge.unit_names(os.path.join(tmp, "a", "proj"), cfg, "bridge")
            b = cfbridge.unit_names(os.path.join(tmp, "b", "proj"), cfg, "bridge")
            self.assertNotEqual(a["cloudflared"], b["cloudflared"])
            self.assertIn("svc:files", a)

    def test_services_without_start_cmd_get_no_unit(self):
        cfg = {"services": [svc(start_cmd="")]}
        names = cfbridge.unit_names("/home/x/proj", cfg, "bridge")
        self.assertNotIn("svc:files", names)


class ValidateServiceTests(unittest.TestCase):
    cfg = {"zone": "example.com", "services": []}

    def test_accepts_a_normal_service(self):
        cfbridge.validate_service(self.cfg, svc(), allow_public=False)

    def test_zone_apex_is_allowed(self):
        cfbridge.validate_service(self.cfg, svc(hostname="example.com"), allow_public=False)

    def test_rejects_substring_zone_match(self):
        # "evilexample.com".endswith("example.com") is True — that must not pass.
        with self.assertRaises(SystemExit):
            cfbridge.validate_service(self.cfg, svc(hostname="evilexample.com"), allow_public=False)

    def test_rejects_hostname_outside_zone(self):
        with self.assertRaises(SystemExit):
            cfbridge.validate_service(self.cfg, svc(hostname="files.other.net"), allow_public=False)

    def test_rejects_invalid_hostname_syntax(self):
        for bad in ("UPPER.example.com", "-bad.example.com", "a..example.com", "files.example.com."):
            with self.assertRaises(SystemExit):
                cfbridge.validate_service(self.cfg, svc(hostname=bad), allow_public=False)

    def test_rejects_bad_name_and_port(self):
        with self.assertRaises(SystemExit):
            cfbridge.validate_service(self.cfg, svc(name="Bad Name"), allow_public=False)
        with self.assertRaises(SystemExit):
            cfbridge.validate_service(self.cfg, svc(port=0), allow_public=False)
        with self.assertRaises(SystemExit):
            cfbridge.validate_service(self.cfg, svc(port=70000), allow_public=False)

    def test_rejects_unknown_auth(self):
        with self.assertRaises(SystemExit):
            cfbridge.validate_service(self.cfg, svc(auth="none"), allow_public=False)

    def test_public_requires_recorded_consent(self):
        s = svc(auth="public")
        with self.assertRaises(SystemExit):
            cfbridge.validate_service(self.cfg, s, allow_public=False)
        with self.assertRaises(SystemExit):
            cfbridge.validate_service(self.cfg, s, allow_public=True)  # consent not recorded
        cfbridge.validate_service(self.cfg, svc(auth="public", public_confirmed=True), allow_public=True)

    def test_rejects_bad_health_path_and_origin(self):
        with self.assertRaises(SystemExit):
            cfbridge.validate_service(self.cfg, svc(health="health"), allow_public=False)
        with self.assertRaises(SystemExit):
            cfbridge.validate_service(self.cfg, svc(origin="ftp://127.0.0.1:21"), allow_public=False)

    def test_https_origin_must_carry_a_tls_decision(self):
        # Bare https://127.0.0.1:8443 is the spelling the docs used to
        # suggest: cloudflared then expects a certificate literally named
        # "127.0.0.1", fails the handshake and answers 502 while the
        # tunnel itself looks perfectly healthy. It must not pass.
        with self.assertRaises(SystemExit):
            cfbridge.validate_service(self.cfg, svc(origin="https://127.0.0.1:8443"), allow_public=False)
        cfbridge.validate_service(
            self.cfg,
            svc(origin="https://127.0.0.1:8443", origin_request={"noTLSVerify": True}),
            allow_public=False)
        cfbridge.validate_service(
            self.cfg,
            svc(origin="https://origin.internal:8443",
                origin_request={"originServerName": "origin.internal"}),
            allow_public=False)

    def test_non_loopback_https_origin_needs_a_certificate_name(self):
        # normalize_origin() only defaults loopback; anywhere else the
        # answer depends on a certificate we cannot inspect.
        with self.assertRaises(SystemExit):
            cfbridge.validate_service(self.cfg, svc(origin="https://10.0.0.5:8443"), allow_public=False)

    def test_http_and_unix_origins_need_no_tls_decision(self):
        cfbridge.validate_service(self.cfg, svc(origin="http://127.0.0.1:9001"), allow_public=False)
        cfbridge.validate_service(self.cfg, svc(origin="unix:/run/app.sock"), allow_public=False)

    def test_raw_tcp_origin_needs_explicit_confirmation(self):
        with self.assertRaises(SystemExit):
            cfbridge.validate_service(self.cfg, svc(origin="tcp://127.0.0.1:5432"), allow_public=False)
        cfbridge.validate_service(
            self.cfg,
            svc(origin="tcp://127.0.0.1:5432", tcp_origin_confirmed=True),
            allow_public=False)

    def test_rejects_unknown_origin_request_keys(self):
        # A typo would otherwise become a rule cloudflared silently ignores.
        with self.assertRaises(SystemExit):
            cfbridge.validate_service(
                self.cfg, svc(origin_request={"originServername": "typo"}), allow_public=False)

    def test_rejects_newline_in_origin_request_value(self):
        with self.assertRaises(SystemExit):
            cfbridge.validate_service(
                self.cfg, svc(origin_request={"originServerName": "a\nb"}), allow_public=False)

    def test_rejects_newlines_that_would_inject_unit_directives(self):
        with self.assertRaises(SystemExit):
            cfbridge.validate_service(self.cfg, svc(start_cmd="/bin/true\nUser=nobody"), allow_public=False)


class OriginTests(unittest.TestCase):
    def test_origin_host(self):
        self.assertEqual(cfbridge.origin_host("https://127.0.0.1:8443"), "127.0.0.1")
        self.assertEqual(cfbridge.origin_host("unix:/run/app.sock"), "")
        self.assertEqual(cfbridge.origin_host(""), "")

    def test_normalize_defaults_loopback_https_to_no_verify(self):
        s = svc(origin="https://127.0.0.1:8443")
        self.assertTrue(cfbridge.normalize_origin(s))
        self.assertEqual(s["origin_request"], {"noTLSVerify": True})

    def test_normalize_is_idempotent(self):
        s = svc(origin="https://127.0.0.1:8443")
        cfbridge.normalize_origin(s)
        self.assertFalse(cfbridge.normalize_origin(s))

    def test_normalize_leaves_an_explicit_decision_alone(self):
        s = svc(origin="https://127.0.0.1:8443", origin_request={"originServerName": "app.local"})
        self.assertFalse(cfbridge.normalize_origin(s))
        self.assertNotIn("noTLSVerify", s["origin_request"])

    def test_normalize_leaves_non_loopback_and_plain_http_alone(self):
        remote = svc(origin="https://10.0.0.5:8443")
        self.assertFalse(cfbridge.normalize_origin(remote))
        self.assertNotIn("origin_request", remote)
        self.assertFalse(cfbridge.normalize_origin(svc(origin="")))

    def test_parse_origin_request(self):
        self.assertEqual(cfbridge.parse_origin_request(""), {})
        self.assertEqual(cfbridge.parse_origin_request('{"noTLSVerify": true}'),
                         {"noTLSVerify": True})
        for bad in ("not json", "[1,2]", '{"bogusKey": 1}'):
            with self.assertRaises(SystemExit):
                cfbridge.parse_origin_request(bad)


class AddServiceCliTests(unittest.TestCase):
    """What the CLI records for an origin, incl. the TLS decision."""

    def _project(self) -> str:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        cfbridge.ensure_project_layout(tmp.name)
        cfbridge.save_config(tmp.name, {"zone": "example.com", "tunnel_name": "t",
                                        "account_id": "", "bridge_port": 17844,
                                        "services": []})
        return tmp.name

    def _add(self, proj: str, *argv: str) -> dict:
        args = cfbridge.build_parser().parse_args(["--project", proj, "add-service", *argv])
        args.fn(args)
        return cfbridge.load_config(proj)["services"][-1]

    def test_loopback_https_origin_defaults_to_skipping_verification(self):
        svc = self._add(self._project(),
                        "--name", "app", "--hostname", "app.example.com", "--port", "8080",
                        "--origin-url", "https://127.0.0.1:8443")
        self.assertEqual(svc["origin_request"], {"noTLSVerify": True})

    def test_non_loopback_https_origin_requires_a_decision(self):
        with self.assertRaises(SystemExit):
            self._add(self._project(),
                      "--name", "app", "--hostname", "app.example.com", "--port", "8080",
                      "--origin-url", "https://10.0.0.5:8443")

    def test_origin_tls_name_is_recorded_for_non_loopback(self):
        svc = self._add(self._project(),
                        "--name", "app", "--hostname", "app.example.com", "--port", "8080",
                        "--origin-url", "https://10.0.0.5:8443",
                        "--origin-tls-name", "app.internal")
        self.assertEqual(svc["origin_request"], {"originServerName": "app.internal"})

    def test_origin_tls_name_needs_an_https_origin(self):
        with self.assertRaises(SystemExit):
            self._add(self._project(),
                      "--name", "app", "--hostname", "app.example.com", "--port", "8080",
                      "--origin-tls-name", "app.internal")

    def test_origin_request_json_is_merged(self):
        svc = self._add(self._project(),
                        "--name", "app", "--hostname", "app.example.com", "--port", "8080",
                        "--origin-url", "https://10.0.0.5:8443",
                        "--origin-tls-name", "app.internal",
                        "--origin-request", '{"caPool": "/etc/ssl/private-ca.pem"}')
        self.assertEqual(svc["origin_request"],
                         {"originServerName": "app.internal", "caPool": "/etc/ssl/private-ca.pem"})

    def test_plain_http_origin_records_no_origin_request(self):
        svc = self._add(self._project(),
                        "--name", "app", "--hostname", "app.example.com", "--port", "8080")
        self.assertEqual(svc["origin_request"], {})
        self.assertEqual(svc["origin"], "")

    def test_raw_tcp_origin_needs_confirmation(self):
        with self.assertRaises(SystemExit):
            self._add(self._project(),
                      "--name", "db", "--hostname", "db.example.com", "--port", "5432",
                      "--origin-url", "tcp://127.0.0.1:5432")
        svc = self._add(self._project(),
                        "--name", "db", "--hostname", "db.example.com", "--port", "5432",
                        "--origin-url", "tcp://127.0.0.1:5432", "--allow-tcp-origin")
        self.assertTrue(svc["tcp_origin_confirmed"])


class PruneLogsCliTests(unittest.TestCase):
    def test_cli_prunes_and_reports_json(self):
        import contextlib
        import io
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        proj = tmp.name
        os.makedirs(os.path.join(proj, "logs"))
        os.makedirs(os.path.join(proj, "run"))
        with open(os.path.join(proj, "logs", "cloudflared.log"), "wb") as f:
            f.write(b"x" * (2 * 1024 * 1024))   # over the default tail, so it rotates
        args = cfbridge.build_parser().parse_args(
            ["--project", proj, "prune-logs", "--retention-hours", "24", "--json"])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            args.fn(args)
        report = json.loads(buf.getvalue())
        self.assertEqual(report["retention_hours"], 24)
        self.assertTrue(any("rotated cloudflared.log" in a for a in report["actions"]),
                        report)
        self.assertEqual(os.path.getsize(os.path.join(proj, "logs", "cloudflared.log")),
                         cfbridge.LOG_TAIL_BYTES_DEFAULT)
        self.assertTrue(os.path.exists(cfbridge.log_retention_state_path(proj)))


class RenderTests(unittest.TestCase):
    def test_render_substitutes(self):
        self.assertEqual(cfbridge.render("a={{X}} b={{Y}}", {"X": "1", "Y": "2"}), "a=1 b=2")

    def test_render_rejects_leftover_placeholder(self):
        with self.assertRaises(SystemExit):
            cfbridge.render("a={{X}} b={{TYPO}}", {"X": "1"})

    def test_render_rejects_newline_values(self):
        with self.assertRaises(SystemExit):
            cfbridge.render("a={{X}}", {"X": "1\n[Service]\nUser=nobody"})

    def test_render_units_has_no_unresolved_placeholders(self):
        with tempfile.TemporaryDirectory() as proj:
            cfg = {"zone": "example.com", "tunnel_name": "t", "bridge_port": 17844,
                   "services": [svc(start_cmd="/bin/true", env_proxy=True),
                                svc(name="plain", hostname="plain.example.com", port=8081)]}
            units = cfbridge.render_units(proj, cfg, "bridge")
            self.assertIn("bridge", units[0] + units[1])  # bridge unit rendered first
            for u in units:
                path = os.path.join(proj, "systemd", u + ".service")
                with open(path, encoding="utf-8") as f:
                    text = f.read()
                self.assertNotIn("{{", text)
            cloudflared = open(os.path.join(proj, "systemd",
                                            cfbridge.unit_names(proj, cfg, "bridge")["cloudflared"] + ".service"),
                               encoding="utf-8").read()
            self.assertIn("TUNNEL_EDGE=127.0.0.1:17844", cloudflared)
            self.assertIn("--token-file", cloudflared)
            self.assertIn("--protocol http2", cloudflared)

    def test_direct_mode_omits_the_bridge_unit_and_env(self):
        with tempfile.TemporaryDirectory() as proj:
            cfg = {"zone": "example.com", "tunnel_name": "t", "bridge_port": 17844,
                   "services": [svc()]}
            units = cfbridge.render_units(proj, cfg, "direct")
            self.assertTrue(all("bridge" not in u for u in units))
            cloudflared = open(os.path.join(proj, "systemd", units[0] + ".service"), encoding="utf-8").read()
            self.assertNotIn("Environment=TUNNEL_EDGE", cloudflared)

    def test_service_envfile_only_when_env_proxy(self):
        with tempfile.TemporaryDirectory() as proj:
            cfg = {"zone": "example.com", "tunnel_name": "t", "bridge_port": 17844,
                   "services": [svc(start_cmd="/bin/true", env_proxy=True)]}
            units = cfbridge.render_units(proj, cfg, "bridge")
            names = cfbridge.unit_names(proj, cfg, "bridge")
            text = open(os.path.join(proj, "systemd", names["svc:files"] + ".service"), encoding="utf-8").read()
            self.assertIn("EnvironmentFile=", text)
            self.assertIn("proxy.env", text)


class SecretTests(unittest.TestCase):
    def test_write_private_sets_mode_at_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "secrets", "bridge-key.txt")
            cfbridge.write_private(path, "s3cret\n", 0o600)
            self.assertEqual(open(path, encoding="utf-8").read(), "s3cret\n")
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode), 0o700)

    def test_write_private_leaves_no_temp_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "k")
            cfbridge.write_private(path, "v")
            self.assertFalse(os.path.exists(path + ".tmp"))

    @unittest.skipIf(os.name == "nt", "POSIX directory modes only")
    def test_write_private_does_not_rechmod_an_existing_directory(self):
        """Only a directory this call creates is locked down.

        Silently re-perming a pre-existing directory would be a nasty
        side effect: write_private is also used for paths whose parent
        belongs to someone else.
        """
        with tempfile.TemporaryDirectory() as tmp:
            shared = os.path.join(tmp, "shared")
            os.makedirs(shared, 0o755)
            os.chmod(shared, 0o755)
            cfbridge.write_private(os.path.join(shared, "k"), "v")
            self.assertEqual(stat.S_IMODE(os.stat(shared).st_mode), 0o755)

    @unittest.skipIf(os.name == "nt", "POSIX directory modes only")
    def test_write_private_dir_mode_none_opts_out(self):
        with tempfile.TemporaryDirectory() as tmp:
            rel = os.path.join(tmp, "loose")
            cfbridge.write_private(os.path.join(rel, "k"), "v", 0o600, dir_mode=None)
            self.assertNotEqual(stat.S_IMODE(os.stat(rel).st_mode) & 0o077, 0)

    @unittest.skipIf(os.name == "nt", "POSIX directory modes only")
    def test_write_secret_locks_the_secrets_directory(self):
        with tempfile.TemporaryDirectory() as proj:
            cfbridge.write_secret(proj, "bridge-key.txt", "k")
            secrets = os.path.join(proj, "secrets")
            self.assertEqual(stat.S_IMODE(os.stat(secrets).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(secrets, "bridge-key.txt")).st_mode), 0o600)

    def test_write_secret_strips_and_newlines(self):
        with tempfile.TemporaryDirectory() as proj:
            cfbridge.write_secret(proj, "tunnel-id.txt", "  abc123  ")
            self.assertEqual(open(os.path.join(proj, "secrets", "tunnel-id.txt"), encoding="utf-8").read(),
                             "abc123\n")

    def test_refresh_proxy_env_records_only_present_vars(self):
        with tempfile.TemporaryDirectory() as proj:
            saved = dict(os.environ)
            self.addCleanup(lambda: (os.environ.clear(), os.environ.update(saved)))
            for k in ("HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"):
                os.environ.pop(k, None)
            os.environ["HTTPS_PROXY"] = "http://user:pw@127.0.0.1:3128"
            self.assertTrue(cfbridge.refresh_proxy_env(proj))
            text = open(os.path.join(proj, "secrets", "proxy.env"), encoding="utf-8").read()
            self.assertIn("HTTPS_PROXY=http://user:pw@127.0.0.1:3128", text)
            self.assertNotIn("NO_PROXY", text)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(os.stat(os.path.join(proj, "secrets", "proxy.env")).st_mode), 0o600)

    def test_refresh_proxy_env_without_proxy_returns_false(self):
        with tempfile.TemporaryDirectory() as proj:
            saved = dict(os.environ)
            self.addCleanup(lambda: (os.environ.clear(), os.environ.update(saved)))
            for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
                os.environ.pop(k, None)
            self.assertFalse(cfbridge.refresh_proxy_env(proj))


class ConfigTests(unittest.TestCase):
    def test_roundtrip_preserves_unicode_and_types(self):
        with tempfile.TemporaryDirectory() as proj:
            cfg = {"zone": "例子.com", "tunnel_name": "t", "services": [svc(port=8080)],
                   "force_dns": True}
            cfbridge.save_config(proj, cfg)
            self.assertEqual(cfbridge.load_config(proj), cfg)
            self.assertFalse(os.path.exists(os.path.join(proj, "config.json.tmp")))

    def test_load_config_dies_without_file(self):
        with tempfile.TemporaryDirectory() as proj:
            with self.assertRaises(SystemExit):
                cfbridge.load_config(proj)

    def test_find_service(self):
        cfg = {"services": [svc()]}
        self.assertIsNotNone(cfbridge.find_service(cfg, "files"))
        self.assertIsNone(cfbridge.find_service(cfg, "nope"))


class CloudflaredTests(unittest.TestCase):
    def test_asset_mapping_covers_the_release_names(self):
        assets = set(cfbridge.ARCH_ASSETS.values())
        self.assertIn("cloudflared-linux-amd64", assets)
        self.assertIn("cloudflared-linux-arm64", assets)
        for a in assets:
            self.assertTrue(a.startswith("cloudflared-linux-"))

    def test_release_url_is_version_pinned(self):
        url = cfbridge.RELEASE_URL.format(version=cfbridge.CLOUDFLARED_VERSION,
                                          asset="cloudflared-linux-amd64")
        self.assertIn(cfbridge.CLOUDFLARED_VERSION, url)
        self.assertNotIn("/latest/", url)

    def test_python_bin_is_absolute(self):
        self.assertTrue(os.path.isabs(cfbridge.python_bin()))
        self.assertTrue(os.path.exists(cfbridge.python_bin()))


if __name__ == "__main__":
    unittest.main()
