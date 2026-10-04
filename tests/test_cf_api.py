"""Tests for cf_api: DNS ownership rules, retries, ingress origins.

Run with:  python3 -m unittest discover -s tests -v
Standard library only; every Cloudflare call is stubbed.
"""
from __future__ import annotations

import io
import os
import sys
import unittest
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bin"))

import cf_api  # noqa: E402

ZONE = "zone-id-1"
TUNNEL = "tun-abc"


class FakeApi:
    """Records calls and replays scripted responses."""

    def __init__(self, script=None):
        self.calls: list[tuple[str, str, dict | None]] = []
        self.script = script or {}

    def __call__(self, method, path, body=None):
        self.calls.append((method, path, body))
        for (m, prefix), resp in self.script.items():
            if m == method and path.startswith(prefix):
                return resp if not callable(resp) else resp(path, body)
        if method == "GET" and "/dns_records" in path:
            return {"success": True, "result": []}
        return {"success": True, "result": {}}

    def paths(self):
        return [(m, p) for m, p, _ in self.calls]


class DnsGuardTests(unittest.TestCase):
    def setUp(self):
        self.original = cf_api.api
        self.api = FakeApi()
        cf_api.api = self.api
        self.addCleanup(lambda: setattr(cf_api, "api", self.original))

    def test_creates_cname_when_hostname_is_free(self):
        self.assertEqual(cf_api.ensure_dns(ZONE, "files.example.com", TUNNEL), "created")
        body = self.api.calls[-1][2]
        self.assertEqual(body["content"], f"{TUNNEL}.cfargotunnel.com")
        self.assertEqual(body["comment"], cf_api.MANAGED_COMMENT)
        self.assertTrue(body["proxied"])

    def test_unchanged_when_already_pointing_at_this_tunnel(self):
        self.api.script[("GET", "/zones/" + ZONE + "/dns_records")] = {
            "success": True,
            "result": [{"id": "r1", "type": "CNAME", "name": "files.example.com",
                        "content": f"{TUNNEL}.cfargotunnel.com"}],
        }
        self.assertEqual(cf_api.ensure_dns(ZONE, "files.example.com", TUNNEL), "unchanged")
        self.assertEqual(len(self.api.calls), 1)  # read only, no write

    def test_refuses_to_clobber_a_foreign_record(self):
        self.api.script[("GET", "/zones/" + ZONE + "/dns_records")] = {
            "success": True,
            "result": [{"id": "r9", "type": "A", "name": "files.example.com", "content": "203.0.113.9"}],
        }
        with self.assertRaises(cf_api.CfError) as ctx:
            cf_api.ensure_dns(ZONE, "files.example.com", TUNNEL)
        self.assertIn("non-managed DNS record", str(ctx.exception))
        self.assertEqual([m for m, _ in self.api.paths()], ["GET"])  # nothing written

    def test_refuses_to_steal_another_tunnels_cname(self):
        self.api.script[("GET", "/zones/" + ZONE + "/dns_records")] = {
            "success": True,
            "result": [{"id": "r2", "type": "CNAME", "name": "files.example.com",
                        "content": "other-tunnel.cfargotunnel.com"}],
        }
        with self.assertRaises(cf_api.CfError):
            cf_api.ensure_dns(ZONE, "files.example.com", TUNNEL)

    def test_force_overwrites_when_explicitly_allowed(self):
        self.api.script[("GET", "/zones/" + ZONE + "/dns_records")] = {
            "success": True,
            "result": [{"id": "r9", "type": "CNAME", "name": "files.example.com",
                        "content": "legacy.example.net"}],
        }
        self.assertEqual(cf_api.ensure_dns(ZONE, "files.example.com", TUNNEL, allow_overwrite=True), "updated")
        self.assertEqual(self.api.calls[-1][0], "PUT")
        self.assertEqual(self.api.calls[-1][2]["content"], f"{TUNNEL}.cfargotunnel.com")

    def test_updates_our_own_record_in_place(self):
        self.api.script[("GET", "/zones/" + ZONE + "/dns_records")] = {
            "success": True,
            "result": [{"id": "r3", "type": "CNAME", "name": "files.example.com",
                        "content": "old-tunnel.cfargotunnel.com",
                        "comment": cf_api.MANAGED_COMMENT}],
        }
        self.assertEqual(cf_api.ensure_dns(ZONE, "files.example.com", TUNNEL), "updated")
        self.assertIn(("PUT", f"/zones/{ZONE}/dns_records/r3"), self.api.paths())


class DeleteTests(unittest.TestCase):
    def setUp(self):
        self.original = cf_api.api
        self.api = FakeApi()
        cf_api.api = self.api
        self.addCleanup(lambda: setattr(cf_api, "api", self.original))

    def test_deletes_only_records_owned_by_this_tunnel(self):
        self.api.script[("GET", "/zones/" + ZONE + "/dns_records")] = {
            "success": True,
            "result": [
                {"id": "mine", "type": "CNAME", "name": "files.example.com",
                 "content": f"{TUNNEL}.cfargotunnel.com"},
                {"id": "theirs", "type": "CNAME", "name": "files.example.com",
                 "content": "someone-elses.cfargotunnel.com"},
                {"id": "a-record", "type": "A", "name": "files.example.com", "content": "203.0.113.5"},
            ],
        }
        deleted = cf_api.delete_tunnel_and_dns("acct", ZONE, TUNNEL, ["files.example.com"])
        self.assertEqual(len(deleted), 1)
        self.assertIn(("DELETE", f"/zones/{ZONE}/dns_records/mine"), self.api.paths())
        self.assertNotIn(("DELETE", f"/zones/{ZONE}/dns_records/theirs"), self.api.paths())
        self.assertNotIn(("DELETE", f"/zones/{ZONE}/dns_records/a-record"), self.api.paths())
        self.assertIn(("DELETE", f"/accounts/acct/cfd_tunnel/{TUNNEL}"), self.api.paths())

    def test_accepts_a_bare_hostname_string(self):
        deleted = cf_api.delete_tunnel_and_dns("acct", ZONE, TUNNEL, "files.example.com")
        self.assertEqual(deleted, [])


class IngressTests(unittest.TestCase):
    def test_default_origin_is_loopback_http(self):
        self.assertEqual(cf_api.service_origin({"port": 8080}), "http://127.0.0.1:8080")

    def test_origin_override_wins(self):
        self.assertEqual(cf_api.service_origin({"port": 8080, "origin": "https://127.0.0.1:8443"}),
                         "https://127.0.0.1:8443")

    def test_blank_origin_falls_back_to_port(self):
        self.assertEqual(cf_api.service_origin({"port": 9000, "origin": "  "}), "http://127.0.0.1:9000")

    def test_set_ingress_emits_catch_all_last(self):
        original = cf_api.api
        calls = []
        cf_api.api = lambda m, p, b=None: (calls.append((m, p, b)), {"success": True})[1]
        self.addCleanup(lambda: setattr(cf_api, "api", original))
        cf_api.set_ingress("acct", TUNNEL, [
            {"hostname": "a.example.com", "port": 80},
            {"hostname": "b.example.com", "port": 81, "origin": "tcp://127.0.0.1:82"},
        ])
        ingress = calls[-1][2]["config"]["ingress"]
        self.assertEqual(ingress[0]["service"], "http://127.0.0.1:80")
        self.assertEqual(ingress[1]["service"], "tcp://127.0.0.1:82")
        self.assertEqual(ingress[-1], {"service": "http_status:404"})


class RetryTests(unittest.TestCase):
    def setUp(self):
        self.original_urlopen = cf_api.urllib.request.urlopen
        self.original_sleep = cf_api.time.sleep
        cf_api.time.sleep = lambda s: None
        os.environ["CF_API_TOKEN"] = "test-token"
        self.addCleanup(lambda: (setattr(cf_api.urllib.request, "urlopen", self.original_urlopen),
                                 setattr(cf_api.time, "sleep", self.original_sleep),
                                 os.environ.pop("CF_API_TOKEN", None)))

    def _http_error(self, code, headers=None):
        return urllib.error.HTTPError("https://api.cloudflare.com/x", code, "err",
                                      headers or {}, io.BytesIO(b'{"errors":[{"message":"busy"}]}'))

    def test_retries_429_then_succeeds(self):
        attempts = []

        def flaky(req, timeout=None):
            attempts.append(req.full_url)
            if len(attempts) < 3:
                raise self._http_error(429, {"Retry-After": "0"})
            return io.BytesIO(b'{"success": true, "result": []}')

        cf_api.urllib.request.urlopen = flaky
        self.assertEqual(cf_api.list_accounts(), [])
        self.assertEqual(len(attempts), 3)

    def test_gives_up_after_max_attempts(self):
        attempts = []

        def always_502(req, timeout=None):
            attempts.append(1)
            raise self._http_error(502)

        cf_api.urllib.request.urlopen = always_502
        with self.assertRaises(cf_api.CfError):
            cf_api.list_accounts()
        self.assertEqual(len(attempts), cf_api.MAX_ATTEMPTS)

    def test_client_error_is_not_retried(self):
        attempts = []

        def forbidden(req, timeout=None):
            attempts.append(1)
            raise self._http_error(403)

        cf_api.urllib.request.urlopen = forbidden
        with self.assertRaises(cf_api.CfError):
            cf_api.list_accounts()
        self.assertEqual(len(attempts), 1)

    def test_missing_credential_raises_cf_error(self):
        os.environ.pop("CF_API_TOKEN", None)
        with self.assertRaises(cf_api.CfError):
            cf_api.list_accounts()


if __name__ == "__main__":
    unittest.main()
