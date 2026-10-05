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
        self.flags: list[dict] = []
        self.script = script or {}

    def __call__(self, method, path, body=None, **kwargs):
        self.calls.append((method, path, body))
        self.flags.append(kwargs)
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
        # Creating a record is not repeatable: a retried POST after a lost
        # response would add a second record for the same name.
        self.assertIs(self.api.flags[-1].get("idempotent"), False)

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
        cf_api.api = lambda m, p, b=None, **kw: (calls.append((m, p, b)), {"success": True})[1]
        self.addCleanup(lambda: setattr(cf_api, "api", original))
        cf_api.set_ingress("acct", TUNNEL, [
            {"hostname": "a.example.com", "port": 80},
            {"hostname": "b.example.com", "port": 81, "origin": "tcp://127.0.0.1:82"},
        ])
        ingress = calls[-1][2]["config"]["ingress"]
        self.assertEqual(ingress[0]["service"], "http://127.0.0.1:80")
        self.assertEqual(ingress[1]["service"], "tcp://127.0.0.1:82")
        self.assertEqual(ingress[-1], {"service": "http_status:404"})

    def test_origin_request_reaches_the_ingress_rule(self):
        original = cf_api.api
        calls = []
        cf_api.api = lambda m, p, b=None, **kw: (calls.append((m, p, b)), {"success": True})[1]
        self.addCleanup(lambda: setattr(cf_api, "api", original))
        cf_api.set_ingress("acct", TUNNEL, [
            {"hostname": "a.example.com", "port": 8443, "origin": "https://127.0.0.1:8443",
             "origin_request": {"noTLSVerify": True}},
            {"hostname": "b.example.com", "port": 80},
        ])
        ingress = calls[-1][2]["config"]["ingress"]
        self.assertEqual(ingress[0]["originRequest"], {"noTLSVerify": True})
        self.assertEqual(ingress[1]["originRequest"], {})


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

    def _count_attempts(self, behaviour):
        attempts = []

        def stub(req, timeout=None):
            attempts.append(req.method)
            return behaviour(len(attempts), req)

        cf_api.urllib.request.urlopen = stub
        return attempts

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

    # --- non-idempotent calls (POST) must not be repeated blindly -----

    def test_post_5xx_is_not_retried(self):
        attempts = self._count_attempts(lambda n, req: (_ for _ in ()).throw(self._http_error(502)))
        with self.assertRaises(cf_api.CfError):
            cf_api.api("POST", "/accounts/x/cfd_tunnel", {"name": "t"})
        self.assertEqual(len(attempts), 1, "a 5xx POST may already have been applied")

    def test_post_transport_error_is_not_retried(self):
        def boom(n, req):
            raise urllib.error.URLError("timed out")

        attempts = self._count_attempts(boom)
        with self.assertRaises(cf_api.CfError):
            cf_api.api("POST", "/accounts/x/cfd_tunnel", {"name": "t"})
        self.assertEqual(len(attempts), 1)

    def test_post_429_is_retried_because_it_never_ran(self):
        def flaky(n, req):
            if n < 2:
                raise self._http_error(429, {"Retry-After": "0"})
            return io.BytesIO(b'{"success": true, "result": {"id": "tun-1"}}')

        attempts = self._count_attempts(flaky)
        out = cf_api.api("POST", "/accounts/x/cfd_tunnel", {"name": "t"})
        self.assertEqual(out["result"]["id"], "tun-1")
        self.assertEqual(len(attempts), 2)

    def test_idempotent_override_forces_retries(self):
        attempts = self._count_attempts(lambda n, req: (_ for _ in ()).throw(self._http_error(502)))
        with self.assertRaises(cf_api.CfError):
            cf_api.api("POST", "/x", {"a": 1}, idempotent=True)
        self.assertEqual(len(attempts), cf_api.MAX_ATTEMPTS)


class PaginationTests(unittest.TestCase):
    """A truncated list is a correctness bug, not just missing data."""

    def setUp(self):
        self.original = cf_api.api
        self.addCleanup(lambda: setattr(cf_api, "api", self.original))

    def test_walks_every_page_reported_by_result_info(self):
        pages = {
            1: {"success": True, "result": [{"id": "a"}, {"id": "b"}],
                "result_info": {"page": 1, "total_pages": 3}},
            2: {"success": True, "result": [{"id": "c"}],
                "result_info": {"page": 2, "total_pages": 3}},
            3: {"success": True, "result": [{"id": "d"}],
                "result_info": {"page": 3, "total_pages": 3}},
        }
        seen = []

        def stub(method, path, body=None, **kwargs):
            page = int(path.rsplit("page=", 1)[1])
            seen.append(page)
            return pages[page]

        cf_api.api = stub
        items = cf_api._get_paged("/accounts", per_page=2)
        self.assertEqual([i["id"] for i in items], ["a", "b", "c", "d"])
        self.assertEqual(seen, [1, 2, 3])

    def test_stops_on_a_short_page_when_result_info_is_absent(self):
        def stub(method, path, body=None, **kwargs):
            page = int(path.rsplit("page=", 1)[1])
            return {"success": True, "result": [{"id": f"p{page}"}] if page == 1 else []}

        cf_api.api = stub
        self.assertEqual(len(cf_api._get_paged("/accounts", per_page=50)), 1)

    def test_existing_query_string_is_extended_not_replaced(self):
        seen = []

        def stub(method, path, body=None, **kwargs):
            seen.append(path)
            return {"success": True, "result": []}

        cf_api.api = stub
        cf_api._get_paged("/zones?account.id=acct&name=example.com")
        self.assertIn("account.id=acct", seen[0])
        self.assertIn("per_page=50", seen[0])
        self.assertIn("page=1", seen[0])

    def test_list_tunnels_sees_tunnels_beyond_the_first_page(self):
        def stub(method, path, body=None, **kwargs):
            page = int(path.rsplit("page=", 1)[1])
            if page == 1:
                return {"success": True, "result": [{"id": "t1", "name": "other"}],
                        "result_info": {"page": 1, "total_pages": 2}}
            return {"success": True, "result": [{"id": "t2", "name": "wanted"}],
                    "result_info": {"page": 2, "total_pages": 2}}

        cf_api.api = stub
        names = [t["name"] for t in cf_api.list_tunnels("acct")]
        self.assertIn("wanted", names)


class EnsureTunnelTests(unittest.TestCase):
    """A failed create POST is ambiguous — never blindly create again."""

    def setUp(self):
        self.original = cf_api.api
        self.addCleanup(lambda: setattr(cf_api, "api", self.original))

    def test_reuses_an_existing_tunnel_without_creating(self):
        calls = []

        def stub(method, path, body=None, **kwargs):
            calls.append((method, path))
            if method == "GET" and path.startswith("/accounts/acct/cfd_tunnel?"):
                return {"success": True, "result": [{"id": "t1", "name": "prod"}]}
            if method == "GET" and path.endswith("/token"):
                return {"success": True, "result": "the-token"}
            raise AssertionError(f"unexpected call {method} {path}")

        cf_api.api = stub
        self.assertEqual(cf_api.ensure_tunnel("acct", "prod"), {"id": "t1", "token": "the-token"})
        self.assertFalse([c for c in calls if c[0] == "POST"])

    def test_re_reads_the_list_when_create_fails(self):
        """The POST blew up, but it may have landed: adopt it, don't re-create."""
        state = {"lists": 0, "posts": 0}

        def stub(method, path, body=None, **kwargs):
            if method == "POST":
                state["posts"] += 1
                raise cf_api.CfError("POST -> transport error: timed out")
            if path.startswith("/accounts/acct/cfd_tunnel?") or path.startswith("/accounts/acct/cfd_tunnel/"):
                if path.endswith("/token"):
                    return {"success": True, "result": "the-token"}
                state["lists"] += 1
                if state["lists"] == 1:
                    return {"success": True, "result": []}
                return {"success": True, "result": [{"id": "t9", "name": "prod"}]}
            raise AssertionError(f"unexpected call {method} {path}")

        cf_api.api = stub
        self.assertEqual(cf_api.ensure_tunnel("acct", "prod"), {"id": "t9", "token": "the-token"})
        self.assertEqual(state["posts"], 1)

    def test_create_failure_with_no_tunnel_still_raises(self):
        def stub(method, path, body=None, **kwargs):
            if method == "POST":
                raise cf_api.CfError("POST -> HTTP 502")
            return {"success": True, "result": []}

        cf_api.api = stub
        with self.assertRaises(cf_api.CfError):
            cf_api.ensure_tunnel("acct", "prod")

    def test_ignores_deleted_tunnels_with_the_same_name(self):
        def stub(method, path, body=None, **kwargs):
            if method == "GET" and path.startswith("/accounts/acct/cfd_tunnel?"):
                return {"success": True, "result": [
                    {"id": "gone", "name": "prod", "deleted_at": "2026-01-01T00:00:00Z"}]}
            if method == "POST":
                return {"success": True, "result": {"id": "fresh", "token": "tok"}}
            raise AssertionError(f"unexpected call {method} {path}")

        cf_api.api = stub
        self.assertEqual(cf_api.ensure_tunnel("acct", "prod"), {"id": "fresh", "token": "tok"})


if __name__ == "__main__":
    unittest.main()
