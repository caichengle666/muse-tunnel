#!/usr/bin/env python3
"""Minimal Cloudflare API client for cf-tunnel-bridge.

Credential resolution, in order:
  1. The `custom.cloudflare` connector, when connected in this Muse
     sandbox (read through the skill-creator surrogate helper; the
     value never touches this process's logs or files).
  2. Environment variable CF_API_TOKEN (Bearer). Use only in shells
     the user controls; never write the token into project files.

Nothing in this module prints credential values. Errors surface the
HTTP status and Cloudflare's error message only.

List endpoints are walked page by page (see _get_paged): a truncated
list is not merely incomplete, it makes ensure_tunnel() create a
duplicate tunnel and makes the DNS ownership check miss records.

Retries follow the method (see api()): idempotent calls are retried on
429/5xx and transport errors; non-idempotent ones only on 429, because
a lost POST response may still have been applied.

DNS hygiene: records created here carry the comment
"cf-tunnel-bridge managed". ensure_dns() only rewrites records it
recognises as its own (by marker, or by already pointing at this
tunnel); anything else is a hard error unless the caller explicitly
opts into overwriting it. delete_tunnel_and_dns() applies the same
ownership test, so tearing one bridge down cannot take another
tunnel's DNS with it.
"""
from __future__ import annotations

import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request

API_BASE = "https://api.cloudflare.com/client/v4"
MANAGED_COMMENT = "cf-tunnel-bridge managed"

# 429/5xx are worth retrying: Cloudflare rate-limits per token and the
# sandbox egress is shared, so a transient 502 is normal rather than fatal.
RETRY_STATUS = {429, 500, 502, 503, 504}
MAX_ATTEMPTS = 4

# Methods that can be repeated without changing the outcome. Everything
# else (POST/PATCH) is treated as "at most once": see api().
IDEMPOTENT_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE"}

# Cloudflare list endpoints default to 20-50 items per page. Walking
# total_pages matters for correctness, not just completeness: a
# truncated tunnel list makes ensure_tunnel() believe the tunnel does
# not exist and create a duplicate.
PAGE_SIZE = 50
MAX_PAGES = 200


class CfError(RuntimeError):
    pass


def _surrogate_headers() -> dict[str, str] | None:
    """Headers for the custom.cloudflare connector, if available."""
    helper_dir = "/opt/hatch/skills/skill-creator/bin"
    if helper_dir not in sys.path:
        sys.path.insert(0, helper_dir)
    try:
        from dynamic_credentials import dynamic_credential_entry  # type: ignore

        entry = dynamic_credential_entry("custom.cloudflare")
        surrogate = entry.get("surrogate")
        if surrogate:
            return {"Authorization": f"Bearer {surrogate}"}
    except Exception:  # noqa: BLE001 - connector absent is a normal case
        return None
    return None


def _headers() -> dict[str, str]:
    h = _surrogate_headers()
    if h:
        return h
    token = os.environ.get("CF_API_TOKEN", "")
    if token:
        return {"Authorization": f"Bearer {token}"}
    raise CfError(
        "no Cloudflare credential: connect the custom.cloudflare connector "
        "or set CF_API_TOKEN in the environment"
    )


def _retry_delay(err: urllib.error.HTTPError, attempt: int) -> float:
    retry_after = err.headers.get("Retry-After") if err.headers else None
    if retry_after:
        try:
            return max(0.0, min(float(retry_after), 30.0))
        except ValueError:
            pass
    return min(2 ** attempt, 8)


def api(method: str, path: str, body: dict | None = None,
        idempotent: bool | None = None) -> dict:
    """One Cloudflare API call, with a retry policy that fits the method.

    Retrying POST is how you end up with two tunnels that share a name
    (Cloudflare does not enforce uniqueness) and with duplicate DNS
    records. So the two failure classes are treated differently for
    non-idempotent calls:

      * HTTP 429 — the request was rejected before it ran, so repeating
        it is safe and is done for every method.
      * HTTP 5xx / transport timeout — ambiguous: the call may well have
        been applied before the failure was reported. For an idempotent
        method that is harmless and we retry; for POST/PATCH we surface
        the error and let the caller decide (ensure_tunnel re-reads the
        tunnel list instead of blindly re-creating).

    Pass idempotent explicitly to override the method-based default.
    """
    if idempotent is None:
        idempotent = method.upper() in IDEMPOTENT_METHODS
    data = json.dumps(body).encode() if body is not None else None
    last_error: Exception | None = None
    for attempt in range(MAX_ATTEMPTS):
        req = urllib.request.Request(API_BASE + path, data=data, method=method)
        for k, v in _headers().items():
            req.add_header(k, v)
        if body is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = json.load(resp)
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:400]
            last_error = CfError(f"{method} {path} -> HTTP {e.code}: {detail}")
            # 429 is safe for any method; the rest only for idempotent ones.
            retryable = e.code == 429 or (idempotent and e.code in RETRY_STATUS)
            if not retryable or attempt == MAX_ATTEMPTS - 1:
                raise last_error from e
            time.sleep(_retry_delay(e, attempt))
            continue
        except (urllib.error.URLError, TimeoutError, socket.timeout) as e:
            # Same transient class: shared egress drops requests — but a
            # dropped POST may still have landed server-side.
            last_error = CfError(f"{method} {path} -> transport error: {e}")
            if not idempotent or attempt == MAX_ATTEMPTS - 1:
                raise last_error from e
            time.sleep(min(2 ** attempt, 8))
            continue
        if not payload.get("success", False):
            raise CfError(f"{method} {path} -> {payload.get('errors')}")
        return payload
    raise last_error or CfError(f"{method} {path} -> failed")


def _get_paged(path: str, per_page: int = PAGE_SIZE) -> list[dict]:
    """GET every page of a Cloudflare list endpoint.

    `result_info.total_pages` is authoritative; if the API omits it we
    fall back to "a short page means the last page". MAX_PAGES is a
    safety stop, not an expected limit.
    """
    out: list[dict] = []
    page = 1
    while page <= MAX_PAGES:
        sep = "&" if "?" in path else "?"
        payload = api("GET", f"{path}{sep}per_page={per_page}&page={page}")
        chunk = payload.get("result") or []
        out.extend(chunk)
        info = payload.get("result_info") or {}
        total_pages = info.get("total_pages")
        if isinstance(total_pages, int) and total_pages > 0:
            if page >= total_pages:
                break
        elif len(chunk) < per_page:
            break
        page += 1
    return out


def list_accounts() -> list[dict]:
    return _get_paged("/accounts")


def find_zone(account_id: str, zone_name: str) -> dict:
    zones = _get_paged(f"/zones?account.id={account_id}&name={zone_name}")
    if not zones:
        raise CfError(f"zone {zone_name} not found under account {account_id}")
    return zones[0]


def list_tunnels(account_id: str) -> list[dict]:
    return _get_paged(f"/accounts/{account_id}/cfd_tunnel")


def _reuse_tunnel(account_id: str, name: str) -> dict | None:
    for t in list_tunnels(account_id):
        if t.get("name") == name and not t.get("deleted_at"):
            tok = api("GET", f"/accounts/{account_id}/cfd_tunnel/{t['id']}/token").get("result")
            return {"id": t["id"], "token": tok}
    return None


def ensure_tunnel(account_id: str, name: str) -> dict:
    """Create (remote-managed) or reuse a tunnel by name.

    Returns {'id': ..., 'token': ...} — token is fetched fresh from the
    API; the caller is responsible for storing it 600 and never logging it.

    The create POST is not retried, so a failed attempt is ambiguous:
    it may have been applied before the error surfaced. Re-reading the
    list before giving up keeps the next `up` from adding a second
    tunnel with the same name.
    """
    existing = _reuse_tunnel(account_id, name)
    if existing:
        return existing
    try:
        created = api("POST", f"/accounts/{account_id}/cfd_tunnel",
                      {"name": name, "config_src": "cloudflare"}, idempotent=False)
    except CfError:
        recovered = _reuse_tunnel(account_id, name)
        if recovered:
            return recovered
        raise
    tun = created.get("result", {})
    token = tun.get("token")
    if not token:
        token = api("GET", f"/accounts/{account_id}/cfd_tunnel/{tun['id']}/token").get("result")
    if not token:
        raise CfError("tunnel created but no token returned")
    return {"id": tun["id"], "token": token}


def service_origin(svc: dict) -> str:
    """Origin URL for one registry entry.

    Defaults to the loopback HTTP port; `origin` in the registry
    overrides it for HTTPS origins, unix sockets, or a non-loopback
    bind the user knowingly chose.
    """
    origin = (svc.get("origin") or "").strip()
    return origin or f"http://127.0.0.1:{svc['port']}"


def set_ingress(account_id: str, tunnel_id: str, services: list[dict]) -> None:
    ingress = [
        {
            "hostname": s["hostname"],
            "service": service_origin(s),
            "originRequest": dict(s.get("origin_request") or {}),
        }
        for s in services
    ]
    ingress.append({"service": "http_status:404"})
    api("PUT", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations", {"config": {"ingress": ingress}})


def dns_target(tunnel_id: str) -> str:
    return f"{tunnel_id}.cfargotunnel.com"


def _is_managed(record: dict, target: str) -> bool:
    """True when this DNS record is ours to rewrite.

    Either we stamped it, or it already points at this very tunnel —
    anything else belongs to something else and must not be silently
    repointed.
    """
    if record.get("comment") == MANAGED_COMMENT:
        return True
    return str(record.get("content", "")) == target


def ensure_dns(zone_id: str, hostname: str, tunnel_id: str, allow_overwrite: bool = False) -> str:
    """Point `hostname` at this tunnel, refusing to clobber foreign records."""
    target = dns_target(tunnel_id)
    existing = _get_paged(f"/zones/{zone_id}/dns_records?name={hostname}")
    for rec in existing:
        if rec.get("type") == "CNAME" and rec.get("content") == target:
            return "unchanged"
    foreign = [r for r in existing if not _is_managed(r, target)]
    if foreign and not allow_overwrite:
        summary = ", ".join(f"{r.get('type')} {r.get('name')} -> {r.get('content')}" for r in foreign[:3])
        raise CfError(
            f"{hostname} already has non-managed DNS record(s): {summary}. "
            "Refusing to overwrite. Pass --force-dns (or set \"force_dns\": true "
            "in config.json) if that record is expendable."
        )
    for rec in existing:
        if rec.get("type") != "CNAME":
            continue
        if not _is_managed(rec, target) and not allow_overwrite:
            continue
        api("PUT", f"/zones/{zone_id}/dns_records/{rec['id']}",
            {"type": "CNAME", "name": hostname, "content": target, "proxied": True, "ttl": 1,
             "comment": MANAGED_COMMENT})
        return "updated"
    # A create is not idempotent: a retried POST after a lost response
    # would add a second record for the same name. Let it fail loudly —
    # the next `up` re-reads the zone and converges.
    api("POST", f"/zones/{zone_id}/dns_records",
        {"type": "CNAME", "name": hostname, "content": target, "proxied": True, "ttl": 1,
         "comment": MANAGED_COMMENT}, idempotent=False)
    return "created"


def delete_tunnel_and_dns(account_id: str, zone_id: str, tunnel_id: str, hostnames: list[str]) -> list[str]:
    """Delete DNS records owned by this tunnel, then the tunnel itself.

    Returns summaries of the records deleted. Records that merely share
    a hostname (someone else's CNAME, an unrelated A record) are left
    alone.
    """
    target = dns_target(tunnel_id)
    if isinstance(hostnames, str):  # tolerate a single hostname by mistake
        hostnames = [hostnames]
    deleted: list[str] = []
    for h in hostnames:
        for rec in _get_paged(f"/zones/{zone_id}/dns_records?name={h}"):
            if str(rec.get("content", "")) != target and rec.get("comment") != MANAGED_COMMENT:
                continue
            api("DELETE", f"/zones/{zone_id}/dns_records/{rec['id']}")
            deleted.append(f"{rec.get('type')} {rec.get('name')} -> {rec.get('content')}")
    api("DELETE", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/connections")
    api("DELETE", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}")
    return deleted


if __name__ == "__main__":
    # Smoke check: list accounts without printing any credential.
    for a in list_accounts():
        print("account:", a["id"], a["name"])
