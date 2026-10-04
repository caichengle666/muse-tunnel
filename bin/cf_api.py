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


def api(method: str, path: str, body: dict | None = None) -> dict:
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
            if e.code not in RETRY_STATUS or attempt == MAX_ATTEMPTS - 1:
                raise last_error from e
            time.sleep(_retry_delay(e, attempt))
            continue
        except (urllib.error.URLError, TimeoutError, socket.timeout) as e:
            # Same transient class: shared egress drops requests.
            last_error = CfError(f"{method} {path} -> transport error: {e}")
            if attempt == MAX_ATTEMPTS - 1:
                raise last_error from e
            time.sleep(min(2 ** attempt, 8))
            continue
        if not payload.get("success", False):
            raise CfError(f"{method} {path} -> {payload.get('errors')}")
        return payload
    raise last_error or CfError(f"{method} {path} -> failed")


def list_accounts() -> list[dict]:
    return api("GET", "/accounts?per_page=50").get("result", [])


def find_zone(account_id: str, zone_name: str) -> dict:
    zones = api("GET", f"/zones?account.id={account_id}&name={zone_name}").get("result", [])
    if not zones:
        raise CfError(f"zone {zone_name} not found under account {account_id}")
    return zones[0]


def list_tunnels(account_id: str) -> list[dict]:
    return api("GET", f"/accounts/{account_id}/cfd_tunnel?per_page=50").get("result", [])


def ensure_tunnel(account_id: str, name: str) -> dict:
    """Create (remote-managed) or reuse a tunnel by name.

    Returns {'id': ..., 'token': ...} — token is fetched fresh from the
    API; the caller is responsible for storing it 600 and never logging it.
    """
    for t in list_tunnels(account_id):
        if t.get("name") == name and not t.get("deleted_at"):
            tok = api("GET", f"/accounts/{account_id}/cfd_tunnel/{t['id']}/token").get("result")
            return {"id": t["id"], "token": tok}
    created = api("POST", f"/accounts/{account_id}/cfd_tunnel", {"name": name, "config_src": "cloudflare"})
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
    existing = api("GET", f"/zones/{zone_id}/dns_records?name={hostname}&per_page=50").get("result", [])
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
    api("POST", f"/zones/{zone_id}/dns_records",
        {"type": "CNAME", "name": hostname, "content": target, "proxied": True, "ttl": 1,
         "comment": MANAGED_COMMENT})
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
        for rec in api("GET", f"/zones/{zone_id}/dns_records?name={h}&per_page=50").get("result", []):
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
