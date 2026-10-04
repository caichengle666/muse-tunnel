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
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

API_BASE = "https://api.cloudflare.com/client/v4"


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


def api(method: str, path: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
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
        raise CfError(f"{method} {path} -> HTTP {e.code}: {detail}") from e
    if not payload.get("success", False):
        raise CfError(f"{method} {path} -> {payload.get('errors')}")
    return payload


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


def set_ingress(account_id: str, tunnel_id: str, services: list[dict]) -> None:
    ingress = [
        {"hostname": s["hostname"], "service": f"http://127.0.0.1:{s['port']}", "originRequest": {}}
        for s in services
    ]
    ingress.append({"service": "http_status:404"})
    api("PUT", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations", {"config": {"ingress": ingress}})


def ensure_dns(zone_id: str, hostname: str, tunnel_id: str) -> str:
    target = f"{tunnel_id}.cfargotunnel.com"
    existing = api("GET", f"/zones/{zone_id}/dns_records?name={hostname}&per_page=5").get("result", [])
    for rec in existing:
        if rec.get("type") == "CNAME" and rec.get("content") == target:
            return "unchanged"
        if rec.get("type") == "CNAME":
            api("PUT", f"/zones/{zone_id}/dns_records/{rec['id']}",
                {"type": "CNAME", "name": hostname, "content": target, "proxied": True, "ttl": 1})
            return "updated"
    api("POST", f"/zones/{zone_id}/dns_records",
        {"type": "CNAME", "name": hostname, "content": target, "proxied": True, "ttl": 1,
         "comment": "cf-tunnel-bridge managed"})
    return "created"


def delete_tunnel_and_dns(account_id: str, zone_id: str, tunnel_id: str, hostnames: list[str]) -> None:
    for h in hostnames:
        for rec in api("GET", f"/zones/{zone_id}/dns_records?name={h}&per_page=5").get("result", []):
            if rec.get("type") == "CNAME" and str(rec.get("content", "")).endswith("cfargotunnel.com"):
                api("DELETE", f"/zones/{zone_id}/dns_records/{rec['id']}")
    api("DELETE", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/connections").get("result")
    api("DELETE", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}")


if __name__ == "__main__":
    # Smoke check: list accounts without printing any credential.
    for a in list_accounts():
        print("account:", a["id"], a["name"])
