#!/usr/bin/env python3
"""cfbridge — Cloudflare Named Tunnel stacks for Muse-style sandboxes.

One project directory (must live under $HOME, the only persistent
volume) holds everything:

    config.json            zone, tunnel name, service registry
    secrets/               tunnel token, bridge key, proxy.env (600/700)
    systemd/               rendered canonical units (reinstalled after
                           container rebuilds wipe /etc)
    bin/cloudflared        project-local copy of the official binary
    logs/, run/            logs and managed-units.txt
    venv/                  python deps for demo/user services

Subcommands:
    doctor            diagnose this sandbox (DNS, proxy, direct 7844)
    init              scaffold a project
    add-service       register a service (hostname -> 127.0.0.1:port)
    demo              register the bundled key-authed WS demo origin
    up                ensure tunnel+DNS, render+install units, start all
    status            units + local/public health
    verify            public end-to-end checks (HTTPS health, WS auth)
    down              stop managed units (tunnel/DNS stay)
    install-autostart render the keepalive hook script + next steps
    teardown          stop units, delete DNS + tunnel (--purge-project)

Credentials come from the custom.cloudflare connector or
CF_API_TOKEN (see cf_api.py). Secret values are never printed.
"""
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import secrets as pysecrets
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import cf_api  # noqa: E402
import edge_bridge  # noqa: E402

DEFAULT_BRIDGE_PORT = 17844


# ---------------------------------------------------------------- utils

def die(msg: str) -> "SystemExit":
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(1)


def project_dir(args) -> str:
    p = getattr(args, "project", None) or os.environ.get("CFBRIDGE_PROJECT") or os.getcwd()
    return os.path.abspath(os.path.expanduser(p))


def slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-")
    return s or "project"


def load_config(proj: str) -> dict:
    path = os.path.join(proj, "config.json")
    if not os.path.exists(path):
        die(f"no config.json in {proj} (run cfbridge init first)")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_config(proj: str, cfg: dict) -> None:
    tmp = os.path.join(proj, "config.json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    os.replace(tmp, os.path.join(proj, "config.json"))


def write_secret(proj: str, name: str, value: str) -> None:
    d = os.path.join(proj, "secrets")
    os.makedirs(d, exist_ok=True)
    os.chmod(d, 0o700)
    path = os.path.join(d, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(value.strip() + "\n")
    os.chmod(path, 0o600)


def refresh_proxy_env(proj: str) -> bool:
    lines = []
    for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"):
        v = os.environ.get(k)
        if v:
            lines.append(f"{k}={v}")
    if not lines:
        return False
    d = os.path.join(proj, "secrets")
    os.makedirs(d, exist_ok=True)
    os.chmod(d, 0o700)
    path = os.path.join(d, "proxy.env")
    content = "\n".join(lines) + "\n"
    old = ""
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            old = f.read()
    if old != content:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(path, 0o600)
    return True


UA = {"User-Agent": "cfbridge/1.0 (health-check)"}


def http_get(url: str, timeout: float = 10) -> tuple[int, str]:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read().decode("utf-8", "replace")


def bridge_port_free(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def ensure_bridge_port(proj: str, cfg: dict) -> None:
    """Two projects on one sandbox cannot share the default bridge
    port. If ours is taken and our own bridge unit is not the listener,
    move to the next free port and persist it (units render from it)."""
    port = int(cfg.get("bridge_port", DEFAULT_BRIDGE_PORT))
    names = unit_names(proj, cfg, "bridge")
    own_active = systemctl("is-active", names["bridge"]).stdout.strip() == "active"
    if bridge_port_free(port):
        # free, or our own bridge already owns it
        return
    if own_active:
        return
    for cand in range(port + 1, port + 30):
        if bridge_port_free(cand):
            print(f"bridge port {port} busy (another project's bridge?); switching to {cand}")
            cfg["bridge_port"] = cand
            save_config(proj, cfg)
            return
    die(f"no free bridge port near {port}; stop the other project's bridge or set bridge_port in config.json")


def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        die(f"command failed: {' '.join(cmd)}\n{r.stdout}{r.stderr}")
    return r


def systemctl(*args: str, check: bool = False) -> subprocess.CompletedProcess:
    return run(["systemctl", *args], check=check)


def render(template: str, mapping: dict[str, str]) -> str:
    out = template
    for k, v in mapping.items():
        out = out.replace("{{" + k + "}}", v)
    return out


def read_template(rel: str) -> str:
    with open(os.path.join(SKILL_DIR, "templates", rel), encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------- doctor

def is_fake_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network("198.18.0.0/15")
    except ValueError:
        return False


def direct_edge_ok(ips: list[str], timeout: float = 5) -> bool:
    """True only if a *verified* TLS handshake with the edge completes.

    Weaker tests lie in these sandboxes: a bare TCP connect may be
    accepted by a transparent proxy and then blackholed, and an
    unverified handshake may complete against an interceptor. Verify
    the certificate for the argotunnel hostname and require ALPN —
    anything less is not the real edge path cloudflared needs.
    """
    import ssl as _ssl

    for ip in ips[:3]:
        try:
            raw = socket.create_connection((ip, edge_bridge.EDGE_PORT), timeout=timeout)
            ctx = _ssl.create_default_context()
            try:
                ctx.set_alpn_protocols(["h2"])
            except NotImplementedError:
                pass
            s = ctx.wrap_socket(raw, server_hostname="region1.v2.argotunnel.com")
            s.close()
            return True
        except Exception:  # noqa: BLE001 - OSError and ssl errors both mean no
            continue
    return False


def cmd_doctor(args) -> None:
    proj = project_dir(args)
    report: dict = {"project": proj, "checks": {}}
    home = os.path.expanduser("~")
    report["checks"]["persistent_location"] = proj.startswith(home)
    report["checks"]["systemd"] = bool(shutil.which("systemctl"))
    cfd = shutil.which("cloudflared") or os.path.join(proj, "bin", "cloudflared")
    report["checks"]["cloudflared"] = cfd if os.path.exists(cfd) else None
    report["checks"]["proxy_env"] = bool(os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy"))

    sys_ips: list[str] = []
    try:
        for info in socket.getaddrinfo("region1.v2.argotunnel.com", 7844, proto=socket.IPPROTO_TCP):
            ip = info[4][0]
            if ip not in sys_ips:
                sys_ips.append(ip)
    except OSError as e:
        report["checks"]["system_dns_error"] = str(e)
    report["checks"]["system_dns_ips"] = sys_ips
    report["checks"]["dns_fake_ip"] = bool(sys_ips) and all(is_fake_ip(ip) for ip in sys_ips)

    real_ips = edge_bridge.fetch_edge_ips()
    report["checks"]["real_edge_candidates"] = len(real_ips)

    direct_ok = direct_edge_ok(real_ips)
    report["checks"]["direct_7844_tls_verified"] = direct_ok
    # Environment signature rule for Muse sandboxes: if system DNS
    # hands out fake IPs for the edge, cloudflared can never dial the
    # edge itself (it resolves through the system resolver), so the
    # bridge is required even if a one-off direct attempt flukes.
    if report["checks"]["dns_fake_ip"]:
        report["mode"] = "bridge"
    else:
        report["mode"] = "direct" if direct_ok else "bridge"

    try:
        accts = cf_api.list_accounts()
        report["checks"]["cf_accounts"] = [a["name"] for a in accts]
    except Exception as e:  # noqa: BLE001
        report["checks"]["cf_error"] = str(e)[:200]

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return
    c = report["checks"]
    print(f"project:            {proj}  (persistent: {c['persistent_location']})")
    print(f"systemd:            {c['systemd']}")
    print(f"cloudflared:        {c['cloudflared']}")
    print(f"proxy env:          {c['proxy_env']}")
    print(f"system DNS edge:    {', '.join(sys_ips) or 'unresolvable'} (fake-IP: {c['dns_fake_ip']})")
    print(f"real edge candidates via DoH: {c['real_edge_candidates']}")
    print(f"direct TLS 7844 (verified):    {direct_ok}")
    if "cf_accounts" in c:
        print(f"cloudflare accounts: {', '.join(c['cf_accounts'])}")
    else:
        print(f"cloudflare:         NOT READY ({c.get('cf_error')})")
    print(f"verdict:            mode = {report['mode']}"
          + (" (edge bridge required)" if report["mode"] == "bridge" else " (cloudflared can dial directly)"))


# ---------------------------------------------------------------- init

def ensure_cloudflared(proj: str) -> str:
    dst = os.path.join(proj, "bin", "cloudflared")
    if os.path.exists(dst):
        return dst
    os.makedirs(os.path.join(proj, "bin"), exist_ok=True)
    src = shutil.which("cloudflared")
    if src:
        shutil.copy2(src, dst)
        os.chmod(dst, 0o755)
        return dst
    url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
    print(f"cloudflared not found locally; downloading official binary from {url}")
    with urllib.request.urlopen(url, timeout=120) as resp, open(dst, "wb") as f:
        shutil.copyfileobj(resp, f)
    os.chmod(dst, 0o755)
    return dst


def cmd_init(args) -> None:
    proj = project_dir(args)
    if not proj.startswith(os.path.expanduser("~")):
        print(f"warning: {proj} is outside $HOME; container rebuilds may wipe it", file=sys.stderr)
    for d in ("secrets", "logs", "run", "systemd", "bin", "services"):
        os.makedirs(os.path.join(proj, d), exist_ok=True)
    os.chmod(os.path.join(proj, "secrets"), 0o700)
    binary = ensure_cloudflared(proj)
    key_path = os.path.join(proj, "secrets", "bridge-key.txt")
    if not os.path.exists(key_path):
        write_secret(proj, "bridge-key.txt", pysecrets.token_urlsafe(32))
    cfg_path = os.path.join(proj, "config.json")
    if os.path.exists(cfg_path):
        print("config.json already exists; leaving it untouched")
    else:
        cfg = {
            "zone": args.zone,
            "tunnel_name": args.tunnel_name or f"{slugify(os.path.basename(proj))}-bridge",
            "account_id": "",
            "bridge_port": args.bridge_port,
            "services": [],
        }
        save_config(proj, cfg)
        print(f"wrote {cfg_path}")
    if not args.no_venv:
        venv = os.path.join(proj, "venv")
        if not os.path.exists(os.path.join(venv, "bin", "python")):
            run([sys.executable, "-m", "venv", venv])
            run([os.path.join(venv, "bin", "pip"), "install", "-q", "websockets", "websocket-client"])
            print("venv ready (websockets, websocket-client)")
    print(f"cloudflared: {binary}")
    print("next: cfbridge add-service ... / cfbridge demo --hostname ... ; then cfbridge up")


# ---------------------------------------------------------------- services

def validate_service(cfg: dict, svc: dict, allow_public: bool) -> None:
    host = svc.get("hostname", "")
    zone = cfg.get("zone", "")
    if not host.endswith(zone):
        die(f"hostname {host} is outside zone {zone}")
    if not re.fullmatch(r"[a-z0-9-]+", svc.get("name", "")):
        die("service name must be [a-z0-9-]+")
    if not (1 <= int(svc.get("port", 0)) <= 65535):
        die("service port out of range")
    auth = svc.get("auth", "key")
    if auth not in ("key", "public"):
        die("auth must be 'key' or 'public'")
    if auth == "public" and not allow_public:
        die("auth=public exposes the service to anyone who knows the URL; "
            "pass --allow-public to confirm that is intended")


def find_service(cfg: dict, name: str) -> dict | None:
    for s in cfg["services"]:
        if s["name"] == name:
            return s
    return None


def cmd_add_service(args) -> None:
    proj = project_dir(args)
    cfg = load_config(proj)
    if find_service(cfg, args.name):
        die(f"service {args.name} already registered (edit config.json or remove it first)")
    svc = {
        "name": args.name,
        "hostname": args.hostname,
        "port": args.port,
        "health": args.health,
        "auth": args.auth,
        "start_cmd": args.start_cmd or "",
        "workdir": args.workdir or proj,
        "env_proxy": bool(args.env_proxy),
    }
    validate_service(cfg, svc, allow_public=args.allow_public)
    cfg["services"].append(svc)
    save_config(proj, cfg)
    print(f"registered {args.name}: {args.hostname} -> 127.0.0.1:{args.port} (auth={args.auth})")
    print("apply with: cfbridge up")


def cmd_demo(args) -> None:
    proj = project_dir(args)
    cfg = load_config(proj)
    if find_service(cfg, args.name):
        die(f"service {args.name} already registered")
    dst = os.path.join(proj, "services", "demo_origin.py")
    if not os.path.exists(dst):
        shutil.copy2(os.path.join(SKILL_DIR, "templates", "demo_origin.py"), dst)
    py = os.path.join(proj, "venv", "bin", "python")
    if not os.path.exists(py):
        die("project venv missing; run cfbridge init first (it installs websockets)")
    start_cmd = f"{py} {dst} --port {args.port} --key-file {proj}/secrets/bridge-key.txt"
    svc = {"name": args.name, "hostname": args.hostname, "port": args.port,
           "health": "/health", "auth": "key", "start_cmd": start_cmd,
           "workdir": proj, "env_proxy": False}
    validate_service(cfg, svc, allow_public=False)
    cfg["services"].append(svc)
    save_config(proj, cfg)
    print(f"demo service {args.name}: {args.hostname} -> 127.0.0.1:{args.port} (WS key auth)")
    print("apply with: cfbridge up ; test with: cfbridge verify")


# ---------------------------------------------------------------- tunnel

def resolve_account_zone(cfg: dict) -> tuple[str, dict]:
    accounts = cf_api.list_accounts()
    if not accounts:
        die("no Cloudflare accounts visible to this credential")
    wanted = cfg.get("account_id")
    candidates = [a for a in accounts if a["id"] == wanted] if wanted else accounts
    for a in candidates + [a for a in accounts if a not in candidates]:
        try:
            zone = cf_api.find_zone(a["id"], cfg["zone"])
            return a["id"], zone
        except cf_api.CfError:
            continue
    die(f"zone {cfg['zone']} not found in any visible account")


def ensure_tunnel_stack(proj: str, cfg: dict) -> tuple[str, str]:
    account_id, zone = resolve_account_zone(cfg)
    if cfg.get("account_id") != account_id:
        cfg["account_id"] = account_id
    tun = cf_api.ensure_tunnel(account_id, cfg["tunnel_name"])
    tunnel_id = tun["id"]
    if cfg.get("tunnel_id") != tunnel_id:
        cfg["tunnel_id"] = tunnel_id
    write_secret(proj, "tunnel-token.txt", tun["token"])
    with open(os.path.join(proj, "secrets", "tunnel-id.txt"), "w", encoding="utf-8") as f:
        f.write(tunnel_id + "\n")
    os.chmod(os.path.join(proj, "secrets", "tunnel-id.txt"), 0o600)
    cf_api.set_ingress(account_id, tunnel_id, cfg["services"])
    for s in cfg["services"]:
        res = cf_api.ensure_dns(zone["id"], s["hostname"], tunnel_id)
        print(f"dns {s['hostname']}: {res}")
    save_config(proj, cfg)
    print(f"tunnel {cfg['tunnel_name']} ({tunnel_id}) ingress for {len(cfg['services'])} service(s)")
    return account_id, zone["id"]


# ---------------------------------------------------------------- units

def project_slug(proj: str) -> str:
    return slugify(os.path.basename(proj.rstrip("/")))


def unit_names(proj: str, cfg: dict, mode: str) -> dict[str, str]:
    slug = project_slug(proj)
    names = {"cloudflared": f"cfb-{slug}-cloudflared"}
    if mode == "bridge":
        names["bridge"] = f"cfb-{slug}-bridge"
    for s in cfg["services"]:
        if s.get("start_cmd"):
            names[f"svc:{s['name']}"] = f"cfb-{slug}-svc-{s['name']}"
    return names


def render_units(proj: str, cfg: dict, mode: str) -> list[str]:
    names = unit_names(proj, cfg, mode)
    out_dir = os.path.join(proj, "systemd")
    os.makedirs(out_dir, exist_ok=True)
    written: list[str] = []

    if mode == "bridge":
        text = render(read_template("systemd/muse-edge-bridge.service.tmpl"), {
            "PROJECT_DIR": proj,
            "SKILL_BIN": HERE,
            "BRIDGE_PORT": str(cfg.get("bridge_port", DEFAULT_BRIDGE_PORT)),
        })
        p = os.path.join(out_dir, names["bridge"] + ".service")
        open(p, "w", encoding="utf-8").write(text)
        written.append(names["bridge"])

    text = render(read_template("systemd/muse-cloudflared.service.tmpl"), {
        "PROJECT_DIR": proj,
        "TUNNEL_NAME": cfg["tunnel_name"],
        "BRIDGE_UNIT_DEP": (names.get("bridge", "") + ".service") if mode == "bridge" else "",
        "TUNNEL_EDGE_ENV": (f"Environment=TUNNEL_EDGE=127.0.0.1:{cfg.get('bridge_port', DEFAULT_BRIDGE_PORT)}"
                            if mode == "bridge" else ""),
    })
    p = os.path.join(out_dir, names["cloudflared"] + ".service")
    open(p, "w", encoding="utf-8").write(text)
    written.append(names["cloudflared"])

    for s in cfg["services"]:
        if not s.get("start_cmd"):
            continue
        uname = names[f"svc:{s['name']}"]
        text = render(read_template("systemd/muse-service.service.tmpl"), {
            "PROJECT_DIR": proj,
            "SERVICE_NAME": s["name"],
            "SERVICE_HOSTNAME": s["hostname"],
            "SERVICE_PORT": str(s["port"]),
            "SERVICE_WORKDIR": s.get("workdir") or proj,
            "SERVICE_START_CMD": s["start_cmd"],
            "SERVICE_ENVFILE": (f"EnvironmentFile={proj}/secrets/proxy.env" if s.get("env_proxy") else ""),
        })
        p = os.path.join(out_dir, uname + ".service")
        open(p, "w", encoding="utf-8").write(text)
        written.append(uname)

    with open(os.path.join(proj, "run", "managed-units.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(written) + "\n")
    return written


def install_units(proj: str, units: list[str]) -> None:
    for u in units:
        shutil.copy2(os.path.join(proj, "systemd", u + ".service"), f"/etc/systemd/system/{u}.service")
    systemctl("daemon-reload", check=True)
    for u in units:
        systemctl("enable", "--quiet", u)


def detect_mode(proj: str, cfg: dict) -> str:
    forced = cfg.get("mode")
    if forced in ("bridge", "direct"):
        return forced
    # Fake-IP DNS signature => cloudflared's own resolver path is
    # poisoned; bridge required regardless of direct flukes.
    try:
        sys_ips = [info[4][0] for info in socket.getaddrinfo("region1.v2.argotunnel.com", 7844, proto=socket.IPPROTO_TCP)]
    except OSError:
        sys_ips = []
    if sys_ips and all(is_fake_ip(ip) for ip in sys_ips):
        return "bridge"
    real = edge_bridge.fetch_edge_ips()
    return "direct" if direct_edge_ok(real) else "bridge"


# ---------------------------------------------------------------- lifecycle

def cmd_up(args) -> None:
    proj = project_dir(args)
    cfg = load_config(proj)
    if not cfg["services"]:
        die("no services registered; use add-service or demo first")
    for s in cfg["services"]:
        validate_service(cfg, s, allow_public=True)
    ensure_cloudflared(proj)
    refresh_proxy_env(proj)
    mode = detect_mode(proj, cfg)
    if mode == "bridge":
        ensure_bridge_port(proj, cfg)
    print(f"mode: {mode}")
    ensure_tunnel_stack(proj, cfg)
    cfg = load_config(proj)
    units = render_units(proj, cfg, mode)
    install_units(proj, units)
    names = unit_names(proj, cfg, mode)
    ordered = ([names["bridge"]] if "bridge" in names else []) + \
              [names[k] for k in names if k.startswith("svc:")] + [names["cloudflared"]]
    systemctl("restart", *ordered, check=True)
    print(f"started: {', '.join(ordered)}")
    wait_local_health(cfg, timeout=45)
    cmd_status(args, quiet=False)


def wait_local_health(cfg: dict, timeout: int = 45) -> None:
    deadline = time.time() + timeout
    pending = {s["name"] for s in cfg["services"]}
    while pending and time.time() < deadline:
        for s in list(cfg["services"]):
            if s["name"] not in pending:
                continue
            try:
                status, _ = http_get(f"http://127.0.0.1:{s['port']}{s.get('health', '/health')}", timeout=3)
                if status == 200:
                    pending.discard(s["name"])
            except Exception:  # noqa: BLE001
                pass
        if pending:
            time.sleep(2)
    if pending:
        print(f"warning: local health not yet ok for: {', '.join(sorted(pending))}")


def cmd_down(args) -> None:
    proj = project_dir(args)
    units_file = os.path.join(proj, "run", "managed-units.txt")
    if not os.path.exists(units_file):
        die("no managed units recorded; nothing to stop")
    units = [l.strip() for l in open(units_file, encoding="utf-8") if l.strip()]
    systemctl("stop", *units)
    for u in units:
        systemctl("disable", "--quiet", u)
    print(f"stopped: {', '.join(units)} (tunnel + DNS kept; cfbridge teardown removes them)")


def cmd_status(args, quiet: bool = False) -> None:
    proj = project_dir(args)
    cfg = load_config(proj)
    units_file = os.path.join(proj, "run", "managed-units.txt")
    units = [l.strip() for l in open(units_file, encoding="utf-8") if l.strip()] if os.path.exists(units_file) else []
    for u in units:
        r = systemctl("is-active", u)
        print(f"unit {u}: {r.stdout.strip()}")
    for s in cfg["services"]:
        local = public = "?"
        try:
            status, _ = http_get(f"http://127.0.0.1:{s['port']}{s.get('health', '/health')}", timeout=4)
            local = str(status)
        except Exception as e:  # noqa: BLE001
            local = f"fail ({type(e).__name__})"
        try:
            status, _ = http_get(f"https://{s['hostname']}{s.get('health', '/health')}", timeout=10)
            public = str(status)
        except Exception as e:  # noqa: BLE001
            public = f"fail ({type(e).__name__})"
        print(f"service {s['name']} ({s['hostname']}): local={local} public={public}")


# ---------------------------------------------------------------- verify (stdlib WS client)

def ws_roundtrip(hostname: str, key: str, timeout: float = 15) -> list[str]:
    ctx = ssl.create_default_context()
    raw = socket.create_connection((hostname, 443), timeout=8)
    raw.settimeout(8)
    conn = ctx.wrap_socket(raw, server_hostname=hostname)
    wskey = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET /ws?key={key} HTTP/1.1\r\nHost: {hostname}\r\nUpgrade: websocket\r\n"
        f"Connection: Upgrade\r\nSec-WebSocket-Key: {wskey}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    conn.sendall(req.encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            raise RuntimeError("handshake closed early")
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    if b" 101 " not in head.split(b"\r\n", 1)[0]:
        raise RuntimeError(f"handshake failed: {head.splitlines()[0]!r}")

    def read_exact(n: int, stash: list[bytes]) -> bytes:
        while sum(len(x) for x in stash) < n:
            chunk = conn.recv(4096)
            if not chunk:
                raise RuntimeError("socket closed")
            stash.append(chunk)
        out = b"".join(stash)
        stash.clear()
        if len(out) > n:
            stash.append(out[n:])
        return out[:n]

    stash = [rest] if rest else []

    def read_frame() -> tuple[int, bytes]:
        h = read_exact(2, stash)
        opcode = h[0] & 0x0F
        ln = h[1] & 0x7F
        if ln == 126:
            ln = int.from_bytes(read_exact(2, stash), "big")
        elif ln == 127:
            ln = int.from_bytes(read_exact(8, stash), "big")
        return opcode, read_exact(ln, stash)

    def send_text(text: str) -> None:
        data = text.encode()
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        header = bytes([0x81, 0x80 | len(data)]) if len(data) < 126 else bytes([0x81, 0x80 | 126]) + len(data).to_bytes(2, "big")
        conn.sendall(header + mask + masked)

    got: list[str] = []
    deadline = time.time() + timeout
    conn.settimeout(5)
    try:
        op, payload = read_frame()
        got.append(payload.decode("utf-8", "replace"))
        send_text("hello-cfbridge")
        while time.time() < deadline:
            op, payload = read_frame()
            text = payload.decode("utf-8", "replace")
            got.append(text)
            if text == "echo:hello-cfbridge":
                break
    finally:
        try:
            conn.close()
        except OSError:
            pass
    return got


def cmd_verify(args) -> None:
    proj = project_dir(args)
    cfg = load_config(proj)
    key_path = os.path.join(proj, "secrets", "bridge-key.txt")
    key = open(key_path, encoding="utf-8").read().strip() if os.path.exists(key_path) else ""
    ok = True
    for s in cfg["services"]:
        host = s["hostname"]
        try:
            status, body = http_get(f"https://{host}{s.get('health', '/health')}", timeout=15)
            print(f"{s['name']}: public health {status} {body.strip()[:40]!r}")
        except Exception as e:  # noqa: BLE001
            ok = False
            print(f"{s['name']}: public health FAILED ({e})")
            continue
        if args.ws:
            if not key:
                print(f"{s['name']}: no bridge key file; skip WS check")
                continue
            try:
                frames = None
                last_err: Exception | None = None
                # VM-side public TLS occasionally stalls on first try
                # (shared egress); one retry is the documented norm.
                for _attempt in range(3):
                    try:
                        frames = ws_roundtrip(host, key)
                        break
                    except Exception as e:  # noqa: BLE001
                        last_err = e
                        time.sleep(2)
                if frames is None:
                    raise RuntimeError(str(last_err))
                joined = " | ".join(frames)
                good = any(f.startswith("server-greeting") for f in frames) and "echo:hello-cfbridge" in frames
                print(f"{s['name']}: WS {'ok' if good else 'UNEXPECTED'} [{joined[:120]}]")
                ok = ok and good
            except Exception as e:  # noqa: BLE001
                ok = False
                print(f"{s['name']}: WS FAILED ({e})")
    if not ok:
        raise SystemExit(1)
    print("verify: all checks passed")


# ---------------------------------------------------------------- autostart / teardown

def cmd_install_autostart(args) -> None:
    proj = project_dir(args)
    slug = project_slug(proj)
    hook_id = f"cfb-{slug}-keepalive"
    script_path = os.path.expanduser(f"~/hooks/scripts/{hook_id}.sh")
    os.makedirs(os.path.dirname(script_path), exist_ok=True)
    text = render(read_template("keepalive-hook.sh.tmpl"), {"PROJECT_DIR": proj})
    with open(script_path, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(script_path, 0o750)
    print(f"hook script written: {script_path}")
    print("agent next steps (Muse hooks tools):")
    print(f"  1) hooks.add id={hook_id} script={script_path} poll_interval_secs=60 timeout=180")
    print(f"  2) hooks.dry_run {hook_id}  (expect silent/healthy)")
    print(f"  3) hooks.enable {hook_id}")
    print("prompt for the hook worker: investigate this project's cf-tunnel-bridge stack "
          "(systemctl status of units in run/managed-units.txt, tails of logs/, public health), "
          "restore if possible, never print secrets/.")


def cmd_teardown(args) -> None:
    proj = project_dir(args)
    cfg = load_config(proj)
    units_file = os.path.join(proj, "run", "managed-units.txt")
    if os.path.exists(units_file):
        units = [l.strip() for l in open(units_file, encoding="utf-8") if l.strip()]
        systemctl("stop", *units)
        for u in units:
            systemctl("disable", "--quiet", u)
            dst = f"/etc/systemd/system/{u}.service"
            if os.path.exists(dst):
                os.remove(dst)
        systemctl("daemon-reload")
        print(f"units removed: {', '.join(units)}")
    account_id = cfg.get("account_id")
    tunnel_id = cfg.get("tunnel_id")
    if account_id and tunnel_id:
        _, zone = resolve_account_zone(cfg)
        cf_api.delete_tunnel_and_dns(account_id, zone["id"], tunnel_id, [s["hostname"] for s in cfg["services"]])
        print(f"tunnel {cfg['tunnel_name']} and its DNS records deleted")
    if args.purge_project:
        shutil.rmtree(proj)
        print(f"project dir purged: {proj}")


# ---------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="cfbridge", description=__doc__)
    ap.add_argument("--project", help="project dir (default: $CFBRIDGE_PROJECT or cwd)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("doctor"); p.add_argument("--json", action="store_true"); p.set_defaults(fn=cmd_doctor)

    p = sub.add_parser("init")
    p.add_argument("--zone", required=True)
    p.add_argument("--tunnel-name", default="")
    p.add_argument("--bridge-port", type=int, default=DEFAULT_BRIDGE_PORT)
    p.add_argument("--no-venv", action="store_true")
    p.set_defaults(fn=cmd_init)

    p = sub.add_parser("add-service")
    p.add_argument("--name", required=True); p.add_argument("--hostname", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--health", default="/health")
    p.add_argument("--auth", choices=["key", "public"], default="key")
    p.add_argument("--allow-public", action="store_true")
    p.add_argument("--start-cmd", default="")
    p.add_argument("--workdir", default="")
    p.add_argument("--env-proxy", action="store_true")
    p.set_defaults(fn=cmd_add_service)

    p = sub.add_parser("demo")
    p.add_argument("--name", default="demo"); p.add_argument("--hostname", required=True)
    p.add_argument("--port", type=int, default=18099)
    p.set_defaults(fn=cmd_demo)

    sub.add_parser("up").set_defaults(fn=cmd_up)
    sub.add_parser("down").set_defaults(fn=cmd_down)
    sub.add_parser("status").set_defaults(fn=lambda a: cmd_status(a))
    p = sub.add_parser("verify"); p.add_argument("--ws", action="store_true"); p.set_defaults(fn=cmd_verify)
    sub.add_parser("install-autostart").set_defaults(fn=cmd_install_autostart)
    p = sub.add_parser("teardown"); p.add_argument("--purge-project", action="store_true"); p.set_defaults(fn=cmd_teardown)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.fn(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
