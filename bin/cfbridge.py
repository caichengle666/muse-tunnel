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
    doctor            self-check every dependency for real, and with
                      --fix repair the ones cfbridge owns
    init              scaffold a project
    add-service       register a service (hostname -> origin)
    demo              register the bundled key-authed WS demo origin
    up                self-heal deps, prune logs, ensure tunnel+DNS,
                      render+install units, start bridge -> services ->
                      cloudflared
    status            units + local/public health
    verify            public end-to-end checks (HTTPS health, WS auth)
    prune-logs        enforce the log retention window
    down              stop managed units (tunnel/DNS stay)
    install-autostart render the keepalive hook script + next steps
    teardown          stop units, delete DNS + tunnel (--purge-project)

Credentials come from the custom.cloudflare connector or
CF_API_TOKEN (see cf_api.py). Secret values are never printed.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import platform
import re
import secrets as pysecrets
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import cf_api  # noqa: E402
import edge_bridge  # noqa: E402

DEFAULT_BRIDGE_PORT = 17844

# cloudflared is pinned rather than tracking "latest": the binary is
# copied into the project and reused forever, so an unreviewed upgrade
# would land silently on the next rebuild. Override with
# CFBRIDGE_CLOUDFLARED_VERSION=latest (or the release URL directly via
# CFBRIDGE_CLOUDFLARED_URL) when a bump is wanted, and pass
# CFBRIDGE_CLOUDFLARED_SHA256 to enforce a checksum — Cloudflare does
# not publish per-asset checksum files, so verification is available
# but not automatic.
CLOUDFLARED_VERSION = "2026.9.3"
RELEASE_URL = "https://github.com/cloudflare/cloudflared/releases/download/{version}/{asset}"
ARCH_ASSETS = {
    "x86_64": "cloudflared-linux-amd64",
    "amd64": "cloudflared-linux-amd64",
    "aarch64": "cloudflared-linux-arm64",
    "arm64": "cloudflared-linux-arm64",
    "armv7l": "cloudflared-linux-arm",
    "armv6l": "cloudflared-linux-armhf",
    "i386": "cloudflared-linux-386",
    "i686": "cloudflared-linux-386",
}
MIN_CLOUDFLARED_BYTES = 5 * 1024 * 1024

# Ingress `service:` begins with one of these. The split matters: an
# http-ish origin is what a browser can open through the tunnel, while
# tcp/ssh/rdp are raw streams that only speak to clients running
# `cloudflared access`. `unix:` is HTTP over a unix socket, so it stays
# on the http side.
HTTP_ORIGIN_SCHEMES = ("http://", "https://", "unix:")
RAW_TCP_ORIGIN_SCHEMES = ("tcp://", "ssh://", "rdp://")
ORIGIN_SCHEMES = HTTP_ORIGIN_SCHEMES + RAW_TCP_ORIGIN_SCHEMES
LOOPBACK_ORIGIN_HOSTS = {"127.0.0.1", "::1", "0.0.0.0", "localhost"}
# Keys we are willing to forward to cloudflared's originRequest. An
# allow-list, because a typo silently becomes a rule that is ignored.
ORIGIN_REQUEST_KEYS = {
    "originServerName", "noTLSVerify", "caPool", "httpHostHeader",
    "http2Origin", "connectTimeout", "tlsTimeout", "keepAliveTimeout",
    "keepAliveConnections", "disableChunkedEncoding", "matchSNItoHost",
}


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


def load_config_or_empty(proj: str) -> dict:
    """config.json if it parses, otherwise an empty skeleton.

    doctor has to run *before* init — that is its whole job — so it
    cannot demand a config the way every other subcommand does.
    """
    if not os.path.exists(os.path.join(proj, "config.json")):
        return {"zone": "", "tunnel_name": "", "services": []}
    cfg = load_config(proj)
    cfg.setdefault("services", [])
    return cfg


def save_config(proj: str, cfg: dict) -> None:
    tmp = os.path.join(proj, "config.json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    os.replace(tmp, os.path.join(proj, "config.json"))


def write_private(path: str, content: str, mode: int = 0o600,
                  dir_mode: int | None = 0o700) -> None:
    """Create/overwrite a file that must never be world-readable.

    os.open() applies the mode at creation time, so there is no window
    during which the file exists with looser permissions (a plain
    open()+chmod() leaves exactly that gap). Writes go through a temp
    file plus rename so a crash cannot leave a half-written secret.

    A 0600 file inside a world-listable directory still leaks names and
    metadata, so when this function has to create the containing
    directory it locks that directory to `dir_mode` (default 0700).
    Directories that already exist are left alone — they belong to
    someone else to manage. Pass dir_mode=None to opt out entirely.
    """
    d = os.path.dirname(path)
    if d:
        created = not os.path.isdir(d)
        os.makedirs(d, exist_ok=True)
        if created and dir_mode is not None:
            try:
                os.chmod(d, dir_mode)
            except OSError:
                pass
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    os.replace(tmp, path)
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def write_secret(proj: str, name: str, value: str) -> None:
    d = os.path.join(proj, "secrets")
    os.makedirs(d, exist_ok=True)
    os.chmod(d, 0o700)
    write_private(os.path.join(d, name), value.strip() + "\n", 0o600)


def refresh_proxy_env(proj: str) -> bool:
    """Persist the effective proxy settings into secrets/proxy.env.

    Returns True only when the file was (re)written, so callers can log
    a real change instead of noise. CFBRIDGE_PROXY wins over the usual
    variables, which is how an agent that knows the sandbox proxy URL
    pins it for the units without exporting anything globally.
    """
    url = proxy_from_env()
    if not url:
        return False
    lines = [f"HTTPS_PROXY={url}", f"https_proxy={url}"]
    for k in ("HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"):
        v = (os.environ.get(k) or "").strip()
        if v:
            lines.append(f"{k}={v}")
    d = os.path.join(proj, "secrets")
    os.makedirs(d, exist_ok=True)
    os.chmod(d, 0o700)
    path = os.path.join(d, "proxy.env")
    content = "\n".join(lines) + "\n"
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                if f.read() == content:
                    return False
        except OSError:
            pass
    write_private(path, content, 0o600)
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
    if bridge_port_free(port):
        # free, or our own bridge already owns it
        return
    own_active = False
    if systemctl_path():
        names = unit_names(proj, cfg, "bridge")
        own_active = systemctl("is-active", names["bridge"]).stdout.strip() == "active"
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


def systemctl_path() -> str:
    """Absolute path to systemctl, or "" on hosts without systemd."""
    return shutil.which("systemctl") or ""


def systemctl(*args: str, check: bool = False) -> subprocess.CompletedProcess:
    """systemctl wrapper that degrades instead of raising when absent.

    Probing code (doctor, dependency checks) calls is-active on hosts
    that have no systemd at all; a FileNotFoundError traceback is not
    an answer. Real installs still die loudly via check=True.
    """
    if not systemctl_path():
        r = subprocess.CompletedProcess(["systemctl", *args], 127, "", "systemctl not found on PATH")
        if check:
            die(f"command failed: systemctl {' '.join(args)}\n{r.stderr}")
        return r
    return run(["systemctl", *args], check=check)


def render(template: str, mapping: dict[str, str]) -> str:
    """Substitute {{KEY}} placeholders and refuse to emit a broken file.

    Two failure modes are worth hard-stopping on: a placeholder left
    behind (typo between template and caller) and a substituted value
    containing a newline, which inside a systemd unit would inject
    arbitrary directives.
    """
    out = template
    for k, v in mapping.items():
        val = "" if v is None else str(v)
        if "\n" in val or "\r" in val:
            die(f"refusing to render {{{{k={k}}}}}: value contains a newline")
        out = out.replace("{{" + k + "}}", val)
    leftover = sorted(set(re.findall(r"\{\{([A-Za-z0-9_]+)\}\}", out)))
    if leftover:
        die(f"unresolved template placeholder(s): {', '.join(leftover)}")
    return out


def require_root(action: str) -> None:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() != 0:
        die(f"{action} needs root (it writes /etc/systemd/system); re-run as root")


def find_python_bin() -> str:
    """Absolute interpreter path for units, or "" when there is none.

    Hardcoding /usr/bin/python3 breaks on images that only ship
    /usr/local/bin/python3; sys.executable is always the interpreter
    actually running this CLI, which is by definition known-good.
    systemd requires an absolute path, hence the explicit check.
    Separate from python_bin() so dependency probing can report the
    problem instead of dying mid-probe.
    """
    exe = sys.executable or ""
    if os.path.isabs(exe) and os.path.exists(exe):
        return exe
    for cand in ("/usr/bin/python3", "/usr/local/bin/python3"):
        if os.path.exists(cand):
            return cand
    return ""


def python_bin() -> str:
    exe = find_python_bin()
    if not exe:
        die("no absolute python3 interpreter found for the bridge unit; run cfbridge with python3")
    return exe


def read_template(rel: str) -> str:
    with open(os.path.join(SKILL_DIR, "templates", rel), encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------- logs
#
# systemd writes every log with `StandardOutput=append:` — raw stdout,
# no timestamps — into the project dir, which on this kind of sandbox is
# the only persistent volume. Nothing bounded them: a chatty user
# program could fill $HOME and take config.json and secrets/ down with
# it, and the log of a service removed long ago would sit there forever.
#
# "How old is this content" cannot be answered from such a file, so the
# window is enforced structurally instead: a size cap on every call,
# plus a rolling interval recorded in run/log-retention.json. Rotation
# happens in place (see rotate_log_in_place) because systemd keeps the
# fd open for appends.

LOG_RETENTION_HOURS_DEFAULT = 24.0
LOG_MAX_BYTES_DEFAULT = 8 * 1024 * 1024
LOG_TAIL_BYTES_DEFAULT = 1 * 1024 * 1024


def log_retention_state_path(proj: str) -> str:
    return os.path.join(proj, "run", "log-retention.json")


def expected_log_names(proj: str) -> set[str]:
    """Log files a currently managed unit of this project may be writing.

    Anything else under logs/ belongs to a unit that no longer exists.
    A missing or unparsable config must not disable pruning, so it is
    read leniently — the worst case is that svc-*.log counts as unknown.
    """
    names = {"cloudflared.log", "bridge.log", "last-doctor-fix.log"}
    try:
        cfg = load_config_or_empty(proj)
    except (OSError, ValueError):
        return names
    for s in cfg.get("services") or []:
        if s.get("start_cmd"):
            names.add(f"svc-{s['name']}.log")
    return names


def rotate_log_in_place(path: str, tail_bytes: int) -> bool:
    """Keep only the last `tail_bytes` of a live log. True if it shrank.

    In place, never by rename: systemd holds the fd open for appends and
    keeps writing to whatever inode it opened, so a rename would orphan
    the live log and leave an invisible, ever-growing file behind.
    Rewriting the same inode works because O_APPEND seeks to the (new)
    end before every write. Keeping the tail rather than emptying the
    file preserves the crash context that makes the log worth having.
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return False
    if size <= tail_bytes:
        return False
    try:
        with open(path, "rb") as f:
            f.seek(-tail_bytes, os.SEEK_END)
            keep = f.read(tail_bytes)
    except OSError:
        return False
    try:
        with open(path, "wb") as f:  # O_TRUNC on the same inode
            f.write(keep)
    except OSError:
        return False
    return True


def retention_hours_from_config(cfg: dict) -> float:
    raw = cfg.get("log_retention_hours", LOG_RETENTION_HOURS_DEFAULT)
    try:
        return max(0.0, float(raw))
    except (TypeError, ValueError):
        return LOG_RETENTION_HOURS_DEFAULT


def _rotation_due(proj: str, now: float, window: float) -> bool:
    if window <= 0:
        return False
    try:
        with open(log_retention_state_path(proj), encoding="utf-8") as f:
            last = float(json.load(f).get("rotated_at") or 0.0)
    except (OSError, ValueError, TypeError, AttributeError):
        return True  # no state yet: start bounding the existing output now
    return (now - last) >= window


def _write_rotation_state(proj: str, now: float, retention_hours: float) -> None:
    try:
        write_private(log_retention_state_path(proj),
                      json.dumps({"rotated_at": now, "window_hours": retention_hours}) + "\n",
                      dir_mode=None)
    except OSError:
        pass


def prune_logs(proj: str, retention_hours: float = LOG_RETENTION_HOURS_DEFAULT,
               max_bytes: int = LOG_MAX_BYTES_DEFAULT,
               tail_bytes: int = LOG_TAIL_BYTES_DEFAULT,
               force_rotate: bool = False) -> list[str]:
    """Enforce the log retention window. Returns what was done, for logs.

    retention_hours <= 0 disables pruning entirely (except --force).
    Called from `up` and from every keepalive-hook poll, so it has to
    stay cheap and idempotent.
    """
    logs_dir = os.path.join(proj, "logs")
    if not os.path.isdir(logs_dir):
        return []
    window = max(0.0, retention_hours) * 3600.0
    if window <= 0 and not force_rotate:
        return []
    now = time.time()
    actions: list[str] = []
    expected = expected_log_names(proj)

    for name in sorted(os.listdir(logs_dir)):
        if not name.endswith(".log"):
            continue
        path = os.path.join(logs_dir, name)
        if not os.path.isfile(path):
            continue
        try:
            st = os.stat(path)
        except OSError:
            continue
        if window > 0 and name not in expected and (now - st.st_mtime) >= window:
            # Nothing writes this any more, so its mtime really is the
            # last write; the file is a leftover from a removed unit.
            try:
                os.remove(path)
                actions.append(f"removed stale log {name}")
            except OSError:
                pass
            continue
        if st.st_size > max_bytes and rotate_log_in_place(path, tail_bytes):
            actions.append(f"capped {name} at {tail_bytes // 1024} KiB")

    if force_rotate or _rotation_due(proj, now, window):
        for name in sorted(expected):
            path = os.path.join(logs_dir, name)
            if os.path.isfile(path) and rotate_log_in_place(path, tail_bytes):
                actions.append(f"rotated {name}")
        _write_rotation_state(proj, now, retention_hours)
    return actions


def cmd_prune_logs(args) -> None:
    proj = project_dir(args)
    hours = args.retention_hours
    if hours is None:
        hours = retention_hours_from_config(load_config_or_empty(proj))
    actions = prune_logs(proj, retention_hours=hours, force_rotate=args.force)
    if getattr(args, "json", False):
        print(json.dumps({"retention_hours": hours, "actions": actions}, ensure_ascii=False))
        return
    if not getattr(args, "quiet", False):
        for line in actions:
            print(f"logs: {line}")


# ---------------------------------------------------------------- dependencies
#
# The stack has real runtime dependencies, and most of them used to be
# "checked" only by looking at the environment instead of by using the
# thing. That is exactly how a stack reports healthy while nothing
# works: HTTPS_PROXY is set — to a proxy that rotated away an hour ago;
# secrets/proxy.env is gone, so the bridge unit's EnvironmentFile cannot
# resolve and systemd refuses to start it; the demo venv was never
# rebuilt so the service unit crash-loops; the bridge port is held by
# another project. Every one of those is observable, and the tool owns
# the fix for most of them, so they are probed for real here and
# repaired where cfbridge is the owner.

PROJECT_LAYOUT = ("secrets", "logs", "run", "systemd", "bin", "services")
WEBSOCKETS_REQ = "websockets>=12,<16"
# cloudflared prints this once the named tunnel is actually registered
# with an edge. Anything earlier is "process is running", not "tunnel
# works".
CF_REGISTERED_MARK = "Registered tunnel connection"
PROXY_ENV_KEYS = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")


def dep(name: str, ok: bool, detail: str, *, required: bool = True, heal: str = "") -> dict:
    return {"name": name, "ok": bool(ok), "required": bool(required), "detail": detail, "heal": heal}


def dep_missing(deps: list[dict]) -> list[dict]:
    return [d for d in deps if d["required"] and not d["ok"]]


def proxy_from_env() -> str:
    v = (os.environ.get("CFBRIDGE_PROXY") or "").strip()
    if v:
        return v
    for k in PROXY_ENV_KEYS:
        v = (os.environ.get(k) or "").strip()
        if v:
            return v
    return ""


def proxy_from_project(proj: str) -> str:
    """The last known-good proxy URL, read back from the project.

    A rebuilt sandbox can come back with a shell that has no proxy
    variables at all while the persistent project directory still holds
    a working value. Reading it back is what lets `up`/doctor self-heal
    instead of dying on a "missing" dependency that is right there.
    """
    path = os.path.join(proj, "secrets", "proxy.env")
    if not os.path.exists(path):
        return ""
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return ""
    for want in ("HTTPS_PROXY", "HTTP_PROXY"):
        for line in lines:
            key, sep, val = line.strip().partition("=")
            if sep and key.strip().upper() == want and val.strip():
                return val.strip()
    return ""


def parse_proxy(url: str) -> tuple[str, int, str | None] | None:
    """URL -> (host, port, basic-auth header value or None)."""
    raw = (url or "").strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "http://" + raw
    try:
        u = urllib.parse.urlparse(raw)
        host = u.hostname or ""
        # urlparse() happily returns "not a url" as a hostname; a value
        # with whitespace is a mangled variable, not a proxy, and
        # dialing it would fail in a far more confusing way.
        if not re.fullmatch(r"[A-Za-z0-9_.:\-]+", host):
            return None
        port = u.port or (443 if u.scheme == "https" else 80)
    except ValueError:
        return None
    auth = None
    if u.username:
        user = urllib.parse.unquote(u.username)
        pw = urllib.parse.unquote(u.password or "")
        auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
    return host, port, auth


def redact_proxy(url: str) -> str:
    """Proxy URLs carry credentials and get printed into logs/chat."""
    target = parse_proxy(url)
    if target is None:
        return "<unparseable proxy URL>"
    host, port, auth = target
    m = re.match(r"^([a-zA-Z0-9+.-]+)://", (url or "").strip())
    scheme = m.group(1).lower() if m else "http"
    shown = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    return f"{scheme}://{'***@' if auth else ''}{shown}"


def probe_proxy_endpoint(url: str, timeout: float = 6) -> tuple[bool, str]:
    """Can the egress proxy actually be used for CONNECT?

    Presence of HTTPS_PROXY proves nothing: the sandbox proxy is a
    shared, rotating service and a stale value looks exactly like a live
    one until something dials it. Reachability alone is not enough
    either — a SOCKS proxy listens fine but cannot carry the CONNECT
    tunnel cloudflared needs.
    """
    target = parse_proxy(url)
    if target is None:
        return False, "unparseable proxy URL"
    scheme = url.split("://", 1)[0].lower() if "://" in url else "http"
    if scheme not in ("http", "https"):
        return False, f"scheme {scheme!r} is not an HTTP proxy (the edge path needs CONNECT)"
    host, port, _ = target
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return False, f"unreachable ({type(e).__name__}: {e})"
    s.close()
    return True, "accepts TCP"


def probe_edge_via_proxy(proxy: tuple[str, int, str | None], ips: list[str],
                         timeout: float = 8) -> tuple[bool, str]:
    """The dependency that actually matters in bridge mode: a CONNECT
    through the proxy to a real edge IP, exactly what the bridge does."""
    tried: list[str] = []
    for ip in ips[:3]:
        tried.append(ip)
        got = edge_bridge.connect_via_proxy(ip, timeout, proxy)
        if got is not None:
            sock, _ = got
            try:
                sock.close()
            except OSError:
                pass
            return True, f"CONNECT {ip}:{edge_bridge.EDGE_PORT} through the proxy succeeded"
    return False, f"CONNECT failed for {', '.join(tried) or 'no candidates'}"


def resolve_proxy(proj: str, timeout: float = 6) -> tuple[str, str, bool, str]:
    """Pick a *working* proxy URL: environment first, project copy next.

    Returns (url, source, ok, detail). A dead environment value is not
    the end of the story — if the project's persisted URL still works
    (the common rotation case), that one is used and reported.
    """
    env_url = proxy_from_env()
    candidates: list[tuple[str, str]] = []
    if env_url:
        candidates.append((env_url, "env"))
    file_url = proxy_from_project(proj)
    if file_url and file_url != env_url:
        candidates.append((file_url, "secrets/proxy.env"))
    if not candidates:
        return "", "unset", False, "no proxy URL in the environment or in secrets/proxy.env"
    last = ""
    for url, source in candidates:
        ok, detail = probe_proxy_endpoint(url, timeout)
        if ok:
            return url, source, True, detail
        last = f"{source} {redact_proxy(url)}: {detail}"
    url, source = candidates[0]
    return url, source, False, last


def ensure_project_layout(proj: str) -> list[str]:
    created: list[str] = []
    for d in PROJECT_LAYOUT:
        path = os.path.join(proj, d)
        if not os.path.isdir(path):
            os.makedirs(path, exist_ok=True)
            created.append(d + "/")
    try:
        os.chmod(os.path.join(proj, "secrets"), 0o700)
    except OSError:
        pass
    return created


def venv_python(proj: str) -> str:
    return os.path.join(proj, "venv", "bin", "python")


def services_needing_venv(proj: str, cfg: dict) -> list[str]:
    """Services whose start_cmd runs the project venv interpreter."""
    marker = venv_python(proj)
    out: list[str] = []
    for s in cfg.get("services") or []:
        if s.get("start_cmd") and marker in s["start_cmd"]:
            out.append(s["name"])
    return out


def ensure_venv(proj: str) -> str:
    """Create the project venv plus the one pinned demo dependency.

    init used to be the only place that built this, so a project whose
    venv was lost started its service unit, let it crash, restarted it,
    and never said why. Building it is a dependency repair.
    """
    py = venv_python(proj)
    if os.path.exists(py):
        return py
    venv = os.path.join(proj, "venv")
    run([sys.executable, "-m", "venv", venv])
    run([os.path.join(venv, "bin", "pip"), "install", "-q", WEBSOCKETS_REQ])
    return py


def collect_deps(proj: str, cfg: dict, mode: str, timeout: float = 6) -> list[dict]:
    """Read-only dependency probe. Nothing here writes or starts anything."""
    deps: list[dict] = []
    geteuid = getattr(os, "geteuid", None)
    is_root = (geteuid() == 0) if geteuid is not None else None
    deps.append(dep("root", bool(is_root), "euid=0" if is_root else "not root",
                    heal="" if is_root else
                    "cannot be fixed from here: re-run as root (units live in /etc/systemd/system)"))
    sctl = systemctl_path()
    deps.append(dep("systemd", bool(sctl), sctl or "systemctl not on PATH",
                    heal="" if sctl else
                    "cannot be fixed from here: cfbridge only manages systemd units"))

    py = find_python_bin()
    deps.append(dep("python3", bool(py), py or "no absolute python3 interpreter",
                    heal="" if py else "cannot be fixed from here"))

    absent = [d for d in PROJECT_LAYOUT if not os.path.isdir(os.path.join(proj, d))]
    deps.append(dep("project layout", not absent,
                    f"{len(PROJECT_LAYOUT)} directories present" if not absent
                    else "missing " + ", ".join(d + "/" for d in absent),
                    heal="" if not absent else "create " + ", ".join(d + "/" for d in absent)))

    cfd = os.path.join(proj, "bin", "cloudflared")
    ver = cloudflared_version(cfd) if os.path.exists(cfd) else None
    system_cfd = shutil.which("cloudflared") or ""
    if ver:
        deps.append(dep("cloudflared", True, f"{cfd} ({ver})"))
    elif system_cfd and cloudflared_version(system_cfd):
        deps.append(dep("cloudflared", False,
                        f"project copy missing or broken (system copy at {system_cfd} is usable)",
                        heal="copy the system binary into the project"))
    else:
        deps.append(dep("cloudflared", False, "no runnable binary",
                        heal=f"download the pinned release {CLOUDFLARED_VERSION} for this architecture"))

    url, source, proxy_ok, proxy_detail = resolve_proxy(proj, timeout=timeout)
    if not url:
        deps.append(dep("proxy", False, proxy_detail,
                        heal="cannot be fixed from here: export HTTPS_PROXY or set CFBRIDGE_PROXY"))
    else:
        deps.append(dep("proxy", proxy_ok, f"{redact_proxy(url)} via {source} — {proxy_detail}",
                        heal="" if proxy_ok else
                        "cannot be fixed from here: the sandbox egress proxy is down or rotated"))

    keyfile = os.path.join(proj, "secrets", "bridge-key.txt")
    deps.append(dep("bridge key", os.path.exists(keyfile),
                    keyfile if os.path.exists(keyfile) else "missing secrets/bridge-key.txt",
                    heal="" if os.path.exists(keyfile) else
                    "generate a new random key (services read it from this path)"))

    if mode == "bridge":
        envfile = os.path.join(proj, "secrets", "proxy.env")
        has_env = os.path.exists(envfile)
        deps.append(dep("secrets/proxy.env", has_env,
                        envfile if has_env else "missing (the bridge unit reads it as EnvironmentFile)",
                        heal="" if has_env else "rewrite it from the working proxy URL"))

    real_ips = edge_bridge.fetch_edge_ips()
    from_fallback = real_ips == list(edge_bridge.FALLBACK_EDGES)
    deps.append(dep("doh edge lookup", not from_fallback,
                    f"{len(real_ips)} candidate edge IPs" + (" (built-in fallback list; DoH unreachable)"
                                                             if from_fallback else " (via DoH)"),
                    required=False,
                    heal="" if not from_fallback else "optional: a fresh DoH round is retried on demand"))

    if mode == "bridge":
        target = parse_proxy(url)
        if target is None:
            deps.append(dep("edge via proxy", False, "no usable proxy URL",
                            heal="cannot be fixed from here: fix the proxy first"))
        else:
            ok, detail = probe_edge_via_proxy(target, real_ips, timeout=timeout)
            deps.append(dep("edge via proxy", ok, detail,
                            heal="" if ok else
                            "cannot be fixed from here: check the proxy's CONNECT policy for port 7844"))
    else:
        ok = direct_edge_ok(real_ips, timeout=timeout)
        deps.append(dep("direct edge", ok, f"verified TLS to edge:7844 = {ok}",
                        heal="" if ok else "switch this project to bridge mode (\"mode\": \"bridge\" in config.json)"))

    if mode == "bridge":
        port = int(cfg.get("bridge_port") or DEFAULT_BRIDGE_PORT)
        free = bridge_port_free(port)
        own = False
        if not free and sctl:
            names = unit_names(proj, cfg, "bridge")
            own = systemctl("is-active", names["bridge"]).stdout.strip() == "active"
        deps.append(dep("bridge port", free or own,
                        f"{port} " + ("free" if free else ("held by our own bridge unit" if own
                                                           else "in use by something else")),
                        heal="" if (free or own) else f"shift to the next free port near {port} and re-render units"))

    need_venv = services_needing_venv(proj, cfg)
    if need_venv:
        exists = os.path.exists(venv_python(proj))
        deps.append(dep("service venv", exists,
                        f"{venv_python(proj)} for {', '.join(need_venv)}" if exists
                        else f"missing, required by {', '.join(need_venv)}",
                        heal="" if exists else f"create the venv and install {WEBSOCKETS_REQ}"))

    jq = shutil.which("jq") or ""
    deps.append(dep("jq", bool(jq), jq or "not installed", required=False,
                    heal="" if jq else
                    "optional: only the hook's wake-throttle needs it; the hook falls back to python3"))

    return deps


def heal_deps(proj: str, cfg: dict, mode: str) -> list[str]:
    """Repair every dependency cfbridge is the owner of.

    Scope is deliberate: project directories, the venv, the project's
    cloudflared copy, secrets/*, the bridge port, and units rendered
    from the project's own canonical copies. It never installs OS
    packages, never edits the sandbox's proxy configuration, and never
    touches another process's files.
    """
    done: list[str] = []
    created = ensure_project_layout(proj)
    if created:
        done.append("created project dirs: " + ", ".join(created))

    keyfile = os.path.join(proj, "secrets", "bridge-key.txt")
    if not os.path.exists(keyfile):
        write_secret(proj, "bridge-key.txt", pysecrets.token_urlsafe(32))
        done.append("generated secrets/bridge-key.txt")

    url, source, ok, _detail = resolve_proxy(proj)
    if url and ok and source != "env":
        # The environment lost (or rotated away from) a proxy the
        # project still remembers; adopt it for this process so every
        # later step — DoH, tunnel API, unit rendering — agrees.
        for k in ("HTTPS_PROXY", "https_proxy"):
            os.environ[k] = url
        done.append(f"adopted the working proxy from {source} (environment had none usable)")
    if url and ok and refresh_proxy_env(proj):
        done.append("refreshed secrets/proxy.env")

    if not cloudflared_version(os.path.join(proj, "bin", "cloudflared")):
        ensure_cloudflared(proj)
        done.append("installed a working cloudflared into the project")

    if mode == "bridge":
        before = cfg.get("bridge_port")
        ensure_bridge_port(proj, cfg)
        if cfg.get("bridge_port") != before:
            done.append(f"moved the bridge port to {cfg['bridge_port']}")

    need_venv = services_needing_venv(proj, cfg)
    if need_venv and not os.path.exists(venv_python(proj)):
        ensure_venv(proj)
        done.append("rebuilt the service venv for " + ", ".join(need_venv))
    return done


def adopt_project_proxy(proj: str) -> str:
    """If the environment has no proxy but the project remembers one,
    adopt it for this process.

    Probe-free on purpose: this has to run before anything that needs
    egress (mode detection, DoH, the Cloudflare API), and in a rebuilt
    sandbox the shell often has no proxy variables at all while the
    persistent project directory still holds the last working URL.
    Returns the URL when it was adopted, "" otherwise.
    """
    if proxy_from_env():
        return ""
    url = proxy_from_project(proj)
    if not url:
        return ""
    for k in ("HTTPS_PROXY", "https_proxy"):
        os.environ[k] = url
    return url


def units_missing_from_etc(proj: str) -> list[str]:
    """Managed units that /etc/systemd/system no longer has.

    Container rebuilds wipe /etc while $HOME survives, so this is the
    normal post-rebuild state, not an error state.
    """
    units_file = os.path.join(proj, "run", "managed-units.txt")
    if not os.path.exists(units_file):
        return []
    try:
        with open(units_file, encoding="utf-8") as f:
            units = [l.strip() for l in f if l.strip()]
    except OSError:
        return []
    return [u for u in units if not os.path.exists(f"/etc/systemd/system/{u}.service")]


def wait_port_listening(host: str, port: int, timeout: float = 20) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        try:
            s.connect((host, port))
            return True
        except OSError:
            time.sleep(0.5)
        finally:
            try:
                s.close()
            except OSError:
                pass
    return False


def log_offset(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def wait_tunnel_registered(proj: str, offset: int = 0, timeout: float = 45) -> bool:
    """cloudflared's own readiness signal, read from the unit log.

    Only bytes past `offset` count: the log is append-only across
    restarts, so an old "Registered tunnel connection" would otherwise
    make a dead stack look ready the moment it is restarted.
    """
    path = os.path.join(proj, "logs", "cloudflared.log")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                f.seek(offset)
                if CF_REGISTERED_MARK in f.read():
                    return True
        except OSError:
            pass
        time.sleep(2)
    return False


def start_order(names: dict[str, str]) -> list[str]:
    """Dependency order: bridge -> services -> cloudflared.

    cloudflared is useless until the bridge is listening, and the tunnel
    cannot reach a service that is not up yet. Starting them as one
    systemctl call — or restarting only cloudflared — is exactly what
    leaves a stack "started" but never registered.
    """
    out = [names["bridge"]] if "bridge" in names else []
    out += [names[k] for k in sorted(names) if k.startswith("svc:")]
    if "cloudflared" in names:
        out.append(names["cloudflared"])
    return out


def start_stack(proj: str, cfg: dict, mode: str, restart: bool = True) -> list[str]:
    """Bring units up in dependency order, waiting on each layer.

    Returns the units that were actually (re)started. A unit left alone
    because it is already active is never bounced: restarting the bridge
    or cloudflared mid-flight would drop every live tunnel connection.
    """
    names = unit_names(proj, cfg, mode)
    ordered = start_order(names)
    if not ordered:
        return []
    verb = "restart" if restart else "start"
    systemctl("reset-failed", *ordered)
    started: list[str] = []
    bridge_unit = names.get("bridge", "")
    cf_unit = names.get("cloudflared", "")

    def act(u: str) -> None:
        if not restart and systemctl("is-active", u).stdout.strip() == "active":
            return
        systemctl(verb, u, check=True)
        started.append(u)

    if bridge_unit:
        act(bridge_unit)
        port = int(cfg.get("bridge_port") or DEFAULT_BRIDGE_PORT)
        if not wait_port_listening("127.0.0.1", port, timeout=20):
            print(f"warning: {bridge_unit} is not listening on 127.0.0.1:{port}; see logs/bridge.log")
    for k in sorted(names):
        if k.startswith("svc:"):
            act(names[k])
    if cf_unit:
        offset = log_offset(os.path.join(proj, "logs", "cloudflared.log"))
        act(cf_unit)
        if not wait_tunnel_registered(proj, offset, timeout=45):
            print("warning: cloudflared has not logged "
                  f"{CF_REGISTERED_MARK!r} yet; see logs/cloudflared.log "
                  "(in bridge mode this usually means the bridge or the proxy is down)")
    return started


def tunnel_registered_tail(proj: str, window: int = 8192) -> bool:
    """Does the cloudflared log tail say the tunnel is registered?"""
    path = os.path.join(proj, "logs", "cloudflared.log")
    try:
        size = os.path.getsize(path)
        with open(path, encoding="utf-8", errors="replace") as f:
            if size > window:
                f.seek(size - window)
            return CF_REGISTERED_MARK in f.read()
    except OSError:
        return False


def heal_stack(proj: str, cfg: dict, mode: str) -> list[str]:
    """Make the units real again: reinstall the ones /etc lost, start the
    ones that are down, bounce a cloudflared that is running but has
    stopped being registered.

    This is the "容器重建后自己把依赖拉起来" half of the dependency
    story; heal_deps() is the other half (the inputs those units need).
    """
    done: list[str] = []
    if not cfg.get("services"):
        return done
    gone = units_missing_from_etc(proj)
    if gone:
        geteuid = getattr(os, "geteuid", None)
        if geteuid is not None and geteuid() != 0:
            done.append("SKIPPED unit reinstall (needs root): " + ", ".join(gone))
        else:
            install_units(proj, render_units(proj, cfg, mode))
            done.append("reinstalled units missing from /etc: " + ", ".join(gone))
    started = start_stack(proj, cfg, mode, restart=False)
    if started:
        done.append("started inactive units: " + ", ".join(started))
    names = unit_names(proj, cfg, mode)
    cf = names.get("cloudflared", "")
    if cf and systemctl("is-active", cf).stdout.strip() == "active" and not tunnel_registered_tail(proj):
        offset = log_offset(os.path.join(proj, "logs", "cloudflared.log"))
        systemctl("restart", cf)
        if wait_tunnel_registered(proj, offset, timeout=45):
            done.append(f"restarted {cf}: it was running but no longer registered")
        else:
            done.append(f"restarted {cf} (still not registered; see logs/cloudflared.log)")
    return done


def print_deps(deps: list[dict]) -> None:
    print("dependencies:")
    for d in deps:
        mark = "ok" if d["ok"] else ("optional" if not d["required"] else "MISSING")
        print(f"  [{mark:8}] {d['name']:17} {d['detail']}")
        if not d["ok"] and d["heal"]:
            print(f"  {'':10} {'':17} -> {d['heal']}")


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


def cloudflared_version(binary: str) -> str | None:
    try:
        r = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    first = (r.stdout or r.stderr).strip().splitlines()
    return first[0][:80] if first else None


def cmd_doctor(args) -> None:
    proj = project_dir(args)
    fix = bool(getattr(args, "fix", False))
    cfg = load_config_or_empty(proj)

    # Adopt a remembered proxy before anything that needs egress: mode
    # detection resolves over DoH, and the Cloudflare API check below
    # both go out through it.
    adopted = adopt_project_proxy(proj)
    if adopted:
        print(f"note: environment had no proxy; using {redact_proxy(adopted)} from secrets/proxy.env")

    report: dict = {"project": proj, "checks": {}}
    home = os.path.expanduser("~")
    report["checks"]["persistent_location"] = proj.startswith(home)
    report["checks"]["arch"] = platform.machine() or "unknown"
    geteuid = getattr(os, "geteuid", None)
    report["checks"]["root"] = (geteuid() == 0) if geteuid else None
    report["checks"]["systemd"] = bool(systemctl_path())
    report["checks"]["python3"] = sys.version.split()[0]
    # The keepalive hook uses jq for config/state parsing; without it the
    # hook degrades, which is worth knowing before install-autostart.
    report["checks"]["jq"] = bool(shutil.which("jq"))
    cfd = shutil.which("cloudflared") or os.path.join(proj, "bin", "cloudflared")
    report["checks"]["cloudflared"] = cfd if os.path.exists(cfd) else None
    report["checks"]["cloudflared_version"] = cloudflared_version(cfd) if os.path.exists(cfd) else None
    report["checks"]["proxy_env"] = bool(proxy_from_env())
    bridge_port = int(cfg.get("bridge_port") or DEFAULT_BRIDGE_PORT)
    report["checks"]["bridge_port"] = bridge_port
    report["checks"]["bridge_port_free"] = bridge_port_free(bridge_port)

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
        mode = "bridge"
    else:
        mode = "direct" if direct_ok else "bridge"
    report["mode"] = mode

    if fix:
        # Repair what cfbridge owns, then say what changed — output that
        # only reports problems is what made "没有自动拉起来" feel true.
        for line in heal_deps(proj, cfg, mode):
            print(f"fixed: {line}")
        for line in heal_stack(proj, cfg, mode):
            print(f"fixed: {line}")
        cfg = load_config_or_empty(proj)

    deps = collect_deps(proj, cfg, mode)
    report["dependencies"] = deps
    missing = dep_missing(deps)
    report["missing_required"] = [d["name"] for d in missing]

    try:
        accts = cf_api.list_accounts()
        report["checks"]["cf_accounts"] = [a["name"] for a in accts]
    except Exception as e:  # noqa: BLE001
        report["checks"]["cf_error"] = str(e)[:200]

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        if missing:
            raise SystemExit(1)
        return
    c = report["checks"]
    print(f"project:            {proj}  (persistent: {c['persistent_location']})")
    print(f"root / systemd:     {c['root']} / {c['systemd']}")
    print(f"arch / python3:     {c['arch']} / {c['python3']}  (jq: {c['jq']})")
    print(f"cloudflared:        {c['cloudflared']} {('(' + c['cloudflared_version'] + ')') if c['cloudflared_version'] else ''}")
    print(f"proxy env:          {c['proxy_env']}")
    print(f"bridge port:        {c['bridge_port']} (free: {c['bridge_port_free']})")
    print(f"system DNS edge:    {', '.join(sys_ips) or 'unresolvable'} (fake-IP: {c['dns_fake_ip']})")
    print(f"real edge candidates via DoH: {c['real_edge_candidates']}")
    print(f"direct TLS 7844 (verified):    {direct_ok}")
    if "cf_accounts" in c:
        print(f"cloudflare accounts: {', '.join(c['cf_accounts'])}")
    else:
        print(f"cloudflare:         NOT READY ({c.get('cf_error')})")
    print_deps(deps)
    print(f"verdict:            mode = {mode}"
          + (" (edge bridge required)" if mode == "bridge" else " (cloudflared can dial directly)"))
    if not missing:
        print("dependencies: all required checks passed")
        return
    print(f"verdict:            {len(missing)} required dependency(ies) missing: "
          + ", ".join(d["name"] for d in missing))
    if not fix:
        print("hint:               run `cfbridge doctor --fix` to repair what cfbridge owns")
    elif not any(d["heal"] for d in missing):
        print("hint:               nothing left that cfbridge can repair on its own")
    raise SystemExit(1)


# ---------------------------------------------------------------- init

def cloudflared_asset() -> str:
    explicit = os.environ.get("CFBRIDGE_CLOUDFLARED_ASSET")
    if explicit:
        return explicit
    machine = (platform.machine() or "").lower()
    asset = ARCH_ASSETS.get(machine)
    if not asset:
        die(f"no cloudflared build known for architecture {machine!r}; "
            "set CFBRIDGE_CLOUDFLARED_ASSET or place a binary at <project>/bin/cloudflared")
    return asset


def download_cloudflared(dst: str) -> str:
    version = os.environ.get("CFBRIDGE_CLOUDFLARED_VERSION", CLOUDFLARED_VERSION)
    url = os.environ.get("CFBRIDGE_CLOUDFLARED_URL") or RELEASE_URL.format(version=version, asset=cloudflared_asset())
    expected = (os.environ.get("CFBRIDGE_CLOUDFLARED_SHA256") or "").lower()
    print(f"cloudflared not found locally; downloading {url}")
    tmp = dst + ".part"
    try:
        resp = urllib.request.urlopen(url, timeout=120)
    except urllib.error.HTTPError as e:
        die(f"cloudflared download failed: HTTP {e.code} for {url}")
    except OSError as e:
        die(f"cloudflared download failed: {e} (is the sandbox proxy up? HTTPS_PROXY)")
    digest = hashlib.sha256()
    try:
        with resp, open(tmp, "wb") as f:
            while True:
                chunk = resp.read(1 << 16)
                if not chunk:
                    break
                digest.update(chunk)
                f.write(chunk)
    except OSError as e:
        try:
            os.remove(tmp)
        except OSError:
            pass
        die(f"cloudflared download interrupted: {e}")
    got = digest.hexdigest()
    if expected:
        if got != expected:
            os.remove(tmp)
            die(f"cloudflared checksum mismatch: expected {expected}, got {got}")
        print("cloudflared sha256 verified")
    else:
        # Cloudflare publishes no per-asset checksum file, so verify what
        # we can locally: right size, real ELF, runs, reports a version.
        size = os.path.getsize(tmp)
        with open(tmp, "rb") as f:
            magic = f.read(4)
        if size < MIN_CLOUDFLARED_BYTES or magic != b"\x7fELF":
            os.remove(tmp)
            die(f"downloaded cloudflared looks wrong ({size} bytes, magic {magic!r}); "
                "set CFBRIDGE_CLOUDFLARED_SHA256 to verify against a known-good hash")
        print(f"cloudflared sha256 = {got} (no reference hash set; size+ELF checked)")
    os.replace(tmp, dst)
    os.chmod(dst, 0o755)
    return dst


def ensure_cloudflared(proj: str) -> str:
    dst = os.path.join(proj, "bin", "cloudflared")
    if not os.path.exists(dst):
        os.makedirs(os.path.join(proj, "bin"), exist_ok=True)
        src = shutil.which("cloudflared")
        if src:
            shutil.copy2(src, dst)
            os.chmod(dst, 0o755)
        else:
            download_cloudflared(dst)
    version = cloudflared_version(dst)
    if not version:
        die(f"{dst} does not run (bad architecture or corrupt copy); remove it and re-run")
    print(f"cloudflared ready: {version}")
    return dst


def cmd_init(args) -> None:
    proj = project_dir(args)
    if not proj.startswith(os.path.expanduser("~")):
        print(f"warning: {proj} is outside $HOME; container rebuilds may wipe it", file=sys.stderr)
    ensure_project_layout(proj)
    binary = ensure_cloudflared(proj)
    key_path = os.path.join(proj, "secrets", "bridge-key.txt")
    if not os.path.exists(key_path):
        write_secret(proj, "bridge-key.txt", pysecrets.token_urlsafe(32))
    if refresh_proxy_env(proj):
        print("secrets/proxy.env written from the current environment")
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
        had_venv = os.path.exists(venv_python(proj))
        ensure_venv(proj)
        if not had_venv:
            print(f"venv ready ({WEBSOCKETS_REQ})")
    print(f"cloudflared: {binary}")
    print("next: cfbridge add-service ... / cfbridge demo --hostname ... ; then cfbridge up")


# ---------------------------------------------------------------- services

def origin_host(origin: str) -> str:
    """Host part of an origin URL ('' for unix sockets or garbage)."""
    raw = (origin or "").strip()
    if not raw:
        return ""
    try:
        return (urllib.parse.urlparse(raw).hostname or "").lower()
    except ValueError:
        return ""


def normalize_origin(svc: dict) -> bool:
    """Fill in the TLS decision for a loopback https origin.

    cloudflared checks the origin certificate against the *service URL
    host* when originServerName is empty, so `https://127.0.0.1:8443`
    demands a certificate whose name is literally `127.0.0.1`. Loopback
    certs are self-signed and almost never carry that name, so the
    tunnel looks healthy while every request is a 502. For a hop that
    never leaves the machine, defaulting to noTLSVerify is the sane
    answer; callers that want real verification pass originServerName.

    Returns True when the service was modified (so callers can persist).
    Non-loopback https origins are left alone for validate_service() to
    reject — there the answer depends on a certificate we cannot see.
    """
    if not (svc.get("origin") or "").strip().startswith("https://"):
        return False
    req = dict(svc.get("origin_request") or {})
    if req.get("originServerName") or req.get("noTLSVerify"):
        return False
    if origin_host(svc.get("origin", "")) not in LOOPBACK_ORIGIN_HOSTS:
        return False
    req["noTLSVerify"] = True
    svc["origin_request"] = req
    return True


def parse_origin_request(raw: str) -> dict:
    """Parse --origin-request JSON, rejecting keys cloudflared ignores."""
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        die(f"--origin-request is not valid JSON: {e}")
    if not isinstance(parsed, dict):
        die("--origin-request must be a JSON object")
    unknown = sorted(set(parsed) - ORIGIN_REQUEST_KEYS)
    if unknown:
        die(f"--origin-request has unsupported key(s) {unknown}; "
            f"allowed: {', '.join(sorted(ORIGIN_REQUEST_KEYS))}")
    return parsed


def validate_service(cfg: dict, svc: dict, allow_public: bool) -> None:
    host = svc.get("hostname", "")
    zone = cfg.get("zone", "")
    if not re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+", host or ""):
        die(f"hostname {host!r} is not a valid DNS name")
    # Boundary matters: a bare endswith() would accept
    # "evilexample.com" for zone "example.com" and hand a third party's
    # hostname to this tunnel's ingress.
    if not (host == zone or host.endswith("." + zone)):
        die(f"hostname {host} is outside zone {zone}")
    if not re.fullmatch(r"[a-z0-9-]+", svc.get("name", "")):
        die("service name must be [a-z0-9-]+")
    if not (1 <= int(svc.get("port", 0)) <= 65535):
        die("service port out of range")
    auth = svc.get("auth", "key")
    if auth not in ("key", "public"):
        die("auth must be 'key' or 'public'")
    if auth == "public" and not (allow_public and svc.get("public_confirmed")):
        die("auth=public exposes the service to anyone who knows the URL; "
            "pass --allow-public to confirm that is intended")
    health = svc.get("health") or "/health"
    if not str(health).startswith("/"):
        die(f"health path must start with '/': {health!r}")
    for field in ("start_cmd", "workdir", "origin"):
        val = svc.get(field) or ""
        if "\n" in val or "\r" in val:
            die(f"{field} must not contain newlines")
    origin = (svc.get("origin") or "").strip()
    if origin and not origin.startswith(ORIGIN_SCHEMES):
        die(f"origin must start with one of {', '.join(ORIGIN_SCHEMES)}: {origin!r}")
    if origin.startswith(RAW_TCP_ORIGIN_SCHEMES) and not svc.get("tcp_origin_confirmed"):
        die(f"origin {origin} is a raw TCP stream: nothing a browser can open. "
            "Clients must run `cloudflared access tcp --hostname <host> "
            "--url 127.0.0.1:<local port>`. Pass --allow-tcp-origin if that "
            "is what you want (an `http://` origin is the browser-reachable one).")
    _validate_origin_request(svc)


def _validate_origin_request(svc: dict) -> None:
    req = svc.get("origin_request") or {}
    if not isinstance(req, dict):
        die("origin_request must be a JSON object")
    unknown = sorted(set(req) - ORIGIN_REQUEST_KEYS)
    if unknown:
        die(f"unsupported origin_request key(s) {unknown}; "
            f"allowed: {', '.join(sorted(ORIGIN_REQUEST_KEYS))}")
    for key, val in req.items():
        if isinstance(val, str) and ("\n" in val or "\r" in val):
            die(f"origin_request.{key} must not contain newlines")
    origin = (svc.get("origin") or "").strip()
    if not origin.startswith("https://"):
        return
    # Without one of these cloudflared verifies against the URL host and
    # the request fails as a 502 that looks like a broken tunnel.
    if not (req.get("originServerName") or req.get("noTLSVerify")):
        host = origin_host(origin) or origin
        die(f"origin {origin} is https but no origin TLS decision is recorded: "
            f"cloudflared would expect a certificate named {host!r} and answer 502 "
            "otherwise. Add \"origin_request\": {\"originServerName\": \"<cert name>\"} "
            "(or {\"noTLSVerify\": true} for a trusted private hop) to the service, "
            "or re-register with --origin-tls-name / --origin-no-verify.")


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
    origin = (args.origin_url or "").strip()
    svc = {
        "name": args.name,
        "hostname": args.hostname,
        "port": args.port,
        "health": args.health,
        "auth": args.auth,
        "public_confirmed": bool(args.auth == "public" and args.allow_public),
        "origin": origin,
        "origin_request": parse_origin_request(args.origin_request),
        "start_cmd": args.start_cmd or "",
        "workdir": args.workdir or proj,
        "env_proxy": bool(args.env_proxy),
    }
    if origin.startswith(RAW_TCP_ORIGIN_SCHEMES):
        # Consistency with --allow-public: the surprising choice has to
        # be stated out loud, because the docs used to imply this was
        # just another origin URL a browser could open.
        svc["tcp_origin_confirmed"] = bool(args.allow_tcp_origin)
    req = svc["origin_request"]
    if args.origin_tls_name:
        if not origin.startswith("https://"):
            die("--origin-tls-name only applies to an https:// origin")
        req["originServerName"] = args.origin_tls_name
    if args.origin_no_verify:
        if not origin.startswith("https://"):
            die("--origin-no-verify only applies to an https:// origin")
        req["noTLSVerify"] = True
    if origin.startswith("https://") and not (req.get("originServerName") or req.get("noTLSVerify")):
        if normalize_origin(svc):  # loopback: default to skipping verification
            print(f"note: https origin on loopback ({origin_host(origin)}); origin TLS "
                  "verification disabled for that private hop. Pass --origin-tls-name "
                  "<cert name> to verify instead.")
        else:
            die(f"--origin-url {origin} is https but no certificate name was given: "
                f"cloudflared would expect the origin certificate to be named "
                f"{origin_host(origin)!r} and return 502 otherwise. Pass "
                "--origin-tls-name <name in the certificate> (preferred), or "
                "--origin-no-verify to skip verification on a trusted hop.")
    validate_service(cfg, svc, allow_public=args.allow_public)
    cfg["services"].append(svc)
    save_config(proj, cfg)
    shown = cf_api.service_origin(svc)
    print(f"registered {args.name}: {args.hostname} -> {shown} (auth={args.auth})")
    if svc.get("origin_request"):
        print(f"originRequest: {json.dumps(svc['origin_request'], ensure_ascii=False)}")
    if svc.get("tcp_origin_confirmed"):
        print(f"note: {shown} is a raw TCP origin; clients need "
              f"`cloudflared access tcp --hostname {args.hostname} --url 127.0.0.1:<port>`")
    print("apply with: cfbridge up")


def cmd_demo(args) -> None:
    proj = project_dir(args)
    cfg = load_config(proj)
    if find_service(cfg, args.name):
        die(f"service {args.name} already registered")
    dst = os.path.join(proj, "services", "demo_origin.py")
    if not os.path.exists(dst):
        shutil.copy2(os.path.join(SKILL_DIR, "templates", "demo_origin.py"), dst)
    py = venv_python(proj)
    if not os.path.exists(py):
        # The demo cannot run without the venv; building it here keeps
        # `demo` from registering a service that can only crash-loop.
        print(f"building the service venv ({WEBSOCKETS_REQ}); this needs the sandbox proxy from cfbridge init")
        py = ensure_venv(proj)
    start_cmd = f"{py} {dst} --port {args.port} --key-file {proj}/secrets/bridge-key.txt"
    svc = {"name": args.name, "hostname": args.hostname, "port": args.port,
           "health": "/health", "auth": "key", "public_confirmed": False, "origin": "",
           "start_cmd": start_cmd, "workdir": proj, "env_proxy": False}
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
    if wanted:
        # Re-verify the recorded account first, then fall back to scanning.
        accounts = [a for a in accounts if a["id"] == wanted] + [a for a in accounts if a["id"] != wanted]
    errors: list[str] = []
    for a in accounts:
        try:
            return a["id"], cf_api.find_zone(a["id"], cfg["zone"])
        except cf_api.CfError as e:
            errors.append(f"{a['name']}: {e}")
    detail = "; ".join(errors[:3]) or "no accounts matched"
    die(f"zone {cfg['zone']} not found in any visible account ({detail})")


def ensure_tunnel_stack(proj: str, cfg: dict, force_dns: bool = False) -> tuple[str, str]:
    account_id, zone = resolve_account_zone(cfg)
    if cfg.get("account_id") != account_id:
        cfg["account_id"] = account_id
    tun = cf_api.ensure_tunnel(account_id, cfg["tunnel_name"])
    tunnel_id = tun["id"]
    if cfg.get("tunnel_id") != tunnel_id:
        cfg["tunnel_id"] = tunnel_id
    write_secret(proj, "tunnel-token.txt", tun["token"])
    write_secret(proj, "tunnel-id.txt", tunnel_id)
    cf_api.set_ingress(account_id, tunnel_id, cfg["services"])
    for s in cfg["services"]:
        res = cf_api.ensure_dns(zone["id"], s["hostname"], tunnel_id,
                                allow_overwrite=bool(force_dns or cfg.get("force_dns")))
        print(f"dns {s['hostname']}: {res}")
    save_config(proj, cfg)
    print(f"tunnel {cfg['tunnel_name']} ({tunnel_id}) ingress for {len(cfg['services'])} service(s)")
    return account_id, zone["id"]


# ---------------------------------------------------------------- units

def project_slug(proj: str) -> str:
    """Unit-name prefix: directory basename + short hash of its path.

    Two projects that happen to share a basename (.../a/bridge and
    .../b/bridge) would otherwise render identical unit names, and the
    second `up` would silently overwrite the first project's units.
    """
    base = slugify(os.path.basename(proj.rstrip("/")))
    digest = hashlib.sha256(os.path.abspath(proj).encode()).hexdigest()[:6]
    return f"{base}-{digest}"


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
            "PYTHON": python_bin(),
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
            "SERVICE_ENVFILE": (f"EnvironmentFile=-{proj}/secrets/proxy.env" if s.get("env_proxy") else ""),
        })
        p = os.path.join(out_dir, uname + ".service")
        open(p, "w", encoding="utf-8").write(text)
        written.append(uname)

    return written


def install_units(proj: str, units: list[str]) -> None:
    """Install rendered units into /etc/systemd/system.

    Units that were managed before but are not in the new list (renamed
    service, changed unit naming, removed service) are stopped, disabled
    and deleted — otherwise they linger and keep a stale ingress alive.
    """
    require_root("installing systemd units")
    src_dir = os.path.join(proj, "systemd")
    dst_dir = "/etc/systemd/system"
    previous: list[str] = []
    units_file = os.path.join(proj, "run", "managed-units.txt")
    if os.path.exists(units_file):
        with open(units_file, encoding="utf-8") as f:
            previous = [l.strip() for l in f if l.strip()]
    for u in previous:
        if u in units:
            continue
        dst = os.path.join(dst_dir, u + ".service")
        systemctl("stop", u)
        systemctl("disable", "--quiet", u)
        if os.path.exists(dst):
            os.remove(dst)
            print(f"removed stale unit {u}")
    changed = False
    for u in units:
        src = os.path.join(src_dir, u + ".service")
        dst = os.path.join(dst_dir, u + ".service")
        with open(src, encoding="utf-8") as f:
            new_text = f.read()
        old_text = ""
        if os.path.exists(dst):
            with open(dst, encoding="utf-8") as f:
                old_text = f.read()
        if old_text != new_text:
            shutil.copy2(src, dst)
            os.chmod(dst, 0o644)
            changed = True
    if changed or previous != units:
        systemctl("daemon-reload", check=True)
    for u in units:
        systemctl("enable", "--quiet", u)
    # Written only once the units are in place: render_units() must not
    # clobber the previous list before we have diffed against it.
    os.makedirs(os.path.join(proj, "run"), exist_ok=True)
    with open(os.path.join(proj, "run", "managed-units.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(units) + "\n")


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
    require_root("cfbridge up")
    normalized = False
    for s in cfg["services"]:
        normalized = normalize_origin(s) or normalized
    if normalized:
        save_config(proj, cfg)
        print("note: filled the default origin TLS decision for loopback https origin(s)")
    for s in cfg["services"]:
        # allow_public=False here on purpose: the public-exposure consent
        # is recorded once at add-service time (public_confirmed) and a
        # hand-edited config.json must not be able to skip it.
        validate_service(cfg, s, allow_public=False)

    adopt_project_proxy(proj)
    mode = detect_mode(proj, cfg)

    # Repair what cfbridge owns before judging anything: `up` is the
    # "bring it up" command, so a missing input it can supply itself
    # (cloudflared copy, venv, proxy.env, a free bridge port) must not
    # be a hard failure the user has to fix by hand.
    for line in heal_deps(proj, cfg, mode):
        print(f"fixed: {line}")
    cfg = load_config(proj)

    deps = collect_deps(proj, cfg, mode)
    missing = dep_missing(deps)
    if missing:
        print_deps(deps)
        detail = "; ".join(f"{d['name']}: {d['detail']}" for d in missing)
        die(f"{len(missing)} required dependency(ies) still missing -> {detail}")

    print(f"mode: {mode}")
    for line in prune_logs(proj, retention_hours=retention_hours_from_config(cfg)):
        print(f"logs: {line}")
    ensure_tunnel_stack(proj, cfg, force_dns=bool(getattr(args, "force_dns", False)))
    cfg = load_config(proj)
    units = render_units(proj, cfg, mode)
    install_units(proj, units)
    started = start_stack(proj, cfg, mode, restart=True)
    print(f"started: {', '.join(started) or 'nothing to start'}")
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
    require_root("cfbridge down")
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
    report: dict = {"project": proj, "units": {}, "services": []}
    for u in units:
        report["units"][u] = systemctl("is-active", u).stdout.strip()
    for s in cfg["services"]:
        entry = {"name": s["name"], "hostname": s["hostname"], "origin": cf_api.service_origin(s),
                 "auth": s.get("auth", "key")}
        health_path = s.get("health", "/health")
        try:
            status, _ = http_get(f"http://127.0.0.1:{s['port']}{health_path}", timeout=4)
            entry["local"] = str(status)
        except Exception as e:  # noqa: BLE001
            entry["local"] = f"fail ({type(e).__name__})"
        try:
            status, _ = http_get(f"https://{s['hostname']}{health_path}", timeout=10)
            entry["public"] = str(status)
        except Exception as e:  # noqa: BLE001
            entry["public"] = f"fail ({type(e).__name__})"
        report["services"].append(entry)
    if getattr(args, "json", False):
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return
    for u, state in report["units"].items():
        print(f"unit {u}: {state}")
    if not report["units"]:
        print("units: none recorded (run cfbridge up first)")
    for s in report["services"]:
        print(f"service {s['name']} ({s['hostname']} -> {s['origin']}, auth={s['auth']}): "
              f"local={s['local']} public={s['public']}")


# ---------------------------------------------------------------- verify (stdlib WS client)

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_TEXT, OP_CLOSE, OP_PING, OP_PONG = 0x1, 0x8, 0x9, 0xA


class WsClient:
    """Minimal RFC 6455 client: just enough for the verify checks.

    The bridge key goes in the X-Bridge-Key header, never in the query
    string — a query parameter ends up in Cloudflare's and the origin's
    access logs, which is exactly the kind of leak the key exists to
    prevent.
    """

    def __init__(self, hostname: str, path: str = "/ws", headers: dict | None = None, timeout: float = 8):
        self.hostname = hostname
        self.timeout = timeout
        ctx = ssl.create_default_context()
        raw = socket.create_connection((hostname, 443), timeout=timeout)
        raw.settimeout(timeout)
        self.sock = ctx.wrap_socket(raw, server_hostname=hostname)
        self.stash = b""
        self._handshake(path, headers or {})

    def _handshake(self, path: str, headers: dict) -> None:
        wskey = base64.b64encode(os.urandom(16)).decode()
        expected = base64.b64encode(hashlib.sha1((wskey + WS_GUID).encode()).digest()).decode()
        lines = [f"GET {path} HTTP/1.1", f"Host: {self.hostname}", "Upgrade: websocket",
                 "Connection: Upgrade", f"Sec-WebSocket-Key: {wskey}", "Sec-WebSocket-Version: 13"]
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        self.sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("handshake closed early")
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        status_line = head.split(b"\r\n", 1)[0]
        if b" 101 " not in status_line:
            raise RuntimeError(f"handshake failed: {status_line!r}")
        accept = ""
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"sec-websocket-accept:"):
                accept = line.split(b":", 1)[1].strip().decode()
        if accept != expected:
            # A mismatched accept means we are not talking to a real WS
            # origin (interceptor / wrong backend), not a fluke.
            raise RuntimeError(f"bad Sec-WebSocket-Accept: {accept!r}")
        self.stash = rest

    def _read_exact(self, n: int) -> bytes:
        while len(self.stash) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("socket closed")
            self.stash += chunk
        out, self.stash = self.stash[:n], self.stash[n:]
        return out

    def read_frame(self) -> tuple[int, bytes]:
        h = self._read_exact(2)
        opcode = h[0] & 0x0F
        ln = h[1] & 0x7F
        if ln == 126:
            ln = int.from_bytes(self._read_exact(2), "big")
        elif ln == 127:
            ln = int.from_bytes(self._read_exact(8), "big")
        mask = self._read_exact(4) if h[1] & 0x80 else b""
        payload = self._read_exact(ln)
        if mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return opcode, payload

    def read_text(self) -> str:
        """Next data frame as text, answering control frames in between."""
        while True:
            opcode, payload = self.read_frame()
            if opcode == OP_TEXT:
                return payload.decode("utf-8", "replace")
            if opcode == OP_PING:
                self.send_frame(OP_PONG, payload)
                continue
            if opcode == OP_CLOSE:
                code = int.from_bytes(payload[:2], "big") if len(payload) >= 2 else None
                raise WsClosed(code, payload[2:].decode("utf-8", "replace"))
            if opcode == OP_PONG:
                continue

    def send_frame(self, opcode: int, data: bytes) -> None:
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        header = bytes([0x80 | opcode])
        if len(data) < 126:
            header += bytes([0x80 | len(data)])
        elif len(data) < 1 << 16:
            header += bytes([0x80 | 126]) + len(data).to_bytes(2, "big")
        else:
            header += bytes([0x80 | 127]) + len(data).to_bytes(8, "big")
        self.sock.sendall(header + mask + masked)

    def send_text(self, text: str) -> None:
        self.send_frame(OP_TEXT, text.encode())

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class WsClosed(RuntimeError):
    def __init__(self, code: int | None, reason: str = ""):
        super().__init__(f"closed by server (code={code} reason={reason!r})")
        self.code = code
        self.reason = reason


def ws_roundtrip(hostname: str, key: str, timeout: float = 15) -> list[str]:
    """Connect with the shared key, greet, and expect greeting + echo."""
    conn = WsClient(hostname, headers={"X-Bridge-Key": key})
    got: list[str] = []
    deadline = time.time() + timeout
    conn.sock.settimeout(5)
    try:
        got.append(conn.read_text())
        conn.send_text("hello-cfbridge")
        while time.time() < deadline:
            text = conn.read_text()
            got.append(text)
            if text == "echo:hello-cfbridge":
                break
    finally:
        conn.close()
    return got


def ws_expect_rejected(hostname: str) -> str:
    """A key-protected origin must refuse a keyless upgrade.

    Returns a human-readable reason when the rejection was observed;
    raises RuntimeError when the server instead behaved like an open
    origin (greeting/serving data without a key).
    """
    try:
        conn = WsClient(hostname, headers={})
    except RuntimeError as e:
        return f"upgrade refused ({e})"
    try:
        conn.sock.settimeout(5)
        try:
            text = conn.read_text()
        except WsClosed as e:
            return f"closed without a key ({e})"
        raise RuntimeError(f"keyless client got data ({text[:40]!r}) — origin is not enforcing auth")
    finally:
        conn.close()


def cmd_verify(args) -> None:
    proj = project_dir(args)
    cfg = load_config(proj)
    key_path = os.path.join(proj, "secrets", "bridge-key.txt")
    key = open(key_path, encoding="utf-8").read().strip() if os.path.exists(key_path) else ""
    ok = True
    for s in cfg["services"]:
        host = s["hostname"]
        health_path = s.get("health", "/health")
        try:
            status, body = http_get(f"https://{host}{health_path}", timeout=15)
            print(f"{s['name']}: public health {status} {body.strip()[:40]!r}")
        except Exception as e:  # noqa: BLE001
            ok = False
            print(f"{s['name']}: public health FAILED ({e})")
            continue
        if not args.ws:
            continue
        if s.get("auth", "key") == "key" and not key:
            print(f"{s['name']}: no bridge key file; skip WS check")
            continue
        if s.get("auth", "key") == "key":
            try:
                # Public TLS via shared egress occasionally stalls on the
                # first try; a bounded retry is the documented norm.
                frames: list[str] | None = None
                last_err: Exception | None = None
                for attempt in range(3):
                    try:
                        frames = ws_roundtrip(host, key)
                        break
                    except Exception as e:  # noqa: BLE001
                        last_err = e
                        if attempt < 2:
                            time.sleep(2)
                if frames is None:
                    raise RuntimeError(str(last_err))
                joined = " | ".join(frames)
                good = any(f.startswith("server-greeting") for f in frames) and "echo:hello-cfbridge" in frames
                print(f"{s['name']}: WS with key {'ok' if good else 'UNEXPECTED'} [{joined[:120]}]")
                ok = ok and good
            except Exception as e:  # noqa: BLE001
                ok = False
                print(f"{s['name']}: WS with key FAILED ({e})")
                continue
            try:
                print(f"{s['name']}: WS without key rejected as expected — {ws_expect_rejected(host)}")
            except Exception as e:  # noqa: BLE001
                ok = False
                print(f"{s['name']}: WS without key NOT rejected ({e})")
        else:
            print(f"{s['name']}: auth=public, skipping WS auth checks")
    if not ok:
        raise SystemExit(1)
    print("verify: all checks passed")


# ---------------------------------------------------------------- autostart / teardown

def cmd_install_autostart(args) -> None:
    proj = project_dir(args)
    slug = project_slug(proj)
    hook_id = f"cfb-{slug}-keepalive"
    script_path = os.path.expanduser(f"~/hooks/scripts/{hook_id}.sh")
    text = render(read_template("keepalive-hook.sh.tmpl"),
                  {"PROJECT_DIR": proj, "SKILL_BIN": HERE})
    # dir_mode=None: ~/hooks/scripts is a shared, non-secret directory
    # owned by the hook runner, which may not be this user; leave its
    # permissions to the system umask as before.
    write_private(script_path, text, 0o750, dir_mode=None)
    print(f"hook script written: {script_path}")
    if not shutil.which("jq"):
        print("note: jq is not on PATH; the hook falls back to python3 for config parsing "
              "and skips wake-throttle state. Install jq for full behaviour.")
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
        require_root("cfbridge teardown (removing units)")
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
        deleted = cf_api.delete_tunnel_and_dns(account_id, zone["id"], tunnel_id,
                                               [s["hostname"] for s in cfg["services"]])
        for rec in deleted:
            print(f"dns deleted: {rec}")
        print(f"tunnel {cfg['tunnel_name']} deleted (records we did not create were left alone)")
    else:
        print("no tunnel recorded in config.json; nothing deleted on Cloudflare's side")
    if args.purge_project:
        # Only ever delete what we would also have created: a project dir
        # under $HOME. A typo'd --project outside it is refused outright.
        if not proj.startswith(os.path.expanduser("~/") ) or proj == os.path.expanduser("~"):
            die(f"refusing to purge {proj}: not a project directory under $HOME")
        if not os.path.exists(os.path.join(proj, "config.json")):
            die(f"refusing to purge {proj}: no config.json (not a cfbridge project)")
        shutil.rmtree(proj)
        print(f"project dir purged: {proj}")


# ---------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="cfbridge",
        description="Cloudflare named-tunnel stacks for Muse-style sandboxes: doctor, init, "
                    "add-service, demo, up, status, verify, down, install-autostart, teardown.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--project", help="project dir (default: $CFBRIDGE_PROJECT or cwd)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("doctor")
    p.add_argument("--json", action="store_true")
    p.add_argument("--fix", action="store_true",
                   help="repair the dependencies cfbridge owns (cloudflared copy, venv, "
                        "proxy.env, bridge port, units wiped from /etc) and start what is down")
    p.set_defaults(fn=cmd_doctor)

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
    p.add_argument("--origin-url", default="",
                   help="override the origin URL (default http://127.0.0.1:<port>). "
                        "http://, https:// and unix: are browser-reachable; "
                        "tcp://, ssh:// and rdp:// are raw streams that need "
                        "`cloudflared access` on the client (--allow-tcp-origin)")
    p.add_argument("--origin-tls-name", default="",
                   help="for an https:// origin: the name cloudflared should expect on "
                        "the origin certificate (sets originRequest.originServerName)")
    p.add_argument("--origin-no-verify", action="store_true",
                   help="for an https:// origin: skip origin certificate verification "
                        "(originRequest.noTLSVerify). Applied automatically to loopback "
                        "origins, which are self-signed by definition")
    p.add_argument("--origin-request", default="",
                   help='extra originRequest as a JSON object, e.g. '
                        '\'{"caPool": "/etc/ssl/certs/internal-ca.crt"}\'')
    p.add_argument("--allow-tcp-origin", action="store_true",
                   help="confirm a raw TCP origin (tcp://, ssh://, rdp://): browsers "
                        "cannot open it, clients must run cloudflared access")
    p.add_argument("--start-cmd", default="")
    p.add_argument("--workdir", default="")
    p.add_argument("--env-proxy", action="store_true")
    p.set_defaults(fn=cmd_add_service)

    p = sub.add_parser("demo")
    p.add_argument("--name", default="demo"); p.add_argument("--hostname", required=True)
    p.add_argument("--port", type=int, default=18099)
    p.set_defaults(fn=cmd_demo)

    p = sub.add_parser("up")
    p.add_argument("--force-dns", action="store_true",
                   help="allow rewriting DNS records this tool did not create")
    p.set_defaults(fn=cmd_up)
    sub.add_parser("down").set_defaults(fn=cmd_down)
    p = sub.add_parser("status"); p.add_argument("--json", action="store_true")
    p.set_defaults(fn=lambda a: cmd_status(a))
    p = sub.add_parser("verify"); p.add_argument("--ws", action="store_true"); p.set_defaults(fn=cmd_verify)
    p = sub.add_parser("prune-logs")
    p.add_argument("--retention-hours", type=float, default=None,
                   help=f"log window in hours (default config log_retention_hours, "
                        f"else {LOG_RETENTION_HOURS_DEFAULT:g}); 0 keeps logs forever")
    p.add_argument("--force", action="store_true", help="rotate now, ignoring the window")
    p.add_argument("--quiet", action="store_true", help="only report through the exit code")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_prune_logs)
    sub.add_parser("install-autostart").set_defaults(fn=cmd_install_autostart)
    p = sub.add_parser("teardown"); p.add_argument("--purge-project", action="store_true"); p.set_defaults(fn=cmd_teardown)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.fn(args)
    except cf_api.CfError as e:
        # A Cloudflare-side failure is a normal outcome to report, not a
        # traceback to dump at the user.
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
