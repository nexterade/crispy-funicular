#!/usr/bin/env python3
"""
HIKARI SUBCLASH OFFLINE ♥️  v2
URI <-> Clash (Mihomo) converter + generator config untuk Box / Nikki / OpenClash.
"""

import base64
import copy
import glob
import json
import os
import re
import secrets
import shutil
import sys
import time
from urllib.parse import parse_qs, quote, unquote, urlsplit

try:
    import yaml
except ImportError:
    print("[!] PyYAML belum terpasang. Jalankan: pip install pyyaml")
    sys.exit(1)

# ---------- PATH CONFIG (semua relatif ke lokasi script, bukan cwd) ----------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.join(SCRIPT_DIR, "Hasil")
RULESET_SOURCE = os.path.join(SCRIPT_DIR, "ruleset")
TEMPLATE_PATH = os.path.join(SCRIPT_DIR, "template.yaml")   # working copy (boleh diedit lewat menu)
TEMPLATE_GLOB = "config-template-v*.yaml"                   # master; dipakai kalau template.yaml belum ada

# node dari link biasanya pakai bug-host/SNI custom -> cert tidak cocok.
# Kalau link eksplisit bilang allowInsecure=0 maka dihormati.
DEFAULT_SKIP_CERT_VERIFY = True

NIKKI_RUN_DIR = "/etc/nikki/run"
WIFI_PROVIDER = "WifiClients"

PLATFORMS = {
    "box": {
        "label": "Box for Root (Android)", "out": "full_config_box",
        "proxy_dir": "proxy", "rule_dir": "ruleset", "prefix": "./",
    },
    "nikki": {
        "label": "Nikki (OpenWrt)", "out": "full_config_nikki",
        "proxy_dir": "proxy", "rule_dir": "ruleset", "prefix": NIKKI_RUN_DIR + "/",
    },
    "openclash": {
        "label": "OpenClash (OpenWrt)", "out": "full_config_openclash",
        "proxy_dir": "proxy_provider", "rule_dir": "rule_provider", "prefix": "./",
    },
}

# Port & key khusus Box for Root (diambil dari template v0.1 varian BFR)
BOX_TOP_LEVEL = {
    "mixed-port": 7890, "port": 7891, "socks-port": 7892,
    "redir-port": 9797, "tproxy-port": 9898,
    "external-controller": "127.0.0.1:9090",   # Android: jangan buka ke LAN
    "find-process-mode": "always",              # dashboard > Connections nampilin package app
    "geodata-mode": True,
    "experimental": {"quic-go-disable-gso": True},
}
BOX_DNS_LISTEN = "0.0.0.0:1053"                 # Box tproxy ngarahin DNS ke port ini
BOX_TUN = {                                     # TUN dikelola Box (settings.ini) -> default off
    "enable": False, "mtu": 9000, "device": "meta", "stack": "mixed",
    "dns-hijack": ["any:53", "tcp://any:53"],
    "auto-route": True, "strict-route": True, "auto-redirect": True,
    "auto-detect-interface": True,
    "include-android-user": [0, 10, 999], "exclude-package": [], "include-package": [],
}


# ---------- ANSI / Style ----------
class C:
    _on = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    RESET   = "\033[0m"  if _on else ""
    BOLD    = "\033[1m"  if _on else ""
    DIM     = "\033[2m"  if _on else ""
    RED     = "\033[91m" if _on else ""
    GREEN   = "\033[92m" if _on else ""
    YELLOW  = "\033[93m" if _on else ""
    CYAN    = "\033[96m" if _on else ""
    MAGENTA = "\033[95m" if _on else ""
    WHITE   = "\033[97m" if _on else ""
    GRAY    = "\033[90m" if _on else ""


def clear_screen():
    if sys.stdout.isatty():
        os.system('cls' if os.name == 'nt' else 'clear')


def sep(width=50, color=None):
    return (color or C.GRAY) + "─" * width + C.RESET


def section(title, width=50):
    t = f" {title} "; pad = max(0, width - len(t)); left = pad // 2; right = pad - left
    print(C.GRAY + "─" * left + C.RESET + C.BOLD + C.WHITE + t + C.RESET + C.GRAY + "─" * right + C.RESET)


def banner():
    print(f"\n  {C.BOLD}{C.MAGENTA}HIKARI SUBCLASH{C.RESET}")
    print(f"  {C.DIM}VLESS · VMess · Trojan  ↔  Mihomo / Clash Meta{C.RESET}")
    print(sep(50, C.MAGENTA) + "\n")


def spinner(msg, duration=0.6):
    if not sys.stdout.isatty():
        return
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]; end = time.time() + duration; i = 0
    while time.time() < end:
        sys.stdout.write(f"\r{C.CYAN}{frames[i % len(frames)]}{C.RESET} {msg}"); sys.stdout.flush(); time.sleep(0.05); i += 1
    sys.stdout.write("\r" + " " * (len(msg) + 4) + "\r"); sys.stdout.flush()


def truncate(text, length):
    return text if len(text) <= length else text[:length - 3] + "..."


def ask(prompt):
    """input() yang aman: EOF (Ctrl+D / stdin habis) = keluar bersih, bukan loop tak berujung."""
    try:
        return input(prompt)
    except EOFError:
        print()
        raise SystemExit(0)


def pause(msg="Tekan Enter untuk kembali..."):
    ask(f"\n{C.DIM}{msg}{C.RESET}")


def ok(msg):   print(f"{C.GREEN}✓{C.RESET} {msg}")
def err(msg):  print(f"{C.RED}✗ {msg}{C.RESET}")
def warn(msg): print(f"{C.YELLOW}! {msg}{C.RESET}")


# =====================================================================
#  Parser URI -> node Clash
# =====================================================================
def _qs(query):
    return {k: v[0] for k, v in parse_qs(query, keep_blank_values=True).items()}


def _flag(value, default):
    if value is None or value == "":
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _userinfo(p):
    return unquote(p.netloc.rpartition("@")[0])


def _host_port(p, default_port=443):
    try:
        port = p.port
    except ValueError:
        raise ValueError("port tidak valid")
    if not p.hostname:
        raise ValueError("server kosong")
    return p.hostname, int(port or default_port)


def _alpn(value):
    return [x.strip() for x in value.split(",") if x.strip()] if value else None


def _apply_transport(node, net, path, host_hdr, service_name=""):
    """Isi network + opts transport. Transport yang belum didukung -> error jelas (bukan node rusak diam-diam)."""
    net = (net or "tcp").lower()
    if net in ("tcp", "raw", ""):
        node["network"] = "tcp"
    elif net == "ws":
        node["network"] = "ws"
        opts = {"path": path or "/"}
        if host_hdr:
            opts["headers"] = {"Host": host_hdr}
        node["ws-opts"] = opts
    elif net == "httpupgrade":
        node["network"] = "ws"
        opts = {"path": path or "/", "v2ray-http-upgrade": True}
        if host_hdr:
            opts["headers"] = {"Host": host_hdr}
        node["ws-opts"] = opts
    elif net == "grpc":
        node["network"] = "grpc"
        node["grpc-opts"] = {"grpc-service-name": service_name or ""}
    elif net in ("h2", "http"):
        node["network"] = "h2"
        opts = {"path": path or "/"}
        if host_hdr:
            opts["host"] = [host_hdr]
        node["h2-opts"] = opts
    else:
        raise ValueError(f"transport '{net}' belum didukung")


def parse_vless(uri):
    p = urlsplit(uri); q = _qs(p.query)
    host, port = _host_port(p)
    uuid = _userinfo(p)
    if not uuid:
        raise ValueError("UUID kosong")
    sec = q.get("security", "none").lower()
    net = q.get("type", "tcp").lower()
    sni = q.get("sni") or q.get("peer") or q.get("host") or host
    tls = sec in ("tls", "reality")

    node = {"name": unquote(p.fragment).strip() or f"{host}:{port}", "type": "vless",
            "server": host, "port": port, "uuid": uuid, "udp": True, "tls": tls}
    if tls:
        node["servername"] = sni
        node["skip-cert-verify"] = _flag(q.get("allowInsecure") or q.get("insecure"), DEFAULT_SKIP_CERT_VERIFY)
        alpn = _alpn(q.get("alpn"))
        if alpn:
            node["alpn"] = alpn
    if q.get("flow"):
        node["flow"] = q["flow"]
    fp = q.get("fp")
    if fp or sec == "reality":
        node["client-fingerprint"] = fp or "chrome"
    if sec == "reality":
        if not q.get("pbk"):
            raise ValueError("reality tanpa public key (pbk)")
        node["reality-opts"] = {"public-key": q["pbk"], "short-id": q.get("sid", "")}
    _apply_transport(node, net, q.get("path", "/"), q.get("host") or (sni if net in ("ws", "httpupgrade") else ""),
                     q.get("serviceName", ""))
    return node


def parse_vmess(uri):
    raw = uri[len("vmess://"):].strip().replace("-", "+").replace("_", "/")
    raw += "=" * (-len(raw) % 4)
    try:
        d = json.loads(base64.b64decode(raw).decode("utf-8"))
    except Exception:
        raise ValueError("Base64/JSON vmess tidak valid")
    server = d.get("add")
    if not server:
        raise ValueError("server kosong")
    if not d.get("id"):
        raise ValueError("UUID kosong")
    try:
        port = int(d.get("port") or 443)
    except (TypeError, ValueError):
        raise ValueError("port tidak valid")
    net = str(d.get("net", "tcp") or "tcp").lower()
    tls = str(d.get("tls", "")).lower() in ("tls", "reality")
    sni = d.get("sni") or d.get("host") or server
    node = {"name": str(d.get("ps") or f"{server}:{port}").strip(), "type": "vmess",
            "server": server, "port": port, "uuid": d["id"],
            "alterId": int(d.get("aid", 0) or 0), "cipher": d.get("scy") or "auto",
            "udp": True, "tls": tls}
    if tls:
        node["servername"] = sni
        node["skip-cert-verify"] = DEFAULT_SKIP_CERT_VERIFY
        alpn = _alpn(d.get("alpn"))
        if alpn:
            node["alpn"] = alpn
        if d.get("fp"):
            node["client-fingerprint"] = d["fp"]
    path = d.get("path", "") or ""
    _apply_transport(node, net, path or "/", d.get("host") or (sni if net in ("ws", "httpupgrade", "h2") else ""),
                     path)
    return node


def parse_trojan(uri):
    p = urlsplit(uri); q = _qs(p.query)
    host, port = _host_port(p)
    password = _userinfo(p)          # di-unquote: %40 -> @, dst
    if not password:
        raise ValueError("password kosong")
    net = q.get("type", "tcp").lower()
    sni = q.get("sni") or q.get("peer") or host
    node = {"name": unquote(p.fragment).strip() or f"{host}:{port}", "type": "trojan",
            "server": host, "port": port, "password": password, "sni": sni, "udp": True,
            "skip-cert-verify": _flag(q.get("allowInsecure") or q.get("insecure"), DEFAULT_SKIP_CERT_VERIFY)}
    alpn = _alpn(q.get("alpn"))
    if alpn:
        node["alpn"] = alpn
    if q.get("fp"):
        node["client-fingerprint"] = q["fp"]
    _apply_transport(node, net, q.get("path", "/"), q.get("host") or (sni if net in ("ws", "httpupgrade") else ""),
                     q.get("serviceName", ""))
    return node


def convert_line(line):
    line = line.strip()
    if not line:
        return None
    if line.startswith("vless://"):  return parse_vless(line)
    if line.startswith("vmess://"):  return parse_vmess(line)
    if line.startswith("trojan://"): return parse_trojan(line)
    raise ValueError("bukan vless/vmess/trojan")


def dedupe_names(nodes, taken=()):
    """Nama proxy harus unik. Duplikat jadi 'Nama (2)', 'Nama (3)', ..."""
    seen = set(taken)
    for n in nodes:
        base = n["name"]; name = base; i = 2
        while name in seen:
            name = f"{base} ({i})"; i += 1
        n["name"] = name; seen.add(name)
    return nodes


# =====================================================================
#  Parser node Clash -> URI
# =====================================================================
def _qv(s, safe="", encoding=None, errors=None):
    return quote(str(s), safe="")


def _query(params):
    return "&".join(f"{quote(str(k), safe='')}={_qv(v)}" for k, v in params.items())


def _fmt_host(server):
    server = str(server)
    return f"[{server}]" if ":" in server and not server.startswith("[") else server


def build_uri_from_proxy(p):
    t = str(p.get("type", "")).lower()
    name = str(p.get("name", "Node"))
    server = p.get("server", ""); port = p.get("port", 443)
    host_uri = _fmt_host(server)
    net = str(p.get("network", "tcp") or "tcp").lower()
    ws = p.get("ws-opts") or {}
    grpc = p.get("grpc-opts") or {}
    h2 = p.get("h2-opts") or {}
    if net == "ws" and ws.get("v2ray-http-upgrade"):
        net = "httpupgrade"
    host_hdr = (ws.get("headers") or {}).get("Host", "") or (h2.get("host") or [""])[0]
    path = ws.get("path") or h2.get("path") or ""
    alpn = ",".join(p["alpn"]) if isinstance(p.get("alpn"), list) else (p.get("alpn") or "")

    if t == "vmess":
        d = {"v": "2", "ps": name, "add": server, "port": str(port), "id": p.get("uuid", ""),
             "aid": str(p.get("alterId", 0)), "scy": p.get("cipher", "auto"), "net": net,
             "type": "none", "host": host_hdr, "path": path, "tls": "tls" if p.get("tls") else "",
             "sni": p.get("servername", "")}
        if net == "grpc":
            d["path"] = grpc.get("grpc-service-name", "")
        if alpn:
            d["alpn"] = alpn
        if p.get("client-fingerprint"):
            d["fp"] = p["client-fingerprint"]
        return "vmess://" + base64.b64encode(json.dumps(d, separators=(",", ":"), ensure_ascii=False).encode()).decode()

    params = {}
    if t == "vless":
        params["encryption"] = "none"
        sec = "reality" if p.get("reality-opts") else ("tls" if p.get("tls") else "none")
        if sec != "none":
            params["security"] = sec
        if net != "tcp":
            params["type"] = net
        if p.get("flow"):
            params["flow"] = p["flow"]
        if p.get("servername"):
            params["sni"] = p["servername"]
        if p.get("client-fingerprint"):
            params["fp"] = p["client-fingerprint"]
        if alpn:
            params["alpn"] = alpn
        if sec == "tls" and p.get("skip-cert-verify"):
            params["allowInsecure"] = "1"
        if net in ("ws", "httpupgrade", "h2"):
            if path:
                params["path"] = path
            if host_hdr:
                params["host"] = host_hdr
        elif net == "grpc" and grpc.get("grpc-service-name"):
            params["serviceName"] = grpc["grpc-service-name"]
        ro = p.get("reality-opts") or {}
        if ro.get("public-key"): params["pbk"] = ro["public-key"]
        if ro.get("short-id"):   params["sid"] = ro["short-id"]
        return f"vless://{quote(str(p.get('uuid', '')), safe='')}@{host_uri}:{port}?{_query(params)}#{quote(name, safe='')}"

    if t == "trojan":
        params["security"] = "tls"
        if p.get("sni"):
            params["sni"] = p["sni"]
        if net != "tcp":
            params["type"] = net
        if alpn:
            params["alpn"] = alpn
        if p.get("client-fingerprint"):
            params["fp"] = p["client-fingerprint"]
        if p.get("skip-cert-verify"):
            params["allowInsecure"] = "1"
        if net in ("ws", "httpupgrade", "h2"):
            if path:
                params["path"] = path
            if host_hdr:
                params["host"] = host_hdr
        elif net == "grpc" and grpc.get("grpc-service-name"):
            params["serviceName"] = grpc["grpc-service-name"]
        return f"trojan://{quote(str(p.get('password', '')), safe='')}@{host_uri}:{port}?{_query(params)}#{quote(name, safe='')}"
    return None


# =====================================================================
#  Template: lokasi, baca, edit teks (komentar template dijaga)
# =====================================================================
def _ver_key(path):
    m = re.search(r"v(\d+(?:\.\d+)*)", os.path.basename(path))
    return tuple(int(x) for x in m.group(1).split(".")) if m else (0,)


def list_master_templates():
    return sorted(glob.glob(os.path.join(SCRIPT_DIR, TEMPLATE_GLOB)), key=_ver_key)


def find_template():
    """template.yaml (working copy) > config-template-vX.Y.yaml terbaru."""
    if os.path.isfile(TEMPLATE_PATH):
        return TEMPLATE_PATH
    masters = list_master_templates()
    return masters[-1] if masters else None


def ensure_working_template():
    """Edit selalu dilakukan di template.yaml; master config-template-v*.yaml dibiarkan utuh."""
    if os.path.isfile(TEMPLATE_PATH):
        return TEMPLATE_PATH
    src = find_template()
    if not src:
        return None
    shutil.copyfile(src, TEMPLATE_PATH)
    return TEMPLATE_PATH


def read_text(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def backup_file(path):
    try:
        shutil.copyfile(path, path + ".bak")
    except OSError:
        pass


def load_template_cfg(path=None):
    path = path or find_template()
    if not path:
        raise FileNotFoundError("template tidak ditemukan (template.yaml / config-template-v*.yaml)")
    cfg = yaml.safe_load(read_text(path))
    if not isinstance(cfg, dict):
        raise ValueError("template bukan YAML mapping")
    return cfg


def reserved_names():
    try:
        cfg = load_template_cfg()
    except Exception:
        return set()
    names = {x.get("name") for x in (cfg.get("proxies") or []) if isinstance(x, dict)}
    names |= {x.get("name") for x in (cfg.get("proxy-groups") or []) if isinstance(x, dict)}
    return {n for n in names if n}


def set_top_scalar(content, key, value_text):
    """Ganti 'key: ...' level-atas (kolom 0). Return (content_baru, ditemukan)."""
    pat = re.compile(rf"^{re.escape(key)}:.*$", re.M)
    if not pat.search(content):
        return content, False
    return pat.sub(lambda m: f"{key}: {value_text}", content, count=1), True


def yaml_quote(s):
    return "'" + str(s).replace("'", "''") + "'"


def _block_bounds(lines, key):
    start = next((i for i, l in enumerate(lines) if re.match(rf"^{re.escape(key)}:\s*(#.*)?$", l)), None)
    if start is None:
        return None
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if lines[j].strip() and lines[j][0] not in (" ", "\t"):
            end = j; break
    return start, end


def block_set_list(content, block, key, items):
    """Ganti daftar `key` di dalam blok level-atas `block` (mis. dns/nameserver). Format asli (indent) dijaga."""
    lines = content.split("\n")
    b = _block_bounds(lines, block)
    if not b:
        return content, False
    s, e = b
    for i in range(s + 1, e):
        m = re.match(rf"^(\s+){re.escape(key)}:\s*(\[.*\])?\s*(#.*)?$", lines[i])
        if not m:
            continue
        indent = m.group(1)
        j = i + 1
        if not m.group(2):
            while j < e and re.match(r"^\s*-\s", lines[j]):
                j += 1
        lines[i:j] = [f"{indent}{key}:"] + [f"{indent}  - {x}" for x in items]
        return "\n".join(lines), True
    # key belum ada -> sisipkan di akhir blok
    last = e
    while last > s + 1 and not lines[last - 1].strip():
        last -= 1
    child_indent = next((re.match(r"^(\s+)\S", l).group(1) for l in lines[s + 1:e] if l.strip() and not l.strip().startswith("#")), "  ")
    lines[last:last] = [f"{child_indent}{key}:"] + [f"{child_indent}  - {x}" for x in items]
    return "\n".join(lines), True


# =====================================================================
#  Build config per platform (YAML dict -> patch -> dump)
# =====================================================================
class _Dumper(yaml.SafeDumper):
    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)


def dump_yaml(data):
    return yaml.dump(data, Dumper=_Dumper, allow_unicode=True, sort_keys=False,
                     default_flow_style=False, width=4096, indent=2)


def _remap_path(path, platform):
    P = PLATFORMS[platform]
    if not isinstance(path, str):
        return path
    for old, folder in (("./proxy/", P["proxy_dir"]), ("./ruleset/", P["rule_dir"])):
        if path.startswith(old):
            return f'{P["prefix"]}{folder}/{path[len(old):]}'
    return path


def _drop_wifi(cfg):
    """Di OpenWrt semua client LAN punya IP sumber 192.168.x.x -> rule WifiClients bakal menangkap SEMUA trafik."""
    dropped_groups = set()
    rules = []
    for r in cfg.get("rules") or []:
        parts = [x.strip() for x in str(r).split(",")]
        if len(parts) >= 3 and parts[0] == "RULE-SET" and parts[1] == WIFI_PROVIDER:
            dropped_groups.add(parts[2]); continue
        rules.append(r)
    cfg["rules"] = rules
    (cfg.get("rule-providers") or {}).pop(WIFI_PROVIDER, None)
    groups = []
    for g in cfg.get("proxy-groups") or []:
        if g.get("name") in dropped_groups:
            continue
        if isinstance(g.get("proxies"), list):
            g["proxies"] = [x for x in g["proxies"] if x not in dropped_groups]
        groups.append(g)
    cfg["proxy-groups"] = groups
    return bool(dropped_groups)


def build_config(tpl_text, platform, provider_mode="template"):
    """Return (cfg_dict, notes). provider_mode: 'template' (ikut template) | 'offline' (http -> file lokal)."""
    cfg = yaml.safe_load(tpl_text)
    if not isinstance(cfg, dict):
        raise ValueError("template bukan YAML mapping")
    cfg = copy.deepcopy(cfg)
    notes = []

    if platform == "box":
        cfg.update(copy.deepcopy(BOX_TOP_LEVEL))
        if isinstance(cfg.get("dns"), dict):
            cfg["dns"]["listen"] = BOX_DNS_LISTEN
        cfg["tun"] = copy.deepcopy(BOX_TUN)
        notes.append("Box: port 9797/9898, dns 1053, blok tun (off), find-process-mode disuntik")
    else:
        if cfg.pop("tun", None) is not None:
            notes.append("tun dihapus dari profile (dikelola Nikki/OpenClash)")
        cfg.pop("find-process-mode", None)
        cfg["external-controller"] = "0.0.0.0:9090"
        if _drop_wifi(cfg):
            notes.append("rule/group/provider WIFI dibuang (SRC-IP 192.168/16 menangkap semua client LAN di OpenWrt)")

    for sect in ("proxy-providers", "rule-providers"):
        for prov in (cfg.get(sect) or {}).values():
            if isinstance(prov, dict) and "path" in prov:
                prov["path"] = _remap_path(prov["path"], platform)

    if provider_mode == "offline":
        n = 0
        for prov in (cfg.get("rule-providers") or {}).values():
            if prov.get("type") == "http":
                prov["type"] = "file"
                for k in ("url", "interval", "proxy"):
                    prov.pop(k, None)
                n += 1
        notes.append(f"mode offline: {n} rule-provider http -> file (tanpa update otomatis)")

    if not cfg.get("secret"):
        cfg["secret"] = secrets.token_urlsafe(9)
        notes.append("secret kosong di template -> dibuat acak")
    return cfg, notes


def render_config(cfg, platform, version_hint=""):
    P = PLATFORMS[platform]
    header = (
        "# =====================================================\n"
        f"# HIKARI — config untuk {P['label']}\n"
        f"# Dibuat : {time.strftime('%Y-%m-%d %H:%M:%S')} oleh hikari_converter.py {version_hint}\n"
        "# File ini hasil generate: edit template-nya, lalu generate ulang.\n"
        "# =====================================================\n\n"
    )
    body = dump_yaml(cfg)
    out, first = [], True
    for line in body.split("\n"):          # baris kosong antar section biar enak dibaca
        if re.match(r"^[A-Za-z0-9_-]+:\s*$", line):    # hanya section berblok (dns:, rules:, ...)
            if not first:
                out.append("")
            first = False
        out.append(line)
    return header + "\n".join(out)


# =====================================================================
#  Validator (audit otomatis)
# =====================================================================
BUILTIN_TARGETS = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"}


def _port_of(addr):
    m = re.search(r":(\d+)$", str(addr or ""))
    return int(m.group(1)) if m else None


def validate_config(cfg, platform, out_dir=None):
    """Return list[(level, msg)] level: 'ERR' | 'WARN'."""
    issues = []
    E = lambda m: issues.append(("ERR", m))
    W = lambda m: issues.append(("WARN", m))
    P = PLATFORMS[platform]

    builtin = [x.get("name") for x in cfg.get("proxies") or [] if isinstance(x, dict)]
    groups = [g.get("name") for g in cfg.get("proxy-groups") or []]
    allnames = builtin + groups
    for n in {x for x in allnames if allnames.count(x) > 1}:
        E(f"nama proxy/group duplikat: {n}")
    valid_targets = set(allnames) | BUILTIN_TARGETS
    pproviders = cfg.get("proxy-providers") or {}
    rproviders = cfg.get("rule-providers") or {}

    for g in cfg.get("proxy-groups") or []:
        for x in g.get("proxies") or []:
            if x not in valid_targets:
                E(f"group '{g['name']}' mengacu ke '{x}' yang tidak ada")
        for u in g.get("use") or []:
            if u not in pproviders:
                E(f"group '{g['name']}' memakai proxy-provider '{u}' yang tidak ada")
        if not g.get("proxies") and not g.get("use"):
            E(f"group '{g['name']}' kosong (tanpa proxies/use)")

    for r in cfg.get("rules") or []:
        parts = [x.strip() for x in str(r).split(",")]
        if parts[0] == "MATCH":
            target = parts[1] if len(parts) > 1 else ""
        elif parts[0] in ("AND", "OR", "NOT", "SUB-RULE"):
            continue
        else:
            target = parts[2] if len(parts) > 2 else ""
            if parts[0] == "RULE-SET" and len(parts) > 1 and parts[1] not in rproviders:
                E(f"rule mengacu ke rule-provider '{parts[1]}' yang tidak ada: {r}")
        if target and target not in valid_targets:
            E(f"rule menuju '{target}' yang tidak ada: {r}")
    if not (cfg.get("rules") or [""])[-1].startswith("MATCH"):
        W("rule terakhir bukan MATCH (traffic yang tidak cocok akan ke DIRECT)")

    def check_rs(items, where):
        for it in items or []:
            if isinstance(it, str) and it.startswith("rule-set:") and it[9:] not in rproviders:
                E(f"{where} mengacu ke rule-provider '{it[9:]}' yang tidak ada")
    check_rs((cfg.get("sniffer") or {}).get("skip-domain"), "sniffer.skip-domain")
    check_rs((cfg.get("sniffer") or {}).get("force-domain"), "sniffer.force-domain")
    check_rs((cfg.get("dns") or {}).get("fake-ip-filter"), "dns.fake-ip-filter")

    for name, pv in rproviders.items():
        t = pv.get("type")
        if t == "http" and not pv.get("url"):
            E(f"rule-provider '{name}' type http tanpa url")
        if pv.get("format") == "mrs" and pv.get("behavior") not in ("domain", "ipcidr"):
            E(f"rule-provider '{name}' format mrs hanya untuk behavior domain/ipcidr")
        if t in ("http", "file") and not pv.get("path"):
            E(f"rule-provider '{name}' tanpa path")
        if t == "http" and not pv.get("interval"):
            W(f"rule-provider '{name}' http tanpa interval (tidak pernah auto-update)")

    # port bentrok
    used = {}
    for k in ("port", "socks-port", "redir-port", "mixed-port", "tproxy-port"):
        if cfg.get(k):
            used.setdefault(cfg[k], []).append(k)
    for k, v in (("external-controller", cfg.get("external-controller")),
                 ("dns.listen", (cfg.get("dns") or {}).get("listen"))):
        pt = _port_of(v)
        if pt:
            used.setdefault(pt, []).append(k)
    for pt, ks in used.items():
        if len(ks) > 1:
            E(f"port {pt} dipakai ganda: {', '.join(ks)}")

    ec = str(cfg.get("external-controller", ""))
    if ec and not ec.startswith(("127.", "localhost", "[::1]")) and not cfg.get("secret"):
        E("external-controller terbuka ke LAN tanpa secret")
    if platform != "box":
        if "tun" in cfg:
            W("blok tun ada di profile OpenWrt (bisa bentrok dengan firewall Nikki/OpenClash)")
        if WIFI_PROVIDER in rproviders:
            E("WifiClients masih ada di profile OpenWrt: semua client LAN (192.168.x.x) akan lolos ke Direct")
    dns = cfg.get("dns") or {}
    if dns.get("respect-rules") and not dns.get("proxy-server-nameserver"):
        E("dns.respect-rules aktif tapi proxy-server-nameserver kosong")
    psn = dns.get("proxy-server-nameserver") or []
    if psn and all("://" in str(x) for x in psn):
        W("proxy-server-nameserver DoH semua: kalau ISP me-reset DoH, domain server proxy tidak bisa di-resolve (semua node timeout)")
    plain = [x for x in (dns.get("nameserver") or []) + (dns.get("fallback") or [])
             if isinstance(x, str) and "://" not in x]
    if plain:
        W("DNS polos (non-DoH) di nameserver/fallback -> bisa bocor ke ISP: " + ", ".join(map(str, plain)))

    if out_dir:
        def local(path):
            if not isinstance(path, str):
                return None
            if path.startswith(P["prefix"]):
                return os.path.join(out_dir, path[len(P["prefix"]):])
            return None
        for sect, d in (("proxy-provider", pproviders), ("rule-provider", rproviders)):
            for name, pv in d.items():
                if pv.get("type") == "file" or (sect == "rule-provider" and pv.get("path")):
                    lp = local(pv.get("path"))
                    if lp and not os.path.isfile(lp):
                        E(f"{sect} '{name}': file tidak ada -> {pv['path']}")
        for fn in glob.glob(os.path.join(out_dir, P["rule_dir"], "*.yaml")):
            try:
                if os.path.getsize(fn) > 200_000:
                    W(f"{os.path.basename(fn)} besar ({os.path.getsize(fn)//1024} KB) — pertimbangkan menu Tools > Padatkan port")
            except OSError:
                pass
    return issues


def print_issues(issues):
    if not issues:
        ok("Validasi: tidak ada masalah.")
        return
    for lvl, msg in issues:
        (err if lvl == "ERR" else warn)(msg)


# =====================================================================
#  File operations
# =====================================================================
def prepare_dirs():
    os.makedirs(BASE_DIR, exist_ok=True)


def load_provider_nodes(path):
    if not os.path.isfile(path):
        return []
    try:
        data = yaml.safe_load(read_text(path))
    except Exception:
        return []
    return [x for x in (data or {}).get("proxies", []) or [] if isinstance(x, dict)] if isinstance(data, dict) else []


def save_proxy_yaml(proxies, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write(dump_yaml({"proxies": proxies}))


def setup_full_config(proxies, target_name, platform, provider_mode="template", write_mode="replace"):
    """Return (out_dir, notes, issues, error)."""
    tpl = find_template()
    if not tpl:
        return None, [], [], "template tidak ditemukan (template.yaml / config-template-v*.yaml)"
    if not os.path.isdir(RULESET_SOURCE):
        return None, [], [], f"folder 'ruleset' tidak ditemukan di samping script ({RULESET_SOURCE})"

    P = PLATFORMS[platform]
    out_dir = os.path.join(BASE_DIR, P["out"])
    proxy_dir = os.path.join(out_dir, P["proxy_dir"])
    try:
        os.makedirs(proxy_dir, exist_ok=True)
        cfg, notes = build_config(read_text(tpl), platform, provider_mode)

        # node: dedupe terhadap nama bawaan template (+ node lama kalau mode append)
        target_path = os.path.join(proxy_dir, target_name)
        existing = load_provider_nodes(target_path) if write_mode == "append" else []
        nodes = dedupe_names([dict(n) for n in proxies], reserved_names() | {x["name"] for x in existing})
        save_proxy_yaml(existing + nodes, target_path)

        other = os.path.join(proxy_dir, "trial.yaml" if target_name == "active.yaml" else "active.yaml")
        if not os.path.exists(other):
            with open(other, "w", encoding="utf-8") as f:
                f.write("proxies: []\n")

        target_rules = os.path.join(out_dir, P["rule_dir"])
        if os.path.exists(target_rules):
            shutil.rmtree(target_rules)
        shutil.copytree(RULESET_SOURCE, target_rules)

        with open(os.path.join(out_dir, "config.yaml"), "w", encoding="utf-8") as f:
            f.write(render_config(cfg, platform, "v2"))
    except PermissionError as e:
        return None, [], [], f"PermissionError: {e}. Taruh folder script di /storage/emulated/0/ (bukan ~ Termux)."
    except (OSError, ValueError, yaml.YAMLError) as e:
        return None, [], [], str(e)

    issues = validate_config(cfg, platform, out_dir)
    return out_dir, notes, issues, None


# =====================================================================
#  Feature: URI -> Clash
# =====================================================================
def _collect_lines(prompt_lines):
    for ln in prompt_lines:
        print(f"  {C.DIM}{ln}{C.RESET}")
    print(sep(50) + "\n")
    lines = []
    while True:
        try:
            s = input(f"{C.CYAN}❯{C.RESET} ")
        except EOFError:
            break
        if s.strip().lower() in ("batal", "batalkan"):
            return None
        if s.strip() == "":
            break
        lines.append(s)
    return lines


def feature_convert_to_clash():
    print()
    section("Masukkan node (Format URI)")
    lines = _collect_lines(["Paste vless:// atau vmess:// atau trojan:// (satu per baris).",
                            "Tekan Enter 2x untuk selesai.", "Ketik 'batal' untuk kembali ke menu."])
    if lines is None:
        return
    if not lines:
        err("Tidak ada input."); time.sleep(1.2); return

    while True:
        valid, invalid = [], []
        for i, ln in enumerate(lines):
            if not ln.strip():
                continue
            try:
                n = convert_line(ln)
                if n:
                    n["_orig_idx"] = i; valid.append(n)
            except Exception as e:
                invalid.append((i, ln.strip(), str(e)))

        clear_screen(); banner()
        section(f"Preview Input ({len(valid)} Valid, {len(invalid)} Gagal)")
        if valid:
            print(f"  {C.BOLD}{'No':<4} | {'Tipe':<7} | {'Nama Node':<20} | {'Server'}{C.RESET}")
            print(f"  {C.GRAY}{'-'*4}-+-{'-'*7}-+-{'-'*20}-+-{'-'*15}{C.RESET}")
            for idx, p in enumerate(valid, 1):
                print(f"  {C.CYAN}{idx:<4}{C.RESET} | {p['type'].upper():<7} | "
                      f"{truncate(str(p['name']), 20):<20} | {C.DIM}{truncate(str(p['server']), 15)}{C.RESET}")
        for i, ln, reason in invalid:
            print(f"  {C.RED}✗ baris {i+1}{C.RESET} {C.DIM}{truncate(ln, 28)}{C.RESET} → {reason}")

        print()
        section("Aksi")
        print(f"  {C.YELLOW}[T]{C.RESET} Tambah node lain")
        print(f"  {C.YELLOW}[H]{C.RESET} Hapus node (nomor, mis: 1 atau 1,3)")
        print(f"  {C.GREEN}[L]{C.RESET} Lanjut Proses")
        print(f"  {C.RED}[B]{C.RESET} Batal / Kembali ke Menu")
        print(sep(50))
        aksi = ask(f"{C.YELLOW}Pilih Aksi ❯{C.RESET} ").strip().lower()

        if aksi == "l":
            if valid:
                break
            warn("Belum ada node valid."); time.sleep(1.2)
        elif aksi == "b":
            return
        elif aksi == "t":
            print(); section("Tambah Node Lagi")
            extra = _collect_lines(["Paste tautan baru (satu per baris).", "Enter kosong = selesai.",
                                    "Ketik 'batalkan' untuk batal nambah."])
            if extra:
                lines += extra
        elif aksi == "h":
            raw = ask("  Nomor yang mau dihapus ❯ ").strip()
            try:
                nums = [int(x) for x in raw.split(",") if x.strip()]
            except ValueError:
                err("Input tidak valid."); time.sleep(1.2); continue
            gone = {valid[n - 1]["_orig_idx"] for n in nums if 1 <= n <= len(valid)}
            lines = [ln for i, ln in enumerate(lines) if i not in gone]
            if not any(ln.strip() for ln in lines):
                err("Semua tautan dihapus. Kembali ke menu."); time.sleep(1.2); return
        else:
            err("Aksi tidak dikenal."); time.sleep(0.8)

    proxies = [{k: v for k, v in p.items() if k != "_orig_idx"} for p in valid]

    print(); section("Pilih Output Config")
    print(f"  {C.CYAN}[B]{C.RESET} Config for Box (Android)")
    print(f"  {C.CYAN}[N]{C.RESET} Config for Nikki (OpenWrt)")
    print(f"  {C.CYAN}[O]{C.RESET} Config for OpenClash (OpenWrt)")
    print(sep(50))
    platform = {"b": "box", "n": "nikki", "o": "openclash"}
    while True:
        plat = platform.get(ask(f"{C.YELLOW}Pilih (B/N/O) ❯{C.RESET} ").strip().lower())
        if plat:
            break
        err("Pilihan tidak valid.")

    print(); section("Pilih Target Provider")
    print(f"  {C.CYAN}[1]{C.RESET} active.yaml\n  {C.CYAN}[2]{C.RESET} trial.yaml")
    print(sep(50))
    while True:
        c = ask(f"{C.YELLOW}Pilih (1/2) ❯{C.RESET} ").strip()
        if c in ("1", "2"):
            target_name = "active.yaml" if c == "1" else "trial.yaml"; break
        err("Pilihan tidak valid.")

    P = PLATFORMS[plat]
    existing = load_provider_nodes(os.path.join(BASE_DIR, P["out"], P["proxy_dir"], target_name))
    write_mode = "replace"
    if existing:
        print()
        warn(f"{target_name} sudah berisi {len(existing)} node.")
        print(f"  {C.CYAN}[1]{C.RESET} Ganti (timpa)   {C.CYAN}[2]{C.RESET} Tambahkan ke yang lama")
        write_mode = "append" if ask(f"{C.YELLOW}Pilih (1/2) ❯{C.RESET} ").strip() == "2" else "replace"

    print(); section("Mode Rule-Provider")
    print(f"  {C.CYAN}[1]{C.RESET} Ikuti template {C.DIM}(http: auto-update dari GitHub){C.RESET}")
    print(f"  {C.CYAN}[2]{C.RESET} Offline        {C.DIM}(file lokal saja, tanpa update){C.RESET}")
    provider_mode = "offline" if ask(f"{C.YELLOW}Pilih (1/2, Enter=1) ❯{C.RESET} ").strip() == "2" else "template"

    print()
    spinner("Membangun & memvalidasi config", 0.5)
    out_dir, notes, issues, error = setup_full_config(proxies, target_name, plat, provider_mode, write_mode)
    if error:
        err(f"Gagal: {error}\n"); pause(); return

    ok(f"Config {P['label']} siap di:\n  {C.BOLD}{C.CYAN}{out_dir}/{C.RESET}")
    print(f"  {C.DIM}├── config.yaml{C.RESET}")
    print(f"  {C.DIM}├── {P['proxy_dir']}/{target_name} ({len(proxies)} node baru){C.RESET}")
    print(f"  {C.DIM}└── {P['rule_dir']}/{C.RESET}\n")
    for n in notes:
        print(f"  {C.DIM}• {n}{C.RESET}")
    print()
    print_issues(issues)
    secret = yaml.safe_load(read_text(os.path.join(out_dir, "config.yaml"))).get("secret")
    print(f"\n  Dashboard secret : {C.BOLD}{secret}{C.RESET}")

    print()
    if plat == "box":
        print(f"{C.YELLOW}💡 BOX ANDROID:{C.RESET} copy SEMUA isi folder di atas ke {C.BOLD}/data/adb/box/clash/{C.RESET}")
    elif plat == "nikki":
        print(f"{C.YELLOW}💡 NIKKI:{C.RESET}")
        print(f"   1. {C.BOLD}config.yaml{C.RESET} → {C.BOLD}/etc/nikki/profiles/{C.RESET}")
        print(f"   2. folder {C.BOLD}proxy/{C.RESET} & {C.BOLD}ruleset/{C.RESET} → {C.BOLD}{NIKKI_RUN_DIR}/{C.RESET}")
    else:
        print(f"{C.YELLOW}💡 OPENCLASH:{C.RESET}")
        print(f"   1. {C.BOLD}config.yaml{C.RESET} → {C.BOLD}/etc/openclash/config/{C.RESET}")
        print(f"   2. folder {C.BOLD}proxy_provider/{C.RESET} & {C.BOLD}rule_provider/{C.RESET} → {C.BOLD}/etc/openclash/{C.RESET}")
    pause("Tekan Enter untuk kembali ke menu...")


# =====================================================================
#  Feature: Clash -> URI
# =====================================================================
def provider_files():
    """Semua file provider hasil generate (Hasil/full_config_*/proxy*/*.yaml)."""
    found = []
    for pid, P in PLATFORMS.items():
        d = os.path.join(BASE_DIR, P["out"], P["proxy_dir"])
        for fn in sorted(glob.glob(os.path.join(d, "*.y*ml"))):
            found.append((f"{pid}/{os.path.basename(fn)}", fn))
    return found


def feature_convert_to_uri():
    clear_screen(); banner(); section("Convert Clash ke URI")
    print(f"  {C.CYAN}[1]{C.RESET} Paste Teks YAML langsung")
    print(f"  {C.CYAN}[2]{C.RESET} Baca dari file hasil generate (Hasil/full_config_*/)")
    print(f"  {C.CYAN}[0]{C.RESET} Batal")
    print(sep(50))
    pilihan = ask(f"{C.YELLOW}Pilih (1/2) ❯{C.RESET} ").strip()
    yaml_text = ""

    if pilihan == "1":
        print(f"\n  {C.DIM}Paste isi YAML. Ketik 'selesai' di baris baru untuk memproses.{C.RESET}")
        print(sep(50) + "\n")
        buf = []
        while True:
            try:
                s = input()
            except EOFError:
                break
            if s.strip().lower() == "selesai":
                break
            buf.append(s)
        yaml_text = "\n".join(buf)
    elif pilihan == "2":
        print(); section("Pilih File")
        files = provider_files()
        if not files:
            err("Belum ada file provider hasil generate."); pause(); return
        for i, (label, _) in enumerate(files, 1):
            print(f"  {C.CYAN}[{i}]{C.RESET} {label}")
        print(f"  {C.CYAN}[0]{C.RESET} Batal\n{sep(50)}")
        while True:
            idx = ask(f"{C.YELLOW}Pilih nomor file ❯{C.RESET} ").strip()
            if idx == "0":
                return
            if idx.isdigit() and 1 <= int(idx) <= len(files):
                yaml_text = read_text(files[int(idx) - 1][1]); break
            err("Pilihan tidak valid.")
    else:
        return

    try:
        data = yaml.safe_load(yaml_text)
        if isinstance(data, dict) and "proxies" in data:
            proxies = data["proxies"]
        elif isinstance(data, list):
            proxies = data
        else:
            raise ValueError("Format YAML tidak dikenali.")
    except Exception as e:
        err(f"Gagal parse YAML: {e}"); pause(); return
    if not proxies:
        warn("Tidak ada node di dalam file tersebut."); pause(); return

    spinner("Mengkonversi ke URI...", 0.4)
    uris, gagal = [], []
    for p in proxies:
        try:
            u = build_uri_from_proxy(p)
            (uris.append(u) if u else gagal.append(str(p.get("name", "?"))))
        except Exception:
            gagal.append(str(p.get("name", "?")) if isinstance(p, dict) else "?")
    if not uris:
        err("Gagal konversi semua node. Pastikan tipe-nya VLESS/VMess/Trojan."); pause(); return

    clear_screen(); banner()
    section(f"Hasil Konversi ({len(uris)} Valid, {len(gagal)} Gagal)")
    for i, u in enumerate(uris, 1):
        print(f"  {C.DIM}[{i}]{C.RESET} {C.CYAN}{u}{C.RESET}\n")
    if gagal:
        warn("Dilewati (tipe tidak didukung): " + ", ".join(truncate(g, 24) for g in gagal))
    print(sep(50))
    if ask("  Simpan ke file? (y/n) ❯ ").strip().lower() == "y":
        os.makedirs(BASE_DIR, exist_ok=True)
        out_path = os.path.join(BASE_DIR, f"URI_{time.strftime('%d%m%Y_%H%M%S')}.txt")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(uris) + "\n")
        ok(f"Tersimpan di: {out_path}")
    pause("Tekan Enter untuk kembali ke menu...")


# =====================================================================
#  Feature: Status
# =====================================================================
def feature_check_status():
    clear_screen(); banner(); section("Status Sistem & Konfigurasi")
    tpl = find_template()
    print(f"  {C.DIM}Template & Ruleset:{C.RESET}")
    if tpl:
        ok(f"template      : {C.GREEN}{os.path.basename(tpl)}{C.RESET}")
        try:
            cfg = load_template_cfg(tpl)
            print(f"    - Mixed port : {C.CYAN}{cfg.get('mixed-port', '-')}{C.RESET}")
            print(f"    - Secret     : {C.CYAN}{cfg.get('secret') or '(kosong → dibuat acak saat build)'}{C.RESET}")
            print(f"    - DNS        : {C.CYAN}{', '.join(map(str, (cfg.get('dns') or {}).get('nameserver', [])))}{C.RESET}")
        except Exception as e:
            err(f"template tidak bisa dibaca: {e}")
    else:
        err("template      : tidak ada")
    n_rs = len(os.listdir(RULESET_SOURCE)) if os.path.isdir(RULESET_SOURCE) else 0
    (ok(f"folder ruleset: {C.GREEN}{n_rs} file{C.RESET}") if n_rs else err("folder ruleset: tidak ada"))

    print(f"\n  {C.DIM}Provider Node:{C.RESET}")
    files = provider_files()
    if not files:
        warn("Belum ada file provider.")
    for label, fp in files:
        try:
            data = yaml.safe_load(read_text(fp))
            count = len(data.get("proxies") or []) if isinstance(data, dict) else 0
            print(f"  {C.GREEN}✓{C.RESET} {label:<24}: {C.BOLD}{count}{C.RESET} node")
        except Exception:
            print(f"  {C.RED}✗{C.RESET} {label:<24}: {C.RED}Format Error{C.RESET}")

    print(f"\n  {C.DIM}Status Full Config:{C.RESET}")
    for pid, P in PLATFORMS.items():
        cp = os.path.join(BASE_DIR, P["out"], "config.yaml")
        (print(f"  {C.GREEN}✓{C.RESET} {P['label']:<24}: {C.GREEN}Siap{C.RESET}") if os.path.isfile(cp)
         else print(f"  {C.GRAY}-{C.RESET} {P['label']:<24}: {C.DIM}Belum ada{C.RESET}"))
    print(f"\n  {C.DIM}Path Output:{C.RESET}\n  {C.CYAN}{BASE_DIR}{C.RESET}")
    pause("Tekan Enter untuk kembali ke menu...")


# =====================================================================
#  Feature: Validasi
# =====================================================================
def feature_validate():
    clear_screen(); banner(); section("Validasi / Audit Config")
    tpl = find_template()
    if not tpl:
        err("Template tidak ditemukan."); pause(); return
    print(f"  {C.DIM}Template: {os.path.basename(tpl)}{C.RESET}\n")
    text = read_text(tpl)
    for pid, P in PLATFORMS.items():
        print(f"{C.BOLD}{P['label']}{C.RESET}")
        try:
            cfg, _ = build_config(text, pid)
            out_dir = os.path.join(BASE_DIR, P["out"])
            issues = validate_config(cfg, pid, out_dir if os.path.isdir(out_dir) else None)
            print_issues(issues)
        except Exception as e:
            err(f"gagal build: {e}")
        print()
    pause("Tekan Enter untuk kembali ke menu...")


# =====================================================================
#  Feature: DNS
# =====================================================================
DNS_PRESETS = {
    "1": ("Cloudflare + Google (DoH)", ["https://1.1.1.1/dns-query", "https://dns.google/dns-query"], ["1.1.1.1", "8.8.8.8"]),
    "2": ("Quad9 Unsecured (tanpa filter)", ["https://dns10.quad9.net/dns-query"], ["9.9.9.10", "149.112.112.10"]),
    "3": ("NextDNS (Custom ID)", None, ["1.1.1.1", "8.8.8.8"]),
    "4": ("AdGuard DNS (filter iklan)", ["https://dns.adguard-dns.com/dns-query"], ["94.140.14.14", "94.140.15.15"]),
    "5": ("Custom manual", None, ["1.1.1.1", "8.8.8.8"]),
}


def feature_config_dns():
    path = ensure_working_template()
    if not path:
        err("Template tidak ditemukan!"); time.sleep(1.5); return
    content = read_text(path)
    clear_screen(); banner(); section("Konfigurasi DNS")
    try:
        dns = (yaml.safe_load(content) or {}).get("dns") or {}
    except yaml.YAMLError as e:
        err(f"Template rusak: {e}"); pause(); return
    print(f"  {C.DIM}DNS aktif di template:{C.RESET}")
    for key in ("nameserver", "proxy-server-nameserver", "default-nameserver", "fallback"):
        if dns.get(key):
            print(f"  {C.CYAN}{key}{C.RESET}: {', '.join(map(str, dns[key]))}")
    if any("://" not in str(x) for x in (dns.get("nameserver") or []) + (dns.get("fallback") or [])):
        warn("Ada DNS polos (non-DoH) di nameserver/fallback → rawan bocor ke ISP.")

    print(); section("Pilih Provider DNS")
    for k, (label, _, _) in DNS_PRESETS.items():
        print(f"  {C.CYAN}[{k}]{C.RESET} {label}")
    print(f"  {C.CYAN}[0]{C.RESET} Batal\n{sep(50)}")
    pilihan = ask(f"{C.YELLOW}Pilih (1-5) ❯{C.RESET} ").strip()
    if pilihan == "0" or pilihan not in DNS_PRESETS:
        if pilihan not in ("0", ""):
            err("Pilihan tidak valid."); time.sleep(1.2)
        return
    _, dns_list, bootstrap = DNS_PRESETS[pilihan]
    if pilihan == "3":
        nid = ask("  NextDNS ID (kosong = default): ").strip()
        dns_list = [f"https://dns.nextdns.io/{nid}" if nid else "https://dns.nextdns.io"]
    elif pilihan == "5":
        print(f"  {C.DIM}URL DoH (satu per baris, Enter kosong = selesai). Contoh: https://dns.example/dns-query{C.RESET}")
        dns_list = []
        while True:
            u = ask(f"  {C.CYAN}URL ❯{C.RESET} ").strip()
            if not u:
                break
            if not u.startswith(("https://", "tls://", "quic://")):
                warn("Disarankan DoH/DoT/DoQ (https://, tls://, quic://) — IP polos bisa bocor ke ISP.")
            dns_list.append(u)
    if not dns_list:
        err("Tidak ada DNS yang dipilih."); time.sleep(1.2); return

    warn("proxy-server-nameserver sebaiknya DNS polos: DoH sering di-reset ISP -> domain server proxy gagal resolve.")
    also_proxy = bool(dns.get("proxy-server-nameserver")) and \
        ask("  Terapkan juga ke proxy-server-nameserver? (y/N) ❯ ").strip().lower() == "y"
    change_boot = ask(f"  Ganti bootstrap default-nameserver → {', '.join(bootstrap)}? (y/N) ❯ ").strip().lower() == "y"

    new = content
    new, f1 = block_set_list(new, "dns", "nameserver", dns_list)
    if also_proxy:
        new, _ = block_set_list(new, "dns", "proxy-server-nameserver", dns_list)
    if change_boot:
        new, _ = block_set_list(new, "dns", "default-nameserver", bootstrap)
    try:
        yaml.safe_load(new)
    except yaml.YAMLError as e:
        err(f"Hasil edit tidak valid, dibatalkan: {e}"); pause(); return
    if not f1:
        err("Blok dns tidak ditemukan di template."); pause(); return
    backup_file(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write(new)
    ok("DNS diterapkan ke template.yaml (backup: template.yaml.bak)")
    print(f"  {C.DIM}Aktif saat generate Full Config berikutnya.{C.RESET}")
    pause()


# =====================================================================
#  Feature: Edit Configuration
# =====================================================================
def feature_edit_config():
    while True:
        clear_screen(); banner(); section("Edit Configuration")
        print(f"  {C.CYAN}[1]{C.RESET} Edit Port & Secret")
        print(f"  {C.CYAN}[2]{C.RESET} Ganti File Template")
        print(f"  {C.CYAN}[3]{C.RESET} Konfigurasi DNS & Nameserver")
        print(f"  {C.CYAN}[0]{C.RESET} Kembali ke Menu Utama\n{sep(50)}")
        pilih = ask(f"{C.YELLOW}Pilih menu ❯{C.RESET} ").strip()
        if pilih == "0":
            break
        elif pilih == "1":
            path = ensure_working_template()
            if not path:
                err("Template belum ada!"); time.sleep(1.5); continue
            content = read_text(path)
            try:
                cfg = yaml.safe_load(content) or {}
            except yaml.YAMLError as e:
                err(f"Template rusak: {e}"); time.sleep(1.5); continue
            print(); section("Edit Port & Secret")
            print(f"  {C.DIM}Enter = tidak diubah. Ketik 'acak' di Secret untuk generate otomatis.{C.RESET}")
            new_port = ask(f"  Mixed Port baru (sekarang: {cfg.get('mixed-port', '-')}): ").strip()
            new_secret = ask(f"  Secret baru (sekarang: {cfg.get('secret') or 'kosong'}): ").strip()
            if new_port and not (new_port.isdigit() and 1 <= int(new_port) <= 65535):
                err("Port harus angka 1-65535."); time.sleep(1.5); continue
            if new_secret.lower() == "acak":
                new_secret = secrets.token_urlsafe(9); print(f"  Secret baru: {C.BOLD}{new_secret}{C.RESET}")
            if not (new_port or new_secret):
                warn("Tidak ada perubahan."); time.sleep(1.2); continue
            new = content
            if new_port:
                new, f = set_top_scalar(new, "mixed-port", new_port)
                if not f:
                    err("Key mixed-port tidak ada di template."); time.sleep(1.5); continue
            if new_secret:
                new, f = set_top_scalar(new, "secret", yaml_quote(new_secret))
                if not f:
                    err("Key secret tidak ada di template."); time.sleep(1.5); continue
            backup_file(path)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(new)
            ok("Template berhasil diupdate!"); time.sleep(1.2)
        elif pilih == "2":
            print(); section("Ganti Template")
            masters = list_master_templates()
            for i, m in enumerate(masters, 1):
                print(f"  {C.CYAN}[{i}]{C.RESET} {os.path.basename(m)}")
            print(f"  {C.DIM}Pilih nomor, atau ketik path lengkap file template. Enter = batal.{C.RESET}")
            src = ask(f"  {C.CYAN}❯{C.RESET} ").strip()
            if src.isdigit() and 1 <= int(src) <= len(masters):
                src = masters[int(src) - 1]
            if not src:
                continue
            src = os.path.expanduser(src)
            if not os.path.isfile(src):
                err("File tidak ditemukan."); time.sleep(1.5); continue
            try:
                text = read_text(src)
                if not isinstance(yaml.safe_load(text), dict):
                    raise ValueError("bukan YAML mapping")
                if os.path.isfile(TEMPLATE_PATH):
                    backup_file(TEMPLATE_PATH)
                with open(TEMPLATE_PATH, "w", encoding="utf-8") as f:
                    f.write(text)
                ok("Template berhasil diganti!")
            except Exception as e:
                err(f"Gagal: {e}")
            time.sleep(1.5)
        elif pilih == "3":
            feature_config_dns()


# =====================================================================
#  Feature: Tools Ruleset (padatkan DST-PORT)
# =====================================================================
def compact_port_payload(payload):
    """Gabung DST-PORT tunggal/berurutan jadi range. Return (payload_baru, jumlah_port_asal)."""
    ports, rest, n_in = set(), [], 0
    for item in payload:
        m = re.fullmatch(r"DST-PORT,\s*(\d+)(?:-(\d+))?", str(item).strip())
        if not m:
            rest.append(item); continue
        a, b = int(m.group(1)), int(m.group(2) or m.group(1))
        ports.update(range(a, b + 1)); n_in += 1
    ranges, start = [], None
    for p in sorted(ports):
        if start is None:
            start = prev = p
        elif p == prev + 1:
            prev = p
        else:
            ranges.append((start, prev)); start = prev = p
    if start is not None:
        ranges.append((start, prev))
    out = [f"DST-PORT,{a}" if a == b else f"DST-PORT,{a}-{b}" for a, b in ranges]
    return rest + out, n_in


def feature_tools():
    clear_screen(); banner(); section("Tools Ruleset")
    print(f"  {C.CYAN}[1]{C.RESET} Padatkan port-games.yaml {C.DIM}(gabung DST-PORT jadi range){C.RESET}")
    print(f"  {C.CYAN}[0]{C.RESET} Kembali\n{sep(50)}")
    if ask(f"{C.YELLOW}Pilih ❯{C.RESET} ").strip() != "1":
        return
    fp = os.path.join(RULESET_SOURCE, "port-games.yaml")
    if not os.path.isfile(fp):
        err("ruleset/port-games.yaml tidak ada."); pause(); return
    try:
        data = yaml.safe_load(read_text(fp))
        payload = data["payload"]
    except Exception as e:
        err(f"Gagal baca: {e}"); pause(); return
    new, n_in = compact_port_payload(payload)
    print(f"  {len(payload)} baris → {len(new)} baris (perilaku routing identik)")
    if ask("  Terapkan? Backup disimpan sebagai port-games.yaml.bak (y/N) ❯ ").strip().lower() != "y":
        return
    backup_file(fp)
    with open(fp, "w", encoding="utf-8") as f:
        f.write("# Port game — dipadatkan oleh hikari_converter (range = perilaku sama dengan DST-PORT satuan)\n"
                "# Sintaks range: https://wiki.metacubex.one/en/handbook/syntax (Port Ranges)\npayload:\n")
        for x in new:
            f.write(f"  - {x}\n")
    ok("port-games.yaml dipadatkan.")
    print(f"  {C.DIM}Jangan lupa upload versi baru ini ke repo kalau rule-provider-nya type http.{C.RESET}")
    pause()


# =====================================================================
#  Menu
# =====================================================================
def feature_convert_menu():
    clear_screen(); banner(); section("Menu Convert")
    print(f"  {C.CYAN}[1]{C.RESET} URI (VLESS/VMess/Trojan)  ➜  Clash (YAML)")
    print(f"  {C.CYAN}[2]{C.RESET} Clash (YAML)              ➜  URI (VLESS/VMess/Trojan)")
    print(f"  {C.CYAN}[0]{C.RESET} Kembali ke Menu Utama\n{sep(50)}")
    pilihan = ask(f"{C.YELLOW}Pilih (1/2) ❯{C.RESET} ").strip()
    if pilihan == "1":
        clear_screen(); banner(); feature_convert_to_clash()
    elif pilihan == "2":
        feature_convert_to_uri()


def main():
    try:
        prepare_dirs()
    except OSError as e:
        err(f"Tidak bisa membuat folder Hasil/: {e}")
        print("  Pindahkan folder script ke /storage/emulated/0/ (jalankan `termux-setup-storage` dulu).")
        sys.exit(1)
    while True:
        clear_screen(); banner(); section("MENU UTAMA")
        print(f"  {C.CYAN}[1]{C.RESET} Convert")
        print(f"  {C.CYAN}[2]{C.RESET} Edit Configuration")
        print(f"  {C.CYAN}[3]{C.RESET} Check Status")
        print(f"  {C.CYAN}[4]{C.RESET} Validasi / Audit Config")
        print(f"  {C.CYAN}[5]{C.RESET} Tools Ruleset")
        print(f"  {C.CYAN}[6]{C.RESET} Exit\n{sep(50)}")
        pilihan = ask(f"{C.YELLOW}Pilih menu ❯{C.RESET} ").strip()
        if pilihan == "1":   feature_convert_menu()
        elif pilihan == "2": feature_edit_config()
        elif pilihan == "3": feature_check_status()
        elif pilihan == "4": feature_validate()
        elif pilihan == "5": feature_tools()
        elif pilihan == "6":
            clear_screen(); print(f"\n  {C.GREEN}Terima kasih sudah pakai Hikari Subclash!{C.RESET}\n"); sys.exit(0)
        else:
            err("Pilihan tidak valid."); time.sleep(0.8)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {C.RED}Program dihentikan.{C.RESET}\n")
        sys.exit(0)
