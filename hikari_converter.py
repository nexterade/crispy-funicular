#!/usr/bin/env python3
"""
HIKARI SUBCLASH OFFLINE ♥️
"""

import base64
import json
import os
import re
import shutil
import sys
import time
import urllib.parse
from urllib.parse import unquote, urlparse, parse_qs

try:
    import yaml
except ImportError:
    print("[!] PyYAML belum terpasang. Jalankan: pip install pyyaml")
    sys.exit(1)

# --- PATH CONFIG ---
BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Hasil")
PROXY_DIR = os.path.join(BASE_DIR, "proxy")

TEMPLATE_FILE = "template.yaml"
RULESET_SOURCE = "ruleset"

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
    os.system('cls' if os.name == 'nt' else 'clear')

def sep(width=50, color=None): return (color or C.GRAY) + "─" * width + C.RESET
def section(title, width=50):
    t = f" {title} "; pad = max(0, width - len(t)); left = pad // 2; right = pad - left
    print(C.GRAY + "─" * left + C.RESET + C.BOLD + C.WHITE + t + C.RESET + C.GRAY + "─" * right + C.RESET)

def banner():
    print(f"\n  {C.BOLD}{C.MAGENTA}HIKARI SUBCLASH{C.RESET}")
    print(f"  {C.DIM}VLESS · VMess · Trojan  ↔  Mihomo / Clash Meta{C.RESET}")
    print(sep(50, C.MAGENTA) + "\n")

def spinner(msg, duration=0.6):
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]; end = time.time() + duration; i = 0
    while time.time() < end:
        sys.stdout.write(f"\r{C.CYAN}{frames[i % len(frames)]}{C.RESET} {msg}"); sys.stdout.flush(); time.sleep(0.05); i += 1
    sys.stdout.write("\r" + " " * (len(msg) + 4) + "\r"); sys.stdout.flush()

def truncate(text, length):
    return text if len(text) <= length else text[:length-3] + "..."

# ---------- Parser (URI -> YAML) ----------
def parse_vless(uri):
    p = urlparse(uri); q = {k: v[0] for k, v in parse_qs(p.query).items()}
    net = q.get("type", "tcp"); sni = q.get("sni") or q.get("host") or p.hostname
    node = {
        "name": unquote(p.fragment) or "VLESS", "server": p.hostname, "port": int(p.port or 443),
        "type": "vless", "uuid": p.username or "", "cipher": "auto",
        "tls": q.get("security", "none") in ("tls", "reality"), "skip-cert-verify": True,
        "servername": sni, "network": net, "udp": True,
    }
    if net == "ws": node["ws-opts"] = {"path": unquote(q.get("path", "/")), "headers": {"Host": q.get("host") or sni}}
    if net == "grpc": node["grpc-opts"] = {"grpc-service-name": q.get("serviceName", "")}
    if q.get("security") == "reality":
        node["reality-opts"] = {"public-key": q.get("pbk", ""), "short-id": q.get("sid", "")}
    return node

def parse_vmess(uri):
    raw = uri[len("vmess://"):]; raw += "=" * (-len(raw) % 4)
    try: d = json.loads(base64.b64decode(raw).decode("utf-8"))
    except Exception: raise ValueError("Base64/JSON vmess tidak valid")
    net = d.get("net", "tcp"); sni = d.get("sni") or d.get("host") or d.get("add")
    node = {
        "name": d.get("ps", "VMess"), "server": d.get("add"), "port": int(d.get("port", 443)),
        "type": "vmess", "uuid": d.get("id", ""), "alterId": int(d.get("aid", 0) or 0),
        "cipher": d.get("scy", "auto") or "auto", "tls": d.get("tls", "") in ("tls", "reality"),
        "skip-cert-verify": True, "servername": sni, "network": net, "udp": True,
    }
    if net == "ws": node["ws-opts"] = {"path": d.get("path", "/") or "/", "headers": {"Host": d.get("host") or sni}}
    if net == "grpc": node["grpc-opts"] = {"grpc-service-name": d.get("path", "")}
    return node

def parse_trojan(uri):
    p = urlparse(uri); q = {k: v[0] for k, v in parse_qs(p.query).items()}
    net = q.get("type", "tcp"); sni = q.get("sni") or q.get("peer") or p.hostname
    node = {
        "name": unquote(p.fragment) or "Trojan", "server": p.hostname, "port": int(p.port or 443),
        "type": "trojan", "password": p.username or "", "sni": sni,
        "skip-cert-verify": True, "network": net, "udp": True,
    }
    if net == "ws": node["ws-opts"] = {"path": unquote(q.get("path", "/")), "headers": {"Host": q.get("host") or sni}}
    if net == "grpc": node["grpc-opts"] = {"grpc-service-name": q.get("serviceName", "")}
    return node

def convert_line(line):
    line = line.strip()
    if not line: return None
    if line.startswith("vless://"): return parse_vless(line)
    if line.startswith("vmess://"): return parse_vmess(line)
    if line.startswith("trojan://"): return parse_trojan(line)
    raise ValueError("bukan vless/vmess/trojan")

# ---------- Parser (YAML -> URI) ----------
def build_uri_from_proxy(p):
    p_type = str(p.get("type", "")).lower()
    name = p.get("name", "Node")
    server = p.get("server", "")
    port = p.get("port", 443)
    net = p.get("network", "tcp")
    
    if p_type == "vmess":
        vmess_dict = {
            "v": "2", "ps": name, "add": server, "port": str(port),
            "id": p.get("uuid", ""), "aid": str(p.get("alterId", 0)),
            "scy": p.get("cipher", "auto"), "net": net,
            "type": "none", "host": "", "path": "", "tls": "",
            "sni": p.get("servername", "")
        }
        if net == "ws":
            ws = p.get("ws-opts", {})
            vmess_dict["path"] = ws.get("path", "/")
            vmess_dict["host"] = ws.get("headers", {}).get("Host", "")
        if p.get("tls"): vmess_dict["tls"] = "tls"
        
        json_str = json.dumps(vmess_dict, separators=(',', ':'))
        b64 = base64.b64encode(json_str.encode()).decode()
        return f"vmess://{b64}"

    params = {}
    if p_type == "vless":
        net_type = net
        if net_type != "tcp": params["type"] = net_type
        
        sec = "none"
        if p.get("tls"): sec = "tls"
        if "reality-opts" in p: sec = "reality"
        if sec != "none": params["security"] = sec
        
        if p.get("servername"):
            params["sni"] = p.get("servername")
            params["host"] = p.get("servername")
            
        if net == "ws":
            ws = p.get("ws-opts", {})
            if ws.get("path"): params["path"] = ws.get("path")
            if ws.get("headers", {}).get("Host"):
                params["host"] = ws.get("headers", {}).get("Host")
        elif net == "grpc":
            grpc = p.get("grpc-opts", {})
            if grpc.get("grpc-service-name"):
                params["serviceName"] = grpc.get("grpc-service-name")
                
        if "reality-opts" in p:
            ro = p.get("reality-opts", {})
            if ro.get("public-key"): params["pbk"] = ro.get("public-key")
            if ro.get("short-id"): params["sid"] = ro.get("short-id")
            if p.get("client-fingerprint"): params["fp"] = p.get("client-fingerprint")
            
        params["encryption"] = "none"
        
        query = urllib.parse.urlencode(params)
        return f"vless://{p.get('uuid', '')}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
        
    elif p_type == "trojan":
        params["security"] = "tls"
        if p.get("sni"): params["sni"] = p.get("sni")
        if net != "tcp": params["type"] = net
        
        if net == "ws":
            ws = p.get("ws-opts", {})
            if ws.get("path"): params["path"] = ws.get("path")
            if ws.get("headers", {}).get("Host"): params["host"] = ws.get("headers", {}).get("Host")
        elif net == "grpc":
            grpc = p.get("grpc-opts", {})
            if grpc.get("grpc-service-name"): params["serviceName"] = grpc.get("grpc-service-name")
            
        query = urllib.parse.urlencode(params)
        return f"trojan://{p.get('password', '')}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
        
    return None

# ---------- File Operations ----------
def prepare_dirs():
    os.makedirs(PROXY_DIR, exist_ok=True)

def save_proxy_yaml(proxies, filename, target_dir):
    path = os.path.join(target_dir, filename)
    yaml_text = yaml.dump({"proxies": proxies}, allow_unicode=True, sort_keys=False, default_flow_style=False, width=4096)
    with open(path, "w", encoding="utf-8") as f: f.write(yaml_text)
    return path

def patch_config_for_platform(template_content, platform):
    """Modifikasi template.yaml sesuai platform target."""
    if platform == "box":
        return template_content # Android pakai aslinya

    # OpenWrt (Nikki/OpenClash) butuh TUN enable: true dan redir-port dihapus
    content = template_content
    
    # 1. Ubah tun: enable: false -> true
    content = re.sub(r"tun:\s*\n(\s+.*\n)*?\s+enable:\s*false", 
                     lambda m: m.group(0).replace("enable: false", "enable: true"), 
                     content)
    
    # 2. Hapus redir-port & tproxy-port (karena OpenWrt pakai TUN murni)
    content = re.sub(r"^redir-port:.*\n?", "", content, flags=re.MULTILINE)
    content = re.sub(r"^tproxy-port:.*\n?", "", content, flags=re.MULTILINE)
    
    # 3. Patch path khusus per platform
    if platform == "nikki":
        # Nikki memisahkan path config (/etc/nikki/profiles/) dan file pendukung (/etc/nikki/run/)
        # Kita ubah semua path relatif './proxy/' & './ruleset/' jadi absolute
        content = content.replace("./proxy/", "/etc/nikki/run/proxy/")
        content = content.replace("./ruleset/", "/etc/nikki/run/ruleset/")
        
    elif platform == "openclash":
        # OpenClash menggunakan folder rule_provider/
        content = content.replace("./ruleset/", "./rule_provider/")
        # OpenClash biasanya pakai proxy_provider/
        content = content.replace("./proxy/", "./proxy_provider/")
        
    return content

def setup_full_config(proxies, target_name, platform):
    if not os.path.isfile(TEMPLATE_FILE):
        return None, "template.yaml tidak ditemukan"

    # Tentukan folder output berdasarkan platform
    if platform == "box":
        out_dir = os.path.join(BASE_DIR, "full_config_box")
        ruleset_folder_name = "ruleset"
        proxy_folder_name = "proxy"
    elif platform == "nikki":
        out_dir = os.path.join(BASE_DIR, "full_config_nikki")
        ruleset_folder_name = "ruleset"
        proxy_folder_name = "proxy"
    elif platform == "openclash":
        out_dir = os.path.join(BASE_DIR, "full_config_openclash")
        ruleset_folder_name = "rule_provider"
        proxy_folder_name = "proxy_provider"

    full_proxy_dir = os.path.join(out_dir, proxy_folder_name)
    os.makedirs(full_proxy_dir, exist_ok=True)
    
    # Baca & Patch Config
    with open(TEMPLATE_FILE, "r", encoding="utf-8") as f:
        tpl_content = f.read()
    patched_content = patch_config_for_platform(tpl_content, platform)
    
    # Tulis config.yaml yang udah dipatch
    target_config = os.path.join(out_dir, "config.yaml")
    with open(target_config, "w", encoding="utf-8") as f:
        f.write(patched_content)

    # Simpan Node
    save_proxy_yaml(proxies, target_name, full_proxy_dir)
    
    other_name = "trial.yaml" if target_name == "active.yaml" else "active.yaml"
    other_path = os.path.join(full_proxy_dir, other_name)
    if not os.path.exists(other_path):
        with open(other_path, "w", encoding="utf-8") as f:
            f.write("proxies: []\n")

    # Copy Folder Ruleset (Rename kalau OpenClash)
    target_ruleset = os.path.join(out_dir, ruleset_folder_name)
    if os.path.isdir(RULESET_SOURCE):
        if os.path.exists(target_ruleset): shutil.rmtree(target_ruleset)
        shutil.copytree(RULESET_SOURCE, target_ruleset)
    else:
        return None, f"Folder '{RULESET_SOURCE}' tidak ditemukan di samping script"

    return out_dir, None

# ---------- Features: Convert URI -> Clash ----------
def feature_convert_to_clash():
    print()
    section("Masukkan node (Format URI)")
    print(f"  {C.DIM}Paste vless:// atau vmess:// atau trojan:// (satu per baris).{C.RESET}")
    print(f"  {C.DIM}Tekan Enter 2x untuk selesai.{C.RESET}")
    print(f"  {C.DIM}Ketik 'batal' untuk kembali ke menu.{C.RESET}")
    print(sep(50) + "\n")
    
    lines = []
    while True:
        try: s = input(f"{C.CYAN}❯{C.RESET} ")
        except EOFError: break
        if s.strip().lower() == "batal": return
        if s.strip() == "": break
        lines.append(s)
        
    if not lines:
        print(f"\n{C.RED}✗ Tidak ada input.{C.RESET}"); time.sleep(1.5); return

    while True:
        valid_proxies = []
        for i, ln in enumerate(lines):
            try:
                n = convert_line(ln)
                if n: 
                    n['_orig_idx'] = i
                    valid_proxies.append(n)
            except Exception:
                pass

        clear_screen()
        banner()
        section(f"Preview Input ({len(valid_proxies)} Valid)")
        
        if not valid_proxies:
            print(f"  {C.RED}✗ Semua tautan tidak valid!{C.RESET}")
            input(f"\n{C.DIM}Tekan Enter untuk kembali...{C.RESET}"); return
            
        print(f"  {C.BOLD}{'No':<4} | {'Tipe':<7} | {'Nama Node':<20} | {'Server'}{C.RESET}")
        print(f"  {C.GRAY}{'-'*4}-+-{'-'*7}-+-{'-'*20}-+-{'-'*15}{C.RESET}")
        for idx, p in enumerate(valid_proxies, 1):
            name = truncate(str(p.get('name', '')), 20)
            server = truncate(str(p.get('server', '')), 15)
            print(f"  {C.CYAN}{idx:<4}{C.RESET} | {p['type'].upper():<7} | {name:<20} | {C.DIM}{server}{C.RESET}")
            
        print()
        section("Aksi")
        print(f"  {C.YELLOW}[T]{C.RESET} Tambah node lain")
        print(f"  {C.YELLOW}[H]{C.RESET} Hapus node (ketik nomor, misal: 1 atau 1,3)")
        print(f"  {C.GREEN}[L]{C.RESET} Lanjut Proses")
        print(f"  {C.RED}[B]{C.RESET} Batal / Kembali ke Menu")
        print(sep(50))

        aksi = input(f"{C.YELLOW}Pilih Aksi ❯{C.RESET} ").strip().lower()
        
        if aksi == 'l':
            if not valid_proxies: continue
            break
        elif aksi == 'b':
            return
        elif aksi == 't':
            print()
            section("Tambah Node Lagi")
            print(f"  {C.DIM}Paste tautan baru (satu per baris).{C.RESET}")
            print(f"  {C.DIM}Enter kosong = selesai nambah.{C.RESET}")
            print(f"  {C.DIM}Ketik 'batalkan' untuk batal nambah.{C.RESET}")
            print(sep(50) + "\n")
            
            lines_backup = list(lines)
            batal_nambah = False
            
            while True:
                try: s = input(f"{C.CYAN}❯{C.RESET} ")
                except EOFError: break
                
                if s.strip().lower() == "batalkan":
                    batal_nambah = True
                    break
                if s.strip() == "": break
                lines.append(s)
            
            if batal_nambah: lines = lines_backup
            continue
        elif aksi == 'h':
            hapus = input(f"  Ketik nomor yang mau dihapus ❯ ").strip()
            try:
                idx_hapus = [int(x.strip()) for x in hapus.split(',')]
                indices_to_delete = set()
                for num in idx_hapus:
                    if 1 <= num <= len(valid_proxies):
                        indices_to_delete.add(valid_proxies[num-1]['_orig_idx'])
                
                lines = [ln for i, ln in enumerate(lines) if i not in indices_to_delete]
                if not lines:
                    print(f"\n{C.RED}✗ Semua tautan dihapus. Kembali ke menu.{C.RESET}")
                    time.sleep(1.5); return
            except ValueError:
                print(f"\n{C.RED}✗ Input tidak valid.{C.RESET}"); time.sleep(1.5)
        else:
            print(f"\n{C.RED}✗ Aksi tidak dikenal.{C.RESET}"); time.sleep(1)

    proxies = []
    for p in valid_proxies:
        p_copy = dict(p)
        del p_copy['_orig_idx']
        proxies.append(p_copy)

    # --- MENU PLATFORM BARU ---
    print()
    section("Pilih Output Config")
    print(f"  {C.CYAN}[B]{C.RESET} Config for Box (Android)")
    print(f"  {C.CYAN}[N]{C.RESET} Config for Nikki (OpenWrt)")
    print(f"  {C.CYAN}[O]{C.RESET} Config for OpenClash (OpenWrt)")
    print(sep(50))
    
    platform_choice = ""
    while True:
        pilihan = input(f"{C.YELLOW}Pilih (B/N/O) ❯{C.RESET} ").strip().lower()
        if pilihan == "b": platform_choice = "box"; break
        elif pilihan == "n": platform_choice = "nikki"; break
        elif pilihan == "o": platform_choice = "openclash"; break
        else: print(f"{C.RED}Pilihan tidak valid.{C.RESET}")

    print()
    section("Pilih Target Provider")
    print(f"  {C.CYAN}[1]{C.RESET} active.yaml")
    print(f"  {C.CYAN}[2]{C.RESET} trial.yaml")
    print(sep(50))
    
    target_name = ""
    while True:
        pilihan = input(f"{C.YELLOW}Pilih (1/2) ❯{C.RESET} ").strip()
        if pilihan == "1": target_name = "active.yaml"; break
        elif pilihan == "2": target_name = "trial.yaml"; break
        else: print(f"{C.RED}Pilihan tidak valid.{C.RESET}")

    print()
    spinner("Menyimpan & mem-patch file", 0.5)
    saved, err = setup_full_config(proxies, target_name, platform_choice)
    
    if err:
        print(f"{C.RED}✗ Gagal: {err}{C.RESET}\n"); time.sleep(1.5); return
        
    print(f"{C.GREEN}✓{C.RESET} Config {platform_choice.upper()} siap pakai di:\n  {C.BOLD}{C.CYAN}{saved}/{C.RESET}")
    print(f"  {C.DIM}├── config.yaml (Auto-Patched){C.RESET}")
    
    proxy_folder = "proxy_provider" if platform_choice == "openclash" else "proxy"
    ruleset_folder = "rule_provider" if platform_choice == "openclash" else "ruleset"
    
    print(f"  {C.DIM}├── {proxy_folder}/{target_name} ({len(proxies)} node){C.RESET}")
    print(f"  {C.DIM}└── {ruleset_folder}/ (di-copy dari folder script){C.RESET}\n")
    
    # --- INSTRUKSI SPESIFIK PER PLATFORM ---
    if platform_choice == "box":
        print(f"{C.YELLOW}💡 PENTING (BOX ANDROID):{C.RESET}")
        print(f"   Copy SEMUA isi folder di atas ke: {C.BOLD}/data/adb/box/clash/{C.RESET}\n")
        
    elif platform_choice == "nikki":
        print(f"{C.YELLOW}💡 PENTING (NIKKI OPENWRT):{C.RESET}")
        print(f"   Nikki memisahkan config & file pendukung:")
        print(f"   1. Copy {C.BOLD}config.yaml{C.RESET} ke {C.BOLD}/etc/nikki/profiles/{C.RESET}")
        print(f"   2. Copy folder {C.BOLD}{proxy_folder}/{C.RESET} & {C.BOLD}{ruleset_folder}/{C.RESET} ke {C.BOLD}/etc/nikki/run/{C.RESET}\n")
        
    elif platform_choice == "openclash":
        print(f"{C.YELLOW}💡 PENTING (OPENCLASH OPENWRT):{C.RESET}")
        print(f"   1. Copy {C.BOLD}config.yaml{C.RESET} ke {C.BOLD}/etc/openclash/config/{C.RESET}")
        print(f"   2. Copy folder {C.BOLD}{proxy_folder}/{C.RESET} & {C.BOLD}{ruleset_folder}/{C.RESET} ke {C.BOLD}/etc/openclash/{C.RESET}\n")
    
    input(f"{C.DIM}Tekan Enter untuk kembali ke menu...{C.RESET}")

# ---------- Features: Convert Clash -> URI ----------
def feature_convert_to_uri():
    clear_screen()
    banner()
    section("Convert Clash ke URI")
    
    print(f"  {C.CYAN}[1]{C.RESET} Paste Teks YAML langsung")
    print(f"  {C.CYAN}[2]{C.RESET} Baca dari File (di folder Hasil/proxy/)")
    print(f"  {C.CYAN}[0]{C.RESET} Batal")
    print(sep(50))
    
    pilihan = input(f"{C.YELLOW}Pilih (1/2) ❯{C.RESET} ").strip()
    yaml_text = ""
    
    if pilihan == "0":
        return
    elif pilihan == "1":
        print()
        print(f"  {C.DIM}Paste isi file YAML di sini.{C.RESET}")
        print(f"  {C.DIM}Ketik 'selesai' di baris baru untuk memproses.{C.RESET}")
        print(sep(50) + "\n")
        
        lines = []
        while True:
            try: s = input()
            except EOFError: break
            if s.strip().lower() == "selesai": break
            lines.append(s)
        yaml_text = "\n".join(lines)
        
    elif pilihan == "2":
        print()
        section("Pilih File")
        files = [f for f in os.listdir(PROXY_DIR) if f.endswith(('.yaml', '.yml'))]
        
        if not files:
            print(f"  {C.RED}✗ Tidak ada file .yaml di folder {PROXY_DIR}{C.RESET}")
            input(f"\n{C.DIM}Tekan Enter untuk kembali...{C.RESET}"); return
            
        for i, f in enumerate(files, 1):
            print(f"  {C.CYAN}[{i}]{C.RESET} {f}")
        print(f"  {C.CYAN}[0]{C.RESET} Batal")
        print(sep(50))
        
        while True:
            idx = input(f"{C.YELLOW}Pilih nomor file ❯{C.RESET} ").strip()
            if idx == "0": return
            try:
                idx = int(idx)
                if 1 <= idx <= len(files):
                    file_path = os.path.join(PROXY_DIR, files[idx-1])
                    with open(file_path, "r", encoding="utf-8") as f:
                        yaml_text = f.read()
                    break
            except ValueError:
                pass
            print(f"  {C.RED}✗ Pilihan tidak valid.{C.RESET}")
            
    if not yaml_text.strip():
        print(f"\n{C.RED}✗ Tidak ada data YAML.{C.RESET}"); time.sleep(1.5); return

    try:
        data = yaml.safe_load(yaml_text)
        if isinstance(data, dict) and "proxies" in data:
            proxies = data["proxies"]
        elif isinstance(data, list):
            proxies = data
        else:
            raise ValueError("Format YAML tidak dikenali.")
    except Exception as e:
        print(f"\n{C.RED}✗ Gagal parse YAML: {e}{C.RESET}"); time.sleep(1.5); return

    if not proxies:
        print(f"\n{C.YELLOW}! Tidak ada node di dalam file tersebut.{C.RESET}"); time.sleep(1.5); return

    print()
    spinner("Mengkonversi ke URI...", 0.5)
    
    uris = []
    gagal = 0
    for p in proxies:
        try:
            uri = build_uri_from_proxy(p)
            if uri: uris.append(uri)
            else: gagal += 1
        except Exception:
            gagal += 1

    if not uris:
        print(f"\n{C.RED}✗ Gagal konversi semua node. Pastikan tipe-nya VLESS/VMess/Trojan.{C.RESET}")
        time.sleep(1.5); return

    clear_screen()
    banner()
    section(f"Hasil Konversi ({len(uris)} Valid, {gagal} Gagal)")
    
    for i, uri in enumerate(uris, 1):
        print(f"  {C.DIM}[{i}]{C.RESET} {C.CYAN}{uri}{C.RESET}\n")
        
    print(sep(50))
    
    save = input(f"  Simpan ke file? (y/n) ❯ ").strip().lower()
    if save == 'y':
        timestamp = time.strftime("%d%m%Y_%H%M%S")
        out_path = os.path.join(BASE_DIR, f"URI_{timestamp}.txt")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(uris))
        print(f"\n  {C.GREEN}✓ Tersimpan di: {out_path}{C.RESET}")

    input(f"\n{C.DIM}Tekan Enter untuk kembali ke menu...{C.RESET}")

# ---------- Features: Check Status ----------
def feature_check_status():
    clear_screen()
    banner()
    section("Status Sistem & Konfigurasi")
    
    # 1. Status Template
    tpl_exist = os.path.isfile(TEMPLATE_FILE)
    rules_exist = os.path.isdir(RULESET_SOURCE)
    
    print(f"  {C.DIM}Template & Ruleset:{C.RESET}")
    print(f"  {C.GREEN}✓{C.RESET} template.yaml : {C.GREEN}Ada{C.RESET}" if tpl_exist else f"  {C.RED}✗ template.yaml : Tidak ada{C.RESET}")
    print(f"  {C.GREEN}✓{C.RESET} folder ruleset: {C.GREEN}Ada{C.RESET}" if rules_exist else f"  {C.RED}✗ folder ruleset: Tidak ada{C.RESET}")
    
    if tpl_exist:
        with open(TEMPLATE_FILE, "r", encoding="utf-8") as f:
            content = f.read()
        port = re.search(r"^mixed-port:\s*(\d+)", content, re.M)
        secret = re.search(r"^secret:\s*['\"]?([^'\"\n]+)['\"]?", content, re.M)
        
        print(f"    - Port   : {C.CYAN}{port.group(1) if port else '-'}{C.RESET}")
        print(f"    - Secret : {C.CYAN}{secret.group(1) if secret else '-'}{C.RESET}")

    # 2. Status Provider
    print(f"\n  {C.DIM}Provider Node (Hasil/proxy/):{C.RESET}")
    if os.path.isdir(PROXY_DIR):
        files = [f for f in os.listdir(PROXY_DIR) if f.endswith(('.yaml', '.yml'))]
        if not files:
            print(f"  {C.YELLOW}! Belum ada file provider.{C.RESET}")
        for f in files:
            fpath = os.path.join(PROXY_DIR, f)
            try:
                with open(fpath, "r", encoding="utf-8") as file:
                    data = yaml.safe_load(file)
                    count = len(data.get("proxies", [])) if isinstance(data, dict) else 0
                print(f"  {C.GREEN}✓{C.RESET} {f:<15} : {C.BOLD}{count}{C.RESET} node")
            except Exception:
                print(f"  {C.RED}✗{C.RESET} {f:<15} : {C.RED}Format Error{C.RESET}")

    # 3. Status Full Config
    print(f"\n  {C.DIM}Status Full Config:{C.RESET}")
    platforms = [
        ("box", "Box (Android)"),
        ("nikki", "Nikki (OpenWrt)"),
        ("openclash", "OpenClash (OpenWrt)")
    ]
    for plat_id, plat_name in platforms:
        fc_dir = os.path.join(BASE_DIR, f"full_config_{plat_id}")
        fc_config = os.path.join(fc_dir, "config.yaml")
        if os.path.isfile(fc_config):
            print(f"  {C.GREEN}✓{C.RESET} {plat_name:<20} : {C.GREEN}Siap{C.RESET}")
        else:
            print(f"  {C.GRAY}-{C.RESET} {plat_name:<20} : {C.DIM}Belum ada{C.RESET}")
        
    print(f"\n  {C.DIM}Path Output:{C.RESET}")
    print(f"  {C.CYAN}{BASE_DIR}{C.RESET}")

    print()
    input(f"{C.DIM}Tekan Enter untuk kembali ke menu...{C.RESET}")

# ---------- Features: Config DNS ----------
def feature_config_dns():
    if not os.path.isfile(TEMPLATE_FILE):
        print(f"\n{C.RED}✗ File template.yaml tidak ditemukan!{C.RESET}")
        time.sleep(1.5); return

    clear_screen()
    banner()
    section("Konfigurasi DNS")
    
    with open(TEMPLATE_FILE, "r", encoding="utf-8") as f:
        content = f.read()
        
    match = re.search(r"^\s*nameserver:\s*\n((?:\s+- .*\n)+)", content, re.MULTILINE)
    current_dns = "Unknown"
    if match:
        current_dns = match.group(1).strip()

    print(f"  {C.DIM}DNS Aktif di Template:{C.RESET}")
    if current_dns != "Unknown":
        for line in current_dns.split('\n')[:3]:
            print(f"  {C.CYAN}{line.strip()}{C.RESET}")
    else:
        print(f"  {C.YELLOW}Tidak terdeteksi (mungkin formatnya beda).{C.RESET}")
    
    print()
    section("Pilih Provider DNS")
    print(f"  {C.CYAN}[1]{C.RESET} Cloudflare + Google {C.DIM}(DoH){C.RESET}")
    print(f"  {C.CYAN}[2]{C.RESET} Quad9 Unsecured    {C.DIM}(Anti-blokir ISP){C.RESET}")
    print(f"  {C.CYAN}[3]{C.RESET} NextDNS            {C.DIM}(Custom ID){C.RESET}")
    print(f"  {C.CYAN}[4]{C.RESET} AdGuard DNS        {C.DIM}(Filter Iklan){C.RESET}")
    print(f"  {C.CYAN}[5]{C.RESET} Custom Manual      {C.DIM}(Input sendiri){C.RESET}")
    print(f"  {C.CYAN}[0]{C.RESET} Batal")
    print(sep(50))
    
    pilihan = input(f"{C.YELLOW}Pilih (1-5) ❯{C.RESET} ").strip()
    
    dns_list = []
    bootstrap_list = ["1.1.1.1", "8.8.8.8"]

    if pilihan == "1":
        dns_list = ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]
    elif pilihan == "2":
        dns_list = ["https://dns.quad9.net/dns-query"]
    elif pilihan == "3":
        next_id = input(f"  Masukkan NextDNS ID (kosongkan untuk default): ").strip()
        if next_id: dns_list = [f"https://dns.nextdns.io/{next_id}"]
        else: dns_list = ["https://dns.nextdns.io"]
    elif pilihan == "4":
        dns_list = ["https://dns.adguard-dns.com/dns-query", "https://dns.google/dns-query"]
    elif pilihan == "5":
        print(f"  {C.DIM}Masukkan URL DoH (satu per baris, enter kosong untuk selesai):{C.RESET}")
        while True:
            url = input(f"  {C.CYAN}URL ❯{C.RESET} ").strip()
            if not url: break
            dns_list.append(url)
    elif pilihan == "0":
        return
    else:
        print(f"{C.RED}✗ Pilihan tidak valid.{C.RESET}"); time.sleep(1.5); return

    if not dns_list:
        print(f"{C.RED}✗ Tidak ada DNS yang dipilih.{C.RESET}"); time.sleep(1.5); return

    print()
    ganti_bootstrap = input(f"  Ganti Bootstrap (default-nameserver) jadi Cloudflare/Google? (y/n) ❯ ").strip().lower()
    if ganti_bootstrap == 'y':
        bootstrap_list = ["1.1.1.1", "8.8.8.8"]

    spinner("Menerapkan konfigurasi DNS...", 0.5)
    
    try:
        with open(TEMPLATE_FILE + ".bak", "w", encoding="utf-8") as f_bak:
            f_bak.write(content)
    except Exception:
        pass

    new_nameserver = "  nameserver:\n" + "".join([f"    - {url}\n" for url in dns_list])
    new_bootstrap = "  default-nameserver:\n" + "".join([f"    - {ip}\n" for ip in bootstrap_list])

    content = re.sub(r"^\s*nameserver:\s*\n((?:\s+- .*\n)+)", new_nameserver, content, flags=re.MULTILINE)
    content = re.sub(r"^\s*default-nameserver:\s*\n((?:\s+- .*\n)+)", new_bootstrap, content, flags=re.MULTILINE)

    try:
        with open(TEMPLATE_FILE, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"\n{C.GREEN}✓ DNS berhasil diterapkan!{C.RESET}")
    except Exception as e:
        print(f"\n{C.RED}✗ Gagal menyimpan: {e}{C.RESET}")

    print(f"  {C.DIM}DNS baru aktif saat kamu nge-generate Full Config lagi.{C.RESET}")
    input(f"\n{C.DIM}Tekan Enter untuk kembali...{C.RESET}")

# ---------- Features: Edit Configuration Menu ----------
def feature_edit_config():
    while True:
        clear_screen()
        banner()
        section("Edit Configuration")
        
        print(f"  {C.CYAN}[1]{C.RESET} Edit Port & Secret")
        print(f"  {C.CYAN}[2]{C.RESET} Ganti File Template")
        print(f"  {C.CYAN}[3]{C.RESET} Konfigurasi DNS & Nameserver")
        print(f"  {C.CYAN}[0]{C.RESET} Kembali ke Menu Utama")
        print(sep(50))
        
        pilih = input(f"{C.YELLOW}Pilih menu ❯{C.RESET} ").strip()
        
        if pilih == "0":
            break
        elif pilih == "1":
            if not os.path.isfile(TEMPLATE_FILE):
                print(f"\n{C.RED}✗ Template belum ada!{C.RESET}"); time.sleep(1.5); continue
            
            with open(TEMPLATE_FILE, "r", encoding="utf-8") as f:
                content = f.read()
            port = re.search(r"^mixed-port:\s*(\d+)", content, re.M)
            secret = re.search(r"^secret:\s*['\"]?([^'\"\n]+)['\"]?", content, re.M)

            print()
            section("Edit Port & Secret")
            print(f"  {C.DIM}Kosongkan (Enter) jika tidak ingin mengubah.{C.RESET}")
            
            new_port = input(f"  Mixed Port Baru (sekarang: {port.group(1) if port else '-'}): ").strip()
            new_secret = input(f"  Secret Baru (sekarang: {secret.group(1) if secret else '-'}): ").strip()
            
            if new_port or new_secret:
                with open(TEMPLATE_FILE, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                
                for i, line in enumerate(lines):
                    if new_port and line.startswith("mixed-port:"):
                        lines[i] = f"mixed-port: {new_port}\n"
                    if new_secret and line.startswith("secret:"):
                        lines[i] = f"secret: '{new_secret}'\n"
                        
                with open(TEMPLATE_FILE, "w", encoding="utf-8") as f:
                    f.writelines(lines)
                print(f"\n{C.GREEN}✓ Template berhasil diupdate!{C.RESET}")
            else:
                print(f"\n{C.YELLOW}Tidak ada perubahan.{C.RESET}")
            time.sleep(1.5)

        elif pilih == "2":
            print()
            section("Ganti Template")
            print(f"  {C.DIM}Masukkan path lengkap file template baru.{C.RESET}")
            src = input(f"  {C.CYAN}Path ❯{C.RESET} ").strip()
            
            if src and os.path.isfile(src):
                try:
                    with open(src, "r", encoding="utf-8") as f_src:
                        isi_baru = f_src.read()
                    with open(TEMPLATE_FILE, "w", encoding="utf-8") as f_dst:
                        f_dst.write(isi_baru)
                    print(f"\n{C.GREEN}✓ Template berhasil diganti!{C.RESET}")
                except Exception as e:
                    print(f"\n{C.RED}✗ Gagal menyalin: {e}{C.RESET}")
            else:
                print(f"\n{C.RED}✗ File tidak ditemukan.{C.RESET}")
            time.sleep(1.5)
            
        elif pilih == "3":
            feature_config_dns()

# ---------- Features: Convert Menu ----------
def feature_convert_menu():
    clear_screen()
    banner()
    section("Menu Convert")
    print(f"  {C.CYAN}[1]{C.RESET} URI (VLESS/VMess/Trojan)  ➜  Clash (YAML)")
    print(f"  {C.CYAN}[2]{C.RESET} Clash (YAML)              ➜  URI (VLESS/VMess/Trojan)")
    print(f"  {C.CYAN}[0]{C.RESET} Kembali ke Menu Utama")
    print(sep(50))
    
    pilihan = input(f"{C.YELLOW}Pilih (1/2) ❯{C.RESET} ").strip()
    
    if pilihan == "1":
        clear_screen()
        banner()
        feature_convert_to_clash()
    elif pilihan == "2":
        feature_convert_to_uri()

# ---------- Main Menu ----------
def main():
    prepare_dirs()
    
    while True:
        clear_screen()
        banner()
        section("MENU UTAMA")
        print(f"  {C.CYAN}[1]{C.RESET} Convert")
        print(f"  {C.CYAN}[2]{C.RESET} Edit Configuration")
        print(f"  {C.CYAN}[3]{C.RESET} Check Status")
        print(f"  {C.CYAN}[4]{C.RESET} Coming Soon...")
        print(f"  {C.CYAN}[5]{C.RESET} Exit")
        print(sep(50))
        
        pilihan = input(f"{C.YELLOW}Pilih menu ❯{C.RESET} ").strip()
        
        if pilihan == "1":
            feature_convert_menu()
        elif pilihan == "2":
            feature_edit_config()
        elif pilihan == "3":
            feature_check_status()
        elif pilihan == "4":
            print(f"\n  {C.MAGENTA}✨ Fitur ini sedang dikembangkan bro! Stay tuned. ✨{C.RESET}")
            time.sleep(1.5)
        elif pilihan == "5":
            clear_screen()
            print(f"\n  {C.GREEN}Terima kasih sudah pakai Hikari Subclash!{C.RESET}\n")
            sys.exit(0)
        else:
            print(f"\n  {C.RED}Pilihan tidak valid.{C.RESET}")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {C.RED}Program dihentikan.{C.RESET}\n")
        sys.exit(0)