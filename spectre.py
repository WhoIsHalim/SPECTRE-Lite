#!/usr/bin/env python3
"""
SPECTRE — Service & Port Enumeration with Covert Title Recon Engine
Version 3.0  |  github.com/WhoIsHalim
Authorized Internal Use Only
"""

import asyncio, ipaddress, json, re, sys, time, warnings
from datetime import datetime
from pathlib import Path
from threading import Lock

import aiohttp
from bs4 import BeautifulSoup

warnings.filterwarnings("ignore")

# ══════════════════════════════════════════════════════════════════════════════
# ANSI Colors
# ══════════════════════════════════════════════════════════════════════════════

class C:
    RESET   = "\033[0m";  BOLD    = "\033[1m";  DIM     = "\033[2m"
    BRED    = "\033[91m"; BGREEN  = "\033[92m"; BYELLOW = "\033[93m"
    BBLUE   = "\033[94m"; BCYAN   = "\033[96m"; BWHITE  = "\033[97m"
    BG_YEL  = "\033[43m"; WHITE   = "\033[37m"

def strip_ansi(t):
    return re.sub(r"\033\[[0-9;]*m", "", t)

# ══════════════════════════════════════════════════════════════════════════════
# Banner
# ══════════════════════════════════════════════════════════════════════════════

BANNER = (
    C.BCYAN + C.BOLD + "\n"
    "  ██████  ██████  ███████  ██████ ████████ ██████  ███████\n"
    " ██      ██    ██ ██      ██         ██    ██   ██ ██\n"
    "  █████  ██    ██ █████   ██         ██    ██████  █████\n"
    "      ██ ██ ▄▄ ██ ██      ██         ██    ██   ██ ██\n"
    "  █████   ██████  ███████  ██████    ██    ██   ██ ███████\n"
    "              ▀▀" + C.RESET + "\n"
    + C.DIM + "  Service & Port Enumeration with Covert Title Recon Engine\n"
    "  ─────────────────────────────────────────────────────────" + C.RESET + "\n"
    "  " + C.BYELLOW + "Version 2.0" + C.RESET
    + "  " + C.DIM + "|" + C.RESET
    + "  " + C.BBLUE + "github.com/WhoIsHalim" + C.RESET
)

DIV  = C.DIM + "  " + "─" * 56 + C.RESET
DIV2 = C.DIM + "  " + "═" * 56 + C.RESET

# ══════════════════════════════════════════════════════════════════════════════
# Config
# ══════════════════════════════════════════════════════════════════════════════

INPUT_DIR       = Path(".")
REPORTS_DIR     = Path("reports")
HTTP_TIMEOUT    = 5
CONNECT_TIMEOUT = 2
BANNER_TIMEOUT  = 2
RETRY_DELAYS    = [5, 10]
DELTA_FILE      = Path(".spectre_last_scan.json")
print_lock      = Lock()

PROBES = {
    21:   b"USER anonymous\r\n",
    22:   b"",
    25:   b"EHLO spectre\r\n",
    110:  b"USER spectre\r\n",
    143:  b"A001 CAPABILITY\r\n",
    6379: b"PING\r\n",
    80:   b"HEAD / HTTP/1.0\r\n\r\n",
    443:  b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
}
DEFAULT_PROBE = b"\r\n"

PORT_NAMES = {
    21:"ftp", 22:"ssh", 23:"telnet", 25:"smtp", 53:"dns",
    80:"http", 110:"pop3", 143:"imap", 443:"https", 445:"smb",
    3306:"mysql", 3389:"rdp", 5432:"postgresql", 6379:"redis",
    8080:"http-alt", 8443:"https-alt", 27017:"mongodb",
}

# ══════════════════════════════════════════════════════════════════════════════
# File Readers
# ══════════════════════════════════════════════════════════════════════════════

def read_ip_ranges(path):
    seen, ips = set(), []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        try:
            net = ipaddress.ip_network(line, strict=False)
            for h in net.hosts():
                s = str(h)
                if s not in seen: seen.add(s); ips.append(s)
        except ValueError:
            if line not in seen: seen.add(line); ips.append(line)
    return ips

def read_ports(path):
    ports = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        for token in line.split(","):
            token = token.strip()
            if "-" in token:
                try:
                    a, b = token.split("-")
                    ports.extend(range(int(a), int(b)+1))
                except: pass
            elif token.isdigit():
                ports.append(int(token))
    return sorted(set(ports))

def read_signatures(path):
    return [l.strip().lower() for l in path.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.startswith("#")]

# ══════════════════════════════════════════════════════════════════════════════
# Stats
# ══════════════════════════════════════════════════════════════════════════════

class Stats:
    def __init__(self):
        self._lock = asyncio.Lock()
        self.open_ports = self.sig_matches = self.http_grabbed = self.ips_done = 0
    async def add(self, open_ports=0, sig_matches=0, http_grabbed=0):
        async with self._lock:
            self.open_ports   += open_ports
            self.sig_matches  += sig_matches
            self.http_grabbed += http_grabbed
            self.ips_done     += 1

STATS = Stats()

# ══════════════════════════════════════════════════════════════════════════════
# Async Network Primitives
# ══════════════════════════════════════════════════════════════════════════════

async def check_port(ip, port, sem):
    async with sem:
        try:
            _, w = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=CONNECT_TIMEOUT)
            w.close()
            try: await w.wait_closed()
            except: pass
            return True
        except: return False

async def banner_grab(ip, port, sem):
    probe = PROBES.get(port, DEFAULT_PROBE)
    async with sem:
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=BANNER_TIMEOUT)
            if probe:
                w.write(probe); await w.drain()
            data = await asyncio.wait_for(r.read(1024), timeout=BANNER_TIMEOUT)
            w.close()
            try: await w.wait_closed()
            except: pass
            return data.decode(errors="replace").strip()
        except: return ""

async def http_grab(ip, port, session):
    for scheme in ("https", "http"):
        url = f"{scheme}://{ip}:{port}"
        for attempt, delay in enumerate([0] + RETRY_DELAYS):
            if delay:
                with print_lock:
                    print(f"  {C.BYELLOW}[~]{C.RESET} {C.DIM}http {ip}:{port}{C.RESET} "
                          f"retry {attempt} in {C.BYELLOW}{delay}s{C.RESET}")
                await asyncio.sleep(delay)
            try:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=HTTP_TIMEOUT),
                    ssl=False, allow_redirects=True
                ) as resp:
                    body  = await resp.text(errors="replace")
                    soup  = BeautifulSoup(body, "html.parser")
                    title = soup.title.string.strip() if soup.title and soup.title.string else ""
                    return {"url": url, "status": resp.status,
                            "title": title, "server": resp.headers.get("Server", "")}
            except aiohttp.ClientSSLError: break
            except: continue
    return {}

def match_sigs(text, sigs):
    tl = text.lower()
    return [s for s in sigs if s in tl]

def guess_service(port, banner):
    if banner:
        bl = banner.lower()
        for kw, svc in [("ssh","ssh"),("ftp","ftp"),("smtp","smtp"),
                        ("imap","imap"),("pop3","pop3"),("http","http"),
                        ("mysql","mysql"),("redis","redis"),("postgresql","postgresql")]:
            if kw in bl: return svc
    return PORT_NAMES.get(port, "unknown")

def guess_version(banner):
    if not banner: return ""
    m = re.search(r"([\w\-/]+[\s/][\d]+\.[\d]+[\.\d]*)", banner)
    return m.group(1).strip() if m else ""

# ══════════════════════════════════════════════════════════════════════════════
# Atomic Output Builder
# Builds entire IP block as one string → prints once → no interleaving
# ══════════════════════════════════════════════════════════════════════════════

def build_ip_block(ip, port_data):
    lines = [
        "",
        f"  {C.BGREEN}[>>]{C.RESET} {C.BOLD}{C.BWHITE}{ip}{C.RESET}  "
        f"{C.DIM}—{C.RESET}  {C.BYELLOW}{len(port_data)} open port(s){C.RESET}",
        DIV,
    ]
    for port, service, version, banner, http, matched in port_data:
        sc = (C.BGREEN if http and 200 <= http.get("status", 0) < 300
              else C.BYELLOW if http else C.RESET)

        # port line
        lines.append(
            f"\n    {C.BBLUE}●{C.RESET} "
            f"{C.BOLD}{C.BWHITE}{port}/tcp{C.RESET}  "
            f"{C.BGREEN}{service}{C.RESET}  "
            f"{C.DIM}{version}{C.RESET}"
        )
        # banner
        if banner:
            b = banner[:90].replace("\n", " ").replace("\r", "")
            lines.append(f"      {C.DIM}banner :{C.RESET}  {C.WHITE}{b}{C.RESET}")
        # http
        if http:
            lines.append(
                f"      {C.DIM}url    :{C.RESET}  {C.BCYAN}{http['url']}{C.RESET}  "
                f"[{sc}{http['status']}{C.RESET}]"
            )
            if http["title"]:
                lines.append(f"      {C.DIM}title  :{C.RESET}  {C.BWHITE}{http['title']}{C.RESET}")
            if http.get("server"):
                lines.append(f"      {C.DIM}server :{C.RESET}  {C.DIM}{http['server']}{C.RESET}")
        # matches
        if matched:
            tags = "  ".join(f"{C.BG_YEL}{C.BOLD} {s.upper()} {C.RESET}" for s in matched)
            lines.append(f"      {C.BRED}★ MATCH{C.RESET}  {tags}")

    lines.append("")
    return "\n".join(lines)

# ══════════════════════════════════════════════════════════════════════════════
# Delta
# ══════════════════════════════════════════════════════════════════════════════

def load_last_scan():
    if DELTA_FILE.exists():
        try: return json.loads(DELTA_FILE.read_text(encoding="utf-8"))
        except: pass
    return {}

def save_scan(data):
    DELTA_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")

def compute_delta(old, new):
    out = []
    for key in sorted(set(old) | set(new)):
        if   key not in old: out.append(("NEW",     key, new[key]))
        elif key not in new: out.append(("CLOSED",  key, old[key]))
        elif old[key] != new[key]: out.append(("CHANGED", key, f"{old[key]}  ->  {new[key]}"))
    return out

# ══════════════════════════════════════════════════════════════════════════════
# HTML Report
# ══════════════════════════════════════════════════════════════════════════════

def generate_html(results, delta, stats, elapsed, ts):
    mins, secs = divmod(int(elapsed), 60)
    rows = ""
    for r in results:
        match_cell = ("  ".join(f'<span class="tag">{s.upper()}</span>' for s in r["matches"])
                      if r["matches"] else '<span class="dim">—</span>')
        sc = "ok" if r.get("status") and 200 <= int(r["status"]) < 300 else "warn"
        url = r.get("url", "")
        rows += (f'<tr><td class="ip">{r["ip"]}</td>'
                 f'<td><b>{r["port"]}</b>/tcp</td>'
                 f'<td class="svc">{r.get("service","")}</td>'
                 f'<td class="ver">{r.get("version","")}</td>'
                 f'<td class="ban">{str(r.get("banner","")).replace("<","&lt;")[:60]}</td>'
                 f'<td><a href="{url}" target="_blank">{url}</a></td>'
                 f'<td class="{sc}">{r.get("status","")}</td>'
                 f'<td>{r.get("title","")}</td>'
                 f'<td>{match_cell}</td></tr>')

    delta_html = ""
    if delta:
        items = ""
        icons = {"NEW": "＋", "CLOSED": "✕", "CHANGED": "△"}
        for kind, key, val in delta:
            items += (f'<li class="{kind.lower()}">'
                      f'<span class="icon">{icons[kind]}</span> <b>{key}</b>  {val}</li>')
        delta_html = (f'<section class="delta-section">'
                      f'<h2>Delta — Changes Since Last Scan</h2>'
                      f'<ul class="delta">{items}</ul></section>')
    else:
        delta_html = '<p class="no-delta">No changes detected since last scan.</p>'

    css = """
:root{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--border:#30363d;
      --text:#c9d1d9;--dim:#6e7681;--cyan:#58a6ff;--green:#3fb950;
      --red:#f85149;--yellow:#d29922;--purple:#bc8cff;}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Courier New',monospace;padding:2rem;}
header{border-bottom:1px solid var(--border);padding-bottom:1.5rem;margin-bottom:2rem;}
h1{color:var(--cyan);font-size:1.6rem;letter-spacing:.05em;}
h1 span{color:var(--dim);font-size:.9rem;font-weight:normal;}
h2{color:var(--text);font-size:.95rem;margin:2rem 0 .8rem;}
.meta{color:var(--dim);font-size:.8rem;margin-top:.4rem;}
.cards{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem;}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;
      padding:1rem 1.5rem;min-width:130px;text-align:center;}
.card .num{font-size:2rem;font-weight:bold;color:var(--cyan);}
.card .lbl{font-size:.72rem;color:var(--dim);margin-top:.3rem;text-transform:uppercase;}
.delta-section{background:var(--bg2);border:1px solid var(--border);
               border-radius:8px;padding:1.2rem 1.5rem;margin-bottom:2rem;}
.delta{list-style:none;}
.delta li{padding:.4rem .75rem;margin:.3rem 0;border-radius:4px;
          border-left:3px solid;font-size:.83rem;display:flex;gap:.6rem;align-items:center;}
.new{border-color:var(--green);background:#3fb9500f;}
.closed{border-color:var(--red);background:#f851490f;}
.changed{border-color:var(--yellow);background:#d299220f;}
.icon{width:1.2rem;text-align:center;}
.no-delta{color:var(--dim);font-style:italic;margin-bottom:2rem;}
.table-wrap{overflow-x:auto;}
table{width:100%;border-collapse:collapse;font-size:.8rem;}
th{background:var(--bg3);color:var(--dim);text-align:left;padding:.55rem .75rem;
   border-bottom:2px solid var(--border);position:sticky;top:0;
   text-transform:uppercase;font-size:.7rem;letter-spacing:.06em;}
td{padding:.45rem .75rem;border-bottom:1px solid var(--border);vertical-align:top;}
tr:hover{background:var(--bg2);}
td a{color:var(--cyan);text-decoration:none;}
td a:hover{text-decoration:underline;}
.ok{color:var(--green);font-weight:bold;}
.warn{color:var(--yellow);}
.tag{background:#d299221a;color:var(--yellow);padding:.1rem .35rem;
     border-radius:3px;font-size:.74rem;margin-right:.2rem;}
.dim{color:var(--dim);}
.ip{color:var(--purple);font-weight:bold;}
.svc{color:var(--green);}
.ver{color:var(--dim);}
.ban{color:var(--dim);font-size:.73rem;max-width:180px;word-break:break-all;}
"""
    return (f'<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
            f'<title>SPECTRE Report — {ts}</title>'
            f'<style>{css}</style></head><body>'
            f'<header><h1>SPECTRE Scanner <span>v3.0</span></h1>'
            f'<p class="meta">{ts} &nbsp;·&nbsp; {mins}m {secs}s &nbsp;·&nbsp; github.com/WhoIsHalim</p></header>'
            f'<div class="cards">'
            f'<div class="card"><div class="num">{stats.ips_done}</div><div class="lbl">IPs Scanned</div></div>'
            f'<div class="card"><div class="num">{stats.open_ports}</div><div class="lbl">Open Ports</div></div>'
            f'<div class="card"><div class="num">{stats.sig_matches}</div><div class="lbl">Sig Matches</div></div>'
            f'<div class="card"><div class="num">{stats.http_grabbed}</div><div class="lbl">HTTP Titles</div></div>'
            f'<div class="card"><div class="num">{mins}m{secs}s</div><div class="lbl">Duration</div></div>'
            f'</div>'
            f'{delta_html}'
            f'<h2>Scan Results</h2><div class="table-wrap"><table>'
            f'<thead><tr><th>IP</th><th>Port</th><th>Service</th><th>Version</th>'
            f'<th>Banner</th><th>URL</th><th>Status</th><th>Title</th><th>Matches</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div></body></html>')

# ══════════════════════════════════════════════════════════════════════════════
# Per-IP Coroutine
# ══════════════════════════════════════════════════════════════════════════════

async def scan_ip(ip, ports, signatures, mode, sem, session, txt_results, json_results):
    # scan all ports in parallel
    checks     = await asyncio.gather(*[check_port(ip, p, sem) for p in ports])
    open_ports = [p for p, ok in zip(ports, checks) if ok]

    if not open_ports:
        with print_lock:
            print(f"  {C.DIM}[-] {ip} — no open ports{C.RESET}")
        await STATS.add()
        return

    port_data     = []
    txt_block     = [f"\n[ {ip} ]"]
    total_matches = 0
    http_count    = 0

    async def process_port(port):
        nonlocal total_matches, http_count
        banner  = await banner_grab(ip, port, sem) if mode in (1, 3) else ""
        http    = await http_grab(ip, port, session) if mode in (2, 3) else {}
        service = guess_service(port, banner)
        version = guess_version(banner)
        title   = http.get("title", "")
        server  = http.get("server", "")
        matched = match_sigs(f"{service} {version} {banner} {title} {server}", signatures)
        total_matches += len(matched)
        if http: http_count += 1
        port_data.append((port, service, version, banner, http or None, matched))
        txt_block.extend([f"  Port {port}/tcp",
                          f"    Service : {service}",
                          f"    Version : {version}"])
        if banner:  txt_block.append(f"    Banner  : {banner[:120]}")
        if http:
            txt_block.extend([f"    URL     : {http['url']}",
                              f"    Status  : {http['status']}",
                              f"    Title   : {title}",
                              f"    Server  : {server}"])
        if matched: txt_block.append(f"    *** MATCH: {', '.join(matched)} ***")
        txt_block.append("")
        json_results.append({"ip": ip, "port": port, "service": service,
                             "version": version, "banner": banner[:120],
                             "url": http.get("url",""), "status": http.get("status",""),
                             "title": title, "server": server, "matches": matched})

    await asyncio.gather(*[process_port(p) for p in open_ports])

    # sort by port, build output atomically
    port_data.sort(key=lambda x: x[0])
    with print_lock:
        print(build_ip_block(ip, port_data))

    txt_results.extend(txt_block)
    await STATS.add(open_ports=len(open_ports),
                    sig_matches=total_matches, http_grabbed=http_count)

# ══════════════════════════════════════════════════════════════════════════════
# UI
# ══════════════════════════════════════════════════════════════════════════════

def ask_choice(prompt, choices):
    print(prompt)
    for i, c in enumerate(choices, 1):
        print(f"  {C.BCYAN}[{i}]{C.RESET} {c}")
    while True:
        try:
            val = input(f"\n  {C.BYELLOW}Select option >{C.RESET} ").strip()
            if val.isdigit() and 1 <= int(val) <= len(choices): return int(val)
            print(f"  {C.BRED}[!]{C.RESET} Invalid choice.")
        except (KeyboardInterrupt, EOFError):
            print("\n  Exiting."); sys.exit(0)

def ask_int(prompt, minimum=1):
    while True:
        try:
            val = input(prompt).strip()
            if val.isdigit() and int(val) >= minimum: return int(val)
            print(f"  {C.BRED}[!]{C.RESET} Enter a number >= {minimum}.")
        except (KeyboardInterrupt, EOFError):
            print("\n  Exiting."); sys.exit(0)

# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

async def async_main():
    print(BANNER)

    mode = ask_choice(
        f"  {C.BWHITE}[?]{C.RESET} Select scan mode:\n",
        [f"Banner scan only  {C.DIM}— protocol-aware banner grabbing (fast){C.RESET}",
         f"HTTP Title only   {C.DIM}— grab page titles via HTTP/HTTPS{C.RESET}",
         f"Full scan         {C.DIM}— banner + HTTP title + delta report{C.RESET}"]
    )
    workers = ask_int(f"\n  {C.BWHITE}[?]{C.RESET} Concurrent workers: ")
    print(C.RESET, end="")

    for f in ["ip_ranges.txt", "ports.txt", "signatures.txt"]:
        if not (INPUT_DIR / f).exists():
            print(f"\n  {C.BRED}[ERROR]{C.RESET} Missing: {f}"); sys.exit(1)

    ips        = read_ip_ranges(INPUT_DIR / "ip_ranges.txt")
    ports      = read_ports(INPUT_DIR / "ports.txt")
    signatures = read_signatures(INPUT_DIR / "signatures.txt")
    last_scan  = load_last_scan()

    mode_names = ["Banner only", "HTTP Title only", "Full scan"]
    mode_name  = mode_names[mode - 1]
    ts         = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    REPORTS_DIR.mkdir(exist_ok=True)

    print(f"\n{DIV2}")
    print(f"  {C.DIM}IPs        :{C.RESET}  {C.BWHITE}{len(ips)}{C.RESET}")
    print(f"  {C.DIM}Ports      :{C.RESET}  {C.BWHITE}{len(ports)}{C.RESET}")
    print(f"  {C.DIM}Signatures :{C.RESET}  {C.BWHITE}{len(signatures)}{C.RESET}")
    print(f"  {C.DIM}Mode       :{C.RESET}  {C.BCYAN}{mode_name}{C.RESET}")
    print(f"  {C.DIM}Workers    :{C.RESET}  {C.BYELLOW}{workers}{C.RESET}")
    print(f"  {C.DIM}Retry      :{C.RESET}  {C.DIM}2x  (5s -> 10s){C.RESET}")
    print(f"  {C.DIM}Delta      :{C.RESET}  " +
          (f"{C.BGREEN}previous scan found{C.RESET}" if last_scan
           else f"{C.DIM}no previous scan{C.RESET}"))
    print(f"  {C.DIM}Output     :{C.RESET}  {C.BBLUE}{REPORTS_DIR}/{C.RESET}")
    print(f"{DIV2}\n")

    txt_results  = ["=" * 60, "  SPECTRE — Scan Report",
                    "  Version : 3.0  |  github.com/WhoIsHalim",
                    f"  Date    : {ts}", f"  Mode    : {mode_name}",
                    f"  Workers : {workers}", "=" * 60]
    json_results = []
    sem          = asyncio.Semaphore(workers)
    start_time   = time.time()

    connector = aiohttp.TCPConnector(ssl=False, limit=workers, limit_per_host=10)
    async with aiohttp.ClientSession(connector=connector) as session:
        await asyncio.gather(*[
            scan_ip(ip, ports, signatures, mode, sem, session, txt_results, json_results)
            for ip in ips
        ])

    elapsed    = time.time() - start_time
    mins, secs = divmod(int(elapsed), 60)

    # delta
    current_scan = {f"{r['ip']}:{r['port']}": f"{r['service']} {r['version']}".strip()
                    for r in json_results}
    delta = compute_delta(last_scan, current_scan)
    save_scan(current_scan)

    # summary terminal
    sc = C.BRED if STATS.sig_matches else C.DIM
    print(f"\n{DIV2}")
    print(f"  {C.BOLD}{C.BWHITE}SCAN SUMMARY{C.RESET}")
    print(DIV)
    print(f"  {C.DIM}IPs scanned       :{C.RESET}  {C.BWHITE}{len(ips)}{C.RESET}")
    print(f"  {C.DIM}Open ports found  :{C.RESET}  {C.BGREEN}{STATS.open_ports}{C.RESET}")
    print(f"  {C.DIM}Signature matches :{C.RESET}  {sc}{STATS.sig_matches}{C.RESET}")
    print(f"  {C.DIM}HTTP titles found :{C.RESET}  {C.BCYAN}{STATS.http_grabbed}{C.RESET}")
    print(f"  {C.DIM}Scan duration     :{C.RESET}  {C.BYELLOW}{mins}m {secs}s{C.RESET}")
    print(DIV2)

    if delta:
        print(f"\n  {C.BOLD}{C.BWHITE}DELTA — Changes Since Last Scan{C.RESET}")
        print(DIV)
        colors = {"NEW": C.BGREEN, "CLOSED": C.BRED, "CHANGED": C.BYELLOW}
        icons  = {"NEW": "+", "CLOSED": "x", "CHANGED": "~"}
        for kind, key, val in delta:
            print(f"  {colors[kind]}{icons[kind]}{C.RESET}  {C.BWHITE}{key}{C.RESET}  {C.DIM}{val}{C.RESET}")
        print()
    else:
        print(f"\n  {C.DIM}No changes detected since last scan.{C.RESET}\n")

    # save files
    summary = ["\n" + "=" * 60, "  SCAN SUMMARY",
               f"  IPs scanned       : {len(ips)}",
               f"  Open ports found  : {STATS.open_ports}",
               f"  Signature matches : {STATS.sig_matches}",
               f"  HTTP titles found : {STATS.http_grabbed}",
               f"  Scan duration     : {mins}m {secs}s",
               "=" * 60]
    if delta:
        summary += ["\n  DELTA"] + [f"  [{k}] {key}  {val}" for k, key, val in delta]
    txt_results.extend(summary)

    tf = REPORTS_DIR / f"spectre_{ts}.txt"
    jf = REPORTS_DIR / f"spectre_{ts}.json"
    hf = REPORTS_DIR / f"spectre_{ts}.html"
    tf.write_text("\n".join(txt_results), encoding="utf-8")
    jf.write_text(json.dumps(json_results, indent=2, ensure_ascii=False), encoding="utf-8")
    hf.write_text(generate_html(json_results, delta, STATS, elapsed, ts), encoding="utf-8")

    print(f"  {C.BGREEN}[+]{C.RESET} TXT  -> {C.BBLUE}{tf}{C.RESET}")
    print(f"  {C.BGREEN}[+]{C.RESET} JSON -> {C.BBLUE}{jf}{C.RESET}")
    print(f"  {C.BGREEN}[+]{C.RESET} HTML -> {C.BBLUE}{hf}{C.RESET}\n")


def main():
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        print(f"\n\n  {C.BRED}[!] Interrupted — exiting gracefully.{C.RESET}\n")

if __name__ == "__main__":
    main()
