# SPECTRE-Lite

**S**ervice & **P**ort **E**numeration with **C**overt **T**itle **R**econ **E**ngine

---

## Features

- Pure Python async scanning — no external tools required
- Protocol-aware banner grabbing (SSH, FTP, SMTP, Redis, HTTP ...)
- HTTP/HTTPS title extraction with automatic SSL bypass
- Retry logic: 2x retries (5s → 10s) before marking host as dead
- Delta scan — detects changes since last run (new / closed / changed ports)
- Colored terminal output with atomic per-host printing (no interleaving)
- Reports exported in TXT, JSON, and HTML (dark theme)

---

## Requirements

- Python 3.8+
- No external binaries needed

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Input Files

| File | Description |
|------|-------------|
| `ip_ranges.txt` | IPs or CIDR ranges to scan (one per line) |
| `ports.txt` | Ports to check (one per line, comma-separated, or ranges like `8080-8090`) |
| `signatures.txt` | Keywords to match against banners and HTTP titles |

---

## Usage

```bash
python spectre.py
```

On launch you will see:

```
[?] Select scan mode:
  [1] Banner scan only  — protocol-aware banner grabbing (fast)
  [2] HTTP Title only   — grab page titles via HTTP/HTTPS
  [3] Full scan         — banner + HTTP title + delta report

[?] Concurrent workers: 
```

---

## Output

All reports are saved inside the `reports/` folder:

| File | Format |
|------|--------|
| `spectre_<timestamp>.txt` | Human-readable plain text |
| `spectre_<timestamp>.json` | Machine-readable JSON |
| `spectre_<timestamp>.html` | Interactive dark-theme HTML report |

Delta comparison is stored in `.spectre_last_scan.json` and updated after every run.

---

## Delta Report

On every run SPECTRE-Lite compares results with the previous scan and highlights:

```
+ 10.0.0.5:8080   http Apache          ← NEW
x 10.0.0.3:22     ssh OpenSSH 7.4      ← CLOSED
~ 10.0.0.1:80     nginx 1.18 -> 1.24   ← CHANGED
```


---

*Developed by [WhoIsHalim](https://github.com/WhoIsHalim)*
