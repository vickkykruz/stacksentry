# StackSentry 🛡️
 
**Automated web application security assessment, AI-powered remediation, and auto-fix.**
 
[![Tests](https://img.shields.io/badge/tests-321%20passing-brightgreen)](https://github.com/vickkykruz/stacksentry)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://pypi.org/project/stacksentry/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![PyPI](https://img.shields.io/badge/pypi-v1.0.0-orange)](https://pypi.org/project/stacksentry/)
 
StackSentry scans your web application stack — Flask/Django/PHP app, Nginx/Apache webserver, Docker containers, and Linux host — assigns a security grade, generates AI-powered fix scripts, and can apply fixes automatically via SSH or directly to your config files.
 
---
 
## What it does
 
```bash
stacksentry -t https://your-app.com --mode full --patch --fix \
  --ssh-host your-server-ip --ssh-user root --ssh-key ~/.ssh/id_ed25519 \
  --dockerfile ./Dockerfile \
  --compose-file ./docker-compose.yml
```
 
In one command, StackSentry:
 
- Runs **24+ security checks** across 4 layers of your stack
- Assigns a **security grade** (A–F) with a percentage score
- Generates a **professional PDF report** with OWASP Top 5 mapping
- Creates **AI-powered fix scripts** organised per scan in `patches/`
- **Auto-applies fixes** via SSH (HOST + WS) or directly to your config files (CONT + WS)
- **Generates and installs SSH keys** before applying `prohibit-password` — so you are never locked out
- Prints **stack-aware code snippets** for APP layer checks (Flask, Django, Laravel, vanilla PHP)
- Tracks **posture drift** — shows what regressed or improved since last scan
- Simulates **what-if scenarios** — projects your grade after specific fixes
- Detects **PHP/Apache/shared hosting** stacks automatically and adjusts checks accordingly
 
---
 
## Real-world results
 
StackSentry was tested against three live applications during development:
 
| Target | Stack | Before | After auto-fix | Checks fixed |
|---|---|---|---|---|
| `admin.vickkykruzprogramming.dev` | nginx/Ubuntu VPS | F (16.7%) | **C (72.7%)** | HSTS, security headers, server token, TLS, request limits, SSH hardening |
| `bblearn.londonmet.ac.uk` | Unknown/SPA (Blackboard LMS) | D (66.7%) | — (no SSH) | Scan only — CSRF PASS, admin WARN (login wall detected) |
| `sacoeteccscdept.com.ng` | PHP/Apache/shared hosting | F (27.3%) | — (no SSH) | Scan only — stack correctly detected from URL alone |
 
The VPS went from **F (16.7%) to C (72.7%)** with **0 attack paths** after auto-fix.
 
---
 
## Quick start
 
```bash
pip install stacksentry
 
# Basic HTTP scan
stacksentry -t https://your-app.com
 
# Full stack scan with PDF report
stacksentry -t https://your-app.com --mode full \
  --ssh-host your-server-ip --ssh-user root --ssh-password yourpass \
  -o report.pdf
 
# Dry-run — see exactly what would change before applying
stacksentry -t https://your-app.com --mode full --fix --dry-run \
  --ssh-host your-server-ip --ssh-user root --ssh-password yourpass
 
# Generate AI-powered fix scripts + auto-apply
stacksentry -t https://your-app.com --mode full --patch --fix \
  --ssh-host your-server-ip --ssh-user root --ssh-password yourpass \
  --dockerfile ./Dockerfile --compose-file ./docker-compose.yml
 
# Use SSH key after StackSentry generates one
stacksentry -t https://your-app.com --mode full --fix \
  --ssh-host your-server-ip --ssh-user root \
  --ssh-key ~/.stacksentry/keys/your-server_20260411.pem
 
# Compare against last scan (posture drift)
stacksentry -t https://your-app.com --compare-last
 
# Scan a PHP/shared hosting app
stacksentry -t https://your-php-app.com/index.php --mode full
 
# View full scan history
stacksentry -t https://your-app.com --history
```
 
---
 
## Installation
 
**From PyPI:**
```bash
pip install stacksentry
```
 
**From source:**
```bash
git clone https://github.com/vickkykruz/stacksentry
cd stacksentry
pip install -e ".[dev]"
```
 
**Optional — SSH auto-fix:**
```bash
pip install paramiko
```
 
**Optional — AI-powered patch generation:**
 
Set your Anthropic API key:
```bash
export ANTHROPIC_API_KEY=sk-ant-your-key-here
```
 
Without the key, StackSentry uses static patch templates. With it, patches are tailored to your specific stack by Claude AI.
 
---
 
## SSH key safety
 
When you run `--fix` with `--ssh-password` and `HOST-SSH-001` fails (PermitRootLogin is `yes`), StackSentry does not blindly apply `prohibit-password` and risk locking you out. Instead it runs a 4-step pre-flight:
 
1. **Generates** an Ed25519 SSH key pair locally (RSA 4096 fallback for older paramiko)
2. **Installs** the public key on the server via your existing password session
3. **Verifies** that key login actually works before touching sshd
4. **Only then** applies `PermitRootLogin prohibit-password` and restarts sshd
 
Keys are saved to `~/.stacksentry/keys/` with OS-appropriate permissions (`chmod 600` on Linux/macOS, `icacls` on Windows). If key verification fails, the sshd config is never touched.
 
Running with `--dry-run` shows the exact key paths and all 4 steps before anything is applied.
 
---
 
## Stack detection
 
StackSentry automatically detects your application stack from HTTP response headers, cookies, and URL patterns — even when the server is unreachable:
 
| Signal | Detection |
|---|---|
| `.php` in URL | PHP detected |
| `X-Powered-By: PHP/8.x` | PHP + version |
| `PHPSESSID` cookie | PHP session |
| `Server: Apache` | Apache webserver |
| `Server: nginx` | nginx webserver |
| `csrftoken` / `sessionid` cookie | Django |
| PHP + Apache, no VPS tells | Shared hosting |
 
When PHP/shared hosting is detected:
- Admin paths expand to include `/phpmyadmin`, `/pma`, `/cpanel`, `/administrator`
- Patch templates output PHP (Laravel `@csrf`, vanilla PHP token generation, CodeIgniter config)
- Infrastructure WARNs from missing SSH/Docker are excluded from scoring
 
---
 
## Auto-fix coverage
 
| Layer | Check | Auto-fix method |
|---|---|---|
| **HOST** | HOST-FW-001 — Firewall enabled | ✅ SSH (`ufw enable`) |
| **HOST** | HOST-SSH-001 — SSH hardening | ✅ SSH (key generation + `prohibit-password`) |
| **HOST** | HOST-UPDATE-001 — Auto-updates | ✅ SSH (`unattended-upgrades`) |
| **HOST** | HOST-PERM-001 — SSH file permissions | ✅ SSH (`chmod`) |
| **HOST** | HOST-LOG-001 — Logging active | ✅ SSH (`rsyslog`) |
| **HOST** | HOST-SVC-001 — Minimal services | 📋 Manual guide |
| **HOST** | HOST-SVC-GUNICORN/UWSGI/MYSQL/REDIS | 📋 Manual guide |
| **WS** | WS-HSTS-001 — HSTS header | ✅ SSH or `--nginx-conf` |
| **WS** | WS-SEC-001 — Security headers | ✅ SSH or `--nginx-conf` |
| **WS** | WS-TLS-001 — TLS 1.2+ | ✅ SSH or `--nginx-conf` (Let's Encrypt aware) |
| **WS** | WS-SRV-001 — Server token disclosure | ✅ SSH or `--nginx-conf` |
| **WS** | WS-DIR-001 — Directory listing | ✅ SSH or `--nginx-conf` |
| **WS** | WS-LIMIT-001 — Request size limits | ✅ SSH or `--nginx-conf` |
| **WS** | WS-CONF-HSTS / WS-CONF-CSP | ✅ SSH or `--nginx-conf` |
| **CONT** | CONT-USER-001 — Non-root user | ✅ `--dockerfile` |
| **CONT** | CONT-CONF-HEALTH — HEALTHCHECK | ✅ `--dockerfile` |
| **CONT** | CONT-RES-001 / CONT-COMP-RES | ✅ `--compose-file` |
| **CONT** | CONT-SEC-001 — Secrets in env | 📋 Manual guide |
| **APP** | APP-DEBUG-001 — Debug mode | 📋 Flask/Django/PHP snippet |
| **APP** | APP-COOKIE-001 — Secure cookies | 📋 Flask/Django/PHP snippet |
| **APP** | APP-CSRF-001 — CSRF protection | 📋 Flask/Django/Laravel/PHP snippet |
| **APP** | APP-ADMIN-001 — Admin endpoints | 📋 Flask/Django/PHP snippet |
| **APP** | APP-RATE-001 — Rate limiting | 📋 Flask/Django/nginx snippet |
| **APP** | APP-PASS-001 — Password policy | 📋 Framework snippet |
 
**Legend:**
- ✅ **Fully automated** — StackSentry applies the fix, validates, and confirms
- 📋 **Code snippet** — StackSentry detects your framework and prints the exact code to add
 
Every automated fix creates a timestamped backup, validates with `nginx -t` or `sshd -t` before applying, and is idempotent. If a fix fails validation, subsequent dependent fixes are skipped with a clear explanation rather than cascading silently.
 
---
 
## Dry-run — always preview before applying
 
Running `--fix --dry-run` shows the complete plan with every command that would run, without touching your server:
 
```
🔍 DRY-RUN — no changes will be made to the server or files.
 
  3 check(s) will be fixed automatically
  6 check(s) require manual action (APP layer)
 
📋 DRY-RUN PLAN — commands that WOULD run:
 
  🔧 [WEBSERVER] WS-HSTS-001   Would run 5 SSH command(s) on 159.198.66.20
         $ mkdir -p /etc/nginx/snippets
         $ nginx -t
         $ systemctl reload nginx
 
  🔧 [HOST    ] HOST-SSH-001
  ⚠️  PASSWORD → KEY MIGRATION REQUIRED
  Step 1: Generate Ed25519 key pair → ~/.stacksentry/keys/server.pem
  Step 2: Install public key on server
  Step 3: Verify key login
  Step 4: Apply PermitRootLogin prohibit-password
 
  Would fix: 3  |  Manual: 6
  ✅ Review complete. Run without --dry-run to apply.
```
 
---
 
## Output formats
 
### PDF report (`-o report.pdf`)
Professional report including executive summary, attack surface heatmap, OWASP Top 5 mapping, prioritised hardening plan (Day 1/7/30), 30-day simulation roadmap, generated patches table, auto-fix results, security posture history, and server fingerprint.
 
### JSON (`--json results.json`)
Structured output for CI/CD pipelines. Includes all check results, scores, attack paths, generated patches with metadata, auto-fix results, and scan history.
 
### Patch files (`--patch`)
Scripts written to `patches/{target}_{date}_scan{N}/`:
- `.sh` shell scripts for host/server fixes
- `.py` Python scripts for Flask/Django app-layer guidance
- `.php` PHP scripts for PHP/Laravel app-layer guidance
- `.conf` nginx configuration snippets
- `README.md` with severity-sorted application order
- `manifest.json` for machine-readable processing
 
---
 
## CLI reference
 
```
stacksentry -t URL [options]
 
Core:
  --target, -t URL       Target web application URL
  --mode, -m MODE        quick (HTTP only) | full (HTTP + Docker + SSH)
  --output, -o PATH      PDF report output path
  --json, -j PATH        JSON results output path
  --verbose, -v          Verbose debug output
 
Scanning:
  --ssh-host HOST        SSH target host/IP (enables host layer + auto-fix)
  --ssh-user USER        SSH username (default: root)
  --ssh-password PASS    SSH password
  --ssh-key PATH         SSH private key path
  --docker-host URL      Docker daemon endpoint
  --nginx-conf PATH      nginx.conf for static analysis and local auto-fix
  --dockerfile PATH      Dockerfile for static analysis and auto-fix
  --compose-file PATH    docker-compose.yml for static analysis and auto-fix
 
Reporting:
  --plan                 Print prioritised hardening plan (Day 1/7/30)
  --simulate CHECK_IDS   What-if simulation (comma-separated check IDs)
  --profile ROLE         Narrative: student|devops|pentester|cto|generic
 
Patch generation:
  --patch                Generate AI-powered remediation fix scripts
  --patch-dir DIR        Output directory (default: patches/)
  --no-llm               Use static templates only (no API key needed)
 
Auto-fix:
  --fix                  Auto-apply fixes using available context
  --dry-run              Preview all fixes without applying (safe to run first)
 
History:
  --compare-last         Show posture drift vs previous scan
  --history              Print scan history timeline and exit
  --no-save              Do not save this scan to history database
  --db-path PATH         Custom history database path
 
Telemetry:
  --telemetry on|off|status   Enable, disable, or check telemetry status
```
 
---
 
## Using as a library
 
```python
from sec_audit.results import ScanResult
from storage import ScanHistory
from storage.drift import DriftEngine
from remediation import PatchGenerator
from remediation.auto_fix import AutoFixer
 
# Generate patches
generator = PatchGenerator(use_llm=True)
patches   = generator.generate_all(scan_result, output_dir="patches/")
 
# Auto-fix with full context
fixer = AutoFixer(
    ssh_host="1.2.3.4",
    ssh_password="...",   # key will be generated automatically if needed
    dockerfile="./Dockerfile",
    compose_file="./docker-compose.yml",
    dry_run=True,         # preview only
)
results = fixer.fix_all(scan_result)
 
# History and drift
history = ScanHistory()
history.save(scan_result)
report  = DriftEngine().compare(previous_scan, scan_result)
```
 
---
 
## Architecture
 
```
stacksentry/
├── sec_audit/          CLI, config, results, scoring, narratives, telemetry
├── checks/             24+ security check functions (4 layers)
├── scanners/           HTTP, SSH, Docker, Nginx, compose scanners
├── reporting/          PDF generator (ReportLab)
├── storage/            SQLite history, drift engine
├── remediation/        Patch generator, LLM integration, auto-fix engine
└── tests/              321 tests, 0 failures
```
 
---
 
## Running tests
 
```bash
pip install -e ".[dev]"
pytest tests/ -v
# 321 passed in ~1.5s
```
 
---
 
## Telemetry
 
StackSentry collects anonymous usage data (scan counts, check grades, platform) to help prioritise development. It is **opt-in only** — you are asked once on first run and can change your preference at any time:
 
```bash
stacksentry --telemetry status   # check current setting
stacksentry --telemetry off      # disable
stacksentry --telemetry on       # enable
```
 
No personally identifiable information is collected. No code, URLs, or scan results are ever sent.
 
---
 
## Roadmap
 
- [x] Phase 1 — 24+ checks, PDF/JSON reports, CLI
- [x] Phase 2 — History, drift detection, posture tracking
- [x] Phase 3 — AI-powered patch generation + auto-fix engine
- [x] Phase 4 — PyPI package, PHP/Apache support, SSH key safety, dry-run *(current)*
- [ ] Phase 5 — SaaS dashboard, team accounts, CI/CD integrations, `--app-path` for application source code auto-fix
 
---
 
## Contributing
 
See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide including check schema, template registration, and test requirements.
 
---
 
## License
 
MIT — see [LICENSE](LICENSE) for details.
 
---
 
*Built by Victor Chukwuemeka Onwuegbuchulem — London Metropolitan University*
 
