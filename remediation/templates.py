"""
remediation/templates.py — Static patch templates for all 24 security checks.
 
Each template is a function that receives a CheckResult and returns a
(filename, file_type, content, instructions, verification) tuple.
 
These are used as:
  1. The primary source when LLM is disabled (--no-llm)
  2. The fallback when the LLM API is unavailable or fails
 
Templates are intentionally verbose — they include comments, dry-run
guards, and verification commands so a sysadmin with no deep security
knowledge can apply them safely.
"""
 
from __future__ import annotations
from typing import Optional
 
 
# ── Return type ───────────────────────────────────────────────────────────────
def _patch(filename: str, file_type: str, content: str,
           instructions: str, verification: str) -> dict:
    return {
        "filename":     filename,
        "file_type":    file_type,
        "content":      content,
        "instructions": instructions,
        "verification": verification,
    }
 
 
# ═══════════════════════════════════════════════════════════════════════════════
# APP LAYER
# ═══════════════════════════════════════════════════════════════════════════════
 
def patch_app_debug(details: str = "", stack: str = "") -> dict:
    return _patch(
        filename="APP-DEBUG-001.py",
        file_type="python",
        content='''\
#!/usr/bin/env python3
"""
StackSentry Patch — APP-DEBUG-001: Disable debug mode
Generated automatically. Review before applying.
 
WHAT THIS DOES:
  Searches common Flask/Django config files for DEBUG=True and replaces
  it with DEBUG=False. Creates a backup before modifying any file.
 
HOW TO APPLY:
  python patches/APP-DEBUG-001.py            # dry run (shows changes only)
  python patches/APP-DEBUG-001.py --apply    # applies the changes
"""
 
import sys
import re
import pathlib
import shutil
from datetime import datetime
 
DRY_RUN = "--apply" not in sys.argv
 
SEARCH_PATHS = [
    "config.py", "settings.py", "app.py",
    "instance/config.py", "config/settings.py",
    "src/config.py", "src/settings.py",
]
 
PATTERN = re.compile(r"(DEBUG\\s*=\\s*)True", re.IGNORECASE)
REPLACEMENT = r"\\g<1>False"
 
found_any = False
for path_str in SEARCH_PATHS:
    p = pathlib.Path(path_str)
    if not p.exists():
        continue
    content = p.read_text(encoding="utf-8")
    if not PATTERN.search(content):
        continue
 
    found_any = True
    new_content = PATTERN.sub(REPLACEMENT, content)
    print(f"  Found:  {p}")
    print(f"  Change: DEBUG=True  →  DEBUG=False")
 
    if not DRY_RUN:
        backup = p.with_suffix(f".bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        shutil.copy2(p, backup)
        p.write_text(new_content, encoding="utf-8")
        print(f"  Backup: {backup}")
        print(f"  Applied ✓")
    else:
        print(f"  [DRY RUN] No changes made. Pass --apply to write.")
 
if not found_any:
    print("No DEBUG=True found in common config paths.")
    print("Check your framework-specific config file manually.")
    sys.exit(1)
''',
        instructions=(
            "Run `python patches/APP-DEBUG-001.py` to preview changes, "
            "then `python patches/APP-DEBUG-001.py --apply` to apply. "
            "Restart your application server after applying."
        ),
        verification="curl -s https://your-app.com | grep -i 'traceback\\|debugger\\|werkzeug'",
    )
 
 
def patch_app_cookies(details: str = "", stack: str = "") -> dict:
    return _patch(
        filename="APP-COOKIE-001.py",
        file_type="python",
        content='''\
#!/usr/bin/env python3
"""
StackSentry Patch — APP-COOKIE-001: Secure session cookies
Add the following configuration to your Flask or Django application.
"""
 
FLASK_CONFIG = """
# ── Secure session cookies (add to your Flask app config) ──────────────────
app.config.update(
    SESSION_COOKIE_SECURE=True,      # Only send over HTTPS
    SESSION_COOKIE_HTTPONLY=True,    # Prevent JavaScript access
    SESSION_COOKIE_SAMESITE="Lax",  # CSRF protection
    REMEMBER_COOKIE_SECURE=True,
    REMEMBER_COOKIE_HTTPONLY=True,
)
"""
 
DJANGO_CONFIG = """
# ── Secure session cookies (add to settings.py) ────────────────────────────
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
"""
 
print("=== APP-COOKIE-001: Secure Session Cookies ===")
print()
print("For Flask applications, add to your app configuration:")
print(FLASK_CONFIG)
print("For Django applications, add to settings.py:")
print(DJANGO_CONFIG)
print("NOTE: SESSION_COOKIE_SECURE requires HTTPS to be enabled.")
''',
        instructions=(
            "Open the printed config snippet and add the appropriate block "
            "to your Flask app config or Django settings.py. "
            "These settings require HTTPS to be active — enabling Secure "
            "cookies on an HTTP-only site will break sessions."
        ),
        verification="curl -I https://your-app.com | grep -i 'set-cookie'",
    )
 
 
def patch_app_csrf(details: str = "", stack: str = "") -> dict:
    return _patch(
        filename="APP-CSRF-001.py",
        file_type="python",
        content='''\
#!/usr/bin/env python3
"""
StackSentry Patch — APP-CSRF-001: Enable CSRF protection
"""
 
FLASK_CONFIG = """
# ── CSRF protection for Flask (using Flask-WTF) ─────────────────────────────
# 1. Install: pip install flask-wtf
# 2. Add to your app:
 
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)
 
# 3. Set a secret key:
app.config["SECRET_KEY"] = "your-secure-random-secret-key"
 
# 4. Add to every HTML form:
# <form method="POST">
#   <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
#   ...
# </form>
"""
 
DJANGO_CONFIG = """
# ── CSRF protection for Django ──────────────────────────────────────────────
# Django includes CSRF protection by default.
# Ensure these are in settings.py:
 
MIDDLEWARE = [
    ...
    "django.middleware.csrf.CsrfViewMiddleware",  # must be present
    ...
]
 
# In templates, include:
# {% csrf_token %}
"""
 
print("=== APP-CSRF-001: CSRF Protection ===")
print(FLASK_CONFIG)
print(DJANGO_CONFIG)
''',
        instructions=(
            "For Flask: install flask-wtf and initialise CSRFProtect. "
            "For Django: ensure CsrfViewMiddleware is in MIDDLEWARE and "
            "{% csrf_token %} is in all POST forms."
        ),
        verification="curl -X POST https://your-app.com/login -d 'user=x' | grep -i '403\\|csrf'",
    )
 
 
def patch_app_admin(details: str = "", stack: str = "") -> dict:
    return _patch(
        filename="APP-ADMIN-001.py",
        file_type="python",
        content='''\
#!/usr/bin/env python3
"""
StackSentry Patch — APP-ADMIN-001: Protect admin/debug endpoints
"""
 
FLASK_EXAMPLE = """
# ── Protect admin endpoints in Flask ────────────────────────────────────────
from functools import wraps
from flask import request, abort
import os
 
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "change-me-immediately")
 
def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-Admin-Token")
        if token != ADMIN_TOKEN:
            abort(403)
        return f(*args, **kwargs)
    return decorated
 
# Apply to your admin routes:
@app.route("/admin")
@require_admin
def admin_panel():
    ...
 
# OR disable debug/test routes entirely in production:
if not app.debug:
    @app.route("/debug")
    def debug_disabled():
        abort(404)
"""
 
NGINX_BLOCK = """
# ── Block admin paths at nginx level (nginx.conf) ───────────────────────────
# Add inside your server block:
location ~ ^/(admin|debug|test|wp-admin) {
    deny all;
    return 403;
}
"""
 
print("=== APP-ADMIN-001: Protect Admin Endpoints ===")
print(FLASK_EXAMPLE)
print("Or block at the nginx level:")
print(NGINX_BLOCK)
''',
        instructions=(
            "Either add authentication to admin routes in your application code, "
            "or block them entirely at the nginx level using the provided location block. "
            "The nginx approach is faster to apply and does not require app restart."
        ),
        verification="curl -o /dev/null -s -w '%{http_code}' https://your-app.com/admin",
    )
 
 
def patch_app_rate_limit(details: str = "", stack: str = "") -> dict:
    return _patch(
        filename="APP-RATE-001.py",
        file_type="python",
        content='''\
#!/usr/bin/env python3
"""
StackSentry Patch — APP-RATE-001: Enable rate limiting
"""
 
FLASK_EXAMPLE = """
# ── Rate limiting for Flask (using Flask-Limiter) ───────────────────────────
# 1. Install: pip install Flask-Limiter
 
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
 
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)
 
# Apply stricter limits to sensitive endpoints:
@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    ...
"""
 
NGINX_EXAMPLE = """
# ── Rate limiting at nginx level (nginx.conf) ────────────────────────────────
# Add to http block:
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
 
# Add to location block:
location /api/ {
    limit_req zone=api burst=20 nodelay;
    limit_req_status 429;
    ...
}
"""
 
print("=== APP-RATE-001: Rate Limiting ===")
print(FLASK_EXAMPLE)
print(NGINX_EXAMPLE)
''',
        instructions=(
            "For Flask: install Flask-Limiter and apply limits to sensitive routes. "
            "For production, use Redis as storage_uri instead of memory://. "
            "Nginx-level rate limiting is recommended as an additional layer."
        ),
        verification="for i in $(seq 1 20); do curl -s -o /dev/null -w '%{http_code}\\n' https://your-app.com/api/; done",
    )
 
 
def patch_app_password(details: str = "", stack: str = "") -> dict:
    return _patch(
        filename="APP-PASS-001.py",
        file_type="python",
        content='''\
#!/usr/bin/env python3
"""
StackSentry Patch — APP-PASS-001: Strong password policy
"""
 
FLASK_EXAMPLE = """
# ── Password validation helper ───────────────────────────────────────────────
import re
 
def validate_password(password: str) -> tuple[bool, str]:
    if len(password) < 12:
        return False, "Password must be at least 12 characters."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\\d", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, "Password is strong."
 
# In your registration/password-change route:
@app.route("/register", methods=["POST"])
def register():
    password = request.form["password"]
    valid, message = validate_password(password)
    if not valid:
        return {"error": message}, 400
    ...
"""
 
print("=== APP-PASS-001: Password Policy ===")
print(FLASK_EXAMPLE)
''',
        instructions="Add the validate_password function to your user registration and password change routes.",
        verification="Test registration with a weak password like '123' — it should return a 400 error.",
    )
 
 
# ═══════════════════════════════════════════════════════════════════════════════
# WEBSERVER LAYER
# ═══════════════════════════════════════════════════════════════════════════════
 
def patch_ws_hsts(details: str = "", stack: str = "") -> dict:
    return _patch(
        filename="WS-HSTS-001.conf",
        file_type="nginx",
        content="""\
# StackSentry Patch — WS-HSTS-001: Enable HSTS
# Add the following inside your HTTPS server block in nginx.conf
# (usually in /etc/nginx/sites-available/your-site or /etc/nginx/nginx.conf)
 
# ── Inside your server { listen 443 ssl; } block: ───────────────────────────
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
 
# ── To apply: ────────────────────────────────────────────────────────────────
# 1. Add the line above to your HTTPS server block
# 2. Test the configuration:  sudo nginx -t
# 3. Reload nginx:             sudo systemctl reload nginx
 
# ── Full minimal HTTPS server block example: ─────────────────────────────────
# server {
#     listen 443 ssl;
#     server_name your-domain.com;
#
#     ssl_certificate     /etc/letsencrypt/live/your-domain.com/fullchain.pem;
#     ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
#
#     add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
#     add_header X-Frame-Options "SAMEORIGIN" always;
#     add_header X-Content-Type-Options "nosniff" always;
#     add_header Referrer-Policy "strict-origin-when-cross-origin" always;
# }
""",
        instructions=(
            "1. Open your nginx server configuration (usually "
            "/etc/nginx/sites-available/your-site). "
            "2. Add the add_header line inside your HTTPS server block. "
            "3. Run `sudo nginx -t` to verify. "
            "4. Run `sudo systemctl reload nginx` to apply."
        ),
        verification="curl -I https://your-domain.com | grep -i 'strict-transport'",
    )
 
 
def patch_ws_security_headers(details: str = "", stack: str = "") -> dict:
    return _patch(
        filename="WS-SEC-001.conf",
        file_type="nginx",
        content="""\
# StackSentry Patch — WS-SEC-001: Security headers
# Add all four security headers to your nginx server block.
 
# ── Add inside your server { } block: ───────────────────────────────────────
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';" always;
 
# NOTE: The Content-Security-Policy above is a strict default.
# If your app loads scripts/styles from CDNs, adjust accordingly.
# Example for apps using Bootstrap CDN:
# add_header Content-Security-Policy "default-src 'self'; script-src 'self' cdn.jsdelivr.net; style-src 'self' cdn.jsdelivr.net 'unsafe-inline';" always;
 
# ── To apply: ────────────────────────────────────────────────────────────────
# sudo nginx -t && sudo systemctl reload nginx
""",
        instructions=(
            "Add all four header lines to your nginx server block. "
            "Adjust the Content-Security-Policy if your app loads resources "
            "from external CDNs. Test with `nginx -t` before reloading."
        ),
        verification="curl -I https://your-domain.com | grep -iE 'x-frame|x-content|referrer|content-security'",
    )
 
 
def patch_ws_tls(details: str = "", stack: str = "") -> dict:
    return _patch(
        filename="WS-TLS-001.conf",
        file_type="nginx",
        content="""\
# StackSentry Patch — WS-TLS-001: TLS 1.2+ with strong ciphers
# Add to your nginx server block or http block.
 
# ── TLS configuration (add to your server block): ───────────────────────────
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256;
ssl_prefer_server_ciphers off;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
 
# ── To apply: ────────────────────────────────────────────────────────────────
# sudo nginx -t && sudo systemctl reload nginx
# Verify with: https://www.ssllabs.com/ssltest/
""",
        instructions=(
            "Add these directives to your nginx HTTPS server block. "
            "After applying, verify with SSL Labs: "
            "https://www.ssllabs.com/ssltest/analyze.html?d=your-domain.com"
        ),
        verification="openssl s_client -connect your-domain.com:443 -tls1 2>&1 | grep 'handshake failure'",
    )
 
 
def patch_ws_server_tokens(details: str = "", stack: str = "") -> dict:
    return _patch(
        filename="WS-SRV-001.conf",
        file_type="nginx",
        content="""\
# StackSentry Patch — WS-SRV-001: Disable server version disclosure
 
# ── Add to your nginx http { } block: ───────────────────────────────────────
server_tokens off;
 
# This removes the nginx version number from:
#   - Server: nginx/1.24.0  →  Server: nginx
#   - Error pages
 
# ── To apply: ────────────────────────────────────────────────────────────────
# 1. Add 'server_tokens off;' inside the http { } block in nginx.conf
# 2. sudo nginx -t && sudo systemctl reload nginx
""",
        instructions=(
            "Add `server_tokens off;` to the http { } block in "
            "/etc/nginx/nginx.conf, then reload nginx."
        ),
        verification="curl -I https://your-domain.com | grep -i 'server:'",
    )
 
 
def patch_ws_request_limits(details: str = "", stack: str = "") -> dict:
    return _patch(
        filename="WS-LIMIT-001.conf",
        file_type="nginx",
        content="""\
# StackSentry Patch — WS-LIMIT-001: Request size limits
 
# ── Add to your nginx server or location block: ──────────────────────────────
client_max_body_size 10m;        # Maximum request body (adjust to your needs)
client_body_timeout 12s;
client_header_timeout 12s;
send_timeout 10s;
keepalive_timeout 15s;
 
# For API endpoints, you may want stricter limits:
# location /api/ {
#     client_max_body_size 1m;
# }
 
# ── To apply: ────────────────────────────────────────────────────────────────
# sudo nginx -t && sudo systemctl reload nginx
""",
        instructions="Add these directives to your nginx server block. Adjust client_max_body_size to match your application's upload requirements.",
        verification="curl -X POST https://your-domain.com/api/ --data-binary @/dev/urandom --max-time 5 | head -1",
    )
 
 
# ═══════════════════════════════════════════════════════════════════════════════
# HOST LAYER
# ═══════════════════════════════════════════════════════════════════════════════
 
def patch_host_ssh(details: str = "", stack: str = "") -> dict:
    return _patch(
        filename="HOST-SSH-001.sh",
        file_type="shell",
        content="""\
#!/bin/bash
# StackSentry Patch — HOST-SSH-001: SSH hardening
# Disables root login and password authentication in sshd_config.
#
# !! IMPORTANT: Ensure you have a non-root SSH user with a key BEFORE applying.
# !! Locking yourself out of SSH is very difficult to recover from.
#
# USAGE:
#   bash patches/HOST-SSH-001.sh          # dry run
#   bash patches/HOST-SSH-001.sh --apply  # applies changes
 
set -euo pipefail
 
DRY_RUN=true
[[ "${1:-}" == "--apply" ]] && DRY_RUN=false
 
SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP="/etc/ssh/sshd_config.bak.$(date +%Y%m%d_%H%M%S)"
 
echo "=== HOST-SSH-001: SSH Hardening ==="
echo
 
# Verify non-root user exists before proceeding
if $DRY_RUN; then
    echo "[DRY RUN] Changes that would be applied to $SSHD_CONFIG:"
    echo
fi
 
changes=(
    "s/^#*PermitRootLogin.*/PermitRootLogin no/"
    "s/^#*PasswordAuthentication.*/PasswordAuthentication no/"
    "s/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/"
    "s/^#*MaxAuthTries.*/MaxAuthTries 3/"
)
 
for change in "${changes[@]}"; do
    pattern=$(echo "$change" | cut -d'/' -f2)
    replacement=$(echo "$change" | cut -d'/' -f3)
    echo "  $pattern  →  $replacement"
done
 
echo
 
if ! $DRY_RUN; then
    # Safety check: ensure at least one non-root sudo user exists
    if ! getent passwd | awk -F: '$3 >= 1000 && $3 < 65534' | grep -q .; then
        echo "ERROR: No non-root users found with UID >= 1000."
        echo "Create a non-root user first: adduser deploy"
        exit 1
    fi
 
    cp "$SSHD_CONFIG" "$BACKUP"
    echo "Backup created: $BACKUP"
 
    for change in "${changes[@]}"; do
        sed -i "$change" "$SSHD_CONFIG"
    done
 
    # Append if not present
    grep -q "^PermitRootLogin" "$SSHD_CONFIG" || echo "PermitRootLogin no" >> "$SSHD_CONFIG"
    grep -q "^PasswordAuthentication" "$SSHD_CONFIG" || echo "PasswordAuthentication no" >> "$SSHD_CONFIG"
 
    sshd -t && echo "Config valid ✓" || { echo "ERROR: sshd config invalid — restoring backup"; cp "$BACKUP" "$SSHD_CONFIG"; exit 1; }
    systemctl restart sshd
    echo "SSH hardening applied ✓"
else
    echo "[DRY RUN] Pass --apply to make changes."
fi
""",
        instructions=(
            "IMPORTANT: Ensure you have a non-root user with SSH key access "
            "before running this script. Run `bash patches/HOST-SSH-001.sh` "
            "for a dry run, then `bash patches/HOST-SSH-001.sh --apply` to apply. "
            "Run this on the server via SSH: "
            "scp patches/HOST-SSH-001.sh user@server: && ssh user@server 'sudo bash HOST-SSH-001.sh --apply'"
        ),
        verification="ssh root@your-server 'echo connected' 2>&1 | grep -i 'permission denied\\|publickey'",
    )
 
 
def patch_host_firewall(details: str = "", stack: str = "") -> dict:
    return _patch(
        filename="HOST-FW-001.sh",
        file_type="shell",
        content="""\
#!/bin/bash
# StackSentry Patch — HOST-FW-001: Enable and configure UFW firewall
#
# USAGE:
#   bash patches/HOST-FW-001.sh          # dry run
#   bash patches/HOST-FW-001.sh --apply  # applies changes
 
set -euo pipefail
 
DRY_RUN=true
[[ "${1:-}" == "--apply" ]] && DRY_RUN=false
 
echo "=== HOST-FW-001: Firewall Configuration ==="
echo
 
RULES=(
    "ufw default deny incoming"
    "ufw default allow outgoing"
    "ufw allow 22/tcp comment 'SSH'"
    "ufw allow 80/tcp comment 'HTTP'"
    "ufw allow 443/tcp comment 'HTTPS'"
)
 
echo "Rules to be applied:"
for rule in "${RULES[@]}"; do
    echo "  $rule"
done
echo "  ufw --force enable"
echo
 
if ! $DRY_RUN; then
    # Ensure SSH is allowed BEFORE enabling firewall
    ufw allow 22/tcp comment "SSH — added by StackSentry patch"
 
    for rule in "${RULES[@]}"; do
        eval "$rule"
    done
 
    ufw --force enable
    ufw status verbose
    echo "Firewall enabled ✓"
else
    echo "[DRY RUN] Pass --apply to enable the firewall."
    echo "Current status:"
    ufw status 2>/dev/null || echo "  (ufw not installed or not running)"
fi
""",
        instructions=(
            "Run `bash patches/HOST-FW-001.sh` for a dry run. "
            "Then `bash patches/HOST-FW-001.sh --apply` on the server. "
            "This opens ports 22, 80, and 443. Add any additional ports your "
            "application needs before running."
        ),
        verification="sudo ufw status verbose | grep -i 'status: active'",
    )
 
 
def patch_host_auto_updates(details: str = "", stack: str = "") -> dict:
    return _patch(
        filename="HOST-UPDATE-001.sh",
        file_type="shell",
        content="""\
#!/bin/bash
# StackSentry Patch — HOST-UPDATE-001: Enable automatic security updates
 
set -euo pipefail
 
DRY_RUN=true
[[ "${1:-}" == "--apply" ]] && DRY_RUN=false
 
echo "=== HOST-UPDATE-001: Automatic Security Updates ==="
echo
 
if ! $DRY_RUN; then
    apt-get update -qq
    apt-get install -y unattended-upgrades apt-listchanges
 
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
 
    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
 
    systemctl enable unattended-upgrades
    systemctl start unattended-upgrades
    echo "Automatic security updates enabled ✓"
else
    echo "[DRY RUN] Would install unattended-upgrades and enable automatic security patching."
    echo "Pass --apply to make changes."
fi
""",
        instructions="Run on the server: `sudo bash patches/HOST-UPDATE-001.sh --apply`",
        verification="systemctl is-enabled unattended-upgrades && echo 'enabled'",
    )
 
 
def patch_host_permissions(details: str = "", stack: str = "") -> dict:
    return _patch(
        filename="HOST-PERM-001.sh",
        file_type="shell",
        content="""\
#!/bin/bash
# StackSentry Patch — HOST-PERM-001: Fix SSH file permissions
 
set -euo pipefail
 
DRY_RUN=true
[[ "${1:-}" == "--apply" ]] && DRY_RUN=false
 
echo "=== HOST-PERM-001: SSH File Permissions ==="
echo
 
WORLD_WRITABLE=$(find /etc/ssh -perm -o+w 2>/dev/null)
if [ -z "$WORLD_WRITABLE" ]; then
    echo "No world-writable files found in /etc/ssh. Nothing to fix."
    exit 0
fi
 
echo "World-writable files found:"
echo "$WORLD_WRITABLE"
echo
 
if ! $DRY_RUN; then
    find /etc/ssh -perm -o+w -exec chmod o-w {} \\;
    echo "Permissions tightened ✓"
    echo "New permissions:"
    ls -la /etc/ssh/
else
    echo "[DRY RUN] Would remove world-write permission from the above files."
fi
""",
        instructions="Run on the server: `sudo bash patches/HOST-PERM-001.sh --apply`",
        verification="find /etc/ssh -perm -o+w 2>/dev/null | wc -l",
    )
 
 
def patch_host_logging(details: str = "", stack: str = "") -> dict:
    return _patch(
        filename="HOST-LOG-001.sh",
        file_type="shell",
        content="""\
#!/bin/bash
# StackSentry Patch — HOST-LOG-001: Enable rsyslog
 
set -euo pipefail
 
DRY_RUN=true
[[ "${1:-}" == "--apply" ]] && DRY_RUN=false
 
echo "=== HOST-LOG-001: Logging Service ==="
 
if ! $DRY_RUN; then
    apt-get install -y rsyslog
    systemctl enable rsyslog
    systemctl start rsyslog
    echo "rsyslog installed and started ✓"
else
    echo "[DRY RUN] Would install and enable rsyslog."
fi
""",
        instructions="Run on the server: `sudo bash patches/HOST-LOG-001.sh --apply`",
        verification="systemctl is-active rsyslog && echo 'active'",
    )
 
 
def patch_host_process_user(check_id: str, process: str, details: str = "") -> dict:
    return _patch(
        filename=f"{check_id}.sh",
        file_type="shell",
        content=f"""\
#!/bin/bash
# StackSentry Patch — {check_id}: Run {process} as non-root user
 
echo "=== {check_id}: {process} Process User ==="
echo
echo "To run {process} as a non-root user, update your systemd service file:"
echo
cat << 'EOF'
[Service]
User=www-data        # or a dedicated service account
Group=www-data
ExecStart=/path/to/{process.lower()} ...
EOF
echo
echo "Steps:"
echo "  1. Create a service account:  sudo useradd -r -s /usr/sbin/nologin {process.lower()}-svc"
echo "  2. Update your systemd service User= directive"
echo "  3. Reload:  sudo systemctl daemon-reload && sudo systemctl restart {process.lower()}"
""",
        instructions=f"Update your {process} systemd service to use a non-root User= directive.",
        verification=f"ps aux | grep '[{process[0].lower()}]{process[1:].lower()}' | awk '{{print $1}}'",
    )
 
 
# ═══════════════════════════════════════════════════════════════════════════════
# CONTAINER LAYER
# ═══════════════════════════════════════════════════════════════════════════════
 
def patch_cont_user(details: str = "", stack: str = "") -> dict:
    return _patch(
        filename="CONT-USER-001.dockerfile",
        file_type="dockerfile",
        content="""\
# StackSentry Patch — CONT-USER-001: Non-root container user
# Add these lines to your Dockerfile (near the end, before CMD/ENTRYPOINT).
 
# ── Add to your Dockerfile: ──────────────────────────────────────────────────
 
# Create a non-root user and group
RUN groupadd -r appgroup && useradd -r -g appgroup appuser
 
# Set ownership of application files
RUN chown -R appuser:appgroup /app
 
# Switch to non-root user
USER appuser
 
# ── Example minimal Dockerfile: ─────────────────────────────────────────────
# FROM python:3.11-slim
# WORKDIR /app
# COPY requirements.txt .
# RUN pip install --no-cache-dir -r requirements.txt
# COPY . .
# RUN groupadd -r appgroup && useradd -r -g appgroup appuser
# RUN chown -R appuser:appgroup /app
# USER appuser
# CMD ["gunicorn", "app:app"]
""",
        instructions=(
            "Add the RUN groupadd, RUN chown, and USER lines to your Dockerfile. "
            "Rebuild with `docker build -t your-image .` and verify the running "
            "user with `docker exec container_name whoami`."
        ),
        verification="docker exec <container_name> whoami",
    )
 
 
def patch_cont_healthcheck(details: str = "", stack: str = "") -> dict:
    return _patch(
        filename="CONT-CONF-HEALTH.dockerfile",
        file_type="dockerfile",
        content="""\
# StackSentry Patch — CONT-CONF-HEALTH: Add HEALTHCHECK to Dockerfile
 
# ── Add to your Dockerfile (before CMD): ────────────────────────────────────
 
# For a web application:
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \\
    CMD curl -f http://localhost/health || exit 1
 
# For a Flask app without a /health endpoint, add one first:
# @app.route("/health")
# def health():
#     return {"status": "ok"}, 200
 
# Alternative using wget:
# HEALTHCHECK --interval=30s --timeout=10s --retries=3 \\
#     CMD wget -qO- http://localhost/health || exit 1
""",
        instructions=(
            "Add a /health endpoint to your application, then add the "
            "HEALTHCHECK line to your Dockerfile. Rebuild the image."
        ),
        verification="docker inspect <container_name> | grep -A5 'Health'",
    )
 
 
def patch_cont_resource_limits(details: str = "", stack: str = "") -> dict:
    return _patch(
        filename="CONT-RES-001.yml",
        file_type="yaml",
        content="""\
# StackSentry Patch — CONT-RES-001: Container resource limits
# Add deploy.resources.limits to each service in docker-compose.yml
 
# ── Example docker-compose.yml with resource limits: ────────────────────────
version: '3.8'
services:
  web:
    image: your-app-image
    deploy:
      resources:
        limits:
          cpus: '0.50'      # Maximum 50% of one CPU core
          memory: 512M      # Maximum 512MB RAM
        reservations:
          cpus: '0.25'      # Guaranteed 25% CPU
          memory: 256M      # Guaranteed 256MB RAM
 
  nginx:
    image: nginx:alpine
    deploy:
      resources:
        limits:
          cpus: '0.25'
          memory: 128M
""",
        instructions=(
            "Add the deploy.resources.limits block to each service in your "
            "docker-compose.yml. Adjust values based on your application's "
            "actual requirements. Apply with `docker compose up -d`."
        ),
        verification="docker stats --no-stream <container_name>",
    )
 
 
def patch_cont_no_secrets(details: str = "", stack: str = "") -> dict:
    return _patch(
        filename="CONT-SEC-001.sh",
        file_type="shell",
        content="""\
#!/bin/bash
# StackSentry Patch — CONT-SEC-001: Remove secrets from container environment
# Moves secrets to a .env file and updates docker-compose.yml
 
echo "=== CONT-SEC-001: Secrets Management ==="
echo
echo "Step 1: Create a .env file (NOT committed to git):"
cat << 'EOF'
# .env — keep this out of version control
DB_PASSWORD=your-actual-password
API_KEY=your-actual-api-key
SECRET_KEY=your-actual-secret-key
EOF
echo
echo "Step 2: Update docker-compose.yml to use env_file:"
cat << 'EOF'
services:
  web:
    env_file:
      - .env          # loaded from disk, not baked into image
    environment:
      # Only non-sensitive values here:
      - APP_ENV=production
      - PORT=8000
EOF
echo
echo "Step 3: Add .env to .gitignore:"
echo "  echo '.env' >> .gitignore"
echo
echo "Step 4: Remove secrets from the existing container:"
echo "  docker compose down && docker compose up -d"
""",
        instructions=(
            "Create a .env file with your secrets, update docker-compose.yml "
            "to use env_file, add .env to .gitignore, and rebuild your containers."
        ),
        verification="docker inspect <container_name> | grep -i 'password\\|secret\\|key'",
    )
 
 
# ═══════════════════════════════════════════════════════════════════════════════
# TEMPLATE REGISTRY
# ═══════════════════════════════════════════════════════════════════════════════
 
def get_template(check_id: str, details: str = "", stack: str = "") -> Optional[dict]:
    """
    Return a static patch template for a given check ID.
    Returns None if no template exists for this check.
    """
    registry = {
        "APP-DEBUG-001":   lambda: patch_app_debug(details, stack),
        "APP-COOKIE-001":  lambda: patch_app_cookies(details, stack),
        "APP-CSRF-001":    lambda: patch_app_csrf(details, stack),
        "APP-ADMIN-001":   lambda: patch_app_admin(details, stack),
        "APP-RATE-001":    lambda: patch_app_rate_limit(details, stack),
        "APP-PASS-001":    lambda: patch_app_password(details, stack),
        "WS-HSTS-001":     lambda: patch_ws_hsts(details, stack),
        "WS-CONF-HSTS":    lambda: patch_ws_hsts(details, stack),
        "WS-SEC-001":      lambda: patch_ws_security_headers(details, stack),
        "WS-TLS-001":      lambda: patch_ws_tls(details, stack),
        "WS-SRV-001":      lambda: patch_ws_server_tokens(details, stack),
        "WS-LIMIT-001":    lambda: patch_ws_request_limits(details, stack),
        "WS-CONF-CSP":     lambda: patch_ws_security_headers(details, stack),
        "HOST-SSH-001":    lambda: patch_host_ssh(details, stack),
        "HOST-FW-001":     lambda: patch_host_firewall(details, stack),
        "HOST-UPDATE-001": lambda: patch_host_auto_updates(details, stack),
        "HOST-PERM-001":   lambda: patch_host_permissions(details, stack),
        "HOST-LOG-001":    lambda: patch_host_logging(details, stack),
        "HOST-SVC-GUNICORN": lambda: patch_host_process_user("HOST-SVC-GUNICORN", "Gunicorn", details),
        "HOST-SVC-UWSGI":    lambda: patch_host_process_user("HOST-SVC-UWSGI", "uWSGI", details),
        "HOST-SVC-MYSQL":    lambda: patch_host_process_user("HOST-SVC-MYSQL", "MySQL", details),
        "HOST-SVC-REDIS":    lambda: patch_host_process_user("HOST-SVC-REDIS", "Redis", details),
        "CONT-USER-001":     lambda: patch_cont_user(details, stack),
        "CONT-CONF-USER":    lambda: patch_cont_user(details, stack),
        "CONT-CONF-HEALTH":  lambda: patch_cont_healthcheck(details, stack),
        "CONT-HEALTH-001":   lambda: patch_cont_healthcheck(details, stack),
        "CONT-RES-001":      lambda: patch_cont_resource_limits(details, stack),
        "CONT-COMP-RES":     lambda: patch_cont_resource_limits(details, stack),
        "CONT-SEC-001":      lambda: patch_cont_no_secrets(details, stack),
    }
    factory = registry.get(check_id)
    return factory() if factory else None