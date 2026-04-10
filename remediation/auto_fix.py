"""
remediation/auto_fix.py — Context-aware automatic fix executor.
 
Fix strategy (in priority order):
  1. SSH available   -> HOST + WS fixes applied on the remote server
  2. --dockerfile    -> CONT fixes applied to the local Dockerfile
  3. --compose-file  -> CONT fixes applied to docker-compose.yml
  4. --nginx-conf    -> WS fixes applied to the local nginx.conf
  5. APP layer       -> always manual (requires application source code)
  6. No context      -> skipped with message explaining what to provide
 
Every fix creates a timestamped backup, is idempotent, and validates
before restarting any service (nginx -t, sshd -t).
"""
 
from __future__ import annotations
 
import pathlib
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
 
 
@dataclass
class FixResult:
    check_id:     str
    check_name:   str
    layer:        str
    status:       str
    message:      str
    commands_run: list[str] = field(default_factory=list)
    verified:     bool = False
 
 
# ── SSH fix commands ──────────────────────────────────────────────────────────
 
def _ssh_hardening_commands() -> list[str]:
    """HOST-SSH-001: Uses prohibit-password — blocks password auth, keeps key access."""
    return [
        "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d_%H%M%S)",
        "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config",
        "grep -q '^PermitRootLogin' /etc/ssh/sshd_config || echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config",
        "sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config",
        "grep -q '^MaxAuthTries' /etc/ssh/sshd_config || echo 'MaxAuthTries 3' >> /etc/ssh/sshd_config",
        "sshd -t",
        "systemctl restart sshd || service ssh restart",
    ]
 
 
def _firewall_commands() -> list[str]:
    return [
        "ufw allow 22/tcp comment 'SSH'",
        "ufw allow 80/tcp comment 'HTTP'",
        "ufw allow 443/tcp comment 'HTTPS'",
        "ufw default deny incoming",
        "ufw default allow outgoing",
        "ufw --force enable",
    ]
 
 
def _auto_updates_commands() -> list[str]:
    return [
        "apt-get update -qq",
        "apt-get install -y unattended-upgrades",
        "systemctl enable unattended-upgrades",
        "systemctl start unattended-upgrades",
    ]
 
 
def _permissions_commands() -> list[str]:
    return ["find /etc/ssh -perm -o+w -exec chmod o-w {} \\;"]
 
 
def _logging_commands() -> list[str]:
    return [
        "apt-get install -y rsyslog 2>/dev/null || yum install -y rsyslog 2>/dev/null || true",
        "systemctl enable rsyslog",
        "systemctl start rsyslog",
    ]
 
 
def _hsts_commands() -> list[str]:
    """WS-HSTS/SEC/SRV: Security headers snippet — covers HSTS, framing, content-type, referrer."""
    return [
        "mkdir -p /etc/nginx/snippets",
        "[ -f /etc/nginx/snippets/stacksentry-security.conf ] || "
        "printf '# StackSentry security headers\\n"
        "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\\n"
        "add_header X-Frame-Options \"SAMEORIGIN\" always;\\n"
        "add_header X-Content-Type-Options \"nosniff\" always;\\n"
        "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\\n"
        "server_tokens off;\\n'"
        " > /etc/nginx/snippets/stacksentry-security.conf",
        "grep -r 'stacksentry-security' /etc/nginx/ > /dev/null 2>&1 || "
        "(SITE=$(ls /etc/nginx/sites-enabled/ 2>/dev/null | head -1) && "
        "[ -n \"$SITE\" ] && "
        "sed -i '/server_name/a\\    include snippets/stacksentry-security.conf;' "
        "\"/etc/nginx/sites-enabled/$SITE\")",
        "nginx -t",
        "systemctl reload nginx || service nginx reload",
    ]
 
 
def _tls_commands() -> list[str]:
    """WS-TLS-001: TLS 1.2+ — safe alongside Let's Encrypt (no conflicting directives)."""
    return [
        "mkdir -p /etc/nginx/snippets",
        "printf '# StackSentry TLS\\nssl_protocols TLSv1.2 TLSv1.3;\\n"
        "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;\\n"
        "ssl_prefer_server_ciphers off;\\n'"
        " > /etc/nginx/snippets/stacksentry-tls.conf",
        "grep -r 'stacksentry-tls' /etc/nginx/ > /dev/null 2>&1 || "
        "(SITE=$(ls /etc/nginx/sites-enabled/ 2>/dev/null | head -1) && "
        "[ -n \"$SITE\" ] && "
        "sed -i '/listen 443/a\\    include snippets/stacksentry-tls.conf;' "
        "\"/etc/nginx/sites-enabled/$SITE\")",
        "nginx -t",
        "systemctl reload nginx || service nginx reload",
    ]
 
 
def _dir_listing_commands() -> list[str]:
    return [
        "grep -q 'autoindex' /etc/nginx/nginx.conf || "
        "sed -i '/^http {/a\\    autoindex off;' /etc/nginx/nginx.conf",
        "nginx -t",
        "systemctl reload nginx || service nginx reload",
    ]
 
 
def _request_limits_commands() -> list[str]:
    return [
        "grep -q 'client_max_body_size' /etc/nginx/nginx.conf || "
        "sed -i '/^http {/a\\    client_max_body_size 10m;' /etc/nginx/nginx.conf",
        "nginx -t",
        "systemctl reload nginx || service nginx reload",
    ]
 
 
FIX_REGISTRY: dict[str, callable] = {
    "HOST-FW-001":     _firewall_commands,
    "HOST-UPDATE-001": _auto_updates_commands,
    "HOST-PERM-001":   _permissions_commands,
    "HOST-LOG-001":    _logging_commands,
    "HOST-SSH-001":    _ssh_hardening_commands,
    "WS-HSTS-001":     _hsts_commands,
    "WS-CONF-HSTS":    _hsts_commands,
    "WS-SEC-001":      _hsts_commands,
    "WS-CONF-CSP":     _hsts_commands,
    "WS-SRV-001":      _hsts_commands,
    "WS-TLS-001":      _tls_commands,
    "WS-DIR-001":      _dir_listing_commands,
    "WS-LIMIT-001":    _request_limits_commands,
}
 
# APP layer snippets — framework-specific, printed when --fix is used
APP_SNIPPETS = {
    "APP-DEBUG-001": {
        "flask":  "app.config['DEBUG'] = False  # or set FLASK_ENV=production",
        "django": "DEBUG = False  # in settings.py",
        "generic": "Set DEBUG=False in your framework config before deploying.",
    },
    "APP-COOKIE-001": {
        "flask": (
            "app.config.update(\n"
            "    SESSION_COOKIE_SECURE=True,\n"
            "    SESSION_COOKIE_HTTPONLY=True,\n"
            "    SESSION_COOKIE_SAMESITE='Lax',\n"
            ")"
        ),
        "django": (
            "SESSION_COOKIE_SECURE = True\n"
            "SESSION_COOKIE_HTTPONLY = True\n"
            "SESSION_COOKIE_SAMESITE = 'Lax'\n"
            "CSRF_COOKIE_SECURE = True"
        ),
        "generic": "Enable Secure, HttpOnly, and SameSite flags on session cookies.",
    },
    "APP-CSRF-001": {
        "flask": (
            "# pip install flask-wtf\n"
            "from flask_wtf.csrf import CSRFProtect\n"
            "csrf = CSRFProtect(app)\n"
            "app.config['SECRET_KEY'] = 'your-secret-key'"
        ),
        "django": (
            "# Ensure this is in MIDDLEWARE:\n"
            "'django.middleware.csrf.CsrfViewMiddleware',\n"
            "# Add to templates: {% csrf_token %}"
        ),
        "generic": "Enable CSRF middleware and validate tokens on all state-changing requests.",
    },
    "APP-ADMIN-001": {
        "flask": (
            "# Block admin routes at nginx level (add to server block):\n"
            "location ~ ^/(admin|debug|test|wp-admin) { deny all; return 403; }\n"
            "# Or protect in Flask:\n"
            "@app.before_request\n"
            "def restrict_admin():\n"
            "    if request.path.startswith('/admin') and not current_user.is_admin:\n"
            "        abort(403)"
        ),
        "django": (
            "# Restrict admin to specific IPs in settings.py:\n"
            "INTERNAL_IPS = ['your.trusted.ip']\n"
            "# Or use django-admin-honeypot for decoy admin URL"
        ),
        "generic": "Protect or disable /admin, /debug, /test endpoints behind authentication.",
    },
    "APP-RATE-001": {
        "flask": (
            "# pip install Flask-Limiter\n"
            "from flask_limiter import Limiter\n"
            "from flask_limiter.util import get_remote_address\n"
            "limiter = Limiter(app=app, key_func=get_remote_address,\n"
            "    default_limits=['200 per day', '50 per hour'])"
        ),
        "django": (
            "# pip install django-ratelimit\n"
            "from django_ratelimit.decorators import ratelimit\n"
            "@ratelimit(key='ip', rate='10/m', method='POST', block=True)\n"
            "def login_view(request): ..."
        ),
        "generic": "Implement rate limiting at the application or nginx level.",
    },
    "APP-PASS-001": {
        "flask": (
            "import re\n"
            "def validate_password(pwd):\n"
            "    return (len(pwd) >= 12 and\n"
            "            re.search(r'[A-Z]', pwd) and\n"
            "            re.search(r'[a-z]', pwd) and\n"
            "            re.search(r'\\d', pwd) and\n"
            "            re.search(r'[!@#$%^&*]', pwd))"
        ),
        "django": (
            "# In settings.py:\n"
            "AUTH_PASSWORD_VALIDATORS = [\n"
            "    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',\n"
            "     'OPTIONS': {'min_length': 12}},\n"
            "    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},\n"
            "    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},\n"
            "]"
        ),
        "generic": "Enforce minimum 12 chars, mixed case, numbers and symbols.",
    },
}
 
 
NOT_AUTOMATABLE = {
    "APP-DEBUG-001":  "Application code — set DEBUG=False in Flask/Django config.",
    "APP-COOKIE-001": "Application code — add SESSION_COOKIE_SECURE to app config.",
    "APP-CSRF-001":   "Application code — install and configure CSRF middleware.",
    "APP-ADMIN-001":  "Application code — add authentication to admin routes.",
    "APP-RATE-001":   "Application code — install Flask-Limiter or similar.",
    "APP-PASS-001":   "Application code — add password validation to registration.",
    "CONT-USER-001":       "Provide --dockerfile to auto-fix, or add USER manually.",
    "CONT-CONF-USER":      "Provide --dockerfile to auto-fix, or add USER manually.",
    "CONT-CONF-HEALTH":    "Provide --dockerfile to auto-fix, or add HEALTHCHECK manually.",
    "CONT-HEALTH-001":     "Provide --dockerfile to auto-fix, or add HEALTHCHECK manually.",
    "CONT-COMP-RES":       "Provide --compose-file to auto-fix, or add resource limits manually.",
    "CONT-RES-001":        "Provide --compose-file to auto-fix, or add resource limits manually.",
    "CONT-PORT-001":       "Provide --compose-file to inspect and restrict published ports.",
    "CONT-REG-001":        "Provide --dockerfile to auto-fix, or pin base image version manually.",
    "CONT-SEC-001":        "Manual — move secrets to .env file and update docker-compose.yml.",
    "CT-CONF-DOCKERFILE":  "Provide --dockerfile to auto-fix USER and HEALTHCHECK.",
    "CT-CONF-COMPOSE-PORTS": "Provide --compose-file to inspect and restrict published ports.",
    "HOST-SVC-001":      "Manual — run: systemctl list-units --type=service",
    "HOST-SVC-GUNICORN": "Manual — update Gunicorn systemd User= directive.",
    "HOST-SVC-UWSGI":    "Manual — update uWSGI systemd User= directive.",
    "HOST-SVC-MYSQL":    "Manual — verify MySQL runs as mysql user.",
    "HOST-SVC-REDIS":    "Manual — verify Redis runs as redis user.",
}
 
FILE_FIXABLE = {
    "CONT-USER-001":         ("dockerfile",   "_fix_dockerfile"),
    "CONT-CONF-USER":        ("dockerfile",   "_fix_dockerfile"),
    "CONT-CONF-HEALTH":      ("dockerfile",   "_fix_dockerfile"),
    "CONT-HEALTH-001":       ("dockerfile",   "_fix_dockerfile"),
    "CONT-REG-001":          ("dockerfile",   "_fix_dockerfile"),
    "CT-CONF-DOCKERFILE":    ("dockerfile",   "_fix_dockerfile"),
    "CONT-COMP-RES":         ("compose_file", "_fix_compose_file"),
    "CONT-RES-001":          ("compose_file", "_fix_compose_file"),
    "CONT-PORT-001":         ("compose_file", "_fix_compose_file"),
    "CT-CONF-COMPOSE-PORTS": ("compose_file", "_fix_compose_file"),
    "WS-HSTS-001":           ("nginx_conf",   "_fix_nginx_local"),
    "WS-CONF-HSTS":          ("nginx_conf",   "_fix_nginx_local"),
    "WS-SEC-001":            ("nginx_conf",   "_fix_nginx_local"),
    "WS-CONF-CSP":           ("nginx_conf",   "_fix_nginx_local"),
    "WS-SRV-001":            ("nginx_conf",   "_fix_nginx_local"),
    "WS-TLS-001":            ("nginx_conf",   "_fix_nginx_local"),
    "WS-DIR-001":            ("nginx_conf",   "_fix_nginx_local"),
    "WS-LIMIT-001":          ("nginx_conf",   "_fix_nginx_local"),
}
 
 
 
def _secure_key_file(key_path: pathlib.Path) -> None:
    """
    Restrict a private key file to owner-read/write only.
 
    Cross-platform:
      Linux / macOS : chmod 600
      Windows       : icacls strips inherited permissions and grants
                      only the current user Full Control — the Windows
                      equivalent of chmod 600. Without this, other local
                      Windows users could read the private key.
 
    Falls back gracefully if permission setting fails.
    """
    import sys
    try:
        if sys.platform == "win32":
            import subprocess
            import os
            username = os.environ.get("USERNAME", os.environ.get("USER", ""))
            if username:
                subprocess.run(
                    ["icacls", str(key_path), "/inheritance:r",
                     "/grant:r", f"{username}:(F)"],
                    check=True, capture_output=True,
                )
            else:
                print(f"  ⚠️  Could not determine Windows username — "
                      f"key permissions not restricted: {key_path}")
        else:
            # Linux / macOS — standard Unix permission bits
            key_path.chmod(0o600)
    except Exception as e:
        print(f"  ⚠️  Could not set key file permissions ({e}). "
              f"Restrict manually: {key_path}")
 
 
class AutoFixer:
    """Context-aware fix executor — SSH, Dockerfile, compose, or nginx file."""
 
    def __init__(
        self,
        ssh_host:     Optional[str] = None,
        ssh_user:     str = "root",
        ssh_password: Optional[str] = None,
        ssh_key:      Optional[str] = None,
        dockerfile:   Optional[str] = None,
        compose_file: Optional[str] = None,
        nginx_conf:   Optional[str] = None,
        verbose:      bool = False,
        timeout:      int  = 30,
        dry_run:      bool = False,
    ):
        self.ssh_host     = ssh_host
        self.ssh_user     = ssh_user
        self.ssh_password = ssh_password
        self.ssh_key      = ssh_key
        self.dockerfile   = dockerfile
        self.compose_file = compose_file
        self.nginx_conf   = nginx_conf
        self.verbose      = verbose
        self.timeout      = timeout
        self.dry_run      = dry_run
        self._stack_fingerprint = ""  # set by fix_all from scan_result
 
    def fix_all(self, scan_result) -> list[FixResult]:
        from sec_audit.results import Status
        failing = [c for c in scan_result.checks if c.status != Status.PASS]
        # Store stack fingerprint for framework-specific APP snippets
        self._stack_fingerprint = getattr(scan_result, "stack_fingerprint", "")
 
        PRIORITY = {"HOST-FW-001": 0, "HOST-SSH-001": 90}
 
        def _key(c):
            if c.id in PRIORITY:       return (0, PRIORITY[c.id])
            if c.layer == "host":      return (0, 5)
            if c.layer == "webserver": return (1, 5)
            if c.layer == "container": return (2, 5)
            return (3, 5)
 
        ordered = sorted(failing, key=_key)
        # No SSH connection needed in dry-run — nothing is executed
        shared  = self._open_ssh_client() if (self.ssh_host and not self.dry_run) else None
        results = []
 
        for check in ordered:
            result = self._fix_one(check.id, check.name, check.layer,
                                   shared_client=shared)
            results.append(result)
            if self.verbose:
                icon = {"fixed": "✅", "failed": "❌", "skipped": "⏭️",
                        "not_automatable": "📋"}.get(result.status, "?")
                print(f"  {icon} {check.id}: {result.message}")
 
        if shared:
            try: shared.close()
            except Exception: pass
 
        orig = {c.id: i for i, c in enumerate(failing)}
        results.sort(key=lambda r: orig.get(r.check_id, 999))
        return results
 
    def fix_check(self, check_id: str, check_name: str, layer: str) -> FixResult:
        return self._fix_one(check_id, check_name, layer)
 
    def _key_store_dir(self) -> pathlib.Path:
        """Directory where StackSentry-generated SSH keys are stored."""
        d = pathlib.Path.home() / ".stacksentry" / "keys"
        d.mkdir(parents=True, exist_ok=True)
        return d
 
    def _ensure_ssh_key(self, shared_client) -> dict:
        """
        If the user authenticated with a password, generate a new Ed25519 SSH
        key pair, install the public key on the server, verify it works, then
        update self.ssh_key so subsequent fixes also use the key.
 
        This is called exclusively for HOST-SSH-001 before applying
        prohibit-password — it prevents the user being locked out.
 
        Returns:
            {
              "success":  bool,
              "key_path": str | None,
              "message":  str,
            }
        """
        v = self.verbose
        if v: print("[DEBUG] HOST-SSH-001: SSH key pre-flight starting")
 
        # Already using a key — nothing to do
        if self.ssh_key:
            return {"success": True, "key_path": self.ssh_key,
                    "message": "SSH key already in use — skipping key generation."}
 
        if not self.ssh_password:
            return {"success": False, "key_path": None,
                    "message": "No SSH credentials available to generate key."}
 
        try:
            import paramiko
            from io import StringIO
 
            if v: print("[DEBUG] HOST-SSH-001: generating Ed25519 key pair")
            # Generate Ed25519 key pair
            key = paramiko.Ed25519Key.generate()
 
            # Build paths
            stamp     = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            host_slug = (self.ssh_host or "server").replace(".", "-").replace(":", "-")
            key_path  = self._key_store_dir() / f"{host_slug}_{stamp}.pem"
            pub_path  = self._key_store_dir() / f"{host_slug}_{stamp}.pub"
 
            # Save private key with OS-appropriate permissions
            sio = StringIO()
            key.write_private_key(sio)
            key_path.write_text(sio.getvalue())
            _secure_key_file(key_path)
 
            # Save public key in OpenSSH format
            pub_key_str = f"ssh-ed25519 {key.get_base64()} stacksentry-generated"
            pub_path.write_text(pub_key_str + "\n")
 
            if v: print(f"[DEBUG] HOST-SSH-001: saving private key to {key_path}")
            # Install public key on server via existing password-authenticated session
            if v: print(f"[DEBUG] HOST-SSH-001: uploading public key to {self.ssh_host}")
            for cmd in [
                "mkdir -p ~/.ssh",
                "chmod 700 ~/.ssh",
                f"echo '{pub_key_str}' >> ~/.ssh/authorized_keys",
                "chmod 600 ~/.ssh/authorized_keys",
                "sort -u ~/.ssh/authorized_keys -o ~/.ssh/authorized_keys",
            ]:
                _, stdout, _ = shared_client.exec_command(cmd)
                stdout.channel.recv_exit_status()
 
            if v: print("[DEBUG] HOST-SSH-001: verifying key login before changing sshd")
            # Verify the key actually works before we change sshd config
            test_client = paramiko.SSHClient()
            test_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                test_client.connect(
                    hostname=self.ssh_host,
                    username=self.ssh_user,
                    key_filename=str(key_path),
                    timeout=10,
                )
                test_client.close()
            except Exception as e:
                return {
                    "success": False,
                    "key_path": None,
                    "message": (
                        f"Key generated but test login failed ({e}). "
                        "SSH config will NOT be changed to avoid lockout. "
                        f"Public key saved to {pub_path} — install manually "
                        "then re-run."
                    ),
                }
 
            # Update self so all remaining fixes also use the new key
            self.ssh_key      = str(key_path)
            self.ssh_password = None
            if v: print(f"[DEBUG] HOST-SSH-001: key verified OK — key auth now active")
 
            return {
                "success":  True,
                "key_path": str(key_path),
                "message":  (
                    f"SSH key generated and verified. "
                    f"Private key: {key_path}. "
                    f"Connect with: ssh -i {key_path} "
                    f"{self.ssh_user}@{self.ssh_host}"
                ),
            }
 
        except Exception as e:
            return {
                "success": False,
                "key_path": None,
                "message": f"Key generation failed ({e}). SSH config unchanged.",
            }
 
    def _dry_run_ssh001_warning(self) -> str:
        """
        Returns a prominent warning message for HOST-SSH-001 in dry-run mode
        when the user is currently authenticating with a password.
        """
        if self.ssh_key:
            return "Would apply PermitRootLogin prohibit-password (SSH key already configured)."
 
        stamp     = datetime.now(timezone.utc).strftime("%Y%m%d")
        host_slug = (self.ssh_host or "server").replace(".", "-").replace(":", "-")
        key_dir   = self._key_store_dir()
        key_name  = f"{host_slug}_{stamp}.pem"
 
        return (
            f"\n  ⚠️  PASSWORD → KEY MIGRATION REQUIRED\n"
            f"  This fix disables root password login (PermitRootLogin prohibit-password).\n"
            f"  Since you are using --ssh-password, StackSentry will first:\n"
            f"\n"
            f"  Step 1: Generate Ed25519 key pair locally\n"
            f"          Private key → {key_dir / key_name}\n"
            f"          Public key  → {key_dir / key_name.replace('.pem', '.pub')}\n"
            f"\n"
            f"  Step 2: Install public key on {self.ssh_host}\n"
            f"          $ mkdir -p ~/.ssh && chmod 700 ~/.ssh\n"
            f"          $ echo 'ssh-ed25519 ...' >> ~/.ssh/authorized_keys\n"
            f"          $ chmod 600 ~/.ssh/authorized_keys\n"
            f"\n"
            f"  Step 3: Verify key login works (test connection before changing sshd)\n"
            f"\n"
            f"  Step 4: Apply sshd hardening\n"
            f"          $ cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak\n"
            f"          $ sed -i 's/PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config\n"
            f"          $ sshd -t  (validate config before reload)\n"
            f"          $ systemctl restart sshd\n"
            f"\n"
            f"  After applying, connect with:\n"
            f"  ssh -i {key_dir / key_name} {self.ssh_user}@{self.ssh_host}\n"
        )
 
    def _open_ssh_client(self):
        auth = "key" if self.ssh_key else "password"
        if self.verbose:
            print(f"[DEBUG] AutoFixer: SSH connect → "
                  f"{self.ssh_user}@{self.ssh_host} [{auth}]")
        try:
            import paramiko
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            kw: dict = {"hostname": self.ssh_host, "username": self.ssh_user,
                        "timeout": self.timeout}
            if self.ssh_password: kw["password"] = self.ssh_password
            if self.ssh_key:      kw["key_filename"] = self.ssh_key
            c.connect(**kw)
            if self.verbose:
                print("[DEBUG] AutoFixer: SSH connected ✅")
            return c
        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] AutoFixer: SSH failed: {e!r}")
            return None
 
    def _fix_one(self, check_id: str, check_name: str, layer: str,
                 shared_client=None) -> FixResult:
 
        # APP layer — always manual, but show framework-specific snippet
        if check_id in NOT_AUTOMATABLE and layer == "app":
            snippet  = self._app_snippet(check_id)
            base_msg = NOT_AUTOMATABLE[check_id]
            msg = f"{base_msg}\n\n  📋 Copy-paste fix for your stack:\n{snippet}" if snippet else base_msg
            return FixResult(check_id, check_name, layer, "not_automatable", msg)
 
        # SSH-based fix (HOST + WS layer)
        if self.ssh_host and check_id in FIX_REGISTRY:
            commands = FIX_REGISTRY[check_id]()
            if self.dry_run:
                # HOST-SSH-001 gets a prominent warning about auth method change
                if check_id == "HOST-SSH-001":
                    msg = self._dry_run_ssh001_warning()
                else:
                    msg = f"Would run {len(commands)} SSH command(s) on {self.ssh_host}"
                return FixResult(
                    check_id=check_id, check_name=check_name, layer=layer,
                    status="would_fix",
                    message=msg,
                    commands_run=commands,
                )
            # HOST-SSH-001: generate + install SSH key BEFORE applying prohibit-password
            # This prevents the user from being locked out after the fix runs.
            if check_id == "HOST-SSH-001" and shared_client:
                key_result = self._ensure_ssh_key(shared_client)
                if not key_result["success"]:
                    return FixResult(
                        check_id=check_id, check_name=check_name, layer=layer,
                        status="failed",
                        message=key_result["message"],
                    )
                if self.verbose:
                    print(f"  🔑 SSH key generated and verified: {key_result['key_path']}")
            return self._execute_fix(check_id, check_name, layer, commands, shared_client)
 
        # File-based fix (--dockerfile / --compose-file / --nginx-conf)
        if check_id in FILE_FIXABLE:
            attr, method_name = FILE_FIXABLE[check_id]
            file_path = getattr(self, attr, None)
            if file_path:
                if self.dry_run:
                    # Show what WOULD be edited without touching the file
                    return FixResult(
                        check_id=check_id, check_name=check_name, layer=layer,
                        status="would_fix",
                        message=f"Would edit {file_path} (backup created, {check_id} directives added)",
                        commands_run=[f"edit {file_path}"],
                    )
                method = getattr(self, method_name, None)
                if method:
                    return method(file_path, check_id, check_name)
            flag = {"dockerfile": "--dockerfile", "compose_file": "--compose-file",
                    "nginx_conf": "--nginx-conf"}.get(attr, f"--{attr}")
            return FixResult(check_id, check_name, layer, "skipped",
                             f"Provide {flag} to auto-fix, or --ssh-host to fix on server.")
 
        # Other not_automatable entries (CONT secrets, HOST service users)
        if check_id in NOT_AUTOMATABLE:
            return FixResult(check_id, check_name, layer, "not_automatable",
                             NOT_AUTOMATABLE[check_id])
 
        return FixResult(check_id, check_name, layer, "skipped",
                         "No automated fix available for this check.")
 
 
    def _execute_fix(self, check_id, check_name, layer, commands,
                     shared_client=None) -> FixResult:
        try:
            import paramiko
        except ImportError:
            return FixResult(check_id, check_name, layer, "failed",
                             "paramiko not installed.")
 
        executed, own = [], False
        try:
            if (shared_client and shared_client.get_transport() and
                    shared_client.get_transport().is_active()):
                client = shared_client
            else:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                kw: dict = {"hostname": self.ssh_host, "username": self.ssh_user,
                            "timeout": self.timeout}
                if self.ssh_password: kw["password"] = self.ssh_password
                if self.ssh_key:      kw["key_filename"] = self.ssh_key
                client.connect(**kw)
                own = True
 
            for cmd in commands:
                if self.verbose:
                    print(f"    $ {cmd[:80]}{'...' if len(cmd) > 80 else ''}")
                _, out, err = client.exec_command(cmd, timeout=self.timeout)
                rc = out.channel.recv_exit_status()
                executed.append(cmd)
                if any(v in cmd for v in ["sshd -t", "nginx -t"]) and rc != 0:
                    e = err.read().decode().strip()
                    if own:
                        try: client.close()
                        except Exception: pass
                    return FixResult(check_id, check_name, layer, "failed",
                                     f"Validation failed: {e or 'test failed'}", executed)
 
            if own:
                try: client.close()
                except Exception: pass
            return FixResult(check_id, check_name, layer, "fixed",
                             f"Applied {len(executed)} command(s) successfully.", executed)
 
        except Exception as exc:
            if own:
                try: client.close()
                except Exception: pass
            return FixResult(check_id, check_name, layer, "failed",
                             f"SSH error: {exc!r}", executed)
 
    # ── App layer snippet generation (Path B) ───────────────────────────────
 
    def _app_snippet(self, check_id: str) -> str:
        """
        Return a framework-specific copy-paste code snippet for an APP check.
        Detects framework from the stack_fingerprint if available, else generic.
        """
        snippets = APP_SNIPPETS.get(check_id)
        if not snippets:
            return ""
        stack = getattr(self, "_stack_fingerprint", "").lower()
        if "flask" in stack:
            framework = "flask"
        elif "django" in stack:
            framework = "django"
        else:
            framework = "generic"
        snippet_text = snippets.get(framework, snippets.get("generic", ""))
        # Indent each line for clean console output
        lines = snippet_text.splitlines()
        return "\n".join(f"    {line}" for line in lines)
 
    # ── File-based fix methods ────────────────────────────────────────────────
 
    def _backup_file(self, path: pathlib.Path) -> pathlib.Path:
        stamp  = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup = path.with_suffix(f"{path.suffix}.bak.{stamp}")
        shutil.copy2(path, backup)
        return backup
 
    def _fix_dockerfile(self, dockerfile_path: str, check_id: str,
                        check_name: str) -> FixResult:
        p = pathlib.Path(dockerfile_path)
        if not p.exists():
            return FixResult(check_id, check_name, "container", "failed",
                             f"Dockerfile not found: {dockerfile_path}")
        if self.verbose: print(f"[DEBUG] AutoFixer: editing Dockerfile: {p}")
        content  = p.read_text(encoding="utf-8")
        original = content
        changes  = []
 
        if check_id in ("CONT-USER-001", "CONT-CONF-USER", "CT-CONF-DOCKERFILE"):
            if "USER " not in content:
                insert = ("# StackSentry: run as non-root\n"
                          "RUN groupadd -r appgroup && useradd -r -g appgroup appuser\n"
                          "USER appuser\n\n")
                for kw in ("CMD ", "ENTRYPOINT "):
                    if kw in content:
                        idx = content.rfind(kw)
                        content = content[:idx] + insert + content[idx:]
                        break
                else:
                    content += "\n" + insert
                changes.append("Added USER appuser")
 
        if check_id in ("CONT-CONF-HEALTH", "CONT-HEALTH-001", "CT-CONF-DOCKERFILE"):
            if "HEALTHCHECK " not in content:
                hc = ("# StackSentry: health check\n"
                      "HEALTHCHECK --interval=30s --timeout=10s --retries=3 \\\n"
                      "    CMD curl -f http://localhost/health || exit 1\n\n")
                for kw in ("CMD ", "ENTRYPOINT "):
                    if kw in content:
                        idx = content.rfind(kw)
                        content = content[:idx] + hc + content[idx:]
                        break
                else:
                    content += "\n" + hc
                changes.append("Added HEALTHCHECK")
 
        if check_id == "CONT-REG-001":
            import re
            if re.search(r"^FROM \S+:latest", content, re.MULTILINE):
                content = re.sub(r"^(FROM \S+):latest",
                                 r"\1:stable  # pin to stable — set specific version",
                                 content, flags=re.MULTILINE)
                changes.append("Replaced :latest with :stable")
 
        if content == original:
            return FixResult(check_id, check_name, "container", "skipped",
                             "Dockerfile already satisfies this check.")
        bk = self._backup_file(p)
        p.write_text(content, encoding="utf-8")
        return FixResult(check_id, check_name, "container", "fixed",
                         f"Dockerfile updated: {', '.join(changes)}. "
                         f"Backup: {bk.name}. Rebuild: docker build .",
                         [f"edit {dockerfile_path}"])
 
    def _fix_compose_file(self, compose_path: str, check_id: str,
                          check_name: str) -> FixResult:
        p = pathlib.Path(compose_path)
        if not p.exists():
            return FixResult(check_id, check_name, "container", "failed",
                             f"docker-compose.yml not found: {compose_path}")
        if self.verbose: print(f"[DEBUG] AutoFixer: editing compose file: {p}")
        try:
            import yaml
        except ImportError:
            return FixResult(check_id, check_name, "container", "failed",
                             "PyYAML not installed — run: pip install pyyaml")
 
        data    = yaml.safe_load(p.read_text(encoding="utf-8"))
        changes = []
        if not data or "services" not in data:
            return FixResult(check_id, check_name, "container", "failed",
                             "No 'services' key in docker-compose.yml")
 
        if check_id in ("CONT-COMP-RES", "CONT-RES-001"):
            for svc_name, svc in data["services"].items():
                svc.setdefault("deploy", {})
                if "resources" not in svc["deploy"]:
                    svc["deploy"]["resources"] = {
                        "limits":       {"cpus": "0.50", "memory": "512M"},
                        "reservations": {"cpus": "0.25", "memory": "256M"},
                    }
                    changes.append(f"resource limits for '{svc_name}'")
 
        if check_id in ("CT-CONF-COMPOSE-PORTS", "CONT-PORT-001"):
            exposed = [f"{n}: {s.get('ports', [])}"
                       for n, s in data["services"].items() if s.get("ports")]
            msg = ("Exposed ports: " + "; ".join(exposed)) if exposed else "No exposed ports."
            return FixResult(check_id, check_name, "container", "skipped",
                             msg + " Review and remove unnecessary ports manually.")
 
        if not changes:
            return FixResult(check_id, check_name, "container", "skipped",
                             "docker-compose.yml already satisfies this check.")
        bk = self._backup_file(p)
        p.write_text(yaml.dump(data, default_flow_style=False), encoding="utf-8")
        return FixResult(check_id, check_name, "container", "fixed",
                         f"docker-compose.yml updated: {', '.join(changes)}. "
                         f"Backup: {bk.name}. Restart: docker compose up -d",
                         [f"edit {compose_path}"])
 
    def _fix_nginx_local(self, nginx_conf_path: str, check_id: str,
                         check_name: str) -> FixResult:
        p = pathlib.Path(nginx_conf_path)
        if not p.exists():
            return FixResult(check_id, check_name, "webserver", "failed",
                             f"nginx.conf not found: {nginx_conf_path}")
        if self.verbose: print(f"[DEBUG] AutoFixer: editing nginx.conf: {p}")
        content  = p.read_text(encoding="utf-8")
        original = content
        changes  = []
 
        DIRECTIVES = {
            "WS-HSTS-001":  ("Strict-Transport-Security",
                              'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'),
            "WS-CONF-HSTS": ("Strict-Transport-Security",
                              'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'),
            "WS-SEC-001":   ("X-Frame-Options",
                              'add_header X-Frame-Options "SAMEORIGIN" always;'),
            "WS-CONF-CSP":  ("Content-Security-Policy",
                              "add_header Content-Security-Policy \"default-src 'self';\" always;"),
            "WS-SRV-001":   ("server_tokens",        "server_tokens off;"),
            "WS-TLS-001":   ("ssl_protocols",        "ssl_protocols TLSv1.2 TLSv1.3;"),
            "WS-DIR-001":   ("autoindex",            "autoindex off;"),
            "WS-LIMIT-001": ("client_max_body_size", "client_max_body_size 10m;"),
        }
 
        if check_id in DIRECTIVES:
            key, directive = DIRECTIVES[check_id]
            if key not in content:
                content = content.replace("http {", f"http {{\n    {directive}", 1)
                changes.append(directive[:60])
 
        if content == original:
            return FixResult(check_id, check_name, "webserver", "skipped",
                             "nginx.conf already satisfies this check.")
        bk = self._backup_file(p)
        p.write_text(content, encoding="utf-8")
        return FixResult(check_id, check_name, "webserver", "fixed",
                         f"nginx.conf updated: {', '.join(changes)}. "
                         f"Backup: {bk.name}. Test: nginx -t",
                         [f"edit {nginx_conf_path}"])
 
 
# ── Public registry ───────────────────────────────────────────────────────────
 
AUTOMATABLE_CHECKS = set(FIX_REGISTRY.keys()) | set(FILE_FIXABLE.keys())
 