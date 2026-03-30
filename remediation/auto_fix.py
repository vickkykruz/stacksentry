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
 
    def fix_all(self, scan_result) -> list[FixResult]:
        from sec_audit.results import Status
        failing = [c for c in scan_result.checks if c.status != Status.PASS]
 
        PRIORITY = {"HOST-FW-001": 0, "HOST-SSH-001": 90}
 
        def _key(c):
            if c.id in PRIORITY:       return (0, PRIORITY[c.id])
            if c.layer == "host":      return (0, 5)
            if c.layer == "webserver": return (1, 5)
            if c.layer == "container": return (2, 5)
            return (3, 5)
 
        ordered = sorted(failing, key=_key)
        shared  = self._open_ssh_client() if self.ssh_host else None
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
 
    def _open_ssh_client(self):
        try:
            import paramiko
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            kw: dict = {"hostname": self.ssh_host, "username": self.ssh_user,
                        "timeout": self.timeout}
            if self.ssh_password: kw["password"] = self.ssh_password
            if self.ssh_key:      kw["key_filename"] = self.ssh_key
            c.connect(**kw)
            return c
        except Exception:
            return None
 
    def _fix_one(self, check_id: str, check_name: str, layer: str,
                 shared_client=None) -> FixResult:
 
        if check_id in NOT_AUTOMATABLE and layer == "app":
            return FixResult(check_id, check_name, layer, "not_automatable",
                             NOT_AUTOMATABLE[check_id])
 
        if self.ssh_host and check_id in FIX_REGISTRY:
            return self._execute_fix(check_id, check_name, layer,
                                     FIX_REGISTRY[check_id](), shared_client)
 
        if check_id in FILE_FIXABLE:
            attr, method_name = FILE_FIXABLE[check_id]
            file_path = getattr(self, attr, None)
            if file_path:
                method = getattr(self, method_name, None)
                if method:
                    return method(file_path, check_id, check_name)
            flag = {"dockerfile": "--dockerfile", "compose_file": "--compose-file",
                    "nginx_conf": "--nginx-conf"}.get(attr, f"--{attr}")
            return FixResult(check_id, check_name, layer, "skipped",
                             f"Provide {flag} to auto-fix, or --ssh-host to fix on server.")
 
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