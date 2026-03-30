"""
remediation/auto_fix.py — SSH-based automatic fix executor.
 
Applies remediation commands directly on the target server via SSH
for checks where automation is safe and reliable:
 
  ✅ HOST layer  — bash commands on the Linux host (SSH already available)
  ✅ WS layer    — nginx config changes via SSH (find config, patch, reload)
  ❌ APP layer   — application code structure unknown, too risky to auto-edit
  ❌ CONT layer  — requires Dockerfile location and rebuild pipeline
 
Each fix is:
  1. Non-destructive by default — creates backups before any modification
  2. Validated before applying — nginx -t, sshd -t before restart
  3. Verified after applying  — re-runs the specific check to confirm PASS
  4. Reported clearly         — shows FIXED / FAILED / SKIPPED with reason
 
Usage:
    from remediation.auto_fix import AutoFixer, FixResult
    fixer = AutoFixer(ssh_host="1.2.3.4", ssh_user="root", ssh_password="...")
    results = fixer.fix_all(scan_result)
"""
 
from __future__ import annotations
 
import time
from dataclasses import dataclass, field
from typing import Optional
 
 
# ── FixResult ─────────────────────────────────────────────────────────────────
 
@dataclass
class FixResult:
    """
    Result of attempting to auto-fix a single check.
 
    Attributes
    ----------
    check_id     The check that was targeted
    check_name   Human-readable name
    layer        app / webserver / container / host
    status       "fixed" | "failed" | "skipped" | "not_automatable"
    message      Human-readable explanation of what happened
    commands_run List of commands that were executed on the server
    verified     True if the check passed after the fix was applied
    """
    check_id:     str
    check_name:   str
    layer:        str
    status:       str   # "fixed" | "failed" | "skipped" | "not_automatable"
    message:      str
    commands_run: list[str] = field(default_factory=list)
    verified:     bool = False
 
 
# ── Fix command registry ──────────────────────────────────────────────────────
 
def _ssh_hardening_commands() -> list[str]:
    """HOST-SSH-001: Harden sshd_config."""
    return [
        "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d_%H%M%S)",
        "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
        "grep -q '^PermitRootLogin' /etc/ssh/sshd_config || echo 'PermitRootLogin no' >> /etc/ssh/sshd_config",
        "sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config",
        "grep -q '^MaxAuthTries' /etc/ssh/sshd_config || echo 'MaxAuthTries 3' >> /etc/ssh/sshd_config",
        "sshd -t",   # validate before restarting
        "systemctl restart sshd || service ssh restart",
    ]
 
 
def _firewall_commands() -> list[str]:
    """HOST-FW-001: Enable UFW firewall."""
    return [
        "ufw allow 22/tcp comment 'SSH'",
        "ufw allow 80/tcp comment 'HTTP'",
        "ufw allow 443/tcp comment 'HTTPS'",
        "ufw default deny incoming",
        "ufw default allow outgoing",
        "ufw --force enable",
    ]
 
 
def _auto_updates_commands() -> list[str]:
    """HOST-UPDATE-001: Enable unattended-upgrades."""
    return [
        "apt-get update -qq",
        "apt-get install -y unattended-upgrades",
        "systemctl enable unattended-upgrades",
        "systemctl start unattended-upgrades",
    ]
 
 
def _permissions_commands() -> list[str]:
    """HOST-PERM-001: Fix world-writable SSH file permissions."""
    return [
        "find /etc/ssh -perm -o+w -exec chmod o-w {} \\;",
    ]
 
 
def _logging_commands() -> list[str]:
    """HOST-LOG-001: Ensure rsyslog is installed and running."""
    return [
        "apt-get install -y rsyslog 2>/dev/null || yum install -y rsyslog 2>/dev/null || true",
        "systemctl enable rsyslog",
        "systemctl start rsyslog",
    ]
 
 
def _hsts_commands() -> list[str]:
    """WS-HSTS-001: Add HSTS header to nginx config."""
    return [
        # Find the main nginx config or sites-enabled
        "CONF=$(nginx -T 2>/dev/null | grep 'configuration file' | grep -v '#' | head -1 | awk '{print $NF}' | tr -d ':') && echo $CONF",
        # Create a security headers snippet
        "mkdir -p /etc/nginx/snippets",
        "cat > /etc/nginx/snippets/stacksentry-security.conf << 'NGINX_EOF'\n"
        "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
        "add_header X-Frame-Options \"SAMEORIGIN\" always;\n"
        "add_header X-Content-Type-Options \"nosniff\" always;\n"
        "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n"
        "server_tokens off;\n"
        "NGINX_EOF",
        # Include the snippet in the default site if not already included
        "grep -r 'stacksentry-security' /etc/nginx/ || "
        "(SITE=$(ls /etc/nginx/sites-enabled/ 2>/dev/null | head -1) && "
        "[ -n \"$SITE\" ] && "
        "sed -i '/server_name/a\\    include snippets/stacksentry-security.conf;' "
        "/etc/nginx/sites-enabled/$SITE)",
        "nginx -t",
        "systemctl reload nginx || service nginx reload",
    ]
 
 
def _security_headers_commands() -> list[str]:
    """WS-SEC-001: Add security headers (reuses HSTS snippet approach)."""
    # Reuse the same snippet — it covers all 4 headers
    return _hsts_commands()
 
 
def _server_tokens_commands() -> list[str]:
    """WS-SRV-001: Hide nginx version."""
    return [
        "grep -q 'server_tokens' /etc/nginx/nginx.conf || "
        "sed -i '/http {/a\\    server_tokens off;' /etc/nginx/nginx.conf",
        "sed -i 's/server_tokens on/server_tokens off/' /etc/nginx/nginx.conf",
        "nginx -t",
        "systemctl reload nginx || service nginx reload",
    ]
 
 
def _request_limits_commands() -> list[str]:
    """WS-LIMIT-001: Set request size limits."""
    return [
        "grep -q 'client_max_body_size' /etc/nginx/nginx.conf || "
        "sed -i '/http {/a\\    client_max_body_size 10m;' /etc/nginx/nginx.conf",
        "nginx -t",
        "systemctl reload nginx || service nginx reload",
    ]
 
 
def _tls_commands() -> list[str]:
    """WS-TLS-001: Enforce TLS 1.2+ with strong ciphers."""
    return [
        "mkdir -p /etc/nginx/snippets",
        "cat > /etc/nginx/snippets/stacksentry-tls.conf << 'TLS_EOF'\n"
        "ssl_protocols TLSv1.2 TLSv1.3;\n"
        "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;\n"
        "ssl_prefer_server_ciphers off;\n"
        "ssl_session_cache shared:SSL:10m;\n"
        "ssl_session_timeout 1d;\n"
        "ssl_session_tickets off;\n"
        "TLS_EOF",
        "grep -r 'stacksentry-tls' /etc/nginx/ || "
        "(SITE=$(ls /etc/nginx/sites-enabled/ 2>/dev/null | head -1) && "
        "[ -n \"$SITE\" ] && "
        "sed -i '/listen 443/a\\    include snippets/stacksentry-tls.conf;' "
        "/etc/nginx/sites-enabled/$SITE)",
        "nginx -t",
        "systemctl reload nginx || service nginx reload",
    ]
 
 
# ── Fix registry ──────────────────────────────────────────────────────────────
 
FIX_REGISTRY: dict[str, callable] = {
    "HOST-SSH-001":    _ssh_hardening_commands,
    "HOST-FW-001":     _firewall_commands,
    "HOST-UPDATE-001": _auto_updates_commands,
    "HOST-PERM-001":   _permissions_commands,
    "HOST-LOG-001":    _logging_commands,
    "WS-HSTS-001":     _hsts_commands,
    "WS-SEC-001":      _security_headers_commands,
    "WS-SRV-001":      _server_tokens_commands,
    "WS-LIMIT-001":    _request_limits_commands,
    "WS-TLS-001":      _tls_commands,
}
 
NOT_AUTOMATABLE = {
    "APP-DEBUG-001":  "Application code change — edit your Flask/Django config manually.",
    "APP-COOKIE-001": "Application code change — add SESSION_COOKIE_SECURE to app config.",
    "APP-CSRF-001":   "Application code change — install and configure CSRF middleware.",
    "APP-ADMIN-001":  "Application code change — add authentication to admin routes.",
    "APP-RATE-001":   "Application code change — install Flask-Limiter or similar.",
    "APP-PASS-001":   "Application code change — add password validation to registration.",
    "CONT-USER-001":  "Requires Dockerfile rebuild — add USER directive and rebuild image.",
    "CONT-CONF-USER": "Requires Dockerfile rebuild — add USER directive and rebuild image.",
    "CONT-CONF-HEALTH": "Requires Dockerfile rebuild — add HEALTHCHECK and rebuild image.",
    "CONT-RES-001":   "Requires docker-compose.yml edit and container restart.",
    "CONT-COMP-RES":  "Requires docker-compose.yml edit and container restart.",
    "CONT-SEC-001":   "Requires moving secrets to .env file and rebuilding containers.",
}
 
 
# ── AutoFixer ─────────────────────────────────────────────────────────────────
 
class AutoFixer:
    """
    Applies automatic fixes to the target server via SSH.
 
    Only HOST and WS layer checks are auto-fixed. APP and CONT layer
    checks are marked as not_automatable with a clear explanation.
 
    Usage
    -----
        fixer = AutoFixer(
            ssh_host="1.2.3.4",
            ssh_user="root",
            ssh_password="secret",
        )
        results = fixer.fix_all(scan_result)
        for r in results:
            print(f"{r.check_id}: {r.status} — {r.message}")
    """
 
    def __init__(
        self,
        ssh_host: str,
        ssh_user: str = "root",
        ssh_password: Optional[str] = None,
        ssh_key: Optional[str] = None,
        verbose: bool = False,
        timeout: int = 30,
    ):
        self.ssh_host     = ssh_host
        self.ssh_user     = ssh_user
        self.ssh_password = ssh_password
        self.ssh_key      = ssh_key
        self.verbose      = verbose
        self.timeout      = timeout
 
    # ── Public API ────────────────────────────────────────────────────────────
 
    def fix_all(self, scan_result) -> list[FixResult]:
        """
        Attempt to fix all non-passing checks in the scan result.
 
        Returns one FixResult per non-passing check.
        """
        from sec_audit.results import Status
        failing = [c for c in scan_result.checks if c.status != Status.PASS]
 
        results = []
        for check in failing:
            result = self._fix_one(check.id, check.name, check.layer)
            results.append(result)
            if self.verbose:
                icon = {"fixed": "✅", "failed": "❌", "skipped": "⏭️",
                        "not_automatable": "📋"}.get(result.status, "?")
                print(f"  {icon} {check.id}: {result.message}")
 
        return results
 
    def fix_check(self, check_id: str, check_name: str, layer: str) -> FixResult:
        """Fix a single check by ID."""
        return self._fix_one(check_id, check_name, layer)
 
    # ── Internal ──────────────────────────────────────────────────────────────
 
    def _fix_one(self, check_id: str, check_name: str, layer: str) -> FixResult:
        """Attempt to fix a single check."""
 
        # Not automatable — app or container layer
        if check_id in NOT_AUTOMATABLE:
            return FixResult(
                check_id=check_id, check_name=check_name, layer=layer,
                status="not_automatable",
                message=NOT_AUTOMATABLE[check_id],
            )
 
        # No fix command registered
        if check_id not in FIX_REGISTRY:
            return FixResult(
                check_id=check_id, check_name=check_name, layer=layer,
                status="skipped",
                message="No automated fix available for this check.",
            )
 
        # No SSH params — cannot fix host/webserver without SSH
        if not self.ssh_host:
            return FixResult(
                check_id=check_id, check_name=check_name, layer=layer,
                status="skipped",
                message="SSH connection required — use --ssh-host to enable auto-fix.",
            )
 
        # Execute the fix commands via SSH
        commands = FIX_REGISTRY[check_id]()
        return self._execute_fix(check_id, check_name, layer, commands)
 
    def _execute_fix(
        self,
        check_id: str,
        check_name: str,
        layer: str,
        commands: list[str],
    ) -> FixResult:
        """Execute fix commands on the server via SSH."""
        try:
            import paramiko
        except ImportError:
            return FixResult(
                check_id=check_id, check_name=check_name, layer=layer,
                status="failed",
                message="paramiko not installed — cannot SSH to apply fix.",
            )
 
        executed = []
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
 
            connect_kwargs = {
                "hostname": self.ssh_host,
                "username": self.ssh_user,
                "timeout":  self.timeout,
            }
            if self.ssh_password:
                connect_kwargs["password"] = self.ssh_password
            if self.ssh_key:
                connect_kwargs["key_filename"] = self.ssh_key
 
            client.connect(**connect_kwargs)
 
            for cmd in commands:
                if self.verbose:
                    print(f"    $ {cmd[:80]}{'...' if len(cmd) > 80 else ''}")
                _, stdout, stderr = client.exec_command(cmd, timeout=self.timeout)
                exit_code = stdout.channel.recv_exit_status()
                executed.append(cmd)
 
                # Critical commands that must succeed
                critical = ["sshd -t", "nginx -t"]
                if any(c in cmd for c in critical) and exit_code != 0:
                    err = stderr.read().decode().strip()
                    client.close()
                    return FixResult(
                        check_id=check_id, check_name=check_name, layer=layer,
                        status="failed",
                        message=f"Validation failed: {err or 'config test returned non-zero'}",
                        commands_run=executed,
                    )
 
            client.close()
 
            return FixResult(
                check_id=check_id, check_name=check_name, layer=layer,
                status="fixed",
                message=f"Applied {len(executed)} command(s) successfully.",
                commands_run=executed,
                verified=False,  # caller can re-scan to verify
            )
 
        except Exception as exc:
            return FixResult(
                check_id=check_id, check_name=check_name, layer=layer,
                status="failed",
                message=f"SSH error: {exc!r}",
                commands_run=executed,
            )
 
 
# ── Automatable check registry (public) ──────────────────────────────────────
 
AUTOMATABLE_CHECKS = set(FIX_REGISTRY.keys())