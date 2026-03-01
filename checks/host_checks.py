"""
Host/Server OS Security Checks (6 checks)

1. SSH hardened (no root login)
2. No unnecessary services running
3. Automatic security updates
4. Correct file permissions
5. Firewall configured
6. Logging/monitoring enabled
"""


from typing import Optional

from sec_audit.results import CheckResult, Status, Severity
from scanners.ssh_scanner import SSHScanner
from sec_audit.results import ScanResult
from sec_audit.config import CHECKS


def _meta(check_id: str):
    for c in CHECKS:
        if c["id"] == check_id:
            return c
    raise KeyError(f"Unknown check id: {check_id}")


# ==================== 6 REAL CHECKS ====================
def check_ssh_hardening(ssh_host: Optional[str] = None, ssh_user: Optional[str] = None, 
                       ssh_key: Optional[str] = None, ssh_password: Optional[str] = None, scan_result: Optional[ScanResult] = None, verbose: bool = False) -> CheckResult:
    """HOST-SSH-001: SSH PermitRootLogin disabled."""
    meta = _meta("HOST-SSH-001")
    
    if not (ssh_host and ssh_user and (ssh_key or ssh_password)):
        if verbose:
            print("[DEBUG] HOST-SSH-001: missing SSH params")
        status = Status.WARN
        details = "SSH credentials missing (--ssh-host --ssh-user and either --ssh-key or --ssh-password)"

        
    # Use scanner instead of inline code
    scanner = SSHScanner(host=ssh_host, user=ssh_user, key_path=ssh_key, password=ssh_password, verbose=verbose)
    try:
        scanner.connect()
        
        # Detect OS version once per scan (if ScanResult provided)
        if scan_result is not None:
            os_name = scanner.detect_os_version()
            if os_name:
                scan_result._os_version = os_name
                
        output, _ = scanner.run_command("grep -i '^PermitRootLogin' /etc/ssh/sshd_config || echo 'no'", verbose=verbose)
        scanner.close()
        
        line = output.strip()
        if verbose:
            print(f"[DEBUG] HOST-SSH-001: PermitRootLogin='{line}'")
            
        if "yes" in line.lower():
            status = Status.FAIL
            details = f"PermitRootLogin enabled: '{line}'. → Edit /etc/ssh/sshd_config → PermitRootLogin no → sudo systemctl restart ssh"

        status = Status.PASS
        details = f"SSH root login disabled ✓ ({line})"

    except Exception as e:
        if verbose:
            print(f"[DEBUG] HOST-SSH-001: error {e}")
        status = Status.WARN
        details = str(e)
    
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )


def check_firewall(ssh_host: Optional[str] = None, ssh_user: Optional[str] = None, 
                  ssh_key: Optional[str] = None, ssh_password: Optional[str] = None, verbose: bool = False) -> CheckResult:
    """HOST-FW-001: Firewall active."""
    meta = _meta("HOST-FW-001")
     
    if not (ssh_host and ssh_user and (ssh_key or ssh_password)):
        if verbose:
            print("[DEBUG] HOST-FW-001: missing SSH params")
        status = Status.WARN
        details = "SSH credentials missing"
    
    # Use scanner instead of inline code
    scanner = SSHScanner(host=ssh_host, user=ssh_user, key_path=ssh_key, password=ssh_password, verbose=verbose)
    try:
        scanner.connect()
        output, _ = scanner.run_command("ufw status 2>/dev/null || iptables -L | wc -l", verbose=verbose)
        scanner.close()
        text = output.lower()
        
        if verbose:
            print(f"[DEBUG] HOST-FW-001: firewall output='{text[:50]}...'")
        
        if "inactive" in text:
            status = Status.FAIL
            details = "ufw inactive. → sudo ufw enable && sudo ufw allow 22/tcp && sudo ufw status"

        if "status: active" in text:
            status = Status.PASS
            details = "Firewall appears active"
        
        status = Status.WARN
        details = "Could not confirm active firewall (ufw not found). Review iptables/nftables rules."

    except Exception as e:
        if verbose:
            print(f"[DEBUG] HOST-FW-001: error {e}")
        status = Status.WARN
        details = str(e)

    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )    


def check_services(ssh_host: Optional[str] = None, ssh_user: Optional[str] = None, 
                  ssh_key: Optional[str] = None, ssh_password: Optional[str] = None, verbose: bool = False) -> CheckResult:
    """HOST-SVC-001: No unnecessary services running."""
    meta = _meta("HOST-SVC-001")
    
    if not (ssh_host and ssh_user and (ssh_key or ssh_password)):
        if verbose:
            print("[DEBUG] HOST-SVC-001: missing SSH params")
        status = Status.WARN
        details = "SSH credentials missing"
        
    
    # Use scanner instead of inline code
    scanner = SSHScanner(host=ssh_host, user=ssh_user, key_path=ssh_key, password=ssh_password, verbose=verbose)
    try:
        scanner.connect()
        output, _ = scanner.run_command("systemctl list-units --type=service --state=running | wc -l", verbose=verbose)
        scanner.close()
        service_count = int(output.strip())
        
        if verbose:
            print(f"[DEBUG] HOST-SVC-001: {service_count} services running")
        
        if service_count > 20:
            status = Status.WARN
            details = f"{service_count} services running. Review: systemctl list-units"

        status = Status.PASS
        details = f"{service_count} services: acceptable"

    except Exception as e:
        if verbose:
            print(f"[DEBUG] HOST-SVC-001: error {e}")
        status = Status.WARN
        details = str(e)
        
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )


def check_auto_updates(ssh_host: Optional[str] = None, ssh_user: Optional[str] = None, 
                      ssh_key: Optional[str] = None, ssh_password: Optional[str] = None, verbose: bool = False) -> CheckResult:
    """HOST-UPDATE-001: Auto-updates configured."""
    meta = _meta("HOST-UPDATE-001")
    
    if not (ssh_host and ssh_user and (ssh_key or ssh_password)):
        if verbose:
            print("[DEBUG] HOST-UPDATE-001: missing SSH params")
        status = Status.WARN
        details = "SSH credentials missing"
    
    # Use scanner instead of inline code
    scanner = SSHScanner(host=ssh_host, user=ssh_user, key_path=ssh_key, password=ssh_password, verbose=verbose)
    try:
        scanner.connect()
        output, _ = scanner.run_command("systemctl is-enabled --quiet unattended-upgrades 2>/dev/null && echo 'enabled' || echo 'disabled'", verbose=verbose)
        scanner.close()
        
        if verbose:
            print(f"[DEBUG] HOST-UPDATE-001: auto-updates='{output.strip()}'")
        
        if "enabled" in output:
            status = Status.PASS
            details = "Unattended  upgrades enabled ✓"

        status = Status.WARN
        details = "Install: apt install unattended-upgrades && systemctl enable"

    except Exception as e:
        if verbose:
            print(f"[DEBUG] HOST-UPDATE-001: error {e}")
        status = Status.WARN
        details = str(e)
        
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )


def check_permissions(ssh_host: Optional[str] = None, ssh_user: Optional[str] = None, 
                     ssh_key: Optional[str] = None, ssh_password: Optional[str] = None, verbose: bool = False) -> CheckResult:
    """HOST-PERM-001: Secure file permissions."""
    meta = _meta("HOST-PERM-001")
    
    if not (ssh_host and ssh_user and (ssh_key or ssh_password)):
        if verbose:
            print("[DEBUG] HOST-PERM-001: missing SSH params")
        status = Status.WARN
        details = "SSH credentials missing"

    
    # Use scanner instead of inline code
    scanner = SSHScanner(host=ssh_host, user=ssh_user, key_path=ssh_key, password=ssh_password, verbose=verbose)
    try:
        scanner.connect()
        output, _ = scanner.run_command("find /etc/ssh -perm -o+w 2>/dev/null | wc -l", verbose=verbose)
        scanner.close()
        world_writable = int(output.strip())
        
        if verbose:
            print(f"[DEBUG] HOST-PERM-001: {world_writable} world-writable SSH files")
        
        if world_writable > 0:
            status = Status.WARN
            details = f"{world_writable} world-writable files in /etc/ssh"

        status = Status.PASS
        details = "No insecure permissions detected"

    except Exception as e:
        if verbose:
            print(f"[DEBUG] HOST-PERM-001: error {e}")
        status = Status.WARN
        details = str(e)
        
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )


def check_logging(ssh_host: Optional[str] = None, ssh_user: Optional[str] = None, 
                 ssh_key: Optional[str] = None, ssh_password: Optional[str] = None, verbose: bool = False) -> CheckResult:
    """HOST-LOG-001: Logging configured."""
    meta = _meta("HOST-LOG-001")
    
    if not (ssh_host and ssh_user and (ssh_key or ssh_password)):
        if verbose:
            print("[DEBUG] HOST-LOG-001: missing SSH params")
        status = Status.WARN
        details = "SSH credentials missing"
    
    # Use scanner instead of inline code
    scanner = SSHScanner(host=ssh_host, user=ssh_user, key_path=ssh_key, password=ssh_password, verbose=verbose)
    try:
        scanner.connect()
        output, _ = scanner.run_command("systemctl is-active rsyslog 2>/dev/null && echo 'active' || echo 'inactive'", verbose=verbose)
        scanner.close()
        
        if verbose:
            print(f"[DEBUG] HOST-LOG-001: rsyslog='{output.strip()}'")
        
        if "active" in output:
            status = Status.PASS
            details = "rsyslog logging service active ✓"

        status = Status.WARN
        details = "Install logging: apt install rsyslog"

    except Exception as e:
        if verbose:
            print(f"[DEBUG] HOST-LOG-001: error {e}")
        status = Status.WARN
        details = str(e)

    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )


def check_gunicorn_user(ssh_host: Optional[str] = None, ssh_user: Optional[str] = None, 
                       ssh_key: Optional[str] = None, ssh_password: Optional[str] = None,
                       verbose: bool = False) -> CheckResult:
    """HOST-SVC-GUNICORN: Gunicorn runs as non-root user."""
    meta = _meta("HOST-SVC-GUNICORN")
    
    if not (ssh_host and ssh_user and (ssh_key or ssh_password)):
        if verbose:
            print("[DEBUG] HOST-SVC-GUNICORN: missing SSH params")
        status = Status.WARN
        details = "SSH credentials missing"

    
    # Use scanner instead of inline code
    scanner = SSHScanner(host=ssh_host, user=ssh_user, key_path=ssh_key, password=ssh_password, verbose=verbose)
    try:
        scanner.connect()
        output, _ = scanner.run_command("ps aux | grep '[g]unicorn' | awk '{print $1}' | head -1", verbose=verbose)
        scanner.close()
        
        gunicorn_user = output.strip()
        
        if verbose:
            print(f"[DEBUG] HOST-SVC-GUNICORN: user='{gunicorn_user}'")
            
        if not gunicorn_user:
            status = Status.WARN
            details = "Gunicorn process not found"

        if gunicorn_user in ("root", "0"):
            status = Status.FAIL
            details = f"Gunicorn runs as root (user: {gunicorn_user}). Use non-root systemd user."

        status = Status.PASS
        details = f"Gunicorn runs as non-root user '{gunicorn_user}' ✓"
    
    except Exception as e:
        if verbose:
            print(f"[DEBUG] HOST-SVC-GUNICORN: error {e}")
        status = Status.WARN
        details = str(e)
        
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )


def check_uwsgi_user(ssh_host: Optional[str] = None, ssh_user: Optional[str] = None, 
                    ssh_key: Optional[str] = None, ssh_password: Optional[str] = None,
                    verbose: bool = False) -> CheckResult:
    """HOST-SVC-UWSGI: uWSGI runs as non-root user."""
    meta = _meta("HOST-SVC-UWSGI")
    
    if not (ssh_host and ssh_user and (ssh_key or ssh_password)):
        if verbose:
            print("[DEBUG] HOST-SVC-UWSGI: missing SSH params")
        status = Status.WARN
        details = "SSH credentials missing"
    
    # Use scanner instead of inline code
    scanner = SSHScanner(host=ssh_host, user=ssh_user, key_path=ssh_key, password=ssh_password, verbose=verbose)
    try:
        scanner.connect()
        output, _ = scanner.run_command("ps aux | grep '[u]wsgi' | awk '{print $1}' | head -1", verbose=verbose)
        scanner.close()
        
        uwsgi_user = output.strip()
        
        if verbose:
            print(f"[DEBUG] HOST-SVC-UWSGI: user='{uwsgi_user}'")
            
        if not uwsgi_user:
            status = Status.PASS
            details = "uWSGI process not found (not in use)"
            
        if uwsgi_user in ("root", "0"):
            status = Status.FAIL
            details = f"uWSGI runs as root (user: {uwsgi_user}). Use non-root systemd user."

        status = Status.PASS
        details = f"uWSGI runs as non-root user '{uwsgi_user}' ✓"

    except Exception as e:
        if verbose:
            print(f"[DEBUG] HOST-SVC-UWSGI: error {e}")
        status = Status.WARN
        details = str(e)

    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )


def check_mysql_user(ssh_host: Optional[str] = None, ssh_user: Optional[str] = None, 
                    ssh_key: Optional[str] = None, ssh_password: Optional[str] = None,
                    verbose: bool = False) -> CheckResult:
    """HOST-SVC-MYSQL: MySQL runs as non-root user."""
    meta = _meta("HOST-SVC-MYSQL")
    
    if not (ssh_host and ssh_user and (ssh_key or ssh_password)):
        if verbose:
            print("[DEBUG] HOST-SVC-MYSQL: missing SSH params")
        status = Status.WARN
        details = "SSH credentials missing"
    
    # Use scanner instead of inline code
    scanner = SSHScanner(host=ssh_host, user=ssh_user, key_path=ssh_key, password=ssh_password, verbose=verbose)
    try:
        scanner.connect()
        output, _ = scanner.run_command("ps aux | grep '[m]ySQL' | awk '{print $1}' | head -1", verbose=verbose)
        scanner.close()
        
        mysql_user = output.strip()
        
        if verbose:
            print(f"[DEBUG] HOST-SVC-MYSQL: user='{mysql_user}'")
            
        if not mysql_user:
            status = Status.PASS
            details = "MySQL process not found (not in use)"

        if mysql_user in ("root", "0"):
            status = Status.FAIL
            details = f"MySQL runs as root (user: {mysql_user}). Should run as 'mysql' user."

        status = Status.PASS
        details = f"MySQL runs as non-root user '{mysql_user}' ✓"

    except Exception as e:
        if verbose:
            print(f"[DEBUG] HOST-SVC-MYSQL: error {e}")
        status = Status.WARN
        details = str(e)

    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )


def check_redis_user(ssh_host: Optional[str] = None, ssh_user: Optional[str] = None, 
                    ssh_key: Optional[str] = None, ssh_password: Optional[str] = None,
                    verbose: bool = False) -> CheckResult:
    """HOST-SVC-REDIS: Redis runs as non-root user."""
    meta = _meta("HOST-SVC-REDIS")
    
    if not (ssh_host and ssh_user and (ssh_key or ssh_password)):
        if verbose:
            print("[DEBUG] HOST-SVC-REDIS: missing SSH params")
        status = Status.WARN
        details = "SSH credentials missing"

    
    # Use scanner instead of inline code
    scanner = SSHScanner(host=ssh_host, user=ssh_user, key_path=ssh_key, password=ssh_password, verbose=verbose)
    try:
        scanner.connect()
        output, _ = scanner.run_command("ps aux | grep '[r]edis-server' | awk '{print $1}' | head -1", verbose=verbose)
        scanner.close()
        
        redis_user = output.strip()
        
        if verbose:
            print(f"[DEBUG] HOST-SVC-REDIS: user='{redis_user}'")
            
        if not redis_user:
            status = Status.PASS
            details = "Redis process not found (not in use)"

        if redis_user in ("root", "0"):
            status = Status.FAIL
            details = f"Redis runs as root (user: {redis_user}). Should run as 'redis' user."

        status = Status.PASS
        details = f"Redis runs as non-root user '{redis_user}' ✓"

    except Exception as e:
        if verbose:
            print(f"[DEBUG] HOST-SVC-REDIS: error {e}")
        status = Status.WARN
        details = str(e)
        
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )
