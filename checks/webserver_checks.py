"""
Web Server Layer Checks - Nginx/Apache (6 checks)
 
1. HSTS header present and strong
2. Security headers (CSP, XFO, XCTO)
3. TLS 1.2+ with strong ciphers
4. No server version disclosure
5. Directory listing disabled
6. Request size limits set
"""
 
 
from typing import Optional
 
from sec_audit.results import CheckResult, Status, Severity
from scanners.http_scanner import HttpScanner
from scanners.nginx_scanner import NginxConfigScanner
from sec_audit.config import CHECKS
 
 
def _meta(check_id: str):
    for c in CHECKS:
        if c["id"] == check_id:
            return c
    raise KeyError(f"Unknown check id: {check_id}")
 
 
def check_hsts_header(http_scanner: HttpScanner, verbose: bool = False) -> CheckResult:
    """
    WS-HSTS-001: HSTS header enabled.
 
    Logic:
    - Send GET (or HEAD) to root.
    - Look for Strict-Transport-Security header.
    - Parse max-age directive if present; expect >= 31536000 (1 year). [web:249][web:252]
    """
    meta = _meta("WS-HSTS-001")
    try:
        if verbose:
            print("[DEBUG] WS-HSTS-001: fetching root URL to inspect HSTS...")
        resp = http_scanner.get_root()
        sts = resp.headers.get("Strict-Transport-Security")
        
        if verbose:
            print(f"[DEBUG] WS-HSTS-001: Strict-Transport-Security={sts!r}")    
 
        if not sts:
            status = Status.FAIL
            details = "Strict-Transport-Security header is missing."
        else:
            sts_lower = sts.lower()
            max_age_value = None
            for part in sts_lower.split(";"):
                part = part.strip()
                if part.startswith("max-age"):
                    try:
                        _, value = part.split("=")
                        max_age_value = int(value)
                    except Exception:
                        max_age_value = None
 
            if max_age_value is not None and max_age_value >= 31536000:
                status = Status.PASS
                details = f"HSTS present with strong max-age={max_age_value}."
            else:
                status = Status.WARN
                details = f"HSTS present but max-age appears weak or unparseable: {sts!r}"
    except Exception as e:
        if verbose:
            print(f"[DEBUG] WS-HSTS-001: exception {e!r}")
        status = Status.ERROR
        details = f"HTTP error while checking HSTS header: {e!r}"
 
    return CheckResult(
        id=meta["id"],
        layer=meta["layer"],
        name=meta["name"],
        status=status,
        severity=Severity[meta["severity"]],
        details=details,
    )
    
    
def check_security_headers(http_scanner: HttpScanner, verbose: bool = False) -> CheckResult:
    """WS-SEC-001: Security headers present."""
    meta = _meta("WS-SEC-001")
    try:
        if verbose:
            print("[DEBUG] WS-SEC-001: fetching root URL to inspect security headers...")
        resp = http_scanner.get_root()
        required_headers = [
            "X-Frame-Options",
            "X-Content-Type-Options", 
            "Content-Security-Policy",
            "Referrer-Policy"
        ]
        present = [h for h in required_headers if h in resp.headers]
        
        if verbose:
            print(f"[DEBUG] WS-SEC-001: present={present}, all_headers={list(resp.headers.keys())}")
            
        count = len(present)
        status = Status.PASS if count >= 2 else Status.FAIL
        details = f"{count}/4 security headers present: {present}"
        
    except Exception as e:
        if verbose:
            print(f"[DEBUG] WS-SEC-001: exception {e!r}")
        status = Status.ERROR
        details = f"HTTP error: {e}"
    
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )
    
    
def check_tls_version(http_scanner: HttpScanner, verbose: bool = False) -> CheckResult:
    """WS-TLS-001: TLS 1.2+ with strong ciphers."""
    meta = _meta("WS-TLS-001")
    try:
        if verbose:
            print("[DEBUG] WS-TLS-001: fetching root URL to inspect TLS cipher...")
        # Simple heuristic: modern sites use TLS 1.2+
        resp = http_scanner.get_root()
        cipher_info = getattr(resp.raw, "connection", None)
        # Depending on HTTP adapter this may differ; try a safe introspection:
        cipher_desc = None
        if cipher_info and hasattr(cipher_info, "sock") and hasattr(cipher_info.sock, "cipher"):
            try:
                cipher_desc = cipher_info.sock.cipher()
            except Exception:
                cipher_desc = None
                
        if verbose:
            print(f"[DEBUG] WS-TLS-001: cipher_desc={cipher_desc!r}")
        
        # Check if TLS 1.3 preferred cipher (heuristic)
        modern_markers = ['ECDHE', 'AESGCM', 'CHACHA20']
        if cipher_desc and any(m in str(cipher_desc) for m in modern_markers):
            status = Status.PASS
            details = f"TLS cipher appears modern: {cipher_desc}"
        else:
            status = Status.WARN
            details = f"TLS details unavailable or cipher does not look clearly modern (heuristic)."
            
    except Exception as e:
        if verbose:
            print(f"[DEBUG] WS-TLS-001: exception {e!r}")
        status = Status.ERROR
        details = f"TLS check failed: {e}"
    
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )
    
    
def check_server_tokens(http_scanner: HttpScanner, verbose: bool = False) -> CheckResult:
    """WS-SRV-001: No server version disclosure."""
    meta = _meta("WS-SRV-001")
    try:
        if verbose:
            print("[DEBUG] WS-SRV-001: fetching root URL to inspect Server header...")
        resp = http_scanner.get_root()
        server_header = resp.headers.get("Server", "") or ""
        sh_lower = server_header.lower()
        
        if verbose:
            print(f"[DEBUG] WS-SRV-001: Server={server_header!r}")
        
        details = f"Server: {server_header}. "
        if "nginx" in sh_lower or "apache" in sh_lower:
            version_match = any(c.isdigit() for c in server_header)
            status = Status.FAIL if version_match else Status.WARN
            details += f"Version {'exposed' if version_match else 'hidden'}."
        else:
            status = Status.PASS
            details += "No common server fingerprint detected."
            
    except Exception as e:
        if verbose:
            print(f"[DEBUG] WS-SRV-001: exception {e!r}")
        status = Status.ERROR
        details = f"HTTP error while checking server banner: {e}"
    
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )
    
    
def check_directory_listing(http_scanner: HttpScanner, verbose: bool = False) -> CheckResult:
    """WS-DIR-001: Directory listing disabled.
 
    Content-based detection — a 200 status alone never triggers FAIL.
    Aborts path scanning early after 2 consecutive timeouts.
    """
    meta = _meta("WS-DIR-001")
    test_paths = ["/", "/static/", "/uploads/", "/images/", "/files/", "/media/"]
 
    DIR_SIGNATURES = [
        "index of /",
        "directory listing for",
        "<title>/</title>",
        "parent directory</a>",
        "[to parent directory]",
    ]
 
    try:
        import requests as _req
        exposed_dirs       = []
        consecutive_timeouts = 0
 
        for path in test_paths:
            if consecutive_timeouts >= 2:
                if verbose:
                    print(f"[DEBUG] WS-DIR-001: 2 consecutive timeouts — server blocking, stopping early")
                break
 
            url = f"{getattr(http_scanner, 'scan_root', http_scanner.base_url).rstrip('/')}{path}"
            try:
                if verbose:
                    print(f"[DEBUG] WS-DIR-001: GET {url}")
                resp = http_scanner.session.get(url, timeout=3)
                consecutive_timeouts = 0
                body_lower = resp.text.lower()
                if verbose:
                    print(f"[DEBUG] WS-DIR-001: {path} status={resp.status_code}, body_len={len(resp.text)}")
 
                if resp.status_code == 200:
                    matched = [sig for sig in DIR_SIGNATURES if sig in body_lower]
                    if matched:
                        exposed_dirs.append(path)
                        if verbose:
                            print(f"[DEBUG] WS-DIR-001: {path} confirmed: {matched}")
            except (_req.exceptions.Timeout,
                    _req.exceptions.ConnectTimeout,
                    _req.exceptions.ReadTimeout) as e:
                consecutive_timeouts += 1
                if verbose:
                    print(f"[DEBUG] WS-DIR-001: timeout {consecutive_timeouts}/2 on {path}")
                continue
            except Exception as e:
                if verbose:
                    print(f"[DEBUG] WS-DIR-001: exception on {path}: {e!r}")
                continue
 
        status  = Status.FAIL if exposed_dirs else Status.PASS
        details = (f"Directory listing exposed: {', '.join(exposed_dirs)}"
                   if exposed_dirs else "Directory listing disabled on tested paths.")
 
    except Exception as e:
        if verbose:
            print(f"[DEBUG] WS-DIR-001: exception {e!r}")
        status  = Status.ERROR
        details = f"Directory listing check failed: {e!r}"
 
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )
 
 
def check_request_limits(http_scanner: HttpScanner, verbose: bool = False) -> CheckResult:
    """WS-LIMIT-001: Request size limits."""
    meta = _meta("WS-LIMIT-001")
    # Heuristic: large POST might trigger limits, but simple test
    try:
        if verbose:
            print("[DEBUG] WS-LIMIT-001: fetching root URL to collect Content-Length...")
        resp = http_scanner.get_root()
        content_length = resp.headers.get("Content-Length", "0")
        
        if verbose:
            print(f"[DEBUG] WS-LIMIT-001: Content-Length={content_length!r}")
        
        status = Status.WARN
        details = f"No direct request limit test available. Content-Length: {content_length}"
    except Exception as e:
        if verbose:
            print(f"[DEBUG] WS-LIMIT-001: exception {e!r}")
        status = Status.ERROR
        details = f"Request limit check failed: {e!r}"
    
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )
    
    
def check_nginx_hsts_config(path: Optional[str] = None, verbose: bool = False) -> CheckResult:
    """
    WS-CONF-HSTS: HSTS configured in nginx.conf.
 
    Guard: returns WARN immediately (without touching NginxConfigScanner)
    when no path is provided. This allows the check to be included in
    every scan safely, even when --nginx-conf is not passed.
    """
    meta = _meta("WS-CONF-HSTS")
 
    # Guard — no path provided, return immediately without parsing
    if not path:
        if verbose:
            print("[DEBUG] WS-CONF-HSTS: nginx.conf path not provided — skipping static check")
        return CheckResult(
            id=meta["id"], layer=meta["layer"], name=meta["name"],
            status=Status.WARN, severity=Severity[meta["severity"]],
            details="nginx.conf path not provided; pass --nginx-conf to enable static HSTS verification.",
        )
 
    try:
        scanner = NginxConfigScanner(path, verbose)
        scanner.load()
        has_hsts = scanner.has_security_header("Strict-Transport-Security")
 
        if verbose:
            print(f"[DEBUG] WS-CONF-HSTS: has_hsts={has_hsts}")
 
        if has_hsts:
            status  = Status.PASS
            details = "Strict-Transport-Security header is configured in nginx.conf."
        else:
            status  = Status.WARN
            details = "Strict-Transport-Security not found in nginx.conf; add HSTS at server or http level."
 
    except Exception as e:
        if verbose:
            print(f"[DEBUG] WS-CONF-HSTS: exception {e!r}")
        status  = Status.WARN
        details = f"Error parsing nginx.conf: {e}"
 
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )
        
 
def check_nginx_csp_config(path: Optional[str] = None, verbose: bool = False) -> CheckResult:
    """
    WS-CONF-CSP: Content-Security-Policy configured in nginx.conf.
 
    Guard: returns WARN immediately (without touching NginxConfigScanner)
    when no path is provided.
    """
    meta = _meta("WS-CONF-CSP")
 
    # Guard — no path provided, return immediately without parsing
    if not path:
        if verbose:
            print("[DEBUG] WS-CONF-CSP: nginx.conf path not provided — skipping static check")
        return CheckResult(
            id=meta["id"], layer=meta["layer"], name=meta["name"],
            status=Status.WARN, severity=Severity[meta["severity"]],
            details="nginx.conf path not provided; pass --nginx-conf to enable static CSP verification.",
        )
 
    try:
        scanner = NginxConfigScanner(path, verbose)
        if scanner.has_csp():
            status  = Status.PASS
            details = "Content-Security-Policy is configured in nginx.conf."
        else:
            status  = Status.WARN
            details = ("Content-Security-Policy not found in nginx.conf; "
                       "define a CSP header for stricter frontend security.")
 
    except Exception as e:
        if verbose:
            print(f"[DEBUG] WS-CONF-CSP: exception {e!r}")
        status  = Status.WARN
        details = f"Error parsing nginx.conf: {e}"
 
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )
  