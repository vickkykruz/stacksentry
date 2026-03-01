"""
Command line argument parsing and validation.

Supports:
--target URL          Target web application
--mode full|quick     Scan scope
--ssh-key PATH        SSH private key for host checks
--docker-host URL     Docker daemon endpoint
--output PATH         PDF report path
--json PATH           JSON export path
"""


# Uses argparse for CLI interface
import json
import argparse
from types import SimpleNamespace

from sec_audit.config import get_layer_totals
from scanners.http_scanner import HttpScanner
from checks.app_checks import (
    check_debug_mode, 
    check_secure_cookies, 
    check_csrf_protection, 
    check_admin_endpoints, 
    check_rate_limiting, 
    check_password_policy
)
from checks.webserver_checks import (
    check_hsts_header, 
    check_directory_listing, 
    check_request_limits, 
    check_security_headers,
    check_server_tokens,
    check_tls_version,
    check_nginx_csp_config,
    check_nginx_hsts_config
)
from checks.container_checks import (
    check_health_checks,
    check_image_registry,
    check_minimal_ports,
    check_no_secrets,
    check_non_root_user,
    check_resource_limits,
    check_compose_resource_limits,
    check_dockerfile_user,
    check_dockerfile_healthcheck,
    check_dockerfile_best_practices,
    check_compose_ports
)
from checks.host_checks import (
    check_ssh_hardening,
    check_services,
    check_auto_updates,
    check_permissions,
    check_firewall,
    check_logging,
    check_gunicorn_user,
    check_mysql_user,
    check_redis_user,
    check_uwsgi_user
)
from sec_audit.results import CheckResult, ScanResult
from sec_audit.baseline import HARDENED_FLASK_BASELINE
from reporting.pdf_generator import generate_pdf


def vprint(verbose: bool, msg: str) -> None:
    """Print debug messages only when --verbose is enabled.

    Args:
        verbose (bool): True if required for logging otherwise False for don't log
        msg (str): Logging Message
    """
    if verbose:
        print(f"[DEBUG] {msg}")
        

def build_parser() -> argparse.ArgumentParser:
    """Build and configure the argument parser."""

    parser = argparse.ArgumentParser(
        prog="sec_audit",
        description="""
        🏛️  SECURITY AUDIT FRAMEWORK
        Automated Web Application Security Configuration Assessment
                
        Scans 24 configuration checks across 4 layers:
        • Web App (Flask/Django): debug mode, CSRF, cookies
        • Web Server (Nginx/Apache): HSTS, security headers, TLS
        • Container (Docker): non-root user, resource limits
        • Host (Linux): SSH hardening, firewall, services
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
        🚀 USAGE EXAMPLES:

            BASIC SCAN (HTTP only):
            python sec_audit.py --target https://example.com

            FULL STACK SCAN (HTTP + Docker + SSH):
            python sec_audit.py --target https://lms.example.com --mode full --output report.pdf

            DEVELOPMENT / LOCAL:
            python sec_audit.py --target http://localhost:5000 --json results.json

            CI/CD PIPELINE:
            python sec_audit.py --target $APP_URL --json /tmp/audit.json --mode quick

            📄 Output Formats:
            --output report.pdf    → Professional PDF remediation report
            --json results.json    → Structured JSON for automation
            (stdout)               → Console summary (default)
        """
    )
    
    # Core arguments
    parser.add_argument(
        "--target", "-t", 
        required=True,
        help="""
        Target web application URL.
        Examples: https://example.com, http://localhost:5000, https://staging.lms.internal
        """,
        metavar="URL"
    )
    
    parser.add_argument(
        "--mode", "-m",
        choices=["quick", "full"],
        default="quick",
        help="""
        Scan scope:
        • quick: HTTP checks only (app + webserver layers, ~30 seconds)
        • full:  HTTP + Docker + SSH checks (all 4 layers, ~2 minutes)
        """,
        metavar="MODE"
    )
    
    parser.add_argument(
       "--output", "-o",
        help="""
        Path to PDF remediation report.
        Example: --output security_audit.pdf
        """,
        metavar="PATH"
    )
    
    parser.add_argument(
        "--json", "-j",
        help="""
        Path to JSON results (CI/CD friendly).
        Example: --json /tmp/audit-results.json
        """,
        metavar="PATH"
    )
    
    # ==================== FUTURE ARGUMENTS (Day 3+) ====================
    docker_group = parser.add_argument_group("Docker scanning (full mode)")
    docker_group.add_argument(
        "--docker-host",
        help="Docker daemon endpoint (tcp://host:port or unix:///var/run/docker.sock)",
        metavar="DOCKER_URL"
    )
    
    ssh_group = parser.add_argument_group("SSH host scanning (full mode)") 
    ssh_group.add_argument("--ssh-host", help="SSH target host/IP")
    ssh_group.add_argument("--ssh-key", help="SSH private key path")
    ssh_group.add_argument("--ssh-password", help="SSH password (alternative to --ssh-key)")
    ssh_group.add_argument("--ssh-user", default="root", help="SSH username (default: root)")
    
    parser.add_argument("--nginx-conf", help="Path to nginx.conf for static analysis")
    parser.add_argument("--dockerfile", help="Path to Dockerfile for static analysis")
    parser.add_argument("--compose-file", help="Path to docker-compose.yml for static analysis")
    
    # ==================== DEBUG / DEV ====================
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output for debugging"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="Security Audit Framework v1.0.0 (MSc Research Prototype)",
        help="Show version information"
    )
    
    return parser


def run_from_args(args: SimpleNamespace) -> None:
    """Execute scan based on parsed arguments."""
    print(f"🏛️  [SEC-AUDIT v1.0.0] Starting scan...")
    print(f"  🎯 Target: {args.target}")
    print(f"  ⚙️  Mode: {args.mode}")
    print(f"  📄 Output: {args.output or 'stdout'}")
    print(f"  💾 JSON: {args.json or 'none'}")
    
    if args.verbose:
        print(f"  🔧 Verbose: enabled")
    print()
    
    # Day 2 Integration Test
    try:
        if args.verbose:
            vprint(args.verbose, "Importing get_layer_totals() from sec_audit.config...")
        totals = get_layer_totals()
        if args.verbose:
            vprint(args.verbose, f"Layer totals from config: {totals!r}")
        
        print("📊 Check Distribution:")
        for layer, count in totals.items():
            print(f"  {layer:10}: {count} checks")
        print()
    except ImportError:
        if args.verbose:
            vprint(args.verbose, f"Failed to import get_layer_totals: {e!r}")
        print("[INFO] config.py not yet implemented.")
    print()
    
    # ───────── CREATE SCANRESULT FIRST ─────────
    scan_result = ScanResult(target=args.target, mode=args.mode, checks=[])
    
    # ───────── CREATE SCANNER ─────────
    if args.verbose:
        vprint(args.verbose, f"Creating HttpScanner for target {args.target!r}")
    http_scanner = HttpScanner(args.target, timeout=10, scan_result=scan_result)
    results: list[CheckResult] = []
    
    # ───────── CREATE SCANRESULT ─────────
    scan_result = ScanResult( target=args.target, mode=args.mode, checks=results)
    
    # ───────── WEB APP LAYER (6 checks) ─────────
    if args.mode in ["quick", "full"]:
        if args.verbose:
            vprint(args.verbose, "Starting Web App Layer checks...")
        print("🔎 Running Web Application checks...")
        results.extend([
            check_debug_mode(http_scanner, verbose=args.verbose),
            check_secure_cookies(http_scanner, verbose=args.verbose),
            check_csrf_protection(http_scanner, verbose=args.verbose),
            check_admin_endpoints(http_scanner, verbose=args.verbose),
            check_rate_limiting(http_scanner, verbose=args.verbose),
            check_password_policy(http_scanner, verbose=args.verbose),
        ])
    
    # ───────── WEB SERVER LAYER (6 checks) ─────────  
    if args.mode in ["quick", "full"]:
        if args.verbose:
            vprint(args.verbose, "Starting Web Server checks...")
        print("🔎 Running Web Server checks...")
        results.extend([
            check_hsts_header(http_scanner, verbose=args.verbose),
            check_security_headers(http_scanner, verbose=args.verbose),
            check_tls_version(http_scanner, verbose=args.verbose),
            check_server_tokens(http_scanner, verbose=args.verbose),
            check_directory_listing(http_scanner, verbose=args.verbose),
            check_request_limits(http_scanner, verbose=args.verbose),
        ])
    
    # ───────── CONTAINER LAYER (6 checks) ─────────
    if args.mode == "full":
        if args.verbose:
            vprint(args.verbose, "Starting Container checks checks...")
        print("⏳ Container checks pending Docker connection...")
        results.extend([
            check_non_root_user(args.docker_host, verbose=args.verbose),
            check_minimal_ports(args.docker_host, verbose=args.verbose),
            check_resource_limits(args.docker_host, verbose=args.verbose),
            check_health_checks(args.docker_host, verbose=args.verbose),
            check_image_registry(args.docker_host, verbose=args.verbose),
            check_no_secrets(args.docker_host, verbose=args.verbose),
        ])
    
    # ───────── HOST LAYER (6 checks) ─────────
    if args.mode == "full":
        if args.verbose:
            vprint(args.verbose, "Starting HOST checks checks...")
        print("⏳ Host checks pending SSH connection...")
        results.extend([
            check_ssh_hardening(args.ssh_host, args.ssh_user, args.ssh_key, args.ssh_password, scan_result=scan_result, verbose=args.verbose),
            check_firewall(args.ssh_host, args.ssh_user, args.ssh_key, args.ssh_password, verbose=args.verbose),
            check_services(args.ssh_host, args.ssh_user, args.ssh_key, args.ssh_password, verbose=args.verbose),
            check_auto_updates(args.ssh_host, args.ssh_user, args.ssh_key, args.ssh_password, verbose=args.verbose),
            check_permissions(args.ssh_host, args.ssh_user, args.ssh_key, args.ssh_password, verbose=args.verbose),
            check_logging(args.ssh_host, args.ssh_user, args.ssh_key, args.ssh_password, verbose=args.verbose),
            check_gunicorn_user(args.ssh_host, args.ssh_user, args.ssh_key, args.ssh_password, verbose=args.verbose),
            check_uwsgi_user(args.ssh_host, args.ssh_user, args.ssh_key, args.ssh_password, verbose=args.verbose),
            check_mysql_user(args.ssh_host, args.ssh_user, args.ssh_key, args.ssh_password, verbose=args.verbose),
            check_redis_user(args.ssh_host, args.ssh_user, args.ssh_key, args.ssh_password, verbose=args.verbose)
        ])
        
    #  ───────── ADDITION CHECKS ─────────
    # Webserver layer extra config check
    if args.nginx_conf:
        if args.verbose:
            vprint(args.verbose, "Starting Webserver layer extra config check...")
        results.append(check_nginx_hsts_config(args.nginx_conf, verbose=args.verbose))
        results.append(check_nginx_csp_config(args.nginx_conf, verbose=args.verbose))
        
        
    # Container layer extra config checks
    if args.dockerfile:
        if args.verbose:
            vprint(args.verbose, "Starting Container layer extra config checks...")
        results.append(check_dockerfile_user(args.dockerfile, verbose=args.verbose))
        results.append(check_dockerfile_healthcheck(args.dockerfile, verbose=args.verbose))
        results.append(check_dockerfile_best_practices(args.dockerfile, verbose=args.verbose))
        
    if args.compose_file:
        if args.verbose:
            vprint(args.verbose, "Starting compose_file config checks...")
        results.append(check_compose_resource_limits(args.compose_file, verbose=args.verbose))
        results.append(check_compose_ports(args.compose_file, verbose=args.verbose))

    
    # ───────── SCORING ─────────
    print("📊 OVERALL SCORE:")
    print(f"  Grade: {scan_result.grade} ({scan_result.score_percentage}%)")
    print(f"  Attack Paths: {scan_result.attack_path_count}")
    print(f"  Max Risk Level: {scan_result.highest_attack_risk}")
    summary_data = scan_result.summary()
    passed_count = summary_data['status_breakdown'].get('PASS', 0)
    print(f"  Status: {passed_count}/{scan_result.total_checks} passed")
    print(f"  High risk issues: {summary_data['high_risk_issues']}")
    print()
    
    drift = scan_result.compare_to_baseline(HARDENED_FLASK_BASELINE)
    print("🔁 CONFIGURATION DRIFT (vs Hardened Flask LMS):")
    print(f"  Grade: {drift['grade_delta']}")
    print(f"  Pass delta: {drift['pass_delta']} checks vs baseline")
    print(f"  Improved checks: {len(drift['improved_checks'])}")
    print(f"  Regressed checks: {len(drift['regressed_checks'])}")
    print()
    
    # ───────── JSON EXPORT ─────────
    if args.json:
        try:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(scan_result.to_dict(), f, indent=2)
            print(f"💾 JSON results written to: {args.json}")
        except Exception as e:
            print(f"❌ Failed to write JSON: {e!r}")
    
    # ───────── PDF EXPORT ─────────
    if args.output:
        try:
            generate_pdf(scan_result, args.output)
            print(f"📄 PDF report generated: {args.output}")
        except Exception as e:
            print(f"❌ Failed to generate PDF: {e!r}")
    
    print("✅ FULL 24-CHECK SCAN COMPLETE!")