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
import time
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
from storage.history import ScanHistory
from storage.drift import DriftEngine
 
 
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
    
    # ==================== POST-PROCESSING / PLANNING ====================
    parser.add_argument(
        "--plan",
        action="store_true",
        help="Print a prioritised hardening plan (Day 1 / Day 7 / Day 30) to the console."
    )
 
    parser.add_argument(
        "--simulate",
        help=(
            "Comma-separated list of check IDs to simulate as fixed, e.g. "
            "APP-DEBUG-001,WS-HSTS-001. Shows simulated grade and score."
        ),
        metavar="CHECK_IDS"
    )
    
    parser.add_argument(
        "--profile",
        choices=["student", "devops", "pentester", "cto", "generic"],
        default="generic",
        help="Generate contextual OWASP narrative for your role (default: generic)"
    )
 
    # ==================== HISTORY / DRIFT ====================
    parser.add_argument(
        "--compare-last",
        action="store_true",
        help=(
            "After scanning, compare results against the previous scan for this "
            "target and print a drift report showing what regressed or improved."
        ),
    )
 
    parser.add_argument(
        "--history",
        action="store_true",
        help=(
            "Print the full scan history timeline for --target and exit. "
            "Does not run a new scan."
        ),
    )
 
    parser.add_argument(
        "--no-save",
        action="store_true",
        help=(
            "Do not save this scan to the local history database. "
            "Useful for CI/CD pipelines or one-off checks."
        ),
    )
 
    parser.add_argument(
        "--db-path",
        default=None,
        metavar="PATH",
        help=(
            "Path to a custom StackSentry history database. "
            "Defaults to ~/.stacksentry/history.db"
        ),
    )
 
    return parser
 
 
def _print_history(target: str, db_path: str = None) -> None:
    """Print the scan history timeline for a target and exit."""
    history = ScanHistory(db_path)
    rows = history.all_for(target, limit=50)
 
    if not rows:
        print(f"  No scan history found for: {target}")
        print(f"  Run a scan first: stacksentry --target {target}")
        return
 
    count = history.count(target)
    print(f"\n📅  SCAN HISTORY — {target}")
    print(f"    {count} scan(s) recorded in {history.db_path}")
    print()
    print(f"  {'Date/Time':<26} {'Grade':<7} {'Score':<8} {'Passed':<8} {'Failed':<8} {'Mode'}")
    print(f"  {'-'*24:<26} {'-'*5:<7} {'-'*6:<8} {'-'*6:<8} {'-'*6:<8} {'-'*5}")
 
    for row in rows:
        scanned_at = row["scanned_at"][:19].replace("T", " ")  # trim to readable datetime
        grade      = row["grade"]
        score      = f"{row['score_percentage']:.1f}%"
        passed     = str(row["passed_checks"])
        failed     = str(row["failed_checks"])
        mode       = row["mode"]
        print(f"  {scanned_at:<26} {grade:<7} {score:<8} {passed:<8} {failed:<8} {mode}")
 
    print()
 
 
def _print_drift_report(drift_report, verbose: bool = False) -> None:
    """Print a formatted drift report to the console."""
    from storage.drift import DriftReport
 
    r = drift_report
 
    if r.is_first_scan:
        print("📊  POSTURE HISTORY: First scan recorded — no baseline to compare against.")
        print(f"    Future scans will be compared against today's results.")
        print()
        return
 
    # Header
    trend_icon = {"improving": "📈", "regressing": "📉", "stable": "➡️"}.get(r.overall_trend, "➡️")
    print(f"\n{trend_icon}  POSTURE DRIFT — since last scan {r.elapsed_days:.0f} day(s) ago")
    print(f"    {r.summary_line}")
    print()
 
    # Grade / score comparison
    direction_symbol = {"improved": "↑", "regressed": "↓", "stable": "→"}.get(r.grade_direction, "→")
    delta_sign = "+" if r.score_delta >= 0 else ""
    print(f"  Grade:  {r.grade_then}  {direction_symbol}  {r.grade_now}   "
          f"({delta_sign}{r.score_delta:.1f}% score change)")
    print()
 
    # Regressions — most important, shown first
    if r.regressions:
        print(f"  ❌ Regressed ({len(r.regressions)} check(s) — was PASS, now FAIL/WARN):")
        for check_id in r.regressions:
            print(f"     • {check_id}")
        print()
 
    # New failures
    if r.new_failures:
        print(f"  🆕 New failures ({len(r.new_failures)} check(s)):")
        for check_id in r.new_failures:
            print(f"     • {check_id}")
        print()
 
    # Improvements
    if r.improvements:
        print(f"  ✅ Improved ({len(r.improvements)} check(s) — now PASS):")
        for check_id in r.improvements:
            print(f"     • {check_id}")
        print()
 
    # Stable failures — persistent issues that need attention
    if r.stable_failures:
        print(f"  ⚠️  Persistent failures ({len(r.stable_failures)} check(s) — still failing):")
        for check_id in r.stable_failures[:5]:  # cap at 5 to keep output readable
            print(f"     • {check_id}")
        if len(r.stable_failures) > 5:
            print(f"     ... and {len(r.stable_failures) - 5} more. See PDF report for full list.")
        print()
 
    if not r.regressions and not r.new_failures and not r.improvements:
        print("  No changes detected since last scan.")
        print()
 
 
def run_from_args(args: SimpleNamespace) -> None:
    """Execute scan based on parsed arguments."""
    start = time.time()
 
    # ───────── --history: show timeline and exit (no scan needed) ─────────
    if getattr(args, "history", False):
        _print_history(args.target, getattr(args, "db_path", None))
        return
 
    print(f"🏛️  [SEC-AUDIT v1.0.0] Starting scan...")
    print(f"  🎯 Target: {args.target}")
    print(f"  ⚙️  Mode: {args.mode}")
    print(f"  📄 Output: {args.output or 'stdout'}")
    print(f"  💾 JSON: {args.json or 'none'}")
    
    if args.verbose:
        print(f"  🔧 Verbose: enabled")
    print()
    
    
    # Layer totals from config
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
    results: list[CheckResult] = []
    scan_result = ScanResult(target=args.target, mode=args.mode, checks=results)
    
    # ───────── CREATE SCANNER ─────────
    if args.verbose:
        vprint(args.verbose, f"Creating HttpScanner for target {args.target!r}")
    http_scanner = HttpScanner(args.target, timeout=10, scan_result=scan_result)
    
    # ───────── MODE FLAGS ─────────
    quick_mode = args.mode == "quick"
    full_mode = args.mode == "full"
    
    # ───────── WEB APP LAYER (always in quick/full) ─────────
    if quick_mode or full_mode:
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
    
    # ───────── WEB SERVER LAYER (always in quick/full) ─────────
    if quick_mode or full_mode:
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
    
    # ───────── CONTAINER LAYER: RUNTIME (only full + docker_host) ─────────
    if full_mode and args.docker_host:
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
    elif full_mode and not args.docker_host and args.verbose:
        vprint(args.verbose, "[INFO] Skipping container runtime checks (no --docker-host provided)")
    
    # ───────── HOST LAYER: SSH (only full + SSH params) ─────────
    have_ssh = bool(args.ssh_host and args.ssh_user and (args.ssh_key or args.ssh_password))
    
    if full_mode and have_ssh:
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
    elif full_mode and not have_ssh and args.verbose:
        vprint(args.verbose, "[INFO] Skipping host layer checks (SSH parameters missing)")
        
    # ───────── ADDITIONAL CONFIG CHECKS (independent of mode) ─────────
    # Webserver extra config (nginx.conf)
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
        
    # Container extra config: docker-compose.yml
    if args.compose_file:
        if args.verbose:
            vprint(args.verbose, "Starting compose_file config checks...")
        results.append(check_compose_resource_limits(args.compose_file, verbose=args.verbose))
        results.append(check_compose_ports(args.compose_file, verbose=args.verbose))
 
    # Attach final results
    scan_result.checks = results
 
    # ───────── AUTO-SAVE TO HISTORY ─────────
    history = ScanHistory(getattr(args, "db_path", None))
    drift_report = None
 
    if not getattr(args, "no_save", False):
        try:
            history.save(scan_result)
            if args.verbose:
                vprint(args.verbose, f"Scan saved to history: {history.db_path}")
        except Exception as e:
            if args.verbose:
                vprint(args.verbose, f"Could not save to history: {e!r}")
 
    # ───────── DRIFT COMPARISON ─────────
    # Always compare against previous scan (shown only when --compare-last)
    # so the data is available for the PDF report regardless of CLI flags.
    try:
        engine = DriftEngine()
        baseline = history.previous(scan_result.target, scan_result.generated_at)
        if baseline:
            drift_report = engine.compare(baseline, scan_result)
        else:
            drift_report = engine.first_scan_report(scan_result)
    except Exception as e:
        if args.verbose:
            vprint(args.verbose, f"Drift comparison failed: {e!r}")
        drift_report = None
 
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
 
    # ───────── POSTURE DRIFT (vs previous scan) ─────────
    if getattr(args, "compare_last", False) and drift_report:
        _print_drift_report(drift_report, verbose=args.verbose)
    elif drift_report and not drift_report.is_first_scan and args.verbose:
        vprint(args.verbose, f"Drift: {drift_report.summary_line}")
    
    # ───────── HARDENING PLAN (optional) ─────────
    if args.plan:
        if args.verbose:
            vprint(args.verbose, "Building prioritised hardening plan from scan results...")
 
        plan_items = scan_result.hardening_plan()
        if not plan_items:
            print("🧩 PRIORITISED HARDENING PLAN: no outstanding issues.")
        else:
            print("🧩 PRIORITISED HARDENING PLAN (top 5 Day 1 fixes):")
            day1_items = [i for i in plan_items if i.get("bucket") == "DAY_1"][:5]
            for item in day1_items:
                if args.verbose:
                    vprint(
                        args.verbose,
                        f"Selected {item['id']} for Day 1 (score={item['priority_score']})"
                    )
                print(
                    f"  - {item['id']} ({item['layer']}, {item['severity']}, "
                    f"score={item['priority_score']})"
                )
            print("  (Full plan available in PDF/JSON report.)")
        print()
        
    # ───────── WHAT-IF SIMULATION (optional) ─────────
    if args.simulate:
        fix_ids = [c.strip() for c in args.simulate.split(",") if c.strip()]
        if args.verbose:
            vprint(args.verbose, f"Running what-if simulation for fixes: {fix_ids!r}")
 
        sim = scan_result.simulate_with_fixes(fix_ids)
 
        print("🧪 WHAT-IF SIMULATION SUMMARY:")
        print(f"  Fixing: {', '.join(fix_ids)}")
        print(
            f"  Grade: {scan_result.grade.value} → {sim['simulated_grade']} "
            f"({scan_result.score_percentage}% → {sim['simulated_score_percentage']}%)"
        )
        print(
            f"  Attack paths: {scan_result.attack_path_count} → "
            f"{sim['simulated_attack_path_count']}"
        )
        print("  (Details available in PDF/JSON report.)")
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
            generate_pdf(scan_result, args.output, profile=args.profile, drift_report=drift_report)
            print(f"📄 PDF report generated: {args.output}")
        except Exception as e:
            print(f"❌ Failed to generate PDF: {e!r}")
    end = time.time()
    duration = end - start
    scan_count = history.count(args.target)
    print(f"⏱  Scan duration: {duration:.1f} seconds  "
          f"(scan #{scan_count} for this target — history at {history.db_path})")