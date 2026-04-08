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
 
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
 
 
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
from sec_audit.telemetry import (
    prompt_first_run, handle_telemetry_flag,
    track_scan_started, track_patch_generated,
    track_fix_applied, track_report_generated,
)
from storage.history import ScanHistory
from remediation.generator import PatchGenerator
from remediation.auto_fix import AutoFixer, AUTOMATABLE_CHECKS
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
            stacksentry --target https://example.com
 
            FULL STACK SCAN (all 4 layers):
            stacksentry --target https://example.com --mode full \
              --ssh-host 1.2.3.4 --ssh-user root --ssh-password yourpass \
              --output report.pdf
 
            WITH AI-POWERED FIX SCRIPTS:
            stacksentry --target https://example.com --mode full --patch \
              --ssh-host 1.2.3.4 --ssh-password yourpass
 
            AUTO-FIX (applies fixes directly on server):
            stacksentry --target https://example.com --mode full --fix \
              --ssh-host 1.2.3.4 --ssh-password yourpass \
              --dockerfile ./Dockerfile --compose-file ./docker-compose.yml
 
            TRACK POSTURE OVER TIME:
            stacksentry --target https://example.com --compare-last
            stacksentry --target https://example.com --history
 
            WHAT-IF SIMULATION:
            stacksentry --target https://example.com \
              --simulate APP-DEBUG-001,WS-HSTS-001,HOST-SSH-001
 
            CI/CD PIPELINE:
            stacksentry --target $APP_URL --json /tmp/audit.json --mode quick --no-save
 
            STATIC FILE ANALYSIS (no live server needed):
            stacksentry --target https://example.com \
              --nginx-conf /etc/nginx/nginx.conf \
              --dockerfile ./Dockerfile \
              --compose-file ./docker-compose.yml
 
            DISABLE AI / USE TEMPLATES ONLY:
            stacksentry --target https://example.com --patch --no-llm
 
            MANAGE TELEMETRY:
            stacksentry --telemetry status
            stacksentry --telemetry off
 
            📄 Output Formats:
            --output report.pdf    → Professional PDF report (OWASP, hardening plan)
            --json results.json    → Structured JSON for automation/CI
            --patch                → AI fix scripts in patches/{target}_{date}_scan{N}/
            (stdout)               → Console summary with grade (default)
        """
    )
    
    # Core arguments
    parser.add_argument(
        "--target", "-t", 
        required=False,
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
 
    parser.add_argument(
        "--telemetry",
        metavar="on|off|status",
        help="Enable/disable anonymous usage telemetry (on | off | status).",
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
 
    # ==================== REMEDIATION ====================
    parser.add_argument(
        "--patch",
        action="store_true",
        help=(
            "Generate ready-to-apply patch files for all failed/warned checks. "
            "Written to a patches/ folder in the current directory."
        ),
    )
 
    parser.add_argument(
        "--patch-dir",
        default="patches",
        metavar="DIR",
        help="Directory to write patch files (default: patches/)",
    )
 
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Disable LLM patch generation and use static templates only.",
    )
 
    parser.add_argument(
        "--fix",
        action="store_true",
        help=(
            "Automatically apply fixes for HOST and WS layer checks via SSH. "
            "APP and CONT layer checks generate guides only. "
            "Requires --ssh-host to be set."
        ),
    )
 
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Preview every command that WOULD run with --fix, without "
            "executing anything. Review the plan then run without --dry-run "
            "to apply. Nothing is changed on the server or files."
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
 
    # ───────── TELEMETRY FLAG ─────────
    if getattr(args, "telemetry", None):
        handle_telemetry_flag(args.telemetry)
        return
 
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
    track_scan_started(args.mode)
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
    print(f"  Grade: {scan_result.grade.value} ({scan_result.score_percentage}%)")
    print(f"  Attack Paths: {scan_result.attack_path_count}")
    print(f"  Max Risk Level: {scan_result.highest_attack_risk}")
    summary_data = scan_result.summary()
    passed_count = summary_data['status_breakdown'].get('PASS', 0)
    print(f"  Status: {passed_count}/{scan_result.total_checks} passed")
    print(f"  High risk issues: {summary_data['high_risk_issues']}")
    print()
    
    drift = scan_result.compare_to_baseline(HARDENED_FLASK_BASELINE)
    print("🔁 CONFIGURATION DRIFT (vs Hardened Flask LMS):")
    print(f"  Grade: {drift['grade_delta'].replace('Grade.', '')}")
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
    sim_result = None
    if args.simulate:
        fix_ids = [c.strip() for c in args.simulate.split(",") if c.strip()]
        if args.verbose:
            vprint(args.verbose, f"Running what-if simulation for fixes: {fix_ids!r}")
 
        sim = scan_result.simulate_with_fixes(fix_ids)
        sim_result = sim  # captured for PDF report
 
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
    
    # ───────── PATCH GENERATION ─────────
    patches = []  # populated if --patch is used
    if getattr(args, "patch", False):
        try:
            use_llm   = not getattr(args, "no_llm", False)
            verbose   = args.verbose
 
            # Build a per-scan subfolder so each run is organised independently:
            # patches/admin-example-com_20260330_scan13/
            import re as _re
            from datetime import datetime as _dt, timezone as _tz
            _base_dir   = getattr(args, "patch_dir", "patches")
            _target_slug = _re.sub(r"https?://", "", scan_result.target).split("/")[0]
            _target_slug = _re.sub(r"[^a-zA-Z0-9-]", "-", _target_slug)[:30].strip("-")
            _scan_date  = _dt.now(tz=_tz.utc).strftime("%Y%m%d")
            _scan_num   = history.count(scan_result.target)
            patch_dir   = f"{_base_dir}/{_target_slug}_{_scan_date}_scan{_scan_num}"
 
            # API key read from ANTHROPIC_API_KEY — never passed as CLI flag
            import os
            api_key = os.environ.get("ANTHROPIC_API_KEY", "")
 
            if verbose:
                mode_label = "LLM (Claude AI) with static fallback" if use_llm and api_key else (
                    "static templates only (no API key found)" if use_llm else "static templates only (--no-llm)"
                )
                vprint(verbose, f"Patch generation mode: {mode_label}")
                failing = [c for c in scan_result.checks if c.status.value != "PASS"]
                vprint(verbose, f"Checks to patch: {len(failing)} ({', '.join(c.id for c in failing)})")
                vprint(verbose, f"Output directory: {patch_dir}/")
 
            generator = PatchGenerator(use_llm=use_llm, verbose=verbose)
            patches   = generator.generate_all(scan_result, output_dir=patch_dir)
 
            llm_count  = sum(1 for p in patches if p.is_llm)
            tmpl_count = len(patches) - llm_count
 
            track_patch_generated(
                count=len(patches),
                llm_count=sum(1 for p in patches if p.is_llm),
            )
            print(f"\n🔧 PATCH FILES GENERATED ({len(patches)} files → {patch_dir}/):")
            for p in patches:
                source = "AI-generated" if p.is_llm else "standard"
                print(f"  [{p.severity:<8}] {p.filename:<35} ({source})")
            print(f"\n  README: {patch_dir}/README.md")
            if llm_count:
                print(f"  {llm_count} AI-generated patch(es), {tmpl_count} standard template(s)")
            print()
        except Exception as e:
            patches = []
            print(f"❌ Patch generation failed: {e!r}")
 
    # ───────── AUTO-FIX (--fix) ─────────
    fix_results = []
    dry_run = getattr(args, "dry_run", False)
 
    if getattr(args, "fix", False):
        if not args.ssh_host and not any([
            getattr(args, "dockerfile", None),
            getattr(args, "compose_file", None),
            getattr(args, "nginx_conf", None),
        ]):
            print("\u26a0\ufe0f  --fix requires --ssh-host or a file flag "
                  "(--dockerfile / --compose-file / --nginx-conf).")
        else:
            from sec_audit.results import Status
            failing     = [c for c in scan_result.checks if c.status != Status.PASS]
            automatable = [c for c in failing if c.id in AUTOMATABLE_CHECKS]
            not_auto    = [c for c in failing if c.id not in AUTOMATABLE_CHECKS]
 
            if dry_run:
                print("\n\U0001f50d DRY-RUN \u2014 no changes will be made to the server or files.")
                print("   Review the plan below, then run without --dry-run to apply.\n")
                print("\u2500" * 60)
            else:
                print("\n\U0001f527 AUTO-FIX \u2014 applying fixes...")
 
            print(f"  {len(automatable)} check(s) will be fixed automatically")
            if not_auto:
                print(f"  {len(not_auto)} check(s) require manual action (APP/CONT layer)")
            print()
 
            fixer = AutoFixer(
                ssh_host=args.ssh_host,
                ssh_user=getattr(args, "ssh_user", "root"),
                ssh_password=getattr(args, "ssh_password", None),
                ssh_key=getattr(args, "ssh_key", None),
                dockerfile=getattr(args, "dockerfile", None),
                compose_file=getattr(args, "compose_file", None),
                nginx_conf=getattr(args, "nginx_conf", None),
                verbose=args.verbose,
                dry_run=dry_run,
            )
            fix_results = fixer.fix_all(scan_result)
 
            fixed_count   = sum(1 for r in fix_results if r.status in ("fixed", "would_fix"))
            failed_count  = sum(1 for r in fix_results if r.status == "failed")
            skipped_count = sum(1 for r in fix_results if r.status in ("skipped", "not_automatable"))
 
            if dry_run:
                print("\U0001f4cb DRY-RUN PLAN \u2014 commands that WOULD run:\n")
            else:
                print("\n\U0001f4ca AUTO-FIX RESULTS:")
 
            for r in fix_results:
                if dry_run:
                    icon = {"would_fix": "\U0001f527", "skipped": "\u23ed\ufe0f",
                            "not_automatable": "\U0001f4cb", "failed": "\u274c"}.get(r.status, "?")
                else:
                    icon = {"fixed": "\u2705", "failed": "\u274c", "skipped": "\u23ed\ufe0f",
                            "not_automatable": "\U0001f4cb"}.get(r.status, "?")
 
                layer_label = r.layer.upper() if hasattr(r, "layer") else "?"
                print(f"  {icon} [{layer_label:<8}] {r.check_id:<25} {r.message}")
 
                # In dry-run, show each command that would run
                if dry_run and r.status == "would_fix" and r.commands_run:
                    for cmd in r.commands_run:
                        print(f"           $ {cmd[:72]}{'...' if len(cmd) > 72 else ''}")
                    print()
 
            if dry_run:
                print("\u2500" * 60)
                print(f"\n  Would fix: {fixed_count}  |  Manual: {skipped_count}")
                print()
                print("  \u2705 Review complete. To apply these fixes, run the same")
                print("     command without --dry-run.")
            else:
                track_fix_applied(fixed=fixed_count, failed=failed_count, manual=skipped_count)
                print(f"\n  Fixed: {fixed_count}  |  Failed: {failed_count}  |  Manual: {skipped_count}")
                if fixed_count > 0:
                    print("  Run --compare-last to verify improvements on next scan.")
            print()
 
    # ───────── JSON EXPORT ─────────
    if args.json:
        try:
            with open(args.json, "w", encoding="utf-8") as f:
                result_dict = scan_result.to_dict()
                if patches:
                    result_dict["patches"] = [
                        {
                            "check_id":     p.check_id,
                            "filename":     p.filename,
                            "file_type":    p.file_type,
                            "severity":     p.severity,
                            "layer":        p.layer,
                            "source":       "AI-generated" if p.is_llm else "standard",
                            "instructions": p.instructions,
                            "verification": p.verification,
                            "path":         str(p.output_path) if p.output_path else None,
                        }
                        for p in patches
                    ]
                if fix_results:
                    result_dict["auto_fix"] = {
                        "fixed":   sum(1 for r in fix_results if r.status == "fixed"),
                        "failed":  sum(1 for r in fix_results if r.status == "failed"),
                        "manual":  sum(1 for r in fix_results if r.status in ("skipped", "not_automatable")),
                        "results": [
                            {
                                "check_id":     r.check_id,
                                "check_name":   r.check_name,
                                "layer":        r.layer,
                                "status":       r.status,
                                "message":      r.message,
                                "commands_run": len(r.commands_run),
                                "verified":     r.verified,
                            }
                            for r in fix_results
                        ],
                    }
                json.dump(result_dict, f, indent=2)
            track_report_generated("json")
            print(f"💾 JSON results written to: {args.json}")
        except Exception as e:
            print(f"❌ Failed to write JSON: {e!r}")
    
    # ───────── PDF EXPORT ─────────
    if args.output:
        try:
            generate_pdf(scan_result, args.output, profile=args.profile, drift_report=drift_report, simulation_result=sim_result, patch_results=patches, fix_results=fix_results, dry_run=dry_run)
            track_report_generated("pdf")
            print(f"📄 PDF report generated: {args.output}")
        except Exception as e:
            print(f"❌ Failed to generate PDF: {e!r}")
    end = time.time()
    duration = end - start
    scan_count = history.count(args.target)
    print(f"⏱  Scan duration: {duration:.1f} seconds  "
          f"(scan #{scan_count} for this target — history at {history.db_path})")
 
def main() -> None:
    """Entry point for `stacksentry` CLI command after pip install."""
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass
 
    # ── First-run consent fires before argparse so it shows on --help too
    prompt_first_run()
 
    parser = build_parser()
    args   = parser.parse_args()
 
    # run_from_args handles --telemetry, --history, and --target validation
    try:
        run_from_args(args)
    except SystemExit:
        raise  # let argparse --help and --version exit cleanly
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted.")
    except EOFError:
        print("\n[INFO] Input stream closed.")
 
 
if __name__ == "__main__":
    main()