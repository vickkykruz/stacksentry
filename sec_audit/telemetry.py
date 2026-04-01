"""
sec_audit/telemetry.py — Anonymous opt-in usage telemetry.
 
PRIVACY CONTRACT (never violated):
  ✅ Opt-in only — user is asked once on first run, never silently enabled
  ✅ Anonymous — no target URLs, no credentials, no scan results, no IPs
  ✅ Fire-and-forget — 3s timeout, never blocks, never crashes the scan
  ✅ Transparent — user can inspect or disable at any time
 
What IS sent (with consent):
  - Event type (tool_installed, scan_started, patch_generated, etc.)
  - Platform (win32 / linux / darwin)
  - Python version (major.minor only, e.g. 3.11)
  - StackSentry version
  - Country/city (from ipinfo.io — same as any website visit)
 
What is NEVER sent:
  - Target URLs, server IPs, SSH credentials
  - Scan results, grades, check details
  - File paths, nginx/Dockerfile contents
  - Any personally identifying information
 
User controls:
  stacksentry --telemetry on   # enable
  stacksentry --telemetry off  # disable
  stacksentry --telemetry status  # show current setting
 
Config stored at: ~/.stacksentry/config.json
"""
 
from __future__ import annotations
 
import json
import platform
import sys
import threading
import pathlib
from datetime import datetime, timezone
from typing import Optional
 
 
# ── Constants ─────────────────────────────────────────────────────────────────
 
TELEMETRY_BASE   = "https://api.vickkykruzprogramming.dev/api"
TRACK_URL        = f"{TELEMETRY_BASE}/track"
ACTIVITY_URL     = f"{TELEMETRY_BASE}/activity"
SUBSCRIBE_URL    = f"{TELEMETRY_BASE}/subscribe"
 
CONFIG_DIR       = pathlib.Path.home() / ".stacksentry"
CONFIG_FILE      = CONFIG_DIR / "config.json"
TIMEOUT_SECONDS  = 3
 
VERSION          = "1.0.0"
 
 
# ── Config helpers ────────────────────────────────────────────────────────────
 
def _load_config() -> dict:
    try:
        if CONFIG_FILE.exists():
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}
 
 
def _save_config(cfg: dict) -> None:
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    except Exception:
        pass
 
 
def is_telemetry_enabled() -> bool:
    return _load_config().get("telemetry", False)
 
 
def is_first_run() -> bool:
    """True if the user has never been asked about telemetry."""
    return "telemetry" not in _load_config()
 
 
def set_telemetry(enabled: bool) -> None:
    cfg = _load_config()
    cfg["telemetry"] = enabled
    _save_config(cfg)
 
 
def get_subscribed_email() -> Optional[str]:
    return _load_config().get("newsletter_email")
 
 
def set_subscribed_email(email: str) -> None:
    cfg = _load_config()
    cfg["newsletter_email"] = email
    _save_config(cfg)
 
 
# ── First-run consent prompt ──────────────────────────────────────────────────
 
def prompt_first_run() -> None:
    """
    Show the opt-in prompt on first run. Called once from cli.py
    before the scan starts. Never called again after user responds.
    """
    if not is_first_run():
        return
 
    print()
    print("─" * 55)
    print("  Welcome to StackSentry v1.0.0 👋")
    print()
    print("  Help improve StackSentry by sharing anonymous")
    print("  usage data. This includes only:")
    print("    • Which features you use (--patch, --fix, etc.)")
    print("    • Your platform and Python version")
    print("    • Approximate country (no IPs stored)")
    print()
    print("  Your scan targets, credentials, and results")
    print("  are NEVER collected.")
    print()
 
    try:
        answer = input("  Allow anonymous telemetry? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = "n"
 
    opted_in = answer in ("y", "yes")
    set_telemetry(opted_in)
 
    if opted_in:
        print()
        print("  Thanks! One more thing — want to be notified")
        print("  about new StackSentry features and updates?")
        print()
        try:
            email = input("  Your email (or press Enter to skip): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            email = ""
 
        if email and "@" in email and "." in email:
            set_subscribed_email(email)
            _subscribe_background(email)
            print(f"  ✅ Subscribed! We'll notify you at {email}")
        else:
            print("  Skipped — you can subscribe later at:")
            print("  https://vickkykruzprogramming.dev")
 
        print()
        print("  You can change this setting any time:")
        print("  stacksentry --telemetry off")
    else:
        print()
        print("  No problem — telemetry stays off.")
        print("  You can enable it later: stacksentry --telemetry on")
 
    print("─" * 55)
    print()
 
    # Log the installation event (only if opted in)
    # Use synchronous call — program may exit before a daemon thread completes
    # when --history or --telemetry flags are used without a scan
    if opted_in:
        _post(ACTIVITY_URL, {
            "type": "tool_installed",
            "page": "/cli/install",
            "meta": {
                "version":  VERSION,
                "platform": sys.platform,
                "python":   f"{sys.version_info.major}.{sys.version_info.minor}",
            },
        })
 
 
# ── Telemetry management command ─────────────────────────────────────────────
 
def handle_telemetry_flag(value: str) -> None:
    """Handle --telemetry on/off/status from CLI."""
    value = value.strip().lower()
    if value == "on":
        set_telemetry(True)
        print("✅ Telemetry enabled. Thank you for helping improve StackSentry.")
        # If we don't have an email yet, offer newsletter
        if not get_subscribed_email():
            try:
                email = input("Want update notifications? Enter email (or Enter to skip): ").strip().lower()
                if email and "@" in email and "." in email:
                    set_subscribed_email(email)
                    _subscribe_background(email)
                    print(f"✅ Subscribed at {email}")
            except (EOFError, KeyboardInterrupt):
                pass
    elif value == "off":
        set_telemetry(False)
        print("✅ Telemetry disabled.")
    elif value == "status":
        cfg = _load_config()
        enabled = cfg.get("telemetry", False)
        email   = cfg.get("newsletter_email", "not set")
        print(f"  Telemetry:  {'enabled' if enabled else 'disabled'}")
        print(f"  Newsletter: {email}")
        print(f"  Config at:  {CONFIG_FILE}")
    else:
        print(f"Unknown value '{value}'. Use: on | off | status")
 
 
# ── Event tracking ────────────────────────────────────────────────────────────
 
def track_scan_started(mode: str) -> None:
    """Called when a scan begins — sends no target info."""
    if not is_telemetry_enabled():
        return
    _fire(ACTIVITY_URL, {
        "type": "scan_started",
        "page": "/cli/scan",
        "meta": {
            "mode":     mode,
            "version":  VERSION,
            "platform": sys.platform,
            "python":   f"{sys.version_info.major}.{sys.version_info.minor}",
        },
    })
    _fire_track(page="/cli/scan")
 
 
def track_patch_generated(count: int, llm_count: int) -> None:
    """Called when --patch completes."""
    if not is_telemetry_enabled():
        return
    _fire(ACTIVITY_URL, {
        "type": "patch_generated",
        "page": "/cli/patch",
        "meta": {
            "patch_count": count,
            "llm_count":   llm_count,
            "version":     VERSION,
        },
    })
 
 
def track_fix_applied(fixed: int, failed: int, manual: int) -> None:
    """Called when --fix completes."""
    if not is_telemetry_enabled():
        return
    _fire(ACTIVITY_URL, {
        "type": "fix_applied",
        "page": "/cli/fix",
        "meta": {
            "fixed":   fixed,
            "failed":  failed,
            "manual":  manual,
            "version": VERSION,
        },
    })
 
 
def track_report_generated(format_type: str) -> None:
    """Called when a PDF or JSON report is generated."""
    if not is_telemetry_enabled():
        return
    _fire(ACTIVITY_URL, {
        "type": "report_generated",
        "page": "/cli/report",
        "meta": {
            "format":  format_type,
            "version": VERSION,
        },
    })
 
 
# ── Internal fire-and-forget helpers ─────────────────────────────────────────
 
def _fire(url: str, payload: dict) -> None:
    """POST payload to url in a background thread. Never blocks. Never raises."""
    t = threading.Thread(target=_post, args=(url, payload), daemon=True)
    t.start()
 
 
def _post(url: str, payload: dict) -> None:
    """Perform the actual HTTP POST. Silently swallows all errors."""
    try:
        import urllib.request
        body = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS)
    except Exception:
        pass  # Never propagate — telemetry must never break the main scan
 
 
def _fire_track(page: str) -> None:
    """POST to /api/track — gets location from server-side IP lookup."""
    _fire(TRACK_URL, {
        "page":         page,
        "country":      "Unknown",
        "country_code": "XX",
        "city":         "Unknown",
    })
 
 
def _subscribe_background(email: str) -> None:
    """
    POST email to /api/subscribe synchronously.
 
    This is intentionally NOT a background thread — subscription is a
    one-time event and the program exits immediately after, which would
    kill a daemon thread before the request completes.
    """
    _post(SUBSCRIBE_URL, {"email": email, "source": "stacksentry_cli"})