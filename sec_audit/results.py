"""
Security Audit Result Models and Validation.

Defines standardized data structures for:
- Individual check results (pass/fail + evidence)
- Aggregated scan results (scores, risk levels)
- Report generation data (tables, summaries)

Supports JSON serialization for CI/CD integration.
"""


# Result dataclass, ScoreCalculator, Validation schemas
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Any
from enum import Enum
from datetime import datetime
from sec_audit.baseline import BaselineProfile, HARDENED_FLASK_BASELINE


class Status(str, Enum):
    """Standardized check statuses."""
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    ERROR = "ERROR"


class Severity(str, Enum):
    """Standardized check severities."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Grade(str, Enum):
    """Overall scan grades (A-F)."""
    A = "A"  # 90-100%
    B = "B"  # 80-89%
    C = "C"  # 70-79%
    D = "D"  # 60-69%
    F = "F"  # <60%
    

@dataclass
class CheckResult:
    """
    Represents the outcome of a single security check.

    Fields:
        id:       Unique check identifier (e.g. APP-DEBUG-001)
        layer:    Stack layer (app, webserver, container, host)
        name:     Human-readable check name
        status:   PASS | FAIL | WARN | ERROR
        severity: CRITICAL | HIGH | MEDIUM | LOW
        details:  Human-readable explanation of the outcome
    """
    id: str
    layer: str
    name: str
    status: Status      # "PASS" | "FAIL" | "WARN" | "ERROR"
    severity: Severity    # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    details: str
    
    
    
@dataclass
class ScanResult:
    """
    Represents the result of a full scan against a single target.

    Fields:
        target: Target URL being scanned
        mode:   Scan mode (quick | full)
        checks: List of CheckResult objects
    """
    target: str
    mode: str
    checks: List[CheckResult]
    generated_at: str = field(init=False, default=None)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return {
            "target": self.target,
            "mode": self.mode,
            "checks": [asdict(c) for c in self.checks],
            "summary": self.summary(),
            "score": {
                "percentage": self.score_percentage,
                "grade": self.grade.value,
                "pass_rate": f"{self.pass_rate:.1f}%"
            },
            "stack_fingerprint": self.stack_fingerprint,
            "attack_paths": self.attack_paths(),
            "attack_path_count": self.attack_path_count,
            "highest_attack_risk": self.highest_attack_risk,
            "layer_summary": self.layer_summary(),
        }
        
        
    def __post_init__(self):
        """Auto-generate timestamp if not provided."""
        if not hasattr(self, 'generated_at') or self.generated_at is None:
            self.generated_at = datetime.utcnow().isoformat() + "Z"

        
    @property
    def total_checks(self) -> int:
        """Total number of checks executed."""
        return len(self.checks)


    @property
    def pass_rate(self) -> float:
        """Percentage of PASS checks (ERRORs excluded from scoring)."""
        passed = sum(1 for c in self.checks if c.status == Status.PASS)
        valid_checks = sum(1 for c in self.checks 
                          if c.status in [Status.PASS, Status.FAIL, Status.WARN])
        return (passed / valid_checks * 100) if valid_checks > 0 else 0.0
    
    
    @property
    def score_percentage(self) -> float:
        """Overall score as percentage (0-100)."""
        return round(self.pass_rate, 1)


    @property
    def grade(self) -> Grade:
        """A-F grade based on pass rate."""
        score = self.score_percentage
        if score >= 90: return Grade.A
        elif score >= 80: return Grade.B
        elif score >= 70: return Grade.C
        elif score >= 60: return Grade.D
        else: return Grade.F
        
        
    def summary(self) -> Dict[str, Any]:
        """Human-readable summary statistics."""
        status_counts = {}
        severity_counts = {}
        for check in self.checks:
            status_counts[check.status.value] = status_counts.get(check.status.value, 0) + 1
            severity_counts[check.severity.value] = severity_counts.get(check.severity.value, 0) + 1
        
        return {
            "total_checks": self.total_checks,
            "grade": self.grade.value,
            "score_percentage": self.score_percentage,
            "status_breakdown": status_counts,
            "severity_breakdown": severity_counts,
            "high_risk_issues": sum(1 for c in self.checks 
                                  if c.status != Status.PASS and c.severity == Severity.HIGH)
        }
        
    def layer_summary(self) -> Dict[str, Dict[str, Any]]:
        """Breakdown by layer (app, webserver, container, host)."""
        layers = {}
        for check in self.checks:
            if check.layer not in layers:
                layers[check.layer] = {"total": 0, "passed": 0}
            layers[check.layer]["total"] += 1
            if check.status == Status.PASS:
                layers[check.layer]["passed"] += 1
        return layers
    
    
    def detect_stack(self) -> str:
        """
        Best-effort detection of application stack from headers and findings.

        Returns strings like:
        - 'Flask + Nginx'
        - 'Django + Apache'
        - 'Unknown stack'
        """
        fingerprint_parts = []

        # 1) Web framework heuristics (from details/names)
        text_blobs = " ".join(
            [c.name for c in self.checks] + [c.details for c in self.checks]
        ).lower()

        if "flask" in text_blobs:
            fingerprint_parts.append("Flask")
        if "django" in text_blobs:
            fingerprint_parts.append("Django")
        if "express" in text_blobs or "node.js" in text_blobs:
            fingerprint_parts.append("Node.js")

        # 2) Web server from headers (you can pass headers via a special check or later via http_scanner)
        server_header = ""
        for c in self.checks:
            if "server:" in c.details.lower():
                # e.g. "Server: nginx/1.24.0"
                server_header = c.details
                break

        server_lower = server_header.lower()
        if "nginx" in server_lower:
            fingerprint_parts.append("Nginx")
        if "apache" in server_lower:
            fingerprint_parts.append("Apache")

        # 3) Container / OS hints (for future Docker/SSH integration)
        if any("docker" in c.details.lower() for c in self.checks):
            fingerprint_parts.append("Docker")
        if any("ubuntu" in c.details.lower() for c in self.checks):
            fingerprint_parts.append("Ubuntu")

        return " + ".join(dict.fromkeys(fingerprint_parts)) if fingerprint_parts else "Unknown stack"
    
    @property
    def stack_fingerprint(self) -> str:
        return self.detect_stack()
    
    
    def attack_paths(self) -> list[dict]:
        """
        Identifies realistic multi-layer attack chains.
        
        Matches your proposal's "layer-to-layer risk analysis" [file:310]
        """
        all_checks = self.checks  # Use ALL checks (PASS/WARN/FAIL/ERROR)
        paths = []
        
        # PATH 1: HTTP Session Hijacking → Container Privilege Escalation
        # Triggers if ANY web weakness + container pending
        web_weaknesses = [
            c for c in all_checks 
            if c.status != Status.PASS and c.layer in ["app", "webserver"]
        ]
        container_checks = [c for c in all_checks if c.layer == "container"]
        
        if web_weaknesses and container_checks:
            paths.append({
                "id": "AP-001",
                "name": "Web → Container Escape",
                "layers": ["app", "webserver", "container"],
                "risk": "HIGH",
                "description": "HTTP misconfigs + unhardened containers enable privilege escalation",
                "score": 8.5,
                "priority_fixes": ["HSTS", "Secure cookies", "Non-root containers"]
            })
        
        # PATH 2: Application Exposure → Host Compromise  
        # Triggers if app issues + host pending
        app_exposures = [
            c for c in all_checks 
            if c.status != Status.PASS and "debug" in c.id.lower()
        ]
        host_checks = [c for c in all_checks if c.layer == "host"]
        
        if app_exposures and host_checks:
            paths.append({
                "id": "AP-002", 
                "name": "App → Host Root Access",
                "layers": ["app", "host"],
                "risk": "MEDIUM",
                "description": "Debug exposure + unhardened host = full server compromise", 
                "score": 7.8,
                "priority_fixes": ["Debug mode", "SSH hardening", "File permissions"]
            })
        
        # PATH 3: Server Misconfig → Internal Pivot
        server_issues = [
            c for c in all_checks 
            if c.status != Status.PASS and c.layer == "webserver"
        ]
        
        if len(server_issues) >= 2:  # 2+ webserver failures
            paths.append({
                "id": "AP-003",
                "name": "Server → Internal Services",
                "layers": ["webserver"],
                "risk": "MEDIUM",
                "description": "Multiple server misconfigs increase attack surface", 
                "score": 6.5,
                "priority_fixes": ["Security headers", "TLS config", "Server tokens"]
            })
        
        return paths

    @property
    def attack_path_count(self) -> int:
        """Number of identified attack paths."""
        return len(self.attack_paths())

    @property
    def highest_attack_risk(self) -> str:
        """Highest risk level across all paths."""
        paths = self.attack_paths()
        if not paths:
            return "LOW"
        
        # Map risks to numeric values
        risk_weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        # Find the path with max risk weight
        highest = max(paths, key=lambda p: risk_weight.get(p["risk"], 0))
        return highest["risk"]
    
    
    def compare_to_baseline(self, baseline: BaselineProfile) -> dict:
        """
        Compare this ScanResult against a given baseline profile.

        Returns:
            {
            "baseline_name": ...,
            "grade_delta": ...,
            "pass_delta": ...,
            "improved_checks": [...],
            "regressed_checks": [...],
            }
        """
        current_status = {c.id: c.status for c in self.checks}

        improved = []
        regressed = []

        for check_id, expected_status in baseline.check_statuses.items():
            current = current_status.get(check_id)
            if not current:
                continue
            if current == "PASS" and expected_status != "PASS":
                improved.append(check_id)
            elif current != "PASS" and expected_status == "PASS":
                regressed.append(check_id)

        pass_delta = self.summary()["status_breakdown"].get("PASS", 0) - baseline.expected_passes

        return {
            "baseline_name": baseline.name,
            "grade_delta": f"{self.grade} vs {baseline.expected_grade}",
            "pass_delta": pass_delta,
            "improved_checks": improved,
            "regressed_checks": regressed,
        }
        
        
    def layer_summary(self) -> Dict[str, Dict[str, Any]]:
        """Returns pass/fail counts per layer for heatmap."""
        layers = {}
        for check in self.checks:
            layer = check.layer
            if layer not in layers:
                layers[layer] = {"total": 0, "passed": 0, "failed": 0, "warned": 0}
            layers[layer]["total"] += 1
            if check.status == Status.PASS:
                layers[layer]["passed"] += 1
            elif check.status in [Status.FAIL, Status.WARN]:
                layers[layer]["failed"] += 1
            else:  # ERROR
                layers[layer]["warned"] += 1
        
        # Calculate pass rates and assign colors
        for layer, stats in layers.items():
            pass_rate = (stats["passed"] / stats["total"] * 100) if stats["total"] > 0 else 0
            if pass_rate >= 80:
                stats["color"] = "🟢"  # Green
                stats["risk"] = "LOW"
            elif pass_rate >= 50:
                stats["color"] = "🟡"  # Yellow
                stats["risk"] = "MEDIUM"
            else:
                stats["color"] = "🔴"  # Red
                stats["risk"] = "HIGH"
            stats["pass_rate"] = round(pass_rate, 1)
        
        return layers
    
    
    def executive_narrative(self) -> str:
        """
        Short AI-style explanation of the current security posture.
        """
        summary = self.summary()
        total = self.total_checks
        passed = summary["status_breakdown"].get("PASS", 0)
        high_risk = summary["high_risk_issues"]
        score_now = self.score_percentage
        layer_data = self.layer_summary()

        # Identify weakest layer
        weakest_layer = None
        weakest_rate = 101
        for layer, stats in layer_data.items():
            if stats["pass_rate"] < weakest_rate:
                weakest_rate = stats["pass_rate"]
                weakest_layer = layer

        layer_labels = {
            "app": "application layer",
            "webserver": "web server layer",
            "container": "container layer",
            "host": "host layer",
        }
        weakest_label = layer_labels.get(weakest_layer, "infrastructure")

        # Build explanation in plain language
        parts = []
        parts.append(
            f"The current security posture is {self.grade} with {passed} of {total} checks passing "
            f"({score_now:.1f}% overall)."
        )

        if high_risk > 0:
            parts.append(
                f"There are {high_risk} high-severity issues, mainly concentrated in the {weakest_label}, "
                f"which significantly increases the likelihood of successful attacks in that area."
            )
        else:
            parts.append(
                "No high-severity issues were detected, but there are still medium and low risks that should be addressed over time."
            )

        # Mention attack paths if any
        paths = self.attack_paths()
        if paths:
            parts.append(
                f"The analysis also identified {len(paths)} multi-step attack path(s), "
                f"showing how an attacker could chain misconfigurations to escalate impact."
            )
        else:
            parts.append(
                "No multi-step attack paths were found, which reduces the chance of chained exploitation across layers."
            )

        return " ".join(parts)
    
    
    def remediation_recommendations(self) -> list[str]:
        """
        Return a short, ordered list of key remediation recommendations.
        """
        recs = []
        checks = [c for c in self.checks if c.status != "PASS"]

        # Group by keywords
        if any("HSTS" in c.id.upper() for c in checks):
            recs.append("Enable HSTS (Strict-Transport-Security) to enforce HTTPS on all responses.")

        if any("COOKIE" in c.id.upper() for c in checks):
            recs.append("Harden session cookies (set Secure, HttpOnly and SameSite attributes).")

        if any("TLS" in c.id.upper() for c in checks):
            recs.append("Update TLS configuration to disable weak protocols/ciphers and prefer TLS 1.2+.")

        if any("DEBUG" in c.id.upper() for c in checks):
            recs.append("Disable debug mode and ensure no debugging endpoints are accessible in production.")

        if any("ADMIN" in c.id.upper() for c in checks):
            recs.append("Restrict admin endpoints behind authentication and, ideally, IP allowlists or VPN.")

        if any("SSH" in c.id.upper() for c in checks):
            recs.append("Harden SSH by disabling root login and password authentication, and using key-based access.")

        if any(c.layer == "container" and c.status != "PASS" for c in checks):
            recs.append("Review container images to ensure non-root users, minimal exposed ports, and no secrets baked into images.")

        if any(c.layer == "host" and c.status != "PASS" for c in checks):
            recs.append("Review host OS hardening: firewall rules, automatic security updates, logging and file permissions.")

        # Limit to top 5 to keep it readable
        return recs[:5]
    
    
    def priority_fixes(self) -> list[dict]:
        """Return top 5 priority fixes as structured data."""
        issues = [r for r in self.checks if r.status != Status.PASS]
        priority = sorted(
            issues,
            key=lambda r: (r.severity.value, 0 if r.status == Status.FAIL else 1)
        )[:5]

        return [
            {
                "id":       result.id,
                "name":     result.name,
                "details":  result.details,
                "severity": result.severity.name,   # e.g. "HIGH"
                "status":   result.status.name,     # e.g. "FAIL"
                "layer":    result.layer,
            }
            for result in priority
        ]


    def server_fingerprint(self) -> dict:
        """Extract version info from checks for fingerprint table."""
        # Safe fallback - uses getattr with defaults
        versions = {
            "os": getattr(self, '_os_version', 'N/A'),
            "docker": getattr(self, '_docker_version', 'N/A'),
            "webserver": getattr(self, '_webserver_version', 'N/A'),
            "app": getattr(self, '_app_version', 'N/A'),
        }
        return versions