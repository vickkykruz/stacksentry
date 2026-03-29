"""
storage/drift.py — Security posture drift detection engine.
 
Compares two ScanResult objects and produces a DriftReport
describing exactly what changed between scans.
 
This is the novel feature that no other lightweight open-source
security tool provides: continuous posture tracking that shows
not just your current state, but how you got here.
 
Terminology
-----------
regression  — a check that was PASS and is now FAIL or WARN
improvement — a check that was FAIL or WARN and is now PASS
new_failure — a check that appears for the first time as FAIL
resolved    — a check that was FAIL and is now PASS (subset of improvement)
stable_fail — a check that was FAIL and is still FAIL (needs attention)
"""
 
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
 
from sec_audit.results import ScanResult, Status
 
 
# ── DriftReport dataclass ─────────────────────────────────────────────────────
 
@dataclass
class DriftReport:
    """
    The output of comparing two scan results.
 
    All lists contain check IDs (e.g. "APP-DEBUG-001") so callers
    can look up full details from the scan result if needed.
 
    Attributes
    ----------
    target              URL that was scanned
    baseline_scanned_at Timestamp of the earlier scan
    current_scanned_at  Timestamp of the newer scan
    elapsed_days        Days between the two scans (float, e.g. 3.5)
 
    grade_then          Grade at the time of the baseline scan
    grade_now           Grade at the time of the current scan
    grade_delta         Human-readable delta, e.g. "B → D" or "C → A"
    grade_direction     "improved", "regressed", or "stable"
 
    score_then          Score percentage of baseline scan
    score_now           Score percentage of current scan
    score_delta         Numeric change, e.g. -15.3 or +8.0
 
    regressions         Checks that went PASS → FAIL or PASS → WARN
    improvements        Checks that went FAIL/WARN → PASS
    new_failures        Checks that are FAIL and were not present before
    resolved_failures   Checks that were FAIL and are now PASS
    stable_failures     Checks that were FAIL and are still FAIL
    stable_passes       Checks that were PASS and are still PASS
 
    overall_trend       "improving", "regressing", or "stable"
    summary_line        One-sentence human-readable summary
    """
    target: str
    baseline_scanned_at: str
    current_scanned_at: str
    elapsed_days: float
 
    grade_then: str
    grade_now: str
    grade_delta: str
    grade_direction: str
 
    score_then: float
    score_now: float
    score_delta: float
 
    regressions: list[str] = field(default_factory=list)
    improvements: list[str] = field(default_factory=list)
    new_failures: list[str] = field(default_factory=list)
    resolved_failures: list[str] = field(default_factory=list)
    stable_failures: list[str] = field(default_factory=list)
    stable_passes: list[str] = field(default_factory=list)
 
    overall_trend: str = "stable"
    summary_line: str = ""
 
    def to_dict(self) -> dict:
        """Serialise to a plain dict for JSON export or PDF rendering."""
        return {
            "target": self.target,
            "baseline_scanned_at": self.baseline_scanned_at,
            "current_scanned_at": self.current_scanned_at,
            "elapsed_days": self.elapsed_days,
            "grade_then": self.grade_then,
            "grade_now": self.grade_now,
            "grade_delta": self.grade_delta,
            "grade_direction": self.grade_direction,
            "score_then": self.score_then,
            "score_now": self.score_now,
            "score_delta": self.score_delta,
            "regressions": self.regressions,
            "improvements": self.improvements,
            "new_failures": self.new_failures,
            "resolved_failures": self.resolved_failures,
            "stable_failures": self.stable_failures,
            "stable_passes": self.stable_passes,
            "overall_trend": self.overall_trend,
            "summary_line": self.summary_line,
        }
 
    @property
    def has_changes(self) -> bool:
        """True if anything changed between the two scans."""
        return bool(self.regressions or self.improvements or self.new_failures)
 
    @property
    def is_first_scan(self) -> bool:
        """True when this is a first-scan placeholder (no baseline exists)."""
        return self.baseline_scanned_at == ""
 
 
# ── Grade ordering ────────────────────────────────────────────────────────────
 
_GRADE_ORDER = {"A": 5, "B": 4, "C": 3, "D": 2, "F": 1}
 
 
def _grade_direction(then: str, now: str) -> str:
    """Return "improved", "regressed", or "stable" based on grade change."""
    then_val = _GRADE_ORDER.get(then.upper(), 0)
    now_val = _GRADE_ORDER.get(now.upper(), 0)
    if now_val > then_val:
        return "improved"
    if now_val < then_val:
        return "regressed"
    return "stable"
 
 
# ── Elapsed time helper ───────────────────────────────────────────────────────
 
def _elapsed_days(ts_then: str, ts_now: str) -> float:
    """
    Calculate the number of days between two ISO 8601 timestamps.
    Returns 0.0 if either timestamp is missing or unparseable.
    """
    try:
        def _parse(ts: str) -> datetime:
            ts = ts.replace("Z", "+00:00")
            return datetime.fromisoformat(ts)
        delta = _parse(ts_now) - _parse(ts_then)
        return round(delta.total_seconds() / 86400, 1)
    except Exception:
        return 0.0
 
 
# ── Summary line builder ──────────────────────────────────────────────────────
 
def _build_summary(report: "DriftReport") -> str:
    """
    Build a single human-readable sentence describing the drift.
 
    This is used in the CLI output and in the PDF drift section.
    """
    if report.is_first_scan:
        return f"First scan recorded for {report.target}. No baseline to compare against."
 
    elapsed = f"{report.elapsed_days:.0f} day{'s' if report.elapsed_days != 1 else ''}"
 
    if not report.has_changes:
        return (
            f"No change since last scan {elapsed} ago. "
            f"Grade remains {report.grade_now} ({report.score_now:.1f}%)."
        )
 
    parts = []
 
    if report.grade_direction == "regressed":
        parts.append(
            f"Grade regressed from {report.grade_then} to {report.grade_now} "
            f"({report.score_delta:+.1f}%) over {elapsed}."
        )
    elif report.grade_direction == "improved":
        parts.append(
            f"Grade improved from {report.grade_then} to {report.grade_now} "
            f"({report.score_delta:+.1f}%) over {elapsed}."
        )
    else:
        parts.append(
            f"Grade unchanged at {report.grade_now} "
            f"({report.score_delta:+.1f}% score change) over {elapsed}."
        )
 
    if report.regressions:
        n = len(report.regressions)
        parts.append(
            f"{n} check{'s' if n > 1 else ''} regressed "
            f"({', '.join(report.regressions[:3])}"
            f"{'...' if n > 3 else ''})."
        )
 
    if report.improvements:
        n = len(report.improvements)
        parts.append(
            f"{n} check{'s' if n > 1 else ''} improved "
            f"({', '.join(report.improvements[:3])}"
            f"{'...' if n > 3 else ''})."
        )
 
    return " ".join(parts)
 
 
# ── DriftEngine ───────────────────────────────────────────────────────────────
 
class DriftEngine:
    """
    Compares two ScanResult objects and produces a DriftReport.
 
    Usage
    -----
        engine = DriftEngine()
 
        # Compare two scan results directly
        report = engine.compare(baseline_scan, current_scan)
 
        # Or use with ScanHistory
        from storage import ScanHistory
        history = ScanHistory()
        baseline = history.latest(target)
        if baseline:
            report = engine.compare(baseline, current_scan)
        else:
            report = engine.first_scan_report(current_scan)
    """
 
    def compare(
        self,
        baseline: ScanResult,
        current: ScanResult,
    ) -> DriftReport:
        """
        Compare a baseline scan against a current scan.
 
        The baseline is the earlier scan (what things looked like before).
        The current is the most recent scan (what things look like now).
        """
        # Build status maps: check_id -> Status
        baseline_statuses = {c.id: c.status for c in baseline.checks}
        current_statuses  = {c.id: c.status for c in current.checks}
 
        all_ids = set(baseline_statuses) | set(current_statuses)
 
        regressions:      list[str] = []
        improvements:     list[str] = []
        new_failures:     list[str] = []
        resolved_failures: list[str] = []
        stable_failures:  list[str] = []
        stable_passes:    list[str] = []
 
        for check_id in sorted(all_ids):
            then = baseline_statuses.get(check_id)
            now  = current_statuses.get(check_id)
 
            # Check appeared for the first time
            if then is None:
                if now == Status.FAIL:
                    new_failures.append(check_id)
                continue
 
            # Check no longer present (removed from scan mode)
            if now is None:
                continue
 
            # Classify the change
            then_passed = (then == Status.PASS)
            now_passed  = (now  == Status.PASS)
 
            if then_passed and not now_passed:
                regressions.append(check_id)
 
            elif not then_passed and now_passed:
                improvements.append(check_id)
                if then == Status.FAIL:
                    resolved_failures.append(check_id)
 
            elif not then_passed and not now_passed:
                if now == Status.FAIL:
                    stable_failures.append(check_id)
 
            else:  # both passed
                stable_passes.append(check_id)
 
        # Grade and score deltas
        grade_then = baseline.grade.value
        grade_now  = current.grade.value
        score_then = baseline.score_percentage
        score_now  = current.score_percentage
        score_delta = round(score_now - score_then, 1)
        direction   = _grade_direction(grade_then, grade_now)
 
        # Overall trend
        if regressions and not improvements:
            trend = "regressing"
        elif improvements and not regressions:
            trend = "improving"
        elif improvements and regressions:
            trend = "improving" if len(improvements) > len(regressions) else "regressing"
        else:
            trend = "stable"
 
        report = DriftReport(
            target=current.target,
            baseline_scanned_at=baseline.generated_at or "",
            current_scanned_at=current.generated_at or "",
            elapsed_days=_elapsed_days(
                baseline.generated_at or "",
                current.generated_at or "",
            ),
            grade_then=grade_then,
            grade_now=grade_now,
            grade_delta=f"{grade_then} → {grade_now}",
            grade_direction=direction,
            score_then=score_then,
            score_now=score_now,
            score_delta=score_delta,
            regressions=regressions,
            improvements=improvements,
            new_failures=new_failures,
            resolved_failures=resolved_failures,
            stable_failures=stable_failures,
            stable_passes=stable_passes,
            overall_trend=trend,
        )
        report.summary_line = _build_summary(report)
        return report
 
    def first_scan_report(self, current: ScanResult) -> DriftReport:
        """
        Return a placeholder DriftReport for targets with no scan history.
 
        This lets callers always work with a DriftReport object
        without needing special-case None checks everywhere.
        """
        report = DriftReport(
            target=current.target,
            baseline_scanned_at="",
            current_scanned_at=current.generated_at or "",
            elapsed_days=0.0,
            grade_then=current.grade.value,
            grade_now=current.grade.value,
            grade_delta="—",
            grade_direction="stable",
            score_then=current.score_percentage,
            score_now=current.score_percentage,
            score_delta=0.0,
            stable_passes=[
                c.id for c in current.checks if c.status == Status.PASS
            ],
            stable_failures=[
                c.id for c in current.checks if c.status == Status.FAIL
            ],
            overall_trend="stable",
        )
        report.summary_line = _build_summary(report)
        return report
 