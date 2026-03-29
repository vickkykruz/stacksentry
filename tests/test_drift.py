"""
test_drift.py — Tests for the temporal drift engine.
 
Covers:
- ScanHistory: save, retrieve, count, delete, timeline
- DriftEngine: regression detection, improvement detection,
  new failures, resolved failures, grade direction, summary lines
- Edge cases: first scan, no changes, all improvements, all regressions
"""
 
import pytest
import pathlib
import tempfile
from datetime import datetime, timezone, timedelta
 
from sec_audit.results import CheckResult, ScanResult, Status, Severity
from storage.history import ScanHistory, _scan_to_dict, _dict_to_scan
from storage.drift import DriftEngine, DriftReport, _grade_direction, _elapsed_days
 
 
# ── Helpers ───────────────────────────────────────────────────────────────────
 
def _ts(offset_days: float = 0.0) -> str:
    """Generate an ISO 8601 UTC timestamp offset by N days from now."""
    dt = datetime.now(tz=timezone.utc) + timedelta(days=offset_days)
    return dt.isoformat().replace("+00:00", "Z")
 
 
def _check(id: str, layer: str, status: Status,
           severity: Severity = Severity.HIGH,
           details: str = "test") -> CheckResult:
    return CheckResult(
        id=id, layer=layer, name=f"Check {id}",
        status=status, severity=severity, details=details,
    )
 
 
def _scan(target: str, checks: list, mode: str = "quick",
          timestamp: str = None) -> ScanResult:
    scan = ScanResult(target=target, mode=mode, checks=checks)
    if timestamp:
        scan.generated_at = timestamp
    return scan
 
 
@pytest.fixture
def tmp_db(tmp_path):
    """Provide a fresh in-memory-equivalent database for each test."""
    db_file = tmp_path / "test_history.db"
    return ScanHistory(str(db_file))
 
 
@pytest.fixture
def engine():
    return DriftEngine()
 
 
# ─────────────────────────────────────────────────────────────────────────────
# ScanHistory — basic persistence
# ─────────────────────────────────────────────────────────────────────────────
 
class TestScanHistorySave:
 
    def test_save_returns_row_id(self, tmp_db):
        scan = _scan("http://example.com", [
            _check("APP-DEBUG-001", "app", Status.PASS),
        ])
        row_id = tmp_db.save(scan)
        assert isinstance(row_id, int)
        assert row_id >= 1
 
    def test_save_increments_row_id(self, tmp_db):
        scan = _scan("http://example.com", [_check("A", "app", Status.PASS)])
        id1 = tmp_db.save(scan)
        id2 = tmp_db.save(scan)
        assert id2 > id1
 
    def test_count_increases_after_save(self, tmp_db):
        target = "http://example.com"
        scan = _scan(target, [_check("A", "app", Status.PASS)])
        assert tmp_db.count(target) == 0
        tmp_db.save(scan)
        assert tmp_db.count(target) == 1
        tmp_db.save(scan)
        assert tmp_db.count(target) == 2
 
    def test_count_is_per_target(self, tmp_db):
        """count() must not mix results from different targets."""
        scan_a = _scan("http://alpha.com", [_check("A", "app", Status.PASS)])
        scan_b = _scan("http://beta.com",  [_check("B", "app", Status.PASS)])
        tmp_db.save(scan_a)
        tmp_db.save(scan_a)
        tmp_db.save(scan_b)
        assert tmp_db.count("http://alpha.com") == 2
        assert tmp_db.count("http://beta.com")  == 1
 
 
class TestScanHistoryRetrieve:
 
    def test_latest_returns_none_when_no_scans(self, tmp_db):
        result = tmp_db.latest("http://new-target.com")
        assert result is None
 
    def test_latest_returns_most_recent_scan(self, tmp_db):
        target = "http://example.com"
        old_scan = _scan(target, [_check("A", "app", Status.FAIL)],
                         timestamp=_ts(-2))
        new_scan = _scan(target, [_check("A", "app", Status.PASS)],
                         timestamp=_ts(0))
        tmp_db.save(old_scan)
        tmp_db.save(new_scan)
        retrieved = tmp_db.latest(target)
        assert retrieved is not None
        # Most recent scan had the check passing
        assert retrieved.checks[0].status == Status.PASS
 
    def test_latest_preserves_target(self, tmp_db):
        target = "http://example.com"
        scan = _scan(target, [_check("A", "app", Status.PASS)])
        tmp_db.save(scan)
        retrieved = tmp_db.latest(target)
        assert retrieved.target == target
 
    def test_latest_preserves_all_checks(self, tmp_db):
        target = "http://example.com"
        checks = [
            _check("APP-DEBUG-001",  "app",       Status.FAIL),
            _check("WS-HSTS-001",    "webserver", Status.PASS),
            _check("CONT-USER-001",  "container", Status.WARN),
            _check("HOST-SSH-001",   "host",      Status.PASS),
        ]
        scan = _scan(target, checks)
        tmp_db.save(scan)
        retrieved = tmp_db.latest(target)
        assert len(retrieved.checks) == 4
        statuses = {c.id: c.status for c in retrieved.checks}
        assert statuses["APP-DEBUG-001"]  == Status.FAIL
        assert statuses["WS-HSTS-001"]    == Status.PASS
        assert statuses["CONT-USER-001"]  == Status.WARN
        assert statuses["HOST-SSH-001"]   == Status.PASS
 
    def test_latest_preserves_severity(self, tmp_db):
        target = "http://example.com"
        scan = _scan(target, [
            _check("A", "app", Status.FAIL, Severity.CRITICAL)
        ])
        tmp_db.save(scan)
        retrieved = tmp_db.latest(target)
        assert retrieved.checks[0].severity == Severity.CRITICAL
 
    def test_all_for_returns_newest_first(self, tmp_db):
        target = "http://example.com"
        for i in range(3):
            scan = _scan(target, [_check("A", "app", Status.PASS)],
                         timestamp=_ts(-i))
            tmp_db.save(scan)
        rows = tmp_db.all_for(target)
        assert len(rows) == 3
        # Rows should be ordered newest first
        timestamps = [r["scanned_at"] for r in rows]
        assert timestamps == sorted(timestamps, reverse=True)
 
    def test_all_for_respects_limit(self, tmp_db):
        target = "http://example.com"
        for i in range(10):
            scan = _scan(target, [_check("A", "app", Status.PASS)],
                         timestamp=_ts(-i))
            tmp_db.save(scan)
        rows = tmp_db.all_for(target, limit=5)
        assert len(rows) == 5
 
    def test_all_for_includes_required_fields(self, tmp_db):
        target = "http://example.com"
        scan = _scan(target, [_check("A", "app", Status.PASS)])
        tmp_db.save(scan)
        rows = tmp_db.all_for(target)
        row = rows[0]
        assert "grade"            in row
        assert "score_percentage" in row
        assert "passed_checks"    in row
        assert "failed_checks"    in row
        assert "scanned_at"       in row
 
    def test_all_targets_returns_distinct_targets(self, tmp_db):
        targets = ["http://alpha.com", "http://beta.com", "http://gamma.com"]
        for t in targets:
            tmp_db.save(_scan(t, [_check("A", "app", Status.PASS)]))
        result = tmp_db.all_targets()
        assert set(result) == set(targets)
 
    def test_previous_returns_scan_before_timestamp(self, tmp_db):
        target = "http://example.com"
        old_scan = _scan(target, [_check("A", "app", Status.FAIL)],
                         timestamp=_ts(-5))
        mid_scan = _scan(target, [_check("A", "app", Status.WARN)],
                         timestamp=_ts(-2))
        new_scan = _scan(target, [_check("A", "app", Status.PASS)],
                         timestamp=_ts(0))
        tmp_db.save(old_scan)
        tmp_db.save(mid_scan)
        tmp_db.save(new_scan)
 
        # Ask for the scan before the current one
        previous = tmp_db.previous(target, new_scan.generated_at)
        assert previous is not None
        assert previous.checks[0].status == Status.WARN  # mid_scan
 
 
class TestScanHistoryDelete:
 
    def test_delete_all_removes_records(self, tmp_db):
        target = "http://example.com"
        for _ in range(3):
            tmp_db.save(_scan(target, [_check("A", "app", Status.PASS)]))
        assert tmp_db.count(target) == 3
        deleted = tmp_db.delete_all(target)
        assert deleted == 3
        assert tmp_db.count(target) == 0
 
    def test_delete_all_does_not_affect_other_targets(self, tmp_db):
        tmp_db.save(_scan("http://alpha.com", [_check("A", "app", Status.PASS)]))
        tmp_db.save(_scan("http://beta.com",  [_check("B", "app", Status.PASS)]))
        tmp_db.delete_all("http://alpha.com")
        assert tmp_db.count("http://alpha.com") == 0
        assert tmp_db.count("http://beta.com")  == 1
 
    def test_delete_nonexistent_target_returns_zero(self, tmp_db):
        result = tmp_db.delete_all("http://never-scanned.com")
        assert result == 0
 
 
class TestScanHistoryDbPath:
 
    def test_custom_db_path_is_used(self, tmp_path):
        custom_path = tmp_path / "custom.db"
        history = ScanHistory(str(custom_path))
        assert history.db_path == custom_path
        assert custom_path.exists()
 
    def test_default_db_path_is_in_home(self):
        history = ScanHistory()
        assert ".stacksentry" in str(history.db_path)
        assert history.db_path.name == "history.db"
 
 
# ─────────────────────────────────────────────────────────────────────────────
# Serialisation round-trip
# ─────────────────────────────────────────────────────────────────────────────
 
class TestSerialisation:
 
    def test_round_trip_preserves_check_count(self):
        checks = [
            _check("A", "app",       Status.PASS),
            _check("B", "webserver", Status.FAIL),
            _check("C", "container", Status.WARN),
        ]
        scan = _scan("http://example.com", checks)
        data = _scan_to_dict(scan)
        restored = _dict_to_scan(data)
        assert len(restored.checks) == 3
 
    def test_round_trip_preserves_status(self):
        scan = _scan("http://example.com", [
            _check("A", "app", Status.FAIL)
        ])
        restored = _dict_to_scan(_scan_to_dict(scan))
        assert restored.checks[0].status == Status.FAIL
 
    def test_round_trip_preserves_severity(self):
        scan = _scan("http://example.com", [
            _check("A", "app", Status.FAIL, Severity.CRITICAL)
        ])
        restored = _dict_to_scan(_scan_to_dict(scan))
        assert restored.checks[0].severity == Severity.CRITICAL
 
    def test_round_trip_preserves_timestamp(self):
        ts = _ts(-3)
        scan = _scan("http://example.com", [_check("A", "app", Status.PASS)],
                     timestamp=ts)
        restored = _dict_to_scan(_scan_to_dict(scan))
        assert restored.generated_at == ts
 
 
# ─────────────────────────────────────────────────────────────────────────────
# DriftEngine — core comparison logic
# ─────────────────────────────────────────────────────────────────────────────
 
class TestDriftEngineRegressions:
 
    def test_detects_pass_to_fail_regression(self, engine):
        baseline = _scan("http://x.com", [
            _check("APP-DEBUG-001", "app", Status.PASS)
        ], timestamp=_ts(-1))
        current = _scan("http://x.com", [
            _check("APP-DEBUG-001", "app", Status.FAIL)
        ], timestamp=_ts(0))
        report = engine.compare(baseline, current)
        assert "APP-DEBUG-001" in report.regressions
 
    def test_detects_pass_to_warn_regression(self, engine):
        baseline = _scan("http://x.com", [
            _check("WS-HSTS-001", "webserver", Status.PASS)
        ], timestamp=_ts(-1))
        current = _scan("http://x.com", [
            _check("WS-HSTS-001", "webserver", Status.WARN)
        ], timestamp=_ts(0))
        report = engine.compare(baseline, current)
        assert "WS-HSTS-001" in report.regressions
 
    def test_regression_not_in_improvements(self, engine):
        baseline = _scan("http://x.com", [
            _check("A", "app", Status.PASS)
        ], timestamp=_ts(-1))
        current = _scan("http://x.com", [
            _check("A", "app", Status.FAIL)
        ], timestamp=_ts(0))
        report = engine.compare(baseline, current)
        assert "A" not in report.improvements
 
 
class TestDriftEngineImprovements:
 
    def test_detects_fail_to_pass_improvement(self, engine):
        baseline = _scan("http://x.com", [
            _check("HOST-SSH-001", "host", Status.FAIL)
        ], timestamp=_ts(-1))
        current = _scan("http://x.com", [
            _check("HOST-SSH-001", "host", Status.PASS)
        ], timestamp=_ts(0))
        report = engine.compare(baseline, current)
        assert "HOST-SSH-001" in report.improvements
        assert "HOST-SSH-001" in report.resolved_failures
 
    def test_detects_warn_to_pass_improvement(self, engine):
        baseline = _scan("http://x.com", [
            _check("A", "app", Status.WARN)
        ], timestamp=_ts(-1))
        current = _scan("http://x.com", [
            _check("A", "app", Status.PASS)
        ], timestamp=_ts(0))
        report = engine.compare(baseline, current)
        assert "A" in report.improvements
 
    def test_warn_to_pass_not_in_resolved_failures(self, engine):
        """resolved_failures is only for FAIL→PASS, not WARN→PASS."""
        baseline = _scan("http://x.com", [
            _check("A", "app", Status.WARN)
        ], timestamp=_ts(-1))
        current = _scan("http://x.com", [
            _check("A", "app", Status.PASS)
        ], timestamp=_ts(0))
        report = engine.compare(baseline, current)
        assert "A" not in report.resolved_failures
 
 
class TestDriftEngineStable:
 
    def test_stable_pass_detected(self, engine):
        baseline = _scan("http://x.com", [
            _check("A", "app", Status.PASS)
        ], timestamp=_ts(-1))
        current = _scan("http://x.com", [
            _check("A", "app", Status.PASS)
        ], timestamp=_ts(0))
        report = engine.compare(baseline, current)
        assert "A" in report.stable_passes
        assert report.regressions == []
        assert report.improvements == []
 
    def test_stable_fail_detected(self, engine):
        baseline = _scan("http://x.com", [
            _check("A", "app", Status.FAIL)
        ], timestamp=_ts(-1))
        current = _scan("http://x.com", [
            _check("A", "app", Status.FAIL)
        ], timestamp=_ts(0))
        report = engine.compare(baseline, current)
        assert "A" in report.stable_failures
 
    def test_no_changes_is_stable_trend(self, engine):
        checks = [_check("A", "app", Status.PASS), _check("B", "app", Status.FAIL)]
        baseline = _scan("http://x.com", checks, timestamp=_ts(-1))
        current  = _scan("http://x.com", checks, timestamp=_ts(0))
        report = engine.compare(baseline, current)
        assert report.overall_trend == "stable"
        assert not report.has_changes
 
 
class TestDriftEngineNewFailures:
 
    def test_new_check_that_fails_is_new_failure(self, engine):
        baseline = _scan("http://x.com", [], timestamp=_ts(-1))
        current = _scan("http://x.com", [
            _check("NEW-CHECK-001", "app", Status.FAIL)
        ], timestamp=_ts(0))
        report = engine.compare(baseline, current)
        assert "NEW-CHECK-001" in report.new_failures
 
    def test_new_check_that_passes_is_not_new_failure(self, engine):
        baseline = _scan("http://x.com", [], timestamp=_ts(-1))
        current = _scan("http://x.com", [
            _check("NEW-CHECK-001", "app", Status.PASS)
        ], timestamp=_ts(0))
        report = engine.compare(baseline, current)
        assert "NEW-CHECK-001" not in report.new_failures
 
 
class TestDriftEngineGradeAndScore:
 
    def test_grade_regression_detected(self, engine):
        """Simulate a grade drop from A to D."""
        baseline_checks = [_check(str(i), "app", Status.PASS) for i in range(10)]
        current_checks  = [_check(str(i), "app", Status.FAIL) for i in range(10)]
        baseline = _scan("http://x.com", baseline_checks, timestamp=_ts(-1))
        current  = _scan("http://x.com", current_checks,  timestamp=_ts(0))
        report = engine.compare(baseline, current)
        assert report.grade_direction == "regressed"
        assert report.score_delta < 0
 
    def test_grade_improvement_detected(self, engine):
        """Simulate a grade improvement from F to A."""
        baseline_checks = [_check(str(i), "app", Status.FAIL) for i in range(10)]
        current_checks  = [_check(str(i), "app", Status.PASS) for i in range(10)]
        baseline = _scan("http://x.com", baseline_checks, timestamp=_ts(-1))
        current  = _scan("http://x.com", current_checks,  timestamp=_ts(0))
        report = engine.compare(baseline, current)
        assert report.grade_direction == "improved"
        assert report.score_delta > 0
 
    def test_grade_delta_format(self, engine):
        baseline = _scan("http://x.com", [
            _check("A", "app", Status.PASS)
        ], timestamp=_ts(-1))
        current = _scan("http://x.com", [
            _check("A", "app", Status.FAIL)
        ], timestamp=_ts(0))
        report = engine.compare(baseline, current)
        assert "→" in report.grade_delta
 
    def test_score_delta_is_numeric(self, engine):
        baseline = _scan("http://x.com", [
            _check("A", "app", Status.FAIL)
        ], timestamp=_ts(-1))
        current = _scan("http://x.com", [
            _check("A", "app", Status.PASS)
        ], timestamp=_ts(0))
        report = engine.compare(baseline, current)
        assert isinstance(report.score_delta, float)
 
 
class TestDriftEngineOverallTrend:
 
    def test_more_improvements_than_regressions_is_improving(self, engine):
        baseline = _scan("http://x.com", [
            _check("A", "app", Status.FAIL),
            _check("B", "app", Status.FAIL),
            _check("C", "app", Status.FAIL),
            _check("D", "app", Status.PASS),
        ], timestamp=_ts(-1))
        current = _scan("http://x.com", [
            _check("A", "app", Status.PASS),  # improved
            _check("B", "app", Status.PASS),  # improved
            _check("C", "app", Status.PASS),  # improved
            _check("D", "app", Status.FAIL),  # regressed
        ], timestamp=_ts(0))
        report = engine.compare(baseline, current)
        assert report.overall_trend == "improving"
 
    def test_more_regressions_than_improvements_is_regressing(self, engine):
        baseline = _scan("http://x.com", [
            _check("A", "app", Status.PASS),
            _check("B", "app", Status.PASS),
            _check("C", "app", Status.PASS),
            _check("D", "app", Status.FAIL),
        ], timestamp=_ts(-1))
        current = _scan("http://x.com", [
            _check("A", "app", Status.FAIL),  # regressed
            _check("B", "app", Status.FAIL),  # regressed
            _check("C", "app", Status.FAIL),  # regressed
            _check("D", "app", Status.PASS),  # improved
        ], timestamp=_ts(0))
        report = engine.compare(baseline, current)
        assert report.overall_trend == "regressing"
 
 
class TestDriftEngineFirstScan:
 
    def test_first_scan_report_is_not_none(self, engine):
        scan = _scan("http://x.com", [_check("A", "app", Status.PASS)])
        report = engine.first_scan_report(scan)
        assert report is not None
 
    def test_first_scan_report_is_first_scan(self, engine):
        scan = _scan("http://x.com", [_check("A", "app", Status.PASS)])
        report = engine.first_scan_report(scan)
        assert report.is_first_scan
 
    def test_first_scan_has_no_regressions(self, engine):
        scan = _scan("http://x.com", [_check("A", "app", Status.FAIL)])
        report = engine.first_scan_report(scan)
        assert report.regressions == []
        assert report.improvements == []
 
    def test_first_scan_summary_mentions_first_scan(self, engine):
        scan = _scan("http://x.com", [_check("A", "app", Status.PASS)])
        report = engine.first_scan_report(scan)
        assert "first" in report.summary_line.lower()
 
 
class TestDriftReportSummaryLine:
 
    def test_regression_summary_mentions_regressed(self, engine):
        baseline = _scan("http://x.com", [
            _check("A", "app", Status.PASS)
        ], timestamp=_ts(-1))
        current = _scan("http://x.com", [
            _check("A", "app", Status.FAIL)
        ], timestamp=_ts(0))
        report = engine.compare(baseline, current)
        assert "regressed" in report.summary_line.lower()
 
    def test_improvement_summary_mentions_improved(self, engine):
        baseline = _scan("http://x.com", [
            _check("A", "app", Status.FAIL)
        ], timestamp=_ts(-1))
        current = _scan("http://x.com", [
            _check("A", "app", Status.PASS)
        ], timestamp=_ts(0))
        report = engine.compare(baseline, current)
        assert "improved" in report.summary_line.lower()
 
    def test_no_change_summary_says_no_change(self, engine):
        checks = [_check("A", "app", Status.PASS)]
        baseline = _scan("http://x.com", checks, timestamp=_ts(-1))
        current  = _scan("http://x.com", checks, timestamp=_ts(0))
        report = engine.compare(baseline, current)
        assert "no change" in report.summary_line.lower()
 
 
class TestDriftReportToDict:
 
    def test_to_dict_contains_all_required_keys(self, engine):
        checks = [_check("A", "app", Status.PASS)]
        baseline = _scan("http://x.com", checks, timestamp=_ts(-1))
        current  = _scan("http://x.com", checks, timestamp=_ts(0))
        report = engine.compare(baseline, current)
        d = report.to_dict()
        required_keys = [
            "target", "grade_then", "grade_now", "grade_delta",
            "score_then", "score_now", "score_delta",
            "regressions", "improvements", "overall_trend", "summary_line",
        ]
        for key in required_keys:
            assert key in d, f"Missing key: {key}"
 
    def test_to_dict_is_json_serialisable(self, engine):
        import json
        checks = [_check("A", "app", Status.FAIL)]
        baseline = _scan("http://x.com", checks, timestamp=_ts(-1))
        current  = _scan("http://x.com", checks, timestamp=_ts(0))
        report = engine.compare(baseline, current)
        # Should not raise
        serialised = json.dumps(report.to_dict())
        assert len(serialised) > 0
 
 
# ─────────────────────────────────────────────────────────────────────────────
# Utility functions
# ─────────────────────────────────────────────────────────────────────────────
 
class TestUtilityFunctions:
 
    def test_grade_direction_improvement(self):
        assert _grade_direction("D", "A") == "improved"
        assert _grade_direction("F", "C") == "improved"
 
    def test_grade_direction_regression(self):
        assert _grade_direction("A", "D") == "regressed"
        assert _grade_direction("B", "F") == "regressed"
 
    def test_grade_direction_stable(self):
        assert _grade_direction("B", "B") == "stable"
        assert _grade_direction("C", "C") == "stable"
 
    def test_elapsed_days_positive(self):
        ts_then = "2025-01-01T00:00:00Z"
        ts_now  = "2025-01-08T00:00:00Z"
        assert _elapsed_days(ts_then, ts_now) == 7.0
 
    def test_elapsed_days_sub_day(self):
        ts_then = "2025-01-01T00:00:00Z"
        ts_now  = "2025-01-01T12:00:00Z"
        assert _elapsed_days(ts_then, ts_now) == 0.5
 
    def test_elapsed_days_bad_input_returns_zero(self):
        assert _elapsed_days("", "") == 0.0
        assert _elapsed_days("not-a-date", "also-not") == 0.0
 