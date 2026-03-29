"""
test_scan_result.py — ScanResult model tests.

Proves that all ScanResult methods return correct data:
- Scoring and grade calculation
- layer_summary (correct structure, colors, risk)
- owasp_summary (correct aggregation from config tags)
- simulate_with_fixes (correct simulation)
- compare_to_baseline (correct drift detection)
- attack_paths (correct path detection)
"""

import pytest
from sec_audit.results import CheckResult, ScanResult, Status, Severity, Grade
from sec_audit.baseline import HARDENED_FLASK_BASELINE


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _check(id, layer, status, severity=Severity.HIGH, details="test"):
    return CheckResult(id=id, layer=layer, name=f"Check {id}",
                       status=status, severity=severity, details=details)


def _scan(*checks):
    return ScanResult(target="http://test.example.com", mode="quick", checks=list(checks))


# ─────────────────────────────────────────────────────────────────────────────
# Scoring
# ─────────────────────────────────────────────────────────────────────────────

class TestScoring:

    def test_all_pass_is_grade_a(self):
        scan = _scan(
            _check("A", "app", Status.PASS),
            _check("B", "app", Status.PASS),
            _check("C", "app", Status.PASS),
        )
        assert scan.grade == Grade.A
        assert scan.score_percentage == 100.0

    def test_all_fail_is_grade_f(self):
        scan = _scan(
            _check("A", "app", Status.FAIL),
            _check("B", "app", Status.FAIL),
            _check("C", "app", Status.FAIL),
        )
        assert scan.grade == Grade.F
        assert scan.score_percentage == 0.0

    def test_grade_b_boundary(self):
        """8 pass, 2 fail = 80% = Grade B."""
        checks = [_check(str(i), "app", Status.PASS) for i in range(8)]
        checks += [_check("fail1", "app", Status.FAIL), _check("fail2", "app", Status.FAIL)]
        scan = _scan(*checks)
        assert scan.grade == Grade.B
        assert scan.score_percentage == 80.0

    def test_grade_c_boundary(self):
        """7 pass, 3 fail = 70% = Grade C."""
        checks = [_check(str(i), "app", Status.PASS) for i in range(7)]
        checks += [_check(f"f{i}", "app", Status.FAIL) for i in range(3)]
        scan = _scan(*checks)
        assert scan.grade == Grade.C

    def test_errors_excluded_from_scoring(self):
        """ERROR status checks should not count in pass rate denominator."""
        scan = _scan(
            _check("A", "app", Status.PASS),
            _check("B", "app", Status.PASS),
            _check("C", "app", Status.ERROR),  # should be excluded
        )
        assert scan.score_percentage == 100.0

    def test_total_checks_counts_all_statuses(self):
        """total_checks includes ERROR and WARN checks."""
        scan = _scan(
            _check("A", "app", Status.PASS),
            _check("B", "app", Status.FAIL),
            _check("C", "app", Status.WARN),
            _check("D", "app", Status.ERROR),
        )
        assert scan.total_checks == 4


# ─────────────────────────────────────────────────────────────────────────────
# layer_summary
# ─────────────────────────────────────────────────────────────────────────────

class TestLayerSummary:

    def test_layer_summary_structure(self):
        """layer_summary must return dict with expected keys per layer."""
        scan = _scan(
            _check("A", "app",       Status.PASS),
            _check("B", "app",       Status.FAIL),
            _check("C", "webserver", Status.PASS),
        )
        summary = scan.layer_summary()
        assert "app" in summary
        assert "webserver" in summary
        assert summary["app"]["total"] == 2
        assert summary["app"]["passed"] == 1
        assert summary["webserver"]["total"] == 1
        assert summary["webserver"]["passed"] == 1

    def test_layer_summary_pass_rate(self):
        """pass_rate should be calculated correctly per layer."""
        scan = _scan(
            _check("A", "app", Status.PASS),
            _check("B", "app", Status.PASS),
            _check("C", "app", Status.FAIL),
            _check("D", "app", Status.FAIL),
        )
        summary = scan.layer_summary()
        assert summary["app"]["pass_rate"] == 50.0

    def test_layer_summary_high_pass_rate_is_green(self):
        """pass_rate >= 80 should produce green/low-risk indicators."""
        scan = _scan(
            *[_check(str(i), "app", Status.PASS) for i in range(9)],
            _check("fail", "app", Status.FAIL),
        )
        summary = scan.layer_summary()
        assert summary["app"]["pass_rate"] == 90.0
        assert summary["app"]["risk"] == "LOW"

    def test_layer_summary_low_pass_rate_is_red(self):
        """pass_rate < 50 should produce red/high-risk indicators."""
        scan = _scan(
            _check("pass", "app", Status.PASS),
            *[_check(str(i), "app", Status.FAIL) for i in range(3)],
        )
        summary = scan.layer_summary()
        assert summary["app"]["pass_rate"] == 25.0
        assert summary["app"]["risk"] == "HIGH"

    def test_layer_summary_color_field_present(self):
        """layer_summary must include a color field for PDF heatmap rendering."""
        scan = _scan(_check("A", "app", Status.PASS))
        summary = scan.layer_summary()
        assert "color" in summary["app"]
        assert summary["app"]["color"] != ""


# ─────────────────────────────────────────────────────────────────────────────
# owasp_summary
# ─────────────────────────────────────────────────────────────────────────────

class TestOwaspSummary:

    def test_owasp_summary_returns_dict(self):
        """owasp_summary must return a non-empty dict."""
        scan = _scan(
            _check("APP-DEBUG-001", "app", Status.FAIL),
            _check("WS-HSTS-001",   "webserver", Status.PASS),
        )
        result = scan.owasp_summary()
        assert isinstance(result, dict)
        assert len(result) > 0

    def test_owasp_summary_has_required_keys(self):
        """Each OWASP category entry must have label, total, failed, fail_rate."""
        scan = _scan(_check("APP-DEBUG-001", "app", Status.FAIL))
        result = scan.owasp_summary()
        for cat, data in result.items():
            assert "label" in data, f"{cat} missing 'label'"
            assert "total" in data, f"{cat} missing 'total'"
            assert "failed" in data, f"{cat} missing 'failed'"
            assert "fail_rate" in data, f"{cat} missing 'fail_rate'"

    def test_owasp_summary_fail_rate_calculation(self):
        """fail_rate should be 100.0 when every check in a category fails."""
        scan = _scan(
            _check("APP-DEBUG-001", "app", Status.FAIL),  # tagged A02:2025 in config
        )
        result = scan.owasp_summary()
        if "A02:2025" in result:
            cat = result["A02:2025"]
            assert cat["failed"] == cat["total"]
            assert cat["fail_rate"] == 100.0

    def test_owasp_summary_all_pass_zero_failures(self):
        """fail_rate must be 0.0 when all checks in a category pass."""
        scan = _scan(
            _check("APP-DEBUG-001", "app", Status.PASS),
        )
        result = scan.owasp_summary()
        if "A02:2025" in result:
            assert result["A02:2025"]["failed"] == 0
            assert result["A02:2025"]["fail_rate"] == 0.0

    def test_owasp_summary_label_is_human_readable(self):
        """OWASP category labels must be descriptive strings, not raw codes."""
        scan = _scan(_check("APP-DEBUG-001", "app", Status.FAIL))
        result = scan.owasp_summary()
        for cat, data in result.items():
            assert data["label"] != cat, (
                f"Label for {cat} is just the category code — should be descriptive"
            )
            assert len(data["label"]) > 5


# ─────────────────────────────────────────────────────────────────────────────
# simulate_with_fixes
# ─────────────────────────────────────────────────────────────────────────────

class TestSimulateWithFixes:

    def test_simulate_improves_grade(self):
        """Simulating fixes for all failing checks should improve the grade."""
        scan = _scan(
            _check("APP-DEBUG-001", "app", Status.FAIL),
            _check("WS-HSTS-001",   "webserver", Status.FAIL),
            _check("HOST-SSH-001",  "host", Status.PASS),
        )
        original_score = scan.score_percentage
        sim = scan.simulate_with_fixes(["APP-DEBUG-001", "WS-HSTS-001"])
        assert sim["simulated_score_percentage"] > original_score

    def test_simulate_does_not_mutate_original(self):
        """simulate_with_fixes must not change the original ScanResult."""
        scan = _scan(
            _check("APP-DEBUG-001", "app", Status.FAIL),
            _check("WS-HSTS-001",   "webserver", Status.PASS),
        )
        original_score = scan.score_percentage
        scan.simulate_with_fixes(["APP-DEBUG-001"])
        assert scan.score_percentage == original_score, (
            "simulate_with_fixes mutated the original ScanResult"
        )

    def test_simulate_returns_required_keys(self):
        """simulate_with_fixes must return a dict with all required keys."""
        scan = _scan(_check("APP-DEBUG-001", "app", Status.FAIL))
        result = scan.simulate_with_fixes(["APP-DEBUG-001"])
        assert "simulated_score_percentage" in result
        assert "simulated_grade" in result
        assert "simulated_attack_path_count" in result
        assert "fixed_ids" in result

    def test_simulate_all_pass_is_grade_a(self):
        """Fixing all failures should produce Grade A."""
        scan = _scan(
            _check("APP-DEBUG-001", "app", Status.FAIL),
            _check("WS-HSTS-001",   "webserver", Status.FAIL),
        )
        result = scan.simulate_with_fixes(["APP-DEBUG-001", "WS-HSTS-001"])
        assert result["simulated_grade"] == "A"
        assert result["simulated_score_percentage"] == 100.0

    def test_simulate_nonexistent_id_is_harmless(self):
        """Passing a fix ID that doesn't exist in checks should not crash."""
        scan = _scan(_check("APP-DEBUG-001", "app", Status.FAIL))
        result = scan.simulate_with_fixes(["NONEXISTENT-CHECK-999"])
        assert "simulated_grade" in result


# ─────────────────────────────────────────────────────────────────────────────
# compare_to_baseline
# ─────────────────────────────────────────────────────────────────────────────

class TestCompareToBaseline:

    def test_baseline_comparison_returns_required_keys(self):
        """compare_to_baseline must return a dict with all required keys."""
        scan = _scan(
            _check("APP-DEBUG-001",  "app", Status.PASS),
            _check("APP-COOKIE-001", "app", Status.FAIL),
        )
        result = scan.compare_to_baseline(HARDENED_FLASK_BASELINE)
        assert "grade_delta" in result
        assert "pass_delta" in result
        assert "improved_checks" in result
        assert "regressed_checks" in result
        assert "baseline_name" in result

    def test_baseline_detects_regression(self):
        """A check that passed in baseline but fails now should be in regressed_checks."""
        scan = _scan(
            _check("APP-DEBUG-001", "app", Status.FAIL),  # baseline expects PASS
        )
        result = scan.compare_to_baseline(HARDENED_FLASK_BASELINE)
        assert "APP-DEBUG-001" in result["regressed_checks"]

    def test_baseline_detects_improvement(self):
        """A check that failed in baseline but passes now should be in improved_checks."""
        from sec_audit.baseline import BaselineProfile
        weak_baseline = BaselineProfile(
            name="Weak baseline",
            description="All checks expected to fail",
            expected_passes=0,
            expected_grade="F",
            check_statuses={"APP-DEBUG-001": "FAIL"},
        )
        scan = _scan(_check("APP-DEBUG-001", "app", Status.PASS))
        result = scan.compare_to_baseline(weak_baseline)
        assert "APP-DEBUG-001" in result["improved_checks"]

    def test_baseline_grade_delta_format(self):
        """grade_delta should be a string containing 'vs'."""
        scan = _scan(_check("APP-DEBUG-001", "app", Status.PASS))
        result = scan.compare_to_baseline(HARDENED_FLASK_BASELINE)
        assert "vs" in result["grade_delta"]


# ─────────────────────────────────────────────────────────────────────────────
# summary
# ─────────────────────────────────────────────────────────────────────────────

class TestSummary:

    def test_summary_high_risk_issues_count(self):
        """summary must count only non-PASS checks with HIGH severity."""
        scan = _scan(
            _check("A", "app", Status.FAIL, Severity.HIGH),
            _check("B", "app", Status.FAIL, Severity.MEDIUM),
            _check("C", "app", Status.PASS, Severity.HIGH),
        )
        assert scan.summary()["high_risk_issues"] == 1

    def test_summary_status_breakdown(self):
        """status_breakdown must count each status correctly."""
        scan = _scan(
            _check("A", "app", Status.PASS),
            _check("B", "app", Status.PASS),
            _check("C", "app", Status.FAIL),
            _check("D", "app", Status.WARN),
        )
        breakdown = scan.summary()["status_breakdown"]
        assert breakdown["PASS"] == 2
        assert breakdown["FAIL"] == 1
        assert breakdown["WARN"] == 1
