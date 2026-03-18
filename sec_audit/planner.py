"""
Hardening plan and what-if simulation logic.

This module builds on ScanResult and the static check definitions
to provide:
- a prioritised hardening plan (Day 1 / Day 7 / Day 30)
- a simple what-if simulator for fixed checks
"""

from typing import List, Dict
from sec_audit.results import ScanResult
from sec_audit.config import CHECKS


# Build an index of check metadata from config
_CHECK_INDEX: Dict[str, dict] = {c["id"]: c for c in CHECKS}


def _severity_score(severity: str) -> float:
    mapping = {
        "CRITICAL": 4.0,
        "HIGH": 3.0,
        "MEDIUM": 2.0,
        "LOW": 1.0,
    }
    return mapping.get(severity.upper(), 1.0)


def _effort_score(effort: str | None) -> float:
    if not effort:
        return 2.0  # default MEDIUM
    effort = effort.upper()
    if effort == "LOW":
        return 1.0
    if effort == "HIGH":
        return 3.0
    return 2.0  # MEDIUM / fallback


def build_hardening_plan(scan_result: ScanResult) -> List[dict]:
    """
    Build a prioritised hardening plan from a ScanResult.

    Returns a list of dicts with:
    - id, name, layer, severity, status
    - priority_score (float)
    - bucket: DAY_1 / DAY_7 / DAY_30
    - recommendation: text
    """
    items: List[dict] = []

    for c in scan_result.checks:
        if c.status.value == "PASS":
            continue

        cfg = _CHECK_INDEX.get(c.id, {})
        effort = cfg.get("effort")
        impact_weight = float(cfg.get("impact_weight", 1.0))

        sev_score = _severity_score(c.severity.value)
        eff_score = _effort_score(effort)
        priority_score = (sev_score * impact_weight) / eff_score

        items.append(
            {
                "id": c.id,
                "name": c.name,
                "layer": c.layer,
                "severity": c.severity.value,
                "status": c.status.value,
                "priority_score": round(priority_score, 2),
                "recommendation": cfg.get("recommendation", ""),
            }
        )

    # Sort by descending priority_score
    items.sort(key=lambda i: i["priority_score"], reverse=True)

    total = len(items)
    if total == 0:
        return []

    # Split into rough buckets: top 30% Day 1, next 40% Day 7, rest Day 30
    day1_cut = max(1, int(total * 0.3))
    day7_cut = max(day1_cut + 1, int(total * 0.7))

    for idx, item in enumerate(items):
        if idx < day1_cut:
            item["bucket"] = "DAY_1"
        elif idx < day7_cut:
            item["bucket"] = "DAY_7"
        else:
            item["bucket"] = "DAY_30"

    return items


def simulate_with_fixes(scan_result: ScanResult, fix_ids: List[str]) -> dict:
    """
    Wrapper around ScanResult.simulate_with_fixes if you want to call it
    from outside without touching results.py.
    """
    return scan_result.simulate_with_fixes(fix_ids)