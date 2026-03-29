"""
storage/history.py — SQLite-backed scan history store.
 
Every completed scan is automatically persisted to:
    ~/.stacksentry/history.db
 
Design principles:
- Local-first: data never leaves the machine by default
- Zero configuration: database is created on first use
- Transparent: scans save automatically, no flags required
- Fast: indexed on target + timestamp for instant retrieval
 
Schema
------
scan_history
    id               INTEGER  PK autoincrement
    target           TEXT     the scanned URL
    mode             TEXT     quick | full
    scanned_at       TEXT     ISO 8601 UTC timestamp
    grade            TEXT     A | B | C | D | F
    score_percentage REAL     0.0 – 100.0
    total_checks     INTEGER
    passed_checks    INTEGER
    failed_checks    INTEGER
    warned_checks    INTEGER
    high_risk_issues INTEGER
    stack_fingerprint TEXT
    scan_json        TEXT     full ScanResult serialised as JSON
"""
 
import json
import sqlite3
import pathlib
from datetime import datetime, timezone
from typing import Optional
 
from sec_audit.results import ScanResult, CheckResult, Status, Severity
 
 
# ── Database location ─────────────────────────────────────────────────────────
 
def _default_db_path() -> pathlib.Path:
    """
    Return the default database path: ~/.stacksentry/history.db
 
    The directory is created automatically if it does not exist.
    This follows the XDG convention of storing user data in a
    hidden dot-directory under the home folder.
    """
    db_dir = pathlib.Path.home() / ".stacksentry"
    db_dir.mkdir(parents=True, exist_ok=True)
    return db_dir / "history.db"
 
 
# ── Serialisation helpers ─────────────────────────────────────────────────────
 
def _scan_to_dict(scan: ScanResult) -> dict:
    """
    Serialise a ScanResult to a plain dict suitable for JSON storage.
 
    We store the full check list so the drift engine can compare
    individual check statuses between any two historical scans.
    """
    return {
        "target": scan.target,
        "mode": scan.mode,
        "generated_at": scan.generated_at,
        "grade": scan.grade.value,
        "score_percentage": scan.score_percentage,
        "total_checks": scan.total_checks,
        "stack_fingerprint": scan.stack_fingerprint,
        "checks": [
            {
                "id": c.id,
                "layer": c.layer,
                "name": c.name,
                "status": c.status.value,
                "severity": c.severity.value,
                "details": c.details,
            }
            for c in scan.checks
        ],
    }
 
 
def _dict_to_scan(data: dict) -> ScanResult:
    """
    Deserialise a stored dict back into a ScanResult.
 
    Used when loading historical scans for drift comparison.
    """
    checks = [
        CheckResult(
            id=c["id"],
            layer=c["layer"],
            name=c["name"],
            status=Status(c["status"]),
            severity=Severity(c["severity"]),
            details=c["details"],
        )
        for c in data.get("checks", [])
    ]
    scan = ScanResult(
        target=data["target"],
        mode=data["mode"],
        checks=checks,
    )
    # Restore the original timestamp rather than generating a new one
    scan.generated_at = data.get("generated_at", scan.generated_at)
    return scan
 
 
# ── ScanHistory ───────────────────────────────────────────────────────────────
 
class ScanHistory:
    """
    Persistent store for StackSentry scan results.
 
    Usage
    -----
        history = ScanHistory()                  # uses ~/.stacksentry/history.db
        history = ScanHistory("/custom/path.db") # custom location
 
        history.save(scan_result)                # persist a scan
        history.latest(target)                   # most recent scan for a URL
        history.all_for(target)                  # full timeline for a URL
        history.count(target)                    # how many scans exist
        history.delete_all(target)               # wipe history for a URL
    """
 
    CREATE_TABLE = """
        CREATE TABLE IF NOT EXISTS scan_history (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            target           TEXT    NOT NULL,
            mode             TEXT    NOT NULL,
            scanned_at       TEXT    NOT NULL,
            grade            TEXT    NOT NULL,
            score_percentage REAL    NOT NULL,
            total_checks     INTEGER NOT NULL,
            passed_checks    INTEGER NOT NULL,
            failed_checks    INTEGER NOT NULL,
            warned_checks    INTEGER NOT NULL,
            high_risk_issues INTEGER NOT NULL,
            stack_fingerprint TEXT,
            scan_json        TEXT    NOT NULL
        );
    """
 
    CREATE_INDEXES = [
        "CREATE INDEX IF NOT EXISTS idx_target     ON scan_history(target);",
        "CREATE INDEX IF NOT EXISTS idx_scanned_at ON scan_history(scanned_at);",
        "CREATE INDEX IF NOT EXISTS idx_target_at  ON scan_history(target, scanned_at);",
    ]
 
    def __init__(self, db_path: Optional[str] = None):
        self._db_path = pathlib.Path(db_path) if db_path else _default_db_path()
        self._init_db()
 
    # ── Internals ─────────────────────────────────────────────────────────────
 
    def _connect(self) -> sqlite3.Connection:
        """Open a connection with foreign keys and WAL mode enabled."""
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")   # safe concurrent writes
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn
 
    def _init_db(self) -> None:
        """Create the table and indexes on first use."""
        with self._connect() as conn:
            conn.execute(self.CREATE_TABLE)
            for idx in self.CREATE_INDEXES:
                conn.execute(idx)
 
    # ── Public API ────────────────────────────────────────────────────────────
 
    def save(self, scan: ScanResult) -> int:
        """
        Persist a completed scan result.
 
        Returns the new row ID so callers can reference this scan.
 
        This is called automatically by cli.py after every scan,
        so users do not need to think about it.
        """
        summary = scan.summary()
        status_counts = summary["status_breakdown"]
 
        scanned_at = scan.generated_at or datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")
 
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO scan_history (
                    target, mode, scanned_at,
                    grade, score_percentage,
                    total_checks, passed_checks, failed_checks, warned_checks,
                    high_risk_issues, stack_fingerprint, scan_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan.target,
                    scan.mode,
                    scanned_at,
                    scan.grade.value,
                    scan.score_percentage,
                    scan.total_checks,
                    status_counts.get("PASS", 0),
                    status_counts.get("FAIL", 0),
                    status_counts.get("WARN", 0),
                    summary["high_risk_issues"],
                    scan.stack_fingerprint,
                    json.dumps(_scan_to_dict(scan)),
                ),
            )
            return cursor.lastrowid
 
    def latest(self, target: str) -> Optional[ScanResult]:
        """
        Return the most recent scan result for a given target URL.
 
        Returns None if no scans exist for this target — callers
        must handle this case (it means it is the first ever scan).
        """
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT scan_json FROM scan_history
                WHERE target = ?
                ORDER BY scanned_at DESC
                LIMIT 1
                """,
                (target,),
            ).fetchone()
 
        if row is None:
            return None
        return _dict_to_scan(json.loads(row["scan_json"]))
 
    def previous(self, target: str, before_timestamp: str) -> Optional[ScanResult]:
        """
        Return the most recent scan for a target that occurred
        strictly before a given timestamp.
 
        Useful for comparing the current scan against the one
        immediately before it without counting the current one.
        """
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT scan_json FROM scan_history
                WHERE target = ? AND scanned_at < ?
                ORDER BY scanned_at DESC
                LIMIT 1
                """,
                (target, before_timestamp),
            ).fetchone()
 
        if row is None:
            return None
        return _dict_to_scan(json.loads(row["scan_json"]))
 
    def all_for(self, target: str, limit: int = 30) -> list[dict]:
        """
        Return summary rows for all scans of a target, newest first.
 
        Returns lightweight dicts (not full ScanResult objects) for
        efficiency — loading the full JSON for 30 scans is wasteful
        when all you need is the timeline.
 
        Each dict contains:
            scanned_at, grade, score_percentage, passed_checks,
            failed_checks, warned_checks, high_risk_issues, mode
        """
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    scanned_at, grade, score_percentage,
                    passed_checks, failed_checks, warned_checks,
                    high_risk_issues, total_checks, mode, stack_fingerprint
                FROM scan_history
                WHERE target = ?
                ORDER BY scanned_at DESC
                LIMIT ?
                """,
                (target, limit),
            ).fetchall()
 
        return [dict(row) for row in rows]
 
    def count(self, target: str) -> int:
        """Return the number of stored scans for a target."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) as n FROM scan_history WHERE target = ?",
                (target,),
            ).fetchone()
        return row["n"]
 
    def all_targets(self) -> list[str]:
        """
        Return all distinct targets that have been scanned,
        ordered by most recently scanned first.
        """
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT DISTINCT target,
                       MAX(scanned_at) as last_seen
                FROM scan_history
                GROUP BY target
                ORDER BY last_seen DESC
                """
            ).fetchall()
        return [row["target"] for row in rows]
 
    def delete_all(self, target: str) -> int:
        """
        Delete all stored scans for a target.
 
        Returns the number of rows deleted.
        Useful for GDPR-style data removal or resetting a target.
        """
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM scan_history WHERE target = ?",
                (target,),
            )
            return cursor.rowcount
 
    @property
    def db_path(self) -> pathlib.Path:
        """The filesystem path to the SQLite database."""
        return self._db_path
 
    def __repr__(self) -> str:
        return f"ScanHistory(db='{self._db_path}')"
 