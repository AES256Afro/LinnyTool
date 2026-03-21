"""SQLite scan history with trend tracking.

Direct port of the WinnyTool history pattern: two tables (scans + findings),
WAL journal mode, foreign keys with cascading deletes, indexed for performance.
"""

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from core import logger


DEFAULT_DB_PATH = Path.home() / ".linnytool" / "history.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S', 'now', 'localtime')),
    scan_type TEXT NOT NULL,
    overall_grade TEXT,
    overall_score REAL,
    duration_seconds REAL,
    distro TEXT,
    kernel TEXT,
    hostname TEXT,
    total_findings INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    category TEXT NOT NULL,
    check_name TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('Critical','High','Medium','Low','Info')),
    status TEXT NOT NULL CHECK(status IN ('Pass','Fail','Error','Skip')),
    description TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
"""


class HistoryDB:
    """SQLite-backed scan history database."""

    def __init__(self, db_path: Path = DEFAULT_DB_PATH):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def _init_schema(self) -> None:
        """Create tables if they don't exist."""
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def save_scan(
        self,
        scan_type: str,
        grade: str = "",
        score: float = 0.0,
        duration: float = 0.0,
        distro: str = "",
        kernel: str = "",
        hostname: str = "",
    ) -> int:
        """Insert a scan record. Returns the scan_id."""
        cur = self.conn.execute(
            """INSERT INTO scans (scan_type, overall_grade, overall_score,
               duration_seconds, distro, kernel, hostname)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (scan_type, grade, score, duration, distro, kernel, hostname),
        )
        self.conn.commit()
        scan_id = cur.lastrowid
        logger.debug("Saved scan %d: type=%s grade=%s", scan_id, scan_type, grade)
        return scan_id

    def save_finding(
        self,
        scan_id: int,
        category: str,
        check_name: str,
        severity: str,
        status: str,
        description: str = "",
        remediation: str = "",
    ) -> None:
        """Insert a single finding."""
        self.conn.execute(
            """INSERT INTO findings (scan_id, category, check_name, severity,
               status, description, remediation)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, category, check_name, severity, status, description, remediation),
        )
        self.conn.commit()

    def save_findings_batch(self, scan_id: int, findings: list[dict]) -> None:
        """Bulk insert findings and update scan severity counts."""
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

        for f in findings:
            severity = f.get("severity", "Info")
            self.conn.execute(
                """INSERT INTO findings (scan_id, category, check_name, severity,
                   status, description, remediation)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    f.get("category", ""),
                    f.get("check_name", ""),
                    severity,
                    f.get("status", "Fail"),
                    f.get("description", ""),
                    f.get("remediation", ""),
                ),
            )
            if severity in counts:
                counts[severity] += 1

        # Update scan counts
        self.conn.execute(
            """UPDATE scans SET total_findings = ?, critical_count = ?,
               high_count = ?, medium_count = ?, low_count = ?
               WHERE id = ?""",
            (len(findings), counts["Critical"], counts["High"],
             counts["Medium"], counts["Low"], scan_id),
        )
        self.conn.commit()

    def get_scans(self, limit: int = 20) -> list[dict]:
        """Get recent scan records, newest first."""
        rows = self.conn.execute(
            "SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_findings(self, scan_id: int) -> list[dict]:
        """Get all findings for a scan, ordered by severity."""
        severity_order = "CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END"
        rows = self.conn.execute(
            f"SELECT * FROM findings WHERE scan_id = ? ORDER BY {severity_order}",
            (scan_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_trend(self, last_n: int = 10) -> list[dict]:
        """Get last N scan scores for trend display."""
        rows = self.conn.execute(
            """SELECT timestamp, scan_type, overall_grade, overall_score,
                      total_findings, critical_count, high_count
               FROM scans ORDER BY timestamp DESC LIMIT ?""",
            (last_n,),
        ).fetchall()
        return [dict(r) for r in reversed(rows)]

    def delete_scan(self, scan_id: int) -> None:
        """Delete a scan and its findings (CASCADE)."""
        self.conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        self.conn.commit()

    def clear_all(self) -> None:
        """Delete all scan history."""
        self.conn.execute("DELETE FROM findings")
        self.conn.execute("DELETE FROM scans")
        self.conn.commit()
        logger.info("Cleared all scan history")

    def close(self) -> None:
        """Close the database connection."""
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
