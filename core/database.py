"""Database layer for storing scan results using SQLite."""

import json
import sqlite3
from datetime import datetime, timezone
from typing import Optional
from .config import Finding, Severity, FindingType


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    config TEXT NOT NULL,
    status TEXT DEFAULT 'running',
    started_at TEXT NOT NULL,
    completed_at TEXT,
    findings_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    url TEXT NOT NULL,
    parameter TEXT NOT NULL,
    payload TEXT NOT NULL,
    evidence TEXT NOT NULL,
    request TEXT DEFAULT '',
    response TEXT DEFAULT '',
    remediation TEXT DEFAULT '',
    confidence REAL DEFAULT 1.0,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS recon (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    url TEXT NOT NULL,
    method TEXT DEFAULT 'GET',
    status_code INTEGER,
    content_length INTEGER,
    content_type TEXT,
    tech TEXT DEFAULT '',
    forms TEXT DEFAULT '[]',
    links TEXT DEFAULT '[]',
    params TEXT DEFAULT '[]',
    depth INTEGER DEFAULT 0,
    discovered_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_recon_scan ON recon(scan_id);
"""


class Database:
    def __init__(self, path: str = "webbreaker.db"):
        self.path = path
        self._conn: Optional[sqlite3.Connection] = None

    def connect(self):
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)

    def close(self):
        if self._conn:
            self._conn.close()

    def create_scan(self, scan_id: str, target: str, config: dict):
        self._conn.execute(
            "INSERT INTO scans (id, target, config, started_at) VALUES (?, ?, ?, ?)",
            (scan_id, target, json.dumps(config), datetime.now(timezone.utc).isoformat()),
        )
        self._conn.commit()

    def update_scan_status(self, scan_id: str, status: str, findings_count: int = 0):
        self._conn.execute(
            "UPDATE scans SET status=?, findings_count=?, completed_at=? WHERE id=?",
            (status, findings_count, datetime.now(timezone.utc).isoformat(), scan_id),
        )
        self._conn.commit()

    def insert_finding(self, scan_id: str, finding: Finding):
        ts = finding.timestamp or datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            """INSERT INTO findings (scan_id, type, severity, url, parameter, payload,
               evidence, request, response, remediation, confidence, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id, finding.finding_type.value, finding.severity.value,
                finding.url, finding.parameter, finding.payload, finding.evidence,
                finding.request, finding.response, finding.remediation,
                finding.confidence, ts,
            ),
        )
        self._conn.commit()

    def insert_recon(self, scan_id: str, url: str, method: str = "GET",
                     status_code: int = 0, content_length: int = 0,
                     content_type: str = "", tech: str = "",
                     forms: list = None, links: list = None,
                     params: list = None, depth: int = 0):
        self._conn.execute(
            """INSERT INTO recon (scan_id, url, method, status_code, content_length,
               content_type, tech, forms, links, params, depth, discovered_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id, url, method, status_code, content_length, content_type,
                tech, json.dumps(forms or []), json.dumps(links or []),
                json.dumps(params or []), depth,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self._conn.commit()

    def get_findings(self, scan_id: str, severity: Optional[str] = None) -> list[dict]:
        if severity:
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE scan_id=? AND severity=? ORDER BY id",
                (scan_id, severity),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE scan_id=? ORDER BY id", (scan_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_recon(self, scan_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM recon WHERE scan_id=? ORDER BY depth, id", (scan_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_scan(self, scan_id: str) -> Optional[dict]:
        row = self._conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return dict(row) if row else None

    def list_scans(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM scans ORDER BY started_at DESC").fetchall()
        return [dict(r) for r in rows]

    def delete_scan(self, scan_id: str):
        self._conn.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
        self._conn.execute("DELETE FROM recon WHERE scan_id=?", (scan_id,))
        self._conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        self._conn.commit()

    def get_stats(self, scan_id: str) -> dict:
        findings = self.get_findings(scan_id)
        by_severity = {}
        by_type = {}
        for f in findings:
            by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
            by_type[f["type"]] = by_type.get(f["type"], 0) + 1
        recon = self.get_recon(scan_id)
        return {
            "scan_id": scan_id,
            "total_findings": len(findings),
            "by_severity": by_severity,
            "by_type": by_type,
            "urls_discovered": len(recon),
        }