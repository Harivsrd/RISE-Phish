"""SQLite persistence layer for RISE-Phish analysis records.

Provides synchronous and async-friendly storage for complete forensic analysis records,
including multi-representation sets, CRCE metrics, SLM reasoning, decision verdicts,
and dual-audience explainability reports using Python's native sqlite3.
"""
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

from backend.app.core.config import get_settings

logger = logging.getLogger("rise_phish.storage")


def get_db_path() -> str:
    """Resolves the SQLite database file path from application settings."""
    settings = get_settings()
    db_url = settings.SQLITE_DB_URL
    if db_url.startswith("sqlite:///"):
        path_str = db_url[len("sqlite:///"):]
    elif db_url.startswith("sqlite://"):
        path_str = db_url[len("sqlite://"):]
    else:
        path_str = "rise_phish.db"
    
    # Ensure parent directory exists if path contains directories
    parent_dir = os.path.dirname(path_str)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)
    return path_str


class DatabaseManager:
    """Manages SQLite connection lifecycle and schema operations."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path or get_db_path()

    def get_connection(self) -> sqlite3.Connection:
        """Creates a connection with WAL mode and row factory enabled."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def init_db(self) -> None:
        """Initializes database tables and performance indexes."""
        with self.get_connection() as conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS analysis_records (
                analysis_id TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                status TEXT NOT NULL,
                verdict TEXT NOT NULL,
                recommended_action TEXT NOT NULL,
                composite_threat_score REAL NOT NULL,
                confidence_score REAL NOT NULL,
                target_brand TEXT,
                registered_domain TEXT,
                visual_normalization_convergence INTEGER NOT NULL,
                report_json TEXT NOT NULL,
                error_message TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT
            );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_analysis_url ON analysis_records(url);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_analysis_created_at ON analysis_records(created_at DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_analysis_verdict ON analysis_records(verdict);")
            conn.commit()
        logger.info(f"SQLite database initialized at {self.db_path}")

    def save_record(
        self,
        analysis_id: str,
        url: str,
        status: str,
        verdict: str,
        recommended_action: str,
        composite_threat_score: float,
        confidence_score: float,
        target_brand: Optional[str],
        registered_domain: Optional[str],
        visual_normalization_convergence: bool,
        report_json: str,
        created_at: str,
        completed_at: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> None:
        """Inserts or updates an analysis record."""
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO analysis_records (
                    analysis_id, url, status, verdict, recommended_action,
                    composite_threat_score, confidence_score, target_brand,
                    registered_domain, visual_normalization_convergence,
                    report_json, error_message, created_at, completed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(analysis_id) DO UPDATE SET
                    url=excluded.url,
                    status=excluded.status,
                    verdict=excluded.verdict,
                    recommended_action=excluded.recommended_action,
                    composite_threat_score=excluded.composite_threat_score,
                    confidence_score=excluded.confidence_score,
                    target_brand=excluded.target_brand,
                    registered_domain=excluded.registered_domain,
                    visual_normalization_convergence=excluded.visual_normalization_convergence,
                    report_json=excluded.report_json,
                    error_message=excluded.error_message,
                    completed_at=excluded.completed_at
                """,
                (
                    analysis_id,
                    url,
                    status,
                    verdict,
                    recommended_action,
                    composite_threat_score,
                    confidence_score,
                    target_brand,
                    registered_domain,
                    1 if visual_normalization_convergence else 0,
                    report_json,
                    error_message,
                    created_at,
                    completed_at,
                ),
            )
            conn.commit()

    def get_record(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves an analysis record by ID."""
        with self.get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM analysis_records WHERE analysis_id = ?",
                (analysis_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return dict(row)

    def find_latest_by_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Retrieves the most recent completed record for a given URL."""
        with self.get_connection() as conn:
            cur = conn.execute(
                """
                SELECT * FROM analysis_records 
                WHERE url = ? AND status = 'COMPLETED'
                ORDER BY created_at DESC LIMIT 1
                """,
                (url,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return dict(row)

    def list_records(
        self,
        limit: int = 50,
        offset: int = 0,
        verdict: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Lists records with pagination and optional verdict filter."""
        with self.get_connection() as conn:
            if verdict:
                count_cur = conn.execute(
                    "SELECT COUNT(*) FROM analysis_records WHERE verdict = ?",
                    (verdict.upper(),),
                )
                total = count_cur.fetchone()[0]
                cur = conn.execute(
                    """
                    SELECT analysis_id, url, status, verdict, recommended_action,
                           composite_threat_score, confidence_score, target_brand,
                           registered_domain, visual_normalization_convergence,
                           created_at, completed_at
                    FROM analysis_records 
                    WHERE verdict = ? 
                    ORDER BY created_at DESC 
                    LIMIT ? OFFSET ?
                    """,
                    (verdict.upper(), limit, offset),
                )
            else:
                count_cur = conn.execute("SELECT COUNT(*) FROM analysis_records")
                total = count_cur.fetchone()[0]
                cur = conn.execute(
                    """
                    SELECT analysis_id, url, status, verdict, recommended_action,
                           composite_threat_score, confidence_score, target_brand,
                           registered_domain, visual_normalization_convergence,
                           created_at, completed_at
                    FROM analysis_records 
                    ORDER BY created_at DESC 
                    LIMIT ? OFFSET ?
                    """,
                    (limit, offset),
                )
            rows = [dict(r) for r in cur.fetchall()]
            return rows, total

    def delete_record(self, analysis_id: str) -> bool:
        """Deletes an analysis record by ID."""
        with self.get_connection() as conn:
            cur = conn.execute(
                "DELETE FROM analysis_records WHERE analysis_id = ?",
                (analysis_id,),
            )
            conn.commit()
            return cur.rowcount > 0

    def get_stats(self) -> Dict[str, Any]:
        """Computes system-wide aggregate telemetry and security metrics."""
        with self.get_connection() as conn:
            total_cur = conn.execute("SELECT COUNT(*) FROM analysis_records")
            total = total_cur.fetchone()[0]

            phish_cur = conn.execute("SELECT COUNT(*) FROM analysis_records WHERE verdict = 'PHISHING'")
            phishing = phish_cur.fetchone()[0]

            safe_cur = conn.execute("SELECT COUNT(*) FROM analysis_records WHERE verdict = 'SAFE'")
            safe = safe_cur.fetchone()[0]

            investigate_cur = conn.execute("SELECT COUNT(*) FROM analysis_records WHERE verdict = 'INVESTIGATE'")
            investigate = investigate_cur.fetchone()[0]

            conv_cur = conn.execute(
                "SELECT COUNT(*) FROM analysis_records WHERE visual_normalization_convergence = 1"
            )
            convergences = conv_cur.fetchone()[0]

            avg_cur = conn.execute("SELECT AVG(composite_threat_score) FROM analysis_records WHERE status = 'COMPLETED'")
            avg_threat = avg_cur.fetchone()[0] or 0.0

            brands_cur = conn.execute(
                """
                SELECT target_brand, COUNT(*) as cnt 
                FROM analysis_records 
                WHERE target_brand IS NOT NULL AND target_brand != ''
                GROUP BY target_brand 
                ORDER BY cnt DESC 
                LIMIT 10
                """
            )
            top_brands = {row["target_brand"]: row["cnt"] for row in brands_cur.fetchall()}

            return {
                "total_scans": total,
                "phishing_detected": phishing,
                "safe_sites": safe,
                "investigate_sites": investigate,
                "visual_convergences_detected": convergences,
                "average_threat_score": round(float(avg_threat), 4),
                "top_targeted_brands": top_brands,
            }


# Singleton database manager instance
_db_manager: Optional[DatabaseManager] = None


def get_db_manager() -> DatabaseManager:
    """Returns the application-wide DatabaseManager singleton."""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
        _db_manager.init_db()
    return _db_manager
