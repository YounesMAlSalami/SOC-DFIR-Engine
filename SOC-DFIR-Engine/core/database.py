# File: core/database.py
# Project: Log Story Studio (LSS) - Production Forensic Engine
# Python Version: 3.13 (Standard Library Only)

import sqlite3
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple


class ForensicDatabase:
    """
    Manages the SQLite forensic vault, enforcing strict referential integrity,
    SHA-256 deduplication, host-centric isolation indexes, and atomic batch commits.
    """

    def __init__(self, db_path: str = "lss_investigation.db") -> None:
        self.db_path = Path(db_path).resolve()
        self._initialize_schema()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA temp_store = MEMORY;")
        conn.execute("PRAGMA cache_size = -64000;")  # 64MB RAM cache for fast CTEs
        return conn

    def _initialize_schema(self) -> None:
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # 1. Traceability Chain Vault (Raw Evidence & Cryptographic Seal)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS evidence_vault (
                    evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_file TEXT NOT NULL,
                    line_number INTEGER NOT NULL,
                    byte_offset INTEGER NOT NULL,
                    sha256_hash TEXT NOT NULL UNIQUE,
                    raw_payload TEXT NOT NULL,
                    ingested_at_utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
                );
            """)

            # 2. Canonical Event Model (Unified Normalized Telemetry + De-obfuscation + MITRE)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS canonical_events (
                    event_uid INTEGER PRIMARY KEY AUTOINCREMENT,
                    evidence_id INTEGER NOT NULL UNIQUE,
                    timestamp_utc TEXT NOT NULL,
                    host TEXT NOT NULL,
                    log_source_type TEXT NOT NULL,
                    event_code INTEGER NOT NULL,
                    event_category TEXT NOT NULL,
                    user_name TEXT NOT NULL,
                    logon_id TEXT NOT NULL,
                    process_guid TEXT NOT NULL,
                    process_id INTEGER,
                    parent_process_guid TEXT NOT NULL,
                    parent_process_id INTEGER,
                    image_path TEXT NOT NULL,
                    parent_image_path TEXT NOT NULL,
                    command_line TEXT NOT NULL,
                    decoded_payload TEXT NOT NULL DEFAULT '',
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    dst_port INTEGER,
                    target_filename TEXT NOT NULL,
                    mitre_tags_json TEXT NOT NULL DEFAULT '[]',
                    risk_score INTEGER NOT NULL DEFAULT 0,
                    confidence_score INTEGER NOT NULL DEFAULT 100,
                    FOREIGN KEY (evidence_id) REFERENCES evidence_vault(evidence_id) ON DELETE CASCADE
                );
            """)

            # 3. Deterministic Attack Chains & Findings Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS forensic_findings (
                    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host TEXT NOT NULL,
                    chain_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    user_name TEXT NOT NULL,
                    logon_id TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    root_pid INTEGER,
                    root_process_guid TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    deterministic_proof TEXT NOT NULL,
                    mitre_tactics_json TEXT NOT NULL,
                    evidence_chain_json TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
                );
            """)

            # 4. Cross-Host Lateral Movement Proofs Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS lateral_movements (
                    pivot_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_host TEXT NOT NULL,
                    target_host TEXT NOT NULL,
                    pivot_src_ip TEXT NOT NULL,
                    pivot_dst_ip TEXT NOT NULL,
                    pivot_port INTEGER,
                    egress_time_utc TEXT NOT NULL,
                    ingress_time_utc TEXT NOT NULL,
                    source_process TEXT NOT NULL,
                    target_user TEXT NOT NULL,
                    target_logon_id TEXT NOT NULL,
                    egress_sha256 TEXT NOT NULL,
                    egress_line INTEGER NOT NULL,
                    ingress_sha256 TEXT NOT NULL,
                    ingress_line INTEGER NOT NULL,
                    proof_narrative TEXT NOT NULL
                );
            """)

            # High-performance composite indexes for deterministic correlation
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ev_hash ON evidence_vault(sha256_hash);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ce_host_time ON canonical_events(host, timestamp_utc);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ce_host_cat ON canonical_events(host, event_category);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ce_host_logon ON canonical_events(host, logon_id, timestamp_utc);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ce_host_pid ON canonical_events(host, process_id, parent_process_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ce_host_pguid ON canonical_events(host, process_guid, parent_process_guid);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ce_net_pivot ON canonical_events(event_category, src_ip, dst_ip, timestamp_utc);")
            conn.commit()

    def insert_canonical_event(self, evidence: Dict[str, Any], event: Dict[str, Any]) -> bool:
        """Inserts a single evidence record and its canonical event atomically."""
        inserted, _ = self.insert_batch([(evidence, event)])
        return inserted == 1

    def insert_batch(self, records: List[Tuple[Dict[str, Any], Dict[str, Any]]]) -> Tuple[int, int]:
        """
        Inserts a batch of (evidence, canonical_event) tuples inside a single transaction.
        Returns (inserted_count, duplicate_skipped_count).
        """
        if not records:
            return 0, 0

        inserted = 0
        skipped = 0

        with self.get_connection() as conn:
            cursor = conn.cursor()
            for evidence, event in records:
                try:
                    cursor.execute("""
                        INSERT INTO evidence_vault (
                            source_file, line_number, byte_offset, sha256_hash, raw_payload
                        ) VALUES (?, ?, ?, ?, ?);
                    """, (
                        evidence["source_file"],
                        evidence["line_number"],
                        evidence["byte_offset"],
                        evidence["sha256_hash"],
                        evidence["raw_payload"]
                    ))
                    ev_id = cursor.lastrowid

                    mitre_json = (
                        json.dumps(event.get("mitre_mappings", []), ensure_ascii=False)
                        if isinstance(event.get("mitre_mappings"), list)
                        else str(event.get("mitre_tags_json", "[]"))
                    )

                    cursor.execute("""
                        INSERT INTO canonical_events (
                            evidence_id, timestamp_utc, host, log_source_type, event_code,
                            event_category, user_name, logon_id, process_guid, process_id,
                            parent_process_guid, parent_process_id, image_path, parent_image_path,
                            command_line, decoded_payload, src_ip, dst_ip, dst_port,
                            target_filename, mitre_tags_json, risk_score, confidence_score
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """, (
                        ev_id,
                        event["timestamp_utc"],
                        event["host"],
                        event["log_source_type"],
                        event["event_code"],
                        event["event_category"],
                        event["user_name"],
                        event["logon_id"],
                        event["process_guid"],
                        event["process_id"],
                        event["parent_process_guid"],
                        event["parent_process_id"],
                        event["image_path"],
                        event["parent_image_path"],
                        event["command_line"],
                        event.get("decoded_payload", ""),
                        event["src_ip"],
                        event["dst_ip"],
                        event["dst_port"],
                        event["target_filename"],
                        mitre_json,
                        event.get("risk_score", 0),
                        event.get("confidence_score", 100)
                    ))
                    inserted += 1
                except sqlite3.IntegrityError:
                    skipped += 1
            conn.commit()

        return inserted, skipped

    def clear_Derived_analysis_tables(self, host: Optional[str] = None) -> None:
        """Clears previous correlation findings before re-running analysis to avoid duplicates."""
        with self.get_connection() as conn:
            if host:
                conn.execute("DELETE FROM forensic_findings WHERE host = ?;", (host.upper(),))
                conn.execute(
                    "DELETE FROM lateral_movements WHERE source_host = ? OR target_host = ?;",
                    (host.upper(), host.upper())
                )
            else:
                conn.execute("DELETE FROM forensic_findings;")
                conn.execute("DELETE FROM lateral_movements;")
            conn.commit()

    def save_forensic_finding(self, finding: Dict[str, Any]) -> int:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO forensic_findings (
                    host, chain_type, severity, risk_score, user_name, logon_id,
                    src_ip, root_pid, root_process_guid, summary, deterministic_proof,
                    mitre_tactics_json, evidence_chain_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                finding["host"],
                finding["chain_type"],
                finding["severity"],
                finding.get("risk_score", 80),
                finding["user_name"],
                finding["logon_id"],
                finding["src_ip"],
                finding.get("root_pid"),
                finding.get("root_process_guid", "N/A"),
                finding["summary"],
                finding["deterministic_proof"],
                json.dumps(finding.get("mitre_tactics", []), ensure_ascii=False),
                json.dumps(finding["evidence_chain"], ensure_ascii=False)
            ))
            conn.commit()
            return int(cursor.lastrowid or 0)

    def save_lateral_movement(self, pivot: Dict[str, Any]) -> int:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO lateral_movements (
                    source_host, target_host, pivot_src_ip, pivot_dst_ip, pivot_port,
                    egress_time_utc, ingress_time_utc, source_process, target_user,
                    target_logon_id, egress_sha256, egress_line, ingress_sha256,
                    ingress_line, proof_narrative
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                pivot["source_host"],
                pivot["target_host"],
                pivot["pivot_src_ip"],
                pivot["pivot_dst_ip"],
                pivot.get("pivot_port"),
                pivot["egress_time"],
                pivot["ingress_time"],
                pivot["source_process"],
                pivot["target_user"],
                pivot["target_logon_id"],
                pivot["egress_sha256"],
                pivot["egress_line"],
                pivot["ingress_sha256"],
                pivot["ingress_line"],
                pivot["proof"]
            ))
            conn.commit()
            return int(cursor.lastrowid or 0)

    def lookup_evidence_by_hash(self, hash_prefix: str) -> List[Dict[str, Any]]:
        """Retrieves complete traceability proof by full or partial SHA-256 hash."""
        clean_prefix = hash_prefix.strip().lower()
        with self.get_connection() as conn:
            rows = conn.execute("""
                SELECT 
                    e.evidence_id, e.source_file, e.line_number, e.byte_offset,
                    e.sha256_hash, e.raw_payload, e.ingested_at_utc,
                    c.event_uid, c.timestamp_utc, c.host, c.log_source_type,
                    c.event_code, c.event_category, c.user_name, c.logon_id,
                    c.process_id, c.parent_process_id, c.image_path, c.command_line,
                    c.decoded_payload, c.mitre_tags_json, c.risk_score
                FROM evidence_vault e
                LEFT JOIN canonical_events c ON e.evidence_id = c.evidence_id
                WHERE lower(e.sha256_hash) LIKE ?
                ORDER BY e.evidence_id ASC;
            """, (clean_prefix + "%",)).fetchall()
            return [dict(r) for r in rows]

    def get_database_statistics(self) -> Dict[str, Any]:
        """Returns global telemetry counts per host and category for CLI status checks."""
        with self.get_connection() as conn:
            total_ev = conn.execute("SELECT COUNT(*) FROM evidence_vault;").fetchone()[0]
            hosts = conn.execute("""
                SELECT host, COUNT(*) AS event_count, MIN(timestamp_utc) AS first_seen, MAX(timestamp_utc) AS last_seen
                FROM canonical_events
                GROUP BY host
                ORDER BY host;
            """).fetchall()
            return {
                "total_evidence_records": total_ev,
                "hosts": [dict(h) for h in hosts]
            }
