# File: core/correlator.py
# Project: Log Story Studio (LSS) - Production Forensic Engine
# Python Version: 3.13 (Standard Library Only)

import json
from typing import List, Dict, Any, Optional
from core.database import ForensicDatabase


class DeterministicCorrelator:
    """
    Executes deterministic SQLite queries and recursive CTEs to reconstruct
    process trees, multi-stage attack chains, and statistical baseline deviations
    strictly isolated per host topology.
    """

    def __init__(self, db: ForensicDatabase) -> None:
        self.db = db

    def get_distinct_hosts(self) -> List[str]:
        with self.db.get_connection() as conn:
            rows = conn.execute("SELECT DISTINCT host FROM canonical_events ORDER BY host ASC;").fetchall()
            return [str(r["host"]) for r in rows]

    def reconstruct_process_tree(self, host: str, root_pid: int) -> List[Dict[str, Any]]:
        """
        Reconstructs the complete parent-child process lineage starting from root_pid
        on a specific host using a cycle-safe SQLite Recursive CTE.
        """
        query = """
        WITH RECURSIVE process_lineage AS (
            SELECT 
                c.event_uid, c.timestamp_utc, c.host, c.user_name, c.logon_id,
                c.process_id, c.parent_process_id, c.process_guid, c.parent_process_guid,
                c.image_path, c.parent_image_path, c.command_line, c.decoded_payload,
                c.mitre_tags_json, c.risk_score,
                e.sha256_hash, e.source_file, e.line_number, e.byte_offset,
                0 AS depth,
                CAST(c.process_id AS TEXT) AS lineage_path
            FROM canonical_events c
            JOIN evidence_vault e ON c.evidence_id = e.evidence_id
            WHERE c.host = ? AND c.event_category = 'PROCESS_CREATE' AND c.process_id = ?

            UNION ALL

            SELECT 
                child.event_uid, child.timestamp_utc, child.host, child.user_name, child.logon_id,
                child.process_id, child.parent_process_id, child.process_guid, child.parent_process_guid,
                child.image_path, child.parent_image_path, child.command_line, child.decoded_payload,
                child.mitre_tags_json, child.risk_score,
                ev.sha256_hash, ev.source_file, ev.line_number, ev.byte_offset,
                p.depth + 1 AS depth,
                p.lineage_path || ' -> ' || CAST(child.process_id AS TEXT) AS lineage_path
            FROM canonical_events child
            JOIN evidence_vault ev ON child.evidence_id = ev.evidence_id
            JOIN process_lineage p ON child.host = p.host
                AND (
                    (child.parent_process_guid != 'N/A' AND p.process_guid != 'N/A' AND child.parent_process_guid = p.process_guid)
                    OR (
                        (child.parent_process_guid = 'N/A' OR p.process_guid = 'N/A')
                        AND child.parent_process_id = p.process_id
                        AND child.process_id != p.process_id
                    )
                )
            WHERE child.event_category = 'PROCESS_CREATE'
              AND child.timestamp_utc >= p.timestamp_utc
              AND p.depth < 16
        )
        SELECT * FROM process_lineage ORDER BY timestamp_utc ASC, depth ASC;
        """
        tree_nodes: List[Dict[str, Any]] = []
        seen_uids = set()
        with self.db.get_connection() as conn:
            rows = conn.execute(query, (host.upper(), root_pid)).fetchall()
            for r in rows:
                if r["event_uid"] not in seen_uids:
                    seen_uids.add(r["event_uid"])
                    node = dict(r)
                    try:
                        node["mitre_mappings"] = json.loads(node.get("mitre_tags_json", "[]"))
                    except Exception:
                        node["mitre_mappings"] = []
                    tree_nodes.append(node)
        return tree_nodes

    def detect_extended_attack_chains(self, host: str) -> List[Dict[str, Any]]:
        """
        Detects deterministic multi-stage attack chains on a host:
        1. Session-bound chains (Failed Logins -> Valid Logon -> Process Execution -> File/Archive -> Egress).
        2. Webshell / Application Exploit chains (Web Exploit HTTP request -> Web server spawning shell).
        """
        host = host.upper()
        findings: List[Dict[str, Any]] = []

        with self.db.get_connection() as conn:
            # --- CHAIN MODEL A: LogonId Session-Bound Multi-Stage Intrusion ---
            logons = conn.execute("""
                SELECT c.*, e.sha256_hash, e.line_number, e.byte_offset, e.source_file
                FROM canonical_events c
                JOIN evidence_vault e ON c.evidence_id = e.evidence_id
                WHERE c.host = ? AND c.event_category = 'AUTH_SUCCESS' AND c.logon_id != '0x0'
                ORDER BY c.timestamp_utc ASC;
            """, (host,)).fetchall()

            for logon in logons:
                logon_id = logon["logon_id"]
                user_name = logon["user_name"]
                src_ip = logon["src_ip"]
                logon_time = logon["timestamp_utc"]

                # Precursor brute-force failures
                failed_prior = conn.execute("""
                    SELECT c.*, e.sha256_hash, e.line_number, e.byte_offset, e.source_file
                    FROM canonical_events c
                    JOIN evidence_vault e ON c.evidence_id = e.evidence_id
                    WHERE c.host = ? AND c.event_category = 'AUTH_FAILED'
                      AND (c.src_ip = ? OR c.user_name = ?)
                      AND c.timestamp_utc <= ?
                    ORDER BY c.timestamp_utc ASC;
                """, (host, src_ip, user_name, logon_time)).fetchall()

                # Post-authentication session activity bound by exact LogonId
                session_events = conn.execute("""
                    SELECT c.*, e.sha256_hash, e.line_number, e.byte_offset, e.source_file
                    FROM canonical_events c
                    JOIN evidence_vault e ON c.evidence_id = e.evidence_id
                    WHERE c.host = ? AND c.logon_id = ? AND c.timestamp_utc >= ?
                    ORDER BY c.timestamp_utc ASC;
                """, (host, logon_id, logon_time)).fetchall()

                if not session_events:
                    continue

                stages_triggered: List[str] = []
                evidence_chain: List[Dict[str, Any]] = []
                mitre_collected: List[Dict[str, str]] = []
                max_risk = int(logon["risk_score"])

                def append_mitre_from_json(raw_json: str) -> List[Dict[str, str]]:
                    try:
                        tags = json.loads(raw_json)
                        for t in tags:
                            if not any(existing["id"] == t["id"] for existing in mitre_collected):
                                mitre_collected.append(t)
                        return tags
                    except Exception:
                        return []

                if len(failed_prior) >= 2:
                    stages_triggered.append(f"BRUTE_FORCE({len(failed_prior)}_FAILS)")
                    for fp in failed_prior:
                        tags = append_mitre_from_json(fp["mitre_tags_json"])
                        evidence_chain.append({
                            "stage": "AUTH_FAILED",
                            "timestamp": fp["timestamp_utc"],
                            "line": fp["line_number"],
                            "byte_offset": fp["byte_offset"],
                            "source_file": fp["source_file"],
                            "sha256": fp["sha256_hash"],
                            "pid": fp["process_id"],
                            "ppid": fp["parent_process_id"],
                            "detail": f"Failed login for '{fp['user_name']}' from IP {fp['src_ip']}",
                            "decoded_payload": fp["decoded_payload"],
                            "mitre_mappings": tags
                        })

                stages_triggered.append("AUTH_SUCCESS")
                logon_tags = append_mitre_from_json(logon["mitre_tags_json"])
                evidence_chain.append({
                    "stage": "AUTH_SUCCESS",
                    "timestamp": logon["timestamp_utc"],
                    "line": logon["line_number"],
                    "byte_offset": logon["byte_offset"],
                    "source_file": logon["source_file"],
                    "sha256": logon["sha256_hash"],
                    "pid": logon["process_id"],
                    "ppid": logon["parent_process_id"],
                    "detail": f"Authenticated session established for '{user_name}' (LogonId={logon_id}, SourceIP={src_ip})",
                    "decoded_payload": logon["decoded_payload"],
                    "mitre_mappings": logon_tags
                })

                root_pid: Optional[int] = None
                root_pguid: str = "N/A"

                for ev in session_events:
                    if ev["evidence_id"] == logon["evidence_id"]:
                        continue

                    cat = ev["event_category"]
                    cmd = ev["command_line"]
                    img = ev["image_path"]
                    decoded = ev["decoded_payload"]
                    ev_risk = int(ev["risk_score"])
                    if ev_risk > max_risk:
                        max_risk = ev_risk

                    inspect_str = f"{cmd.lower()} {decoded.lower()} {img.lower()}"

                    if cat == "PROCESS_CREATE":
                        if root_pid is None and ev["process_id"] is not None:
                            root_pid = int(ev["process_id"])
                            root_pguid = str(ev["process_guid"])

                        # Check for archiving / impact tools first
                        if any(k in inspect_str for k in ("7z", "rar", "compress-archive", "tar ", "zip ", "vssadmin", "wbadmin")):
                            if "DATA_ARCHIVING_OR_IMPACT" not in stages_triggered:
                                stages_triggered.append("DATA_ARCHIVING_OR_IMPACT")
                            tags = append_mitre_from_json(ev["mitre_tags_json"])
                            evidence_chain.append({
                                "stage": "DATA_STAGING",
                                "timestamp": ev["timestamp_utc"],
                                "line": ev["line_number"],
                                "byte_offset": ev["byte_offset"],
                                "source_file": ev["source_file"],
                                "sha256": ev["sha256_hash"],
                                "pid": ev["process_id"],
                                "ppid": ev["parent_process_id"],
                                "detail": f"PID {ev['process_id']} (Parent {ev['parent_process_id']}) executed staging/impact utility: {cmd}",
                                "decoded_payload": decoded,
                                "mitre_mappings": tags
                            })
                        elif ev_risk >= 20 or any(k in inspect_str for k in ("powershell", "cmd.exe", "whoami", "net ", "bash", "sh ", "certutil", "mshta", "mimikatz")):
                            if "SUSPICIOUS_EXECUTION" not in stages_triggered:
                                stages_triggered.append("SUSPICIOUS_EXECUTION")
                            tags = append_mitre_from_json(ev["mitre_tags_json"])
                            evidence_chain.append({
                                "stage": "PROCESS_CREATE",
                                "timestamp": ev["timestamp_utc"],
                                "line": ev["line_number"],
                                "byte_offset": ev["byte_offset"],
                                "source_file": ev["source_file"],
                                "sha256": ev["sha256_hash"],
                                "pid": ev["process_id"],
                                "ppid": ev["parent_process_id"],
                                "detail": f"PID {ev['process_id']} (Parent {ev['parent_process_id']}) executed: {cmd}",
                                "decoded_payload": decoded,
                                "mitre_mappings": tags
                            })

                    elif cat == "FILE_CREATE":
                        tfile = ev["target_filename"]
                        if any(tfile.lower().endswith(ext) for ext in (".7z", ".zip", ".rar", ".ps1", ".bat", ".exe", ".dll", ".php", ".aspx", ".dmp")):
                            if "SENSITIVE_ARTIFACT_DROP" not in stages_triggered:
                                stages_triggered.append("SENSITIVE_ARTIFACT_DROP")
                            tags = append_mitre_from_json(ev["mitre_tags_json"])
                            evidence_chain.append({
                                "stage": "FILE_CREATE",
                                "timestamp": ev["timestamp_utc"],
                                "line": ev["line_number"],
                                "byte_offset": ev["byte_offset"],
                                "source_file": ev["source_file"],
                                "sha256": ev["sha256_hash"],
                                "pid": ev["process_id"],
                                "ppid": ev["parent_process_id"],
                                "detail": f"Process {img} (PID {ev['process_id']}) dropped artifact: {tfile}",
                                "decoded_payload": decoded,
                                "mitre_mappings": tags
                            })

                    elif cat in ("NETWORK_CONNECT", "DB_QUERY_OR_EGRESS"):
                        if ev["dst_ip"] not in ("127.0.0.1", "::1", "N/A", "-"):
                            if "EXTERNAL_EGRESS_OR_EXFIL" not in stages_triggered:
                                stages_triggered.append("EXTERNAL_EGRESS_OR_EXFIL")
                            tags = append_mitre_from_json(ev["mitre_tags_json"])
                            evidence_chain.append({
                                "stage": "NETWORK_EGRESS",
                                "timestamp": ev["timestamp_utc"],
                                "line": ev["line_number"],
                                "byte_offset": ev["byte_offset"],
                                "source_file": ev["source_file"],
                                "sha256": ev["sha256_hash"],
                                "pid": ev["process_id"],
                                "ppid": ev["parent_process_id"],
                                "detail": f"Outbound egress by {img} (PID {ev['process_id']}) -> {ev['dst_ip']}:{ev['dst_port']} ({cmd})",
                                "decoded_payload": decoded,
                                "mitre_mappings": tags
                            })

                if len(stages_triggered) >= 3:
                    chain_str = " -> ".join(stages_triggered)
                    severity = "CRITICAL" if ("EXTERNAL_EGRESS_OR_EXFIL" in stages_triggered or max_risk >= 70) else "HIGH"
                    proof = (
                        f"Deterministic Session Chain Proven on Host='{host}' via LogonId='{logon_id}'. "
                        f"Account='{user_name}', OriginIP='{src_ip}'. "
                        f"Correlated {len(evidence_chain)} cryptographic evidence records across {len(stages_triggered)} attack phases."
                    )
                    finding = {
                        "host": host,
                        "chain_type": chain_str,
                        "severity": severity,
                        "risk_score": max_risk,
                        "user_name": user_name,
                        "logon_id": logon_id,
                        "src_ip": src_ip,
                        "root_pid": root_pid,
                        "root_process_guid": root_pguid,
                        "summary": f"Multi-stage intrusion chain bound to session {logon_id} ({user_name})",
                        "deterministic_proof": proof,
                        "mitre_tactics": mitre_collected,
                        "evidence_chain": evidence_chain
                    }
                    self.db.save_forensic_finding(finding)
                    findings.append(finding)

            # --- CHAIN MODEL B: Web Exploit / Webshell Process Spawning ---
            web_shells = conn.execute("""
                SELECT c.*, e.sha256_hash, e.line_number, e.byte_offset, e.source_file
                FROM canonical_events c
                JOIN evidence_vault e ON c.evidence_id = e.evidence_id
                WHERE c.host = ? AND c.event_category = 'PROCESS_CREATE'
                  AND (
                      lower(c.parent_image_path) LIKE '%w3wp.exe%'
                      OR lower(c.parent_image_path) LIKE '%php%'
                      OR lower(c.parent_image_path) LIKE '%apache%'
                      OR lower(c.parent_image_path) LIKE '%nginx%'
                      OR lower(c.parent_image_path) LIKE '%tomcat%'
                  );
            """, (host,)).fetchall()

            for ws in web_shells:
                # Check if already captured in a session chain
                if any(ws["sha256_hash"] == item["sha256"] for f in findings for item in f["evidence_chain"]):
                    continue

                web_exploits = conn.execute("""
                    SELECT c.*, e.sha256_hash, e.line_number, e.byte_offset, e.source_file
                    FROM canonical_events c
                    JOIN evidence_vault e ON c.evidence_id = e.evidence_id
                    WHERE c.host = ? AND c.event_category = 'WEB_EXPLOIT_ATTEMPT'
                      AND c.timestamp_utc <= ?
                    ORDER BY c.timestamp_utc ASC;
                """, (host, ws["timestamp_utc"])).fetchall()

                ev_chain: List[Dict[str, Any]] = []
                mitre_list: List[Dict[str, str]] = []

                for we in web_exploits:
                    tags = json.loads(we["mitre_tags_json"])
                    for t in tags:
                        if not any(m["id"] == t["id"] for m in mitre_list):
                            mitre_list.append(t)
                    ev_chain.append({
                        "stage": "WEB_EXPLOIT_ATTEMPT",
                        "timestamp": we["timestamp_utc"],
                        "line": we["line_number"],
                        "byte_offset": we["byte_offset"],
                        "source_file": we["source_file"],
                        "sha256": we["sha256_hash"],
                        "pid": None,
                        "ppid": None,
                        "detail": f"HTTP Exploit from {we['src_ip']}: {we['command_line']}",
                        "decoded_payload": we["decoded_payload"],
                        "mitre_mappings": tags
                    })

                ws_tags = json.loads(ws["mitre_tags_json"])
                for t in ws_tags:
                    if not any(m["id"] == t["id"] for m in mitre_list):
                        mitre_list.append(t)
                ev_chain.append({
                    "stage": "WEBSHELL_PROCESS_SPAWN",
                    "timestamp": ws["timestamp_utc"],
                    "line": ws["line_number"],
                    "byte_offset": ws["byte_offset"],
                    "source_file": ws["source_file"],
                    "sha256": ws["sha256_hash"],
                    "pid": ws["process_id"],
                    "ppid": ws["parent_process_id"],
                    "detail": f"Web daemon '{ws['parent_image_path']}' (PID {ws['parent_process_id']}) spawned shell '{ws['image_path']}' (PID {ws['process_id']}): {ws['command_line']}",
                    "decoded_payload": ws["decoded_payload"],
                    "mitre_mappings": ws_tags
                })

                finding = {
                    "host": host,
                    "chain_type": "WEB_EXPLOIT -> WEBSHELL_OS_COMMAND_EXECUTION",
                    "severity": "CRITICAL",
                    "risk_score": 95,
                    "user_name": ws["user_name"],
                    "logon_id": ws["logon_id"],
                    "src_ip": web_exploits[-1]["src_ip"] if web_exploits else "WEB_INGRESS",
                    "root_pid": ws["process_id"],
                    "root_process_guid": ws["process_guid"],
                    "summary": f"Web server daemon spawned operating system shell (PID {ws['process_id']})",
                    "deterministic_proof": f"ParentProcessName='{ws['parent_image_path']}' directly spawned child PID={ws['process_id']} ('{ws['image_path']}').",
                    "mitre_tactics": mitre_list,
                    "evidence_chain": ev_chain
                }
                self.db.save_forensic_finding(finding)
                findings.append(finding)

        return findings

    def analyze_baseline_deviations(self, host: str) -> List[Dict[str, Any]]:
        """
        Calculates statistical baseline deviations on the target host:
        1. Rare Parent-Child Process Lineage anomalies.
        2. High-risk de-obfuscated command anomalies.
        """
        deviations: List[Dict[str, Any]] = []
        host = host.upper()

        with self.db.get_connection() as conn:
            total_row = conn.execute("""
                SELECT COUNT(*) AS cnt FROM canonical_events
                WHERE host = ? AND event_category = 'PROCESS_CREATE';
            """, (host,)).fetchone()
            total_procs = int(total_row["cnt"]) if total_row else 0

            if total_procs == 0:
                return deviations

            rows = conn.execute("""
                SELECT 
                    c.parent_image_path,
                    c.image_path,
                    COUNT(*) AS pair_count,
                    MIN(c.timestamp_utc) AS first_seen,
                    MAX(c.command_line) AS sample_cmd,
                    MAX(c.decoded_payload) AS sample_decoded,
                    MAX(c.risk_score) AS max_risk,
                    MAX(e.sha256_hash) AS sample_hash,
                    MAX(e.line_number) AS sample_line
                FROM canonical_events c
                JOIN evidence_vault e ON c.evidence_id = e.evidence_id
                WHERE c.host = ? AND c.event_category = 'PROCESS_CREATE'
                GROUP BY c.parent_image_path, c.image_path
                HAVING pair_count <= 2
                ORDER BY max_risk DESC, first_seen ASC;
            """, (host,)).fetchall()

            suspicious_parents = ("w3wp.exe", "winrshost.exe", "winword.exe", "excel.exe", "powerpnt.exe", "apache", "nginx", "php", "sshd")
            suspicious_children = ("powershell.exe", "pwsh.exe", "cmd.exe", "whoami.exe", "7z.exe", "rar.exe", "certutil.exe", "mshta.exe", "vssadmin.exe", "bash")

            for r in rows:
                p_img = str(r["parent_image_path"])
                img = str(r["image_path"])
                freq_pct = round((int(r["pair_count"]) / total_procs) * 100.0, 2)

                is_anomalous = (
                    int(r["max_risk"]) >= 30
                    or any(sp in p_img.lower() for sp in suspicious_parents)
                    or any(sc in img.lower() for sc in suspicious_children)
                )

                if is_anomalous:
                    deviations.append({
                        "host": host,
                        "metric": "Parent-Child Process Lineage Frequency",
                        "expected_baseline": "Standard OS/Service process hierarchy (>15.0% baseline occurrence)",
                        "actual_observed": f"{p_img} -> {img} ({r['pair_count']}/{total_procs} events = {freq_pct}%)",
                        "timestamp_utc": r["first_seen"],
                        "command_line": r["sample_cmd"],
                        "decoded_payload": r["sample_decoded"],
                        "risk_score": r["max_risk"],
                        "line_number": r["sample_line"],
                        "sha256_hash": r["sample_hash"],
                        "reason": (
                            f"Statistically rare process lineage ({freq_pct}% host frequency) with elevated "
                            f"forensic risk score ({r['max_risk']}/100)."
                        )
                    })

        return deviations
