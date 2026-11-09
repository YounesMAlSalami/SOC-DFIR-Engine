# File: core/normalizer.py
# Project: Log Story Studio (LSS) - Production Forensic Engine
# Python Version: 3.13 (Standard Library Only)

import hashlib
import json
import re
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List

from core.database import ForensicDatabase
from core.deobfuscator import ForensicDeobfuscator
from core.multi_parsers import MultiFormatParsers

# Standard RFC 3164 / Linux Auth Syslog Regex
SYSLOG_REGEX = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>[a-zA-Z0-9_\-\./]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)

MONTH_MAP: Dict[str, int] = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}


class CanonicalNormalizer:
    """
    Primary ingestion orchestrator.
    Handles Windows EVTX JSON and Linux Syslog directly, delegates Web/IIS/CSV/Firewall
    logs and C-Bridge streaming to MultiFormatParsers, enriches via ForensicDeobfuscator,
    and commits atomic batches to ForensicDatabase.
    """

    def __init__(self, db: ForensicDatabase, batch_size: int = 2000) -> None:
        self.db = db
        self.batch_size = batch_size

    @staticmethod
    def compute_sha256(raw_bytes: bytes) -> str:
        return hashlib.sha256(raw_bytes).hexdigest()

    @staticmethod
    def _safe_int(val: Any) -> Optional[int]:
        return MultiFormatParsers._safe_int(val)

    @staticmethod
    def normalize_timestamp(ts_str: str) -> str:
        return MultiFormatParsers.normalize_web_or_iso_time(ts_str)

    def parse_windows_json(self, raw_line: str) -> Optional[Dict[str, Any]]:
        """Parses Windows Sysmon and Security Event JSON records."""
        try:
            record = json.loads(raw_line)
            if not isinstance(record, dict):
                return None
        except json.JSONDecodeError:
            return None

        sys_node = record.get("Event", {}).get("System", record.get("System", record))
        data_node = record.get("Event", {}).get("EventData", record.get("EventData", record))

        event_id = self._safe_int(sys_node.get("EventID", record.get("EventID")))
        if event_id is None:
            return None

        raw_time = (
            sys_node.get("TimeCreated", {}).get("SystemTime")
            if isinstance(sys_node.get("TimeCreated"), dict)
            else sys_node.get("TimeCreated", record.get("Timestamp", record.get("@timestamp", "")))
        )
        timestamp_utc = self.normalize_timestamp(str(raw_time))
        host = str(sys_node.get("Computer", record.get("Host", record.get("host", "UNKNOWN_HOST")))).strip().upper()

        category_map = {
            1: "PROCESS_CREATE",
            3: "NETWORK_CONNECT",
            7: "IMAGE_LOAD",
            8: "CREATE_REMOTE_THREAD",
            10: "PROCESS_ACCESS",
            11: "FILE_CREATE",
            12: "REGISTRY_EVENT",
            13: "REGISTRY_VALUE_SET",
            22: "DNS_QUERY",
            4624: "AUTH_SUCCESS",
            4625: "AUTH_FAILED",
            4688: "PROCESS_CREATE",
            4697: "SERVICE_INSTALL",
            7045: "SERVICE_INSTALL"
        }
        event_category = category_map.get(event_id, f"EVENT_{event_id}")

        user_name = str(
            data_node.get("User")
            or data_node.get("TargetUserName")
            or data_node.get("SubjectUserName")
            or "SYSTEM"
        ).strip()

        logon_id = str(
            data_node.get("LogonId")
            or data_node.get("TargetLogonId")
            or data_node.get("SubjectLogonId")
            or "0x0"
        ).strip()

        process_guid = str(data_node.get("ProcessGuid") or data_node.get("SourceProcessGuid") or "N/A").strip()
        parent_process_guid = str(data_node.get("ParentProcessGuid") or "N/A").strip()

        process_id = self._safe_int(
            data_node.get("ProcessId") or data_node.get("NewProcessId") or data_node.get("SourceProcessId")
        )
        parent_process_id = self._safe_int(
            data_node.get("ParentProcessId") or data_node.get("CreatorProcessId")
        )

        image_path = str(
            data_node.get("Image") or data_node.get("NewProcessName") or data_node.get("SourceImage") or "N/A"
        ).strip()
        parent_image_path = str(
            data_node.get("ParentImage") or data_node.get("ParentProcessName") or "N/A"
        ).strip()
        command_line = str(
            data_node.get("CommandLine") or data_node.get("ServiceFileName") or data_node.get("QueryName") or "N/A"
        ).strip()

        src_ip = str(data_node.get("SourceIp") or data_node.get("IpAddress") or "N/A").strip()
        dst_ip = str(data_node.get("DestinationIp") or "N/A").strip()
        dst_port = self._safe_int(data_node.get("DestinationPort"))
        target_filename = str(
            data_node.get("TargetFilename") or data_node.get("TargetObject") or data_node.get("ImageLoaded") or "N/A"
        ).strip()

        return {
            "timestamp_utc": timestamp_utc,
            "host": host,
            "log_source_type": "WINDOWS_EVTX_JSON",
            "event_code": event_id,
            "event_category": event_category,
            "user_name": user_name,
            "logon_id": logon_id,
            "process_guid": process_guid,
            "process_id": process_id,
            "parent_process_guid": parent_process_guid,
            "parent_process_id": parent_process_id,
            "image_path": image_path,
            "parent_image_path": parent_image_path,
            "command_line": command_line,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "target_filename": target_filename,
            "confidence_score": 100
        }

    def parse_linux_syslog(self, raw_line: str, reference_year: int = 2026) -> Optional[Dict[str, Any]]:
        """Parses Linux Syslog / Auth.log events into the Canonical Event Model."""
        match = SYSLOG_REGEX.match(raw_line.strip())
        if not match:
            return None

        g = match.groupdict()
        month = MONTH_MAP.get(g["month"], 1)
        day = int(g["day"])
        timestamp_utc = f"{reference_year:04d}-{month:02d}-{day:02d}T{g['time']}.000Z"

        host = g["host"].strip().upper()
        process_name = g["process"].strip()
        pid = self._safe_int(g["pid"])
        msg = g["msg"].strip()

        event_code = 1000
        event_category = "SYSLOG_GENERIC"
        user_name = "root"
        src_ip = "N/A"
        logon_id = f"LINUX_SESS_{pid}" if pid else "0x0"

        if "Failed password for" in msg or "authentication failure" in msg:
            event_code = 4625
            event_category = "AUTH_FAILED"
            u_match = re.search(r"for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)", msg)
            if u_match:
                user_name = u_match.group("user")
                src_ip = u_match.group("ip")
        elif "Accepted password for" in msg or "Accepted publickey for" in msg:
            event_code = 4624
            event_category = "AUTH_SUCCESS"
            u_match = re.search(r"for (?P<user>\S+) from (?P<ip>\S+)", msg)
            if u_match:
                user_name = u_match.group("user")
                src_ip = u_match.group("ip")
        elif "COMMAND=" in msg or "EXEC" in msg:
            event_code = 1
            event_category = "PROCESS_CREATE"
            u_match = re.search(r"^\s*(?P<user>[a-zA-Z0-9_\-]+)\s*:", msg)
            if u_match:
                user_name = u_match.group("user")

        return {
            "timestamp_utc": timestamp_utc,
            "host": host,
            "log_source_type": "LINUX_SYSLOG",
            "event_code": event_code,
            "event_category": event_category,
            "user_name": user_name,
            "logon_id": logon_id,
            "process_guid": f"{host}_{pid}" if pid else "N/A",
            "process_id": pid,
            "parent_process_guid": "N/A",
            "parent_process_id": None,
            "image_path": process_name,
            "parent_image_path": "init_or_systemd",
            "command_line": msg,
            "src_ip": src_ip,
            "dst_ip": "N/A",
            "dst_port": None,
            "target_filename": "N/A",
            "confidence_score": 95
        }

    def _route_and_parse(
        self,
        decoded_line: str,
        csv_headers: Optional[List[str]] = None,
        default_host: str = "WEB-SERVER-01"
    ) -> Optional[Dict[str, Any]]:
        """Routes each raw line across OS and MultiFormatParsers, then enriches via Deobfuscator."""
        parsed: Optional[Dict[str, Any]] = None

        if decoded_line.startswith("{") and decoded_line.endswith("}"):
            parsed = self.parse_windows_json(decoded_line)
        elif csv_headers is not None and "," in decoded_line:
            parsed = MultiFormatParsers.parse_csv_telemetry_row(decoded_line, csv_headers)
        else:
            parsed = (
                MultiFormatParsers.parse_web_access_log(decoded_line, default_host=default_host)
                or MultiFormatParsers.parse_iis_w3c_log(decoded_line, default_host=default_host)
                or self.parse_linux_syslog(decoded_line)
                or MultiFormatParsers.parse_kv_firewall_log(decoded_line, default_host=default_host)
            )

        if parsed is not None:
            enrichment = ForensicDeobfuscator.enrich_and_map_mitre(parsed)
            parsed["decoded_payload"] = enrichment["decoded_payload"]
            parsed["mitre_mappings"] = enrichment["mitre_mappings"]
            parsed["risk_score"] = enrichment["risk_score"]

        return parsed

    def ingest_file(
        self,
        file_path: str,
        c_binary_path: Optional[str] = None,
        filter_token: Optional[str] = None,
        default_host: str = "WEB-SERVER-01"
    ) -> Tuple[int, int, int]:
        path_obj = Path(file_path).resolve()
        if not path_obj.exists():
            raise FileNotFoundError(f"Evidence file not found: {file_path}")

        csv_headers: Optional[List[str]] = None
        if path_obj.suffix.lower() == ".csv":
            with open(path_obj, "r", encoding="utf-8", errors="replace") as cf:
                first_line = cf.readline().strip()
                if "," in first_line:
                    csv_headers = [h.strip().lower() for h in first_line.split(",")]

        batch: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
        total_ingested = 0
        total_skipped = 0
        total_corrupted = 0

        use_c_bridge = bool(c_binary_path and Path(c_binary_path).resolve().is_file())

        if use_c_bridge and c_binary_path:
            for line_num, byte_offset, payload_bytes in MultiFormatParsers.stream_via_c_indexer(
                c_binary_path, str(path_obj), filter_token
            ):
                if csv_headers and line_num == 1:
                    continue
                try:
                    decoded_line = payload_bytes.decode("utf-8")
                except UnicodeDecodeError:
                    decoded_line = payload_bytes.decode("latin-1", errors="replace")

                parsed_event = self._route_and_parse(decoded_line, csv_headers, default_host)
                if parsed_event is None:
                    total_corrupted += 1
                    continue

                evidence_rec = {
                    "source_file": str(path_obj),
                    "line_number": line_num,
                    "byte_offset": byte_offset,
                    "sha256_hash": self.compute_sha256(payload_bytes),
                    "raw_payload": decoded_line
                }
                batch.append((evidence_rec, parsed_event))

                if len(batch) >= self.batch_size:
                    ins, skp = self.db.insert_batch(batch)
                    total_ingested += ins
                    total_skipped += skp
                    batch.clear()
        else:
            line_num = 0
            with open(path_obj, "rb") as f:
                while True:
                    byte_offset = f.tell()
                    raw_bytes = f.readline()
                    if not raw_bytes:
                        break
                    line_num += 1

                    stripped_bytes = raw_bytes.strip()
                    if not stripped_bytes:
                        continue
                    if csv_headers and line_num == 1:
                        continue
                    if filter_token and filter_token.encode("utf-8").lower() not in stripped_bytes.lower():
                        continue

                    try:
                        decoded_line = stripped_bytes.decode("utf-8")
                    except UnicodeDecodeError:
                        decoded_line = stripped_bytes.decode("latin-1", errors="replace")

                    parsed_event = self._route_and_parse(decoded_line, csv_headers, default_host)
                    if parsed_event is None:
                        total_corrupted += 1
                        continue

                    evidence_rec = {
                        "source_file": str(path_obj),
                        "line_number": line_num,
                        "byte_offset": byte_offset,
                        "sha256_hash": self.compute_sha256(stripped_bytes),
                        "raw_payload": decoded_line
                    }
                    batch.append((evidence_rec, parsed_event))

                    if len(batch) >= self.batch_size:
                        ins, skp = self.db.insert_batch(batch)
                        total_ingested += ins
                        total_skipped += skp
                        batch.clear()

        if batch:
            ins, skp = self.db.insert_batch(batch)
            total_ingested += ins
            total_skipped += skp
            batch.clear()

        return total_ingested, total_skipped, total_corrupted
