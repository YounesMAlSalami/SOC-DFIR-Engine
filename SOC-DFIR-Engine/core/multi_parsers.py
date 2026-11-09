# File: core/multi_parsers.py
# Project: Log Story Studio (LSS) - Production Forensic Engine
# Python Version: 3.13 (Standard Library Only)

import csv
import io
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List, Iterator, Tuple

# 1. Apache / Nginx Combined Access Log Regex
WEB_ACCESS_REGEX = re.compile(
    r'^(?P<src_ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

# 2. Microsoft IIS W3C Extended Log Regex:
# date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status
IIS_W3C_REGEX = re.compile(
    r'^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<s_ip>\S+)\s+(?P<method>[A-Z]+)\s+(?P<uri_stem>\S+)\s+(?P<uri_query>\S+)\s+'
    r'(?P<s_port>\d+)\s+(?P<user>\S+)\s+(?P<c_ip>\S+)\s+(?P<ua>\S+)\s+(?P<status>\d{3})'
)

# 3. Key-Value Firewall / Security Appliance Regex (FortiGate, PaloAlto, Netfilter, Auditd)
KV_PAIR_REGEX = re.compile(r'([a-zA-Z0-9_\-]+)=(?:"([^"]*)"|(\S+))')


class MultiFormatParsers:
    """
    Specialized forensic parsers for non-OS telemetry:
    - Apache / Nginx Combined Web Access Logs
    - Microsoft IIS W3C Web Server Logs
    - Key-Value Firewall & Network Appliance Logs (FortiGate / Syslog KV / Auditd)
    - Structured CSV / TSV Database Audit & Egress Logs
    - High-speed C Pre-Indexer binary stream bridge
    """

    @staticmethod
    def _safe_int(val: Any) -> Optional[int]:
        if val is None or val == "" or val == "-":
            return None
        try:
            return int(str(val).strip(), 0)
        except ValueError:
            return None

    @staticmethod
    def normalize_web_or_iso_time(ts_str: str) -> str:
        if not ts_str:
            return "1970-01-01T00:00:00.000Z"
        clean_ts = ts_str.strip()

        # Apache/Nginx format: 10/Nov/2026:14:22:01 +0000
        if "/" in clean_ts and ":" in clean_ts and clean_ts[2:3] == "/":
            try:
                dt = datetime.strptime(clean_ts, "%d/%b/%Y:%H:%M:%S %z")
                return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            except ValueError:
                pass

        try:
            if clean_ts.endswith("Z"):
                if "." in clean_ts:
                    main_part, frac = clean_ts[:-1].split(".", 1)
                    frac = (frac + "000000")[:6]
                    clean_ts = f"{main_part}.{frac}+00:00"
                else:
                    clean_ts = clean_ts[:-1] + "+00:00"
            dt = datetime.fromisoformat(clean_ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            dt_utc = dt.astimezone(timezone.utc)
            return dt_utc.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        except ValueError:
            return clean_ts

    @classmethod
    def parse_web_access_log(cls, raw_line: str, default_host: str = "WEB-SERVER-01") -> Optional[Dict[str, Any]]:
        """Parses Apache / Nginx Combined Access Logs and detects web exploit attempts."""
        m = WEB_ACCESS_REGEX.match(raw_line.strip())
        if not m:
            return None

        d = m.groupdict()
        timestamp_utc = cls.normalize_web_or_iso_time(d["time"])
        status_code = int(d["status"])
        uri = d["uri"]
        method = d["method"]
        ua = (d.get("ua") or "N/A").strip()
        src_ip = d["src_ip"].strip()

        category = "WEB_ACCESS"
        uri_lower = uri.lower()
        exploit_indicators = (
            "cmd=", "exec=", "shell", ".php?", ".jsp?", ".aspx?",
            "union%20select", "select+", "../", "..%2f", "eval(",
            "base64", "/etc/passwd", "xp_cmdshell", "whoami"
        )
        if any(tok in uri_lower for tok in exploit_indicators):
            category = "WEB_EXPLOIT_ATTEMPT"
        elif status_code in (401, 403):
            category = "AUTH_FAILED"

        return {
            "timestamp_utc": timestamp_utc,
            "host": default_host.upper(),
            "log_source_type": "WEB_ACCESS_LOG",
            "event_code": status_code,
            "event_category": category,
            "user_name": d["user"] if d["user"] != "-" else "WEB_CLIENT",
            "logon_id": f"HTTP_{src_ip}",
            "process_guid": "N/A",
            "process_id": None,
            "parent_process_guid": "N/A",
            "parent_process_id": None,
            "image_path": f"HTTP_{method}",
            "parent_image_path": ua[:120],
            "command_line": f"{method} {uri} [HTTP {status_code}, Bytes: {d['bytes']}]",
            "src_ip": src_ip,
            "dst_ip": default_host.upper(),
            "dst_port": 80,
            "target_filename": uri.split("?")[0],
            "confidence_score": 95
        }

    @classmethod
    def parse_iis_w3c_log(cls, raw_line: str, default_host: str = "IIS-WEB-01") -> Optional[Dict[str, Any]]:
        """Parses Microsoft IIS W3C Extended Web Server Logs."""
        stripped = raw_line.strip()
        if stripped.startswith("#"):
            return None

        m = IIS_W3C_REGEX.match(stripped)
        if not m:
            return None

        d = m.groupdict()
        timestamp_utc = f"{d['date']}T{d['time']}.000Z"
        status_code = int(d["status"])
        uri_stem = d["uri_stem"]
        uri_query = d["uri_query"] if d["uri_query"] != "-" else ""
        full_uri = f"{uri_stem}?{uri_query}" if uri_query else uri_stem
        method = d["method"]
        src_ip = d["c_ip"]

        category = "WEB_ACCESS"
        if any(tok in full_uri.lower() for tok in ("cmd=", "shell", ".aspx", "union", "../", "eval(", "powershell")):
            category = "WEB_EXPLOIT_ATTEMPT"
        elif status_code in (401, 403):
            category = "AUTH_FAILED"

        return {
            "timestamp_utc": timestamp_utc,
            "host": default_host.upper(),
            "log_source_type": "IIS_W3C_LOG",
            "event_code": status_code,
            "event_category": category,
            "user_name": d["user"] if d["user"] != "-" else "IIS_ANONYMOUS",
            "logon_id": f"IIS_{src_ip}",
            "process_guid": "N/A",
            "process_id": None,
            "parent_process_guid": "N/A",
            "parent_process_id": None,
            "image_path": f"IIS_{method}",
            "parent_image_path": d["ua"][:120],
            "command_line": f"{method} {full_uri} [Status: {status_code}]",
            "src_ip": src_ip,
            "dst_ip": d["s_ip"],
            "dst_port": cls._safe_int(d["s_port"]),
            "target_filename": uri_stem,
            "confidence_score": 95
        }

    @classmethod
    def parse_kv_firewall_log(cls, raw_line: str, default_host: str = "FW-GATEWAY-01") -> Optional[Dict[str, Any]]:
        """Parses Key-Value security & firewall logs (e.g., srcip=... dstip=... action=...)."""
        if "=" not in raw_line:
            return None

        matches = KV_PAIR_REGEX.findall(raw_line)
        if len(matches) < 4:
            return None

        kv: Dict[str, str] = {}
        for key, quoted_val, plain_val in matches:
            kv[key.lower()] = (quoted_val if quoted_val != "" else plain_val).strip()

        src_ip = kv.get("srcip") or kv.get("src") or kv.get("src_ip") or kv.get("saddr")
        dst_ip = kv.get("dstip") or kv.get("dst") or kv.get("dst_ip") or kv.get("daddr")
        if not src_ip and not dst_ip:
            return None

        date_part = kv.get("date", "2026-11-10")
        time_part = kv.get("time", "00:00:00")
        raw_ts = kv.get("timestamp") or f"{date_part}T{time_part}Z"
        timestamp_utc = cls.normalize_web_or_iso_time(raw_ts)

        host = (kv.get("devname") or kv.get("host") or kv.get("device") or default_host).upper()
        action = (kv.get("action") or kv.get("status") or "FLOW").upper()
        user = kv.get("user") or kv.get("srcuser") or "N/A"
        dst_port = cls._safe_int(kv.get("dstport") or kv.get("dport") or kv.get("dst_port"))
        session_id = kv.get("sessionid") or kv.get("logon_id") or f"FW_{src_ip or '0.0.0.0'}"

        category = "NETWORK_CONNECT"
        event_code = 3
        if action in ("DENY", "DROP", "BLOCK", "REJECT", "FAILED"):
            category = "AUTH_FAILED"
            event_code = 4625

        return {
            "timestamp_utc": timestamp_utc,
            "host": host,
            "log_source_type": "KV_FIREWALL_LOG",
            "event_code": event_code,
            "event_category": category,
            "user_name": user,
            "logon_id": session_id,
            "process_guid": "N/A",
            "process_id": cls._safe_int(kv.get("pid")),
            "parent_process_guid": "N/A",
            "parent_process_id": cls._safe_int(kv.get("ppid")),
            "image_path": kv.get("app") or kv.get("service") or f"FW_{action}",
            "parent_image_path": "N/A",
            "command_line": kv.get("msg") or kv.get("cmd") or f"Firewall {action}: {src_ip} -> {dst_ip}:{dst_port}",
            "src_ip": src_ip or "N/A",
            "dst_ip": dst_ip or "N/A",
            "dst_port": dst_port,
            "target_filename": kv.get("file") or "N/A",
            "confidence_score": 90
        }

    @classmethod
    def parse_csv_telemetry_row(cls, raw_line: str, headers: List[str]) -> Optional[Dict[str, Any]]:
        """Parses structured CSV telemetry (Database Egress Audit, Network Flows, EDR Exports)."""
        try:
            reader = csv.DictReader(io.StringIO(raw_line), fieldnames=headers)
            row = next(reader)
        except Exception:
            return None

        if not row or row.get(headers[0], "").strip().lower() == headers[0].lower():
            return None

        norm_row = {k.strip().lower(): (v.strip() if v else "") for k, v in row.items() if k}

        raw_ts = norm_row.get("timestamp") or norm_row.get("time") or norm_row.get("date") or ""
        timestamp_utc = cls.normalize_web_or_iso_time(raw_ts)
        host = (norm_row.get("host") or norm_row.get("device") or norm_row.get("server") or "TELEMETRY-NODE").upper()
        src_ip = norm_row.get("src_ip") or norm_row.get("source_ip") or norm_row.get("client_ip") or "N/A"
        dst_ip = norm_row.get("dst_ip") or norm_row.get("dest_ip") or norm_row.get("destination_ip") or "N/A"
        dst_port = cls._safe_int(norm_row.get("dst_port") or norm_row.get("dest_port") or norm_row.get("port"))
        user_name = norm_row.get("user") or norm_row.get("username") or norm_row.get("db_user") or "N/A"
        logon_id = norm_row.get("logon_id") or norm_row.get("session_id") or f"CSV_{src_ip}"
        action = (norm_row.get("action") or norm_row.get("event_type") or "TELEMETRY_FLOW").upper()
        cmd_or_query = (
            norm_row.get("query")
            or norm_row.get("command")
            or norm_row.get("payload")
            or f"Action={action} BytesOut={norm_row.get('bytes_out', '0')}"
        )

        event_category = "NETWORK_CONNECT"
        event_code = 3
        if any(w in cmd_or_query.upper() or w in action for w in ("SELECT ", "DUMP", "EGRESS", "EXFIL", "EXPORT", "OUTFILE")):
            event_category = "DB_QUERY_OR_EGRESS"
            event_code = 9001
        elif "DENY" in action or "FAIL" in action:
            event_category = "AUTH_FAILED"
            event_code = 4625

        return {
            "timestamp_utc": timestamp_utc,
            "host": host,
            "log_source_type": "CSV_TELEMETRY",
            "event_code": event_code,
            "event_category": event_category,
            "user_name": user_name,
            "logon_id": logon_id,
            "process_guid": "N/A",
            "process_id": cls._safe_int(norm_row.get("pid") or norm_row.get("process_id")),
            "parent_process_guid": "N/A",
            "parent_process_id": cls._safe_int(norm_row.get("ppid") or norm_row.get("parent_process_id")),
            "image_path": norm_row.get("process") or norm_row.get("app") or action,
            "parent_image_path": "N/A",
            "command_line": cmd_or_query,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "target_filename": norm_row.get("file") or norm_row.get("table") or "N/A",
            "confidence_score": 90
        }

    @staticmethod
    def stream_via_c_indexer(
        binary_path: str,
        log_file_path: str,
        filter_token: Optional[str] = None
    ) -> Iterator[Tuple[int, int, bytes]]:
        """
        Executes the compiled C binary (`raw_pre_indexer`) via subprocess pipe
        and yields (line_number, byte_offset, clean_payload_bytes) tuples.
        """
        cmd = [str(Path(binary_path).resolve()), str(Path(log_file_path).resolve())]
        if filter_token:
            cmd.append(filter_token)

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert proc.stdout is not None

        for raw_out in proc.stdout:
            parts = raw_out.rstrip(b"\r\n").split(b"|", 3)
            if len(parts) == 4:
                line_num = int(parts[0])
                byte_offset = int(parts[1])
                payload_bytes = parts[3].strip()
                yield line_num, byte_offset, payload_bytes

        proc.wait()
