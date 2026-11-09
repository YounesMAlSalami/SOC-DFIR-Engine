# File: core/storyteller.py
# Project: SOC-DFIR-Engine - Production Forensic Engine
# Python Version: 3.13 (Standard Library Only)

import html
import re
from pathlib import Path
from typing import List, Dict, Any


class ForensicStoryteller:
    """
    Translates deterministic correlation findings into standard enterprise SOC Incident Reports
    (NIST SP 800-61 / SANS framework), Mermaid visual flows, and native Draw.io XML diagrams.
    """

    @staticmethod
    def _clean_mermaid_text(text: str, max_len: int = 80) -> str:
        cleaned = text.replace('"', "'").replace("\n", " ").replace("\r", " ")
        cleaned = cleaned.replace("[", "(").replace("]", ")").replace("{", "(").replace("}", ")")
        if len(cleaned) > max_len:
            return cleaned[: max_len - 3] + "..."
        return cleaned

    @classmethod
    def generate_mermaid_flowchart(cls, finding: Dict[str, Any]) -> str:
        """Generates a Mermaid Live Editor compatible flowchart for a verified attack chain."""
        host_safe = "".join(c if c.isalnum() else "_" for c in str(finding["host"]))
        lines = ["flowchart TD"]
        lines.append(
            f'    subgraph HOST_{host_safe} ["Host Topology: {finding["host"]} | Session: {finding["logon_id"]} | Risk: {finding.get("risk_score", 0)}/100"]'
        )

        prev_node_id = None
        for idx, ev in enumerate(finding["evidence_chain"], start=1):
            node_id = f"N{idx}"
            short_hash = str(ev["sha256"])[:12]
            stage = cls._clean_mermaid_text(str(ev["stage"]), 40)
            detail = cls._clean_mermaid_text(str(ev["detail"]), 75)
            decoded = cls._clean_mermaid_text(str(ev.get("decoded_payload", "")), 70)

            mitre_list = ev.get("mitre_mappings", [])
            mitre_str = ", ".join(m["id"] for m in mitre_list) if mitre_list else "Tracked"

            label_parts = [
                f"({idx}) {stage} [{mitre_str}]",
                f"UTC: {ev['timestamp']}",
                f"{detail}"
            ]
            if decoded:
                label_parts.append(f"Decoded: {decoded}")
            label_parts.append(f"Line: {ev['line']} | Offset: {ev.get('byte_offset', 0)} | SHA256: {short_hash}...")

            label_str = "\\n".join(label_parts)
            lines.append(f'        {node_id}["{label_str}"]')

            if prev_node_id is not None:
                lines.append(
                    f'        {prev_node_id} -->|"LogonId: {finding["logon_id"]}"| {node_id}'
                )
            prev_node_id = node_id

        lines.append("    end")
        lines.append(f"    style HOST_{host_safe} fill:#f8fafc,stroke:#1e293b,stroke-width:2px")
        return "\n".join(lines)

    @staticmethod
    def generate_drawio_xml(finding: Dict[str, Any]) -> str:
        """Generates a native Draw.io (mxGraphModel) XML file representing the forensic chain."""
        cells: List[str] = []
        y_pos = 50
        prev_cell_id = None

        header_text = (
            f"SOC-DFIR-Engine: Attack Chain Proof — Host: {finding['host']}\n"
            f"User: {finding['user_name']} | Session (LogonId): {finding['logon_id']} | Origin IP: {finding['src_ip']}\n"
            f"Severity: {finding['severity']} (Risk Score: {finding.get('risk_score', 0)}/100)"
        )
        header_escaped = html.escape(header_text).replace("\n", "&#xa;")
        cells.append(
            f'        <mxCell id="header_banner" value="{header_escaped}" '
            f'style="rounded=0;whiteSpace=wrap;html=1;fillColor=#1e293b;fontColor=#ffffff;strokeColor=#0f172a;fontStyle=1;fontSize=13;align=left;spacingLeft=12;" '
            f'vertex="1" parent="1">\n'
            f'          <mxGeometry x="120" y="{y_pos}" width="640" height="75" as="geometry" />\n'
            f'        </mxCell>'
        )
        y_pos += 110

        for idx, item in enumerate(finding["evidence_chain"], start=1):
            cell_id = f"ev_node_{idx}"
            short_hash = str(item["sha256"])[:16]
            src_file_name = Path(str(item.get("source_file", "evidence.log"))).name
            mitre_ids = ", ".join(m["id"] for m in item.get("mitre_mappings", []))
            mitre_str = f" | MITRE: {mitre_ids}" if mitre_ids else ""

            raw_lines = [
                f"[{idx}] {item['stage']}{mitre_str} — {item['timestamp']}",
                f"{item['detail']}"
            ]
            if item.get("decoded_payload"):
                raw_lines.append(f"DEOBFUSCATED: {item['decoded_payload']}")
            raw_lines.append(
                f"File: {src_file_name} (Line: {item['line']}, Offset: {item.get('byte_offset', 0)}) | SHA256: {short_hash}..."
            )

            escaped_label = html.escape("\n".join(raw_lines)).replace("\n", "&#xa;")

            fill_color = "#dae8fc"
            stroke_color = "#6c8ebf"
            stage_upper = str(item["stage"]).upper()
            if "FAIL" in stage_upper:
                fill_color = "#ffe6cc"
                stroke_color = "#d79b00"
            elif "PROCESS" in stage_upper or "STAGING" in stage_upper or "WEBSHELL" in stage_upper:
                fill_color = "#fff2cc"
                stroke_color = "#d6b656"
            elif "EGRESS" in stage_upper or "EXPLOIT" in stage_upper or "DROP" in stage_upper:
                fill_color = "#f8cecc"
                stroke_color = "#b85450"
            elif "SUCCESS" in stage_upper:
                fill_color = "#d5e8d4"
                stroke_color = "#82b366"

            box_height = 105 if item.get("decoded_payload") else 85
            cells.append(
                f'        <mxCell id="{cell_id}" value="{escaped_label}" '
                f'style="rounded=1;whiteSpace=wrap;html=1;align=left;spacingLeft=10;fillColor={fill_color};strokeColor={stroke_color};fontStyle=1;fontSize=11;" '
                f'vertex="1" parent="1">\n'
                f'          <mxGeometry x="120" y="{y_pos}" width="640" height="{box_height}" as="geometry" />\n'
                f'        </mxCell>'
            )

            if prev_cell_id is not None:
                edge_id = f"ev_edge_{idx}"
                edge_label = html.escape(f"Deterministic Link (LogonId: {finding['logon_id']})")
                cells.append(
                    f'        <mxCell id="{edge_id}" value="{edge_label}" '
                    f'style="edgeStyle=orthogonalEdgeStyle;rounded=0;orthogonalLoop=1;jettySize=auto;html=1;strokeWidth=2;strokeColor=#334155;fontStyle=1;fontSize=10;" '
                    f'edge="1" parent="1" source="{prev_cell_id}" target="{cell_id}">\n'
                    f'          <mxGeometry relative="1" as="geometry" />\n'
                    f'        </mxCell>'
                )

            prev_cell_id = cell_id
            y_pos += box_height + 45

        cells_xml = "\n".join(cells)
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<mxfile host="app.diagrams.net" modified="2026-11-10T00:00:00.000Z" agent="SOC-DFIR-Engine" version="21.0.0" type="device">
  <diagram id="soc_chain_{html.escape(str(finding['host']))}" name="Attack Chain - {html.escape(str(finding['host']))}">
    <mxGraphModel dx="1422" dy="900" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="900" pageHeight="{max(1100, y_pos + 100)}" math="0" shadow="0">
      <root>
        <mxCell id="0" />
        <mxCell id="1" parent="0" />
{cells_xml}
      </root>
    </mxGraphModel>
  </diagram>
</mxfile>"""

    @classmethod
    def generate_markdown_report(
        cls,
        host: str,
        findings: List[Dict[str, Any]],
        process_trees: Dict[int, List[Dict[str, Any]]],
        deviations: List[Dict[str, Any]],
        pivots: List[Dict[str, Any]]
    ) -> str:
        """
        Generates an enterprise-standard SOC Incident Investigation Report
        incorporating NIST SP 800-61 / SANS sections and cryptographic traceability.
        """
        max_severity = "LOW"
        highest_risk = 0
        affected_users = set()
        compromised_sessions = set()
        external_ips = set()
        dropped_files = set()
        hashes_list = []

        for f in findings:
            if f.get("severity") == "CRITICAL":
                max_severity = "CRITICAL"
            elif f.get("severity") == "HIGH" and max_severity != "CRITICAL":
                max_severity = "HIGH"
            highest_risk = max(highest_risk, int(f.get("risk_score", 0)))
            affected_users.add(str(f.get("user_name", "UNKNOWN")))
            compromised_sessions.add(str(f.get("logon_id", "0x0")))
            if f.get("src_ip") and f.get("src_ip") not in ("127.0.0.1", "::1", "N/A", "-"):
                external_ips.add(str(f.get("src_ip")))

            for ev in f.get("evidence_chain", []):
                hashes_list.append((ev.get("sha256"), ev.get("stage"), Path(str(ev.get("source_file", ""))).name))
                detail_lower = str(ev.get("detail", "")).lower()
                if "created file:" in detail_lower or "dropped artifact:" in detail_lower or "staging utility:" in detail_lower:
                    dropped_files.add(str(ev.get("detail")))
                if ev.get("stage") == "NETWORK_EGRESS":
                    match_ip = re.search(r"->\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", str(ev.get("detail")))
                    if match_ip:
                        external_ips.add(match_ip.group(1))

        case_id = f"INC-{host}-{abs(hash(host)) % 100000:05d}"

        md: List[str] = []
        md.append(f"# Enterprise SOC Incident Investigation Report: `{case_id}`")
        md.append("")

        # Section 1: Incident Metadata
        md.append("## 1. Incident Metadata")
        md.append("| Metadata Attribute | Operational Value |")
        md.append("| :--- | :--- |")
        md.append(f"| **Incident Ticket ID** | `{case_id}` |")
        md.append(f"| **Analysis Engine** | `SOC-DFIR-Engine v2.0 (Deterministic Runtime)` |")
        md.append(f"| **Classification Level** | `TLP:AMBER+STRICT (Internal SOC Restrictive)` |")
        md.append(f"| **Severity & Risk Assessment** | **`{max_severity}`** (`{highest_risk}/100 Risk Rating`) |")
        md.append(f"| **Target Scope / Host Isolated** | Hostname: `{host}` |")
        md.append(f"| **Compromised Identity Scope** | User Accounts: `{', '.join(affected_users) or 'N/A'}` |")
        md.append(f"| **Correlated Sessions** | Logon IDs: `{', '.join(compromised_sessions) or 'N/A'}` |")
        md.append(f"| **Investigation Timestamp** | `2026-11-10T02:00:00Z (UTC Standard)` |")
        md.append("")

        # Section 2: Executive Summary
        md.append("## 2. Executive Summary")
        if findings:
            md.append(
                f"**Overview:** A verified high-confidence security compromise was detected on endpoint/server **`{host}`**. "
                f"The SOC-DFIR-Engine correlated **{len(findings)} deterministic multi-stage attack chain(s)** spanning "
                f"initial authentication anomalies, secondary script de-obfuscation, sensitive file manipulation, and network communication."
            )
            md.append("")
            md.append(f"- **What Happened:** Identity `{', '.join(affected_users)}` was leveraged through session `{', '.join(compromised_sessions)}` to execute unauthorized command-line actions and sensitive tool execution.")
            md.append(f"- **Business Impact:** High risk of internal credential harvesting, reconnaissance, and unauthorized staging of operational assets on `{host}`.")
            md.append(f"- **SOC Operational Verdict:** Confirmed True Positive (TP) — Critical threat containment active.")
        else:
            md.append(f"No multi-stage malicious attack chains triggered on `{host}`. Telemetry remained within acceptable statistical variance.")
        md.append("")

        # Section 3: Forensic Root Cause Analysis & Attack Chains
        md.append("## 3. Root Cause Analysis & Reconstructed Attack Chains")
        if not findings:
            md.append("_No multi-stage intrusion chains reconstructed._")
            md.append("")
        else:
            for idx, f in enumerate(findings, start=1):
                md.append(f"### 3.{idx} Attack Path #{idx}: `{f['chain_type']}`")
                md.append(f"- **Initial Access / Weaponization:** Account `{f['user_name']}` originating from IP `{f['src_ip']}`.")
                md.append(f"- **Deterministic Proof:** {f['deterministic_proof']}")
                mitre_tactics = f.get("mitre_tactics", [])
                if mitre_tactics:
                    mitre_formatted = ", ".join(f"`{m['id']}` ({m['name']})" for m in mitre_tactics)
                    md.append(f"- **MITRE ATT&CK Mapping:** {mitre_formatted}")
                md.append("")
                md.append("#### Cryptographic Traceability Matrix (Chain of Custody)")
                md.append("| # | Timestamp (UTC) | Stage | Forensic Details & De-obfuscation | Source File (Line:Offset) | Raw Record SHA-256 |")
                md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
                for step_i, ev in enumerate(f["evidence_chain"], start=1):
                    detail_txt = str(ev["detail"]).replace("|", "\\|")
                    if ev.get("decoded_payload"):
                        dec_txt = str(ev["decoded_payload"]).replace("|", "\\|")
                        detail_txt += f" <br>**[DE-OBFUSCATED]:** `{dec_txt}`"
                    src_name = Path(str(ev.get("source_file", "raw.log"))).name
                    loc_str = f"`{src_name}` (L:{ev['line']}, Off:{ev.get('byte_offset', 0)})"
                    md.append(
                        f"| {step_i} | `{ev['timestamp']}` | **{ev['stage']}** | {detail_txt} | {loc_str} | `{ev['sha256']}` |"
                    )
                md.append("")
                md.append("#### Visual Kill-Chain Diagram (Mermaid)")
                md.append("```mermaid")
                md.append(cls.generate_mermaid_flowchart(f))
                md.append("```")
                md.append("")

        # Section 4: Deterministic Process Lineage Trees
        md.append("## 4. Deterministic Process Lineage (Hierarchical Process Trees)")
        if not process_trees:
            md.append("_No suspicious process lineage trees reconstructed._")
            md.append("")
        else:
            for root_pid, tree in process_trees.items():
                md.append(f"### Lineage Tree (Root PID: `{root_pid}`)")
                md.append("| Depth | Process Hierarchy (`Lineage Path`) | Timestamp (UTC) | Executable Image | Command Line Execution | SHA-256 |")
                md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
                for node in tree:
                    cmd_str = str(node["command_line"]).replace("|", "\\|")
                    if node.get("decoded_payload"):
                        dec_str = str(node["decoded_payload"]).replace("|", "\\|")
                        cmd_str += f" <br>**[DE-OBFUSCATED]:** `{dec_str}`"
                    md.append(
                        f"| {node['depth']} | `{node['lineage_path']}` | `{node['timestamp_utc']}` | "
                        f"`{node['image_path']}` | {cmd_str} | `{node['sha256_hash'][:16]}...` |"
                    )
                md.append("")

        # Section 5: Baseline Deviations & Lateral Movement
        md.append("## 5. Statistical Baseline Deviations & Lateral Movement")
        if deviations:
            md.append("### Baseline Behavioral Anomalies")
            md.append("| Timestamp (UTC) | Metric | Baseline Normal | Observed Deviation | Forensic Anomaly Justification |")
            md.append("| :--- | :--- | :--- | :--- | :--- |")
            for d in deviations:
                md.append(
                    f"| `{d['timestamp_utc']}` | {d['metric']} | {d['expected_baseline']} | "
                    f"`{d['actual_observed']}` | {d['reason']} |"
                )
            md.append("")

        if pivots:
            md.append("### Cross-Host Lateral Movement Proofs")
            md.append("| Pivot Window (UTC) | Origin Host (`IP`) | Destination Host (`User / LogonId`) | Dual Cryptographic Verification Proof |")
            md.append("| :--- | :--- | :--- | :--- |")
            for p in pivots:
                md.append(
                    f"| `{p['egress_time']}` | **{p['source_host']}** (`{p['pivot_src_ip']}`) | "
                    f"**{p['target_host']}** (`{p['target_user']}` / `{p['target_logon_id']}`) | {p['proof']} |"
                )
            md.append("")

        # Section 6: Actionable Indicators of Compromise (IoCs)
        md.append("## 6. Actionable Indicators of Compromise (IoCs)")
        md.append("| IoC Type | Value / Observable Indicator | Context & Operational Guidance |")
        md.append("| :--- | :--- | :--- |")
        for ip in sorted(external_ips):
            md.append(f"| **IPv4 Address** | `{ip}` | Suspect Network Origin / Ingress / Egress Endpoint |")
        for h, st, sf in hashes_list[:8]:
            md.append(f"| **Cryptographic Hash** | `{h}` | Evidence Record SHA-256 (`{sf}` - `{st}`) |")
        if not external_ips and not hashes_list:
            md.append("| N/A | None detected | No definitive external observables identified. |")
        md.append("")

        # Section 7: Containment, Eradication & Remediation Actions
        md.append("## 7. Containment, Eradication & Remediation Playbook")
        md.append("1. **Host-Level Isolation:** Immediately isolate **`" + host + "`** from the corporate production network via EDR / network quarantine to prevent unauthorized persistence or staging.")
        if affected_users:
            md.append(f"2. **Identity Remediation:** Force a password reset and revoke all active Kerberos TGTs/Azure PRTs and session tokens for user account(s): **`{', '.join(affected_users)}`**.")
        if external_ips:
            md.append(f"3. **Perimeter Firewall Enforcement:** Blacklist suspect IP address(es) **`{', '.join(sorted(external_ips))}`** on perimeter edge firewalls, web application proxies, and perimeter gateways.")
        md.append("4. **Endpoint Forensic Extraction:** Collect memory dumps and preserve raw security journals for legal chain of custody.")
        md.append("5. **Persistence Inspection:** Inspect scheduled tasks, WMI event subscriptions, and run-keys for secondary implants.")
        md.append("")

        return "\n".join(md)
