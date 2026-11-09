# File: core/storyteller.py
# Project: Log Story Studio (LSS) - Production Forensic Engine
# Python Version: 3.13 (Standard Library Only)

import html
from pathlib import Path
from typing import List, Dict, Any


class ForensicStoryteller:
    """
    Translates deterministic correlation findings, recursive process trees,
    baseline deviations, and lateral movement proofs into publication-ready
    Markdown reports, Mermaid flowcharts, and native Draw.io XML diagrams.
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
        host_safe = re.sub_safe = "".join(c if c.isalnum() else "_" for c in str(finding["host"]))
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

        # Header Banner Cell
        header_text = (
            f"FORENSIC ATTACK CHAIN — HOST: {finding['host']}\n"
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

            # Color coding based on forensic stage
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
<mxfile host="app.diagrams.net" modified="2026-11-10T00:00:00.000Z" agent="LogStoryStudio-DFIR" version="21.0.0" type="device">
  <diagram id="lss_chain_{html.escape(str(finding['host']))}" name="Attack Chain - {html.escape(str(finding['host']))}">
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
        """Generates a comprehensive Markdown forensic report with full cryptographic traceability."""
        md: List[str] = []
        md.append(f"# Forensic Investigation & Attack Narrative Report — Host: `{host}`")
        md.append("")
        md.append("## 1. Executive Summary & Host-Centric Topology")
        md.append(f"- **Isolated Target Host:** `{host}`")
        md.append(f"- **Verified Multi-Stage Attack Chains:** `{len(findings)}`")
        md.append(f"- **Reconstructed Root Process Trees:** `{len(process_trees)}`")
        md.append(f"- **Statistical Baseline Deviations:** `{len(deviations)}`")
        md.append(f"- **Cross-Host Lateral Movement Links Involving Host:** `{len(pivots)}`")
        md.append("")

        md.append("---")
        md.append("## 2. Reconstructed Attack Chains & Traceability Proof")
        if not findings:
            md.append("_No multi-stage attack chains triggered on this host._")
            md.append("")
        else:
            for idx, f in enumerate(findings, start=1):
                md.append(f"### 2.{idx} Attack Chain #{idx}: `{f['chain_type']}`")
                md.append(f"- **Severity / Risk Score:** `{f['severity']}` (`{f.get('risk_score', 0)}/100`)")
                md.append(f"- **Compromised Account:** `{f['user_name']}`")
                md.append(f"- **Deterministic Session Binding (`LogonId`):** `{f['logon_id']}`")
                md.append(f"- **Origin / Source IP:** `{f['src_ip']}`")
                md.append(f"- **Forensic Proof:** {f['deterministic_proof']}")

                mitre_tactics = f.get("mitre_tactics", [])
                if mitre_tactics:
                    mitre_formatted = ", ".join(f"`{m['id']}` ({m['name']} - _{m['tactic']}_)" for m in mitre_tactics)
                    md.append(f"- **MITRE ATT&CK Coverage:** {mitre_formatted}")
                md.append("")

                md.append("#### Cryptographic Traceability Matrix (`Alert -> Event -> Source File:Line:Offset -> SHA-256`)")
                md.append("| Step | Timestamp (UTC) | Stage | Event Details & De-obfuscation | MITRE | Source File (Line / Offset) | Raw Record SHA-256 |")
                md.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
                for step_i, ev in enumerate(f["evidence_chain"], start=1):
                    detail_txt = str(ev["detail"]).replace("|", "\\|")
                    if ev.get("decoded_payload"):
                        dec_txt = str(ev["decoded_payload"]).replace("|", "\\|")
                        detail_txt += f" <br>**[DECODED]:** `{dec_txt}`"
                    mitre_ids = ", ".join(f"`{m['id']}`" for m in ev.get("mitre_mappings", [])) or "-"
                    src_name = Path(str(ev.get("source_file", "raw.log"))).name
                    loc_str = f"`{src_name}` (L:{ev['line']}, Off:{ev.get('byte_offset', 0)})"
                    md.append(
                        f"| {step_i} | `{ev['timestamp']}` | **{ev['stage']}** | {detail_txt} | {mitre_ids} | {loc_str} | `{ev['sha256']}` |"
                    )
                md.append("")
                md.append("#### Mermaid Visual Attack Narrative")
                md.append("```mermaid")
                md.append(cls.generate_mermaid_flowchart(f))
                md.append("```")
                md.append("")

        md.append("---")
        md.append("## 3. Deterministic Process Lineage (Recursive Process Trees)")
        if not process_trees:
            md.append("_No suspicious process lineage trees reconstructed._")
            md.append("")
        else:
            for root_pid, tree in process_trees.items():
                md.append(f"### Root Process ID: `{root_pid}`")
                md.append("| Depth | Lineage Path (`PID -> Child`) | Timestamp (UTC) | Image | Command Line & Decoded Payload | Risk | Record SHA-256 |")
                md.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
                for node in tree:
                    cmd_str = str(node["command_line"]).replace("|", "\\|")
                    if node.get("decoded_payload"):
                        dec_str = str(node["decoded_payload"]).replace("|", "\\|")
                        cmd_str += f" <br>**[DECODED]:** `{dec_str}`"
                    md.append(
                        f"| {node['depth']} | `{node['lineage_path']}` | `{node['timestamp_utc']}` | "
                        f"`{node['image_path']}` | {cmd_str} | `{node.get('risk_score', 0)}` | `{node['sha256_hash']}` (L:{node['line_number']}) |"
                    )
                md.append("")

        md.append("---")
        md.append("## 4. Baseline Deviations & Behavioral Anomalies")
        if not deviations:
            md.append("_No statistical baseline deviations detected on this host._")
            md.append("")
        else:
            md.append("| Timestamp (UTC) | Metric | Expected Baseline | Actual Observed | Sample Command & Decoded Payload | Forensic Justification | Record SHA-256 |")
            md.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
            for d in deviations:
                cmd_d = str(d["command_line"]).replace("|", "\\|")
                if d.get("decoded_payload"):
                    cmd_d += f" <br>**[DECODED]:** `{str(d['decoded_payload']).replace('|', '\\|')}`"
                md.append(
                    f"| `{d['timestamp_utc']}` | {d['metric']} | {d['expected_baseline']} | "
                    f"`{d['actual_observed']}` | {cmd_d} | {d['reason']} | `{d['sha256_hash']}` (L:{d['line_number']}) |"
                )
            md.append("")

        md.append("---")
        md.append("## 5. Cross-Host Lateral Movement Proofs")
        if not pivots:
            md.append("_No cross-host lateral movement pivots detected involving this host._")
            md.append("")
        else:
            md.append("| Egress Time (UTC) | Source Host (`IP`) | Target Host (`User / LogonId`) | Deterministic Dual-Hash Proof | Egress SHA-256 | Ingress SHA-256 |")
            md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for p in pivots:
                md.append(
                    f"| `{p['egress_time']}` | **{p['source_host']}** (`{p['pivot_src_ip']}`) | "
                    f"**{p['target_host']}** (`{p['target_user']}` / `{p['target_logon_id']}`) | "
                    f"{p['proof']} | `{p['egress_sha256']}` (L:{p['egress_line']}) | `{p['ingress_sha256']}` (L:{p['ingress_line']}) |"
                )
            md.append("")

        return "\n".join(md)
