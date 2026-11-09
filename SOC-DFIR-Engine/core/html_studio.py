# File: core/html_studio.py
# Project: Log Story Studio (LSS) - Production Forensic Engine
# Python Version: 3.13 (Standard Library Only)

import html
from pathlib import Path
from typing import List, Dict, Any


class HTMLForensicWorkbench:
    """
    Builds a zero-dependency, single-file interactive HTML DFIR Workbench
    for rapid triage, de-obfuscation inspection, process tree visualization,
    and cryptographic hash verification.
    """

    @staticmethod
    def generate_interactive_html(
        host: str,
        findings: List[Dict[str, Any]],
        process_trees: Dict[int, List[Dict[str, Any]]],
        deviations: List[Dict[str, Any]],
        pivots: List[Dict[str, Any]]
    ) -> str:
        chain_cards_html: List[str] = []

        for idx, f in enumerate(findings, start=1):
            rows_html: List[str] = []
            for step_i, ev in enumerate(f["evidence_chain"], start=1):
                mitre_badges = " ".join(
                    f'<span class="badge mitre" title="{html.escape(m.get("tactic", ""))}">'
                    f'{html.escape(m["id"])}: {html.escape(m["name"])}</span>'
                    for m in ev.get("mitre_mappings", [])
                )

                decoded_box = ""
                if ev.get("decoded_payload"):
                    decoded_box = (
                        f'<div class="decoded-box">'
                        f'<strong>DE-OBFUSCATED PAYLOAD:</strong> '
                        f'<code>{html.escape(str(ev["decoded_payload"]))}</code>'
                        f'</div>'
                    )

                src_file_short = Path(str(ev.get("source_file", "evidence.log"))).name
                loc_info = f"{html.escape(src_file_short)}<br><span class='muted'>Line: {ev['line']} | Offset: {ev.get('byte_offset', 0)}</span>"

                rows_html.append(f"""
                <tr>
                    <td><strong>{step_i}</strong></td>
                    <td><code>{html.escape(str(ev['timestamp']))}</code></td>
                    <td><span class="badge stage">{html.escape(str(ev['stage']))}</span></td>
                    <td>
                        <div class="cmd-text">{html.escape(str(ev['detail']))}</div>
                        {decoded_box}
                        <div style="margin-top:6px;">{mitre_badges}</div>
                    </td>
                    <td>{loc_info}</td>
                    <td><code class="hash">{html.escape(str(ev['sha256']))}</code></td>
                </tr>
                """)

            chain_mitre_summary = " ".join(
                f'<span class="badge mitre">{html.escape(m["id"])} ({html.escape(m["tactic"])})</span>'
                for m in f.get("mitre_tactics", [])
            )

            chain_cards_html.append(f"""
            <div class="card">
                <div class="card-header">
                    <h3>Attack Chain #{idx}: {html.escape(str(f['chain_type']))}</h3>
                    <span class="badge crit">{html.escape(str(f['severity']))} | Risk: {f.get('risk_score', 0)}/100</span>
                </div>
                <p>
                    <strong>Compromised User:</strong> <code>{html.escape(str(f['user_name']))}</code> &nbsp;|&nbsp;
                    <strong>Session Binding (LogonId):</strong> <code>{html.escape(str(f['logon_id']))}</code> &nbsp;|&nbsp;
                    <strong>Origin IP:</strong> <code>{html.escape(str(f['src_ip']))}</code>
                </p>
                <div class="proof">{html.escape(str(f['deterministic_proof']))}</div>
                <div style="margin-bottom:12px;">{chain_mitre_summary}</div>
                <input type="text" class="search-input" onkeyup="filterTable(this)" placeholder="Instant filter by command, decoded payload, MITRE ID, line number, or SHA-256 hash...">
                <table>
                    <thead>
                        <tr>
                            <th style="width:40px;">#</th>
                            <th style="width:185px;">Timestamp (UTC)</th>
                            <th style="width:160px;">Stage</th>
                            <th>Forensic Event Details / De-obfuscated Payload / MITRE ATT&CK</th>
                            <th style="width:170px;">Source File & Offset</th>
                            <th style="width:240px;">Raw Record SHA-256</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows_html)}
                    </tbody>
                </table>
            </div>
            """)

        # Process Trees Section
        tree_cards_html: List[str] = []
        for root_pid, nodes in process_trees.items():
            t_rows: List[str] = []
            for n in nodes:
                indent = "&nbsp;&nbsp;&nbsp;&nbsp;" * int(n["depth"])
                branch_prefix = "&#9492;&#9472;&rsaquo; " if int(n["depth"]) > 0 else "&#9679; "
                dec_html = (
                    f'<div class="decoded-box"><strong>DECODED:</strong> <code>{html.escape(str(n["decoded_payload"]))}</code></div>'
                    if n.get("decoded_payload") else ""
                )
                t_rows.append(f"""
                <tr>
                    <td><code>{n['depth']}</code></td>
                    <td><code>{html.escape(str(n['lineage_path']))}</code></td>
                    <td><code>{html.escape(str(n['timestamp_utc']))}</code></td>
                    <td>{indent}{branch_prefix}<strong>{html.escape(str(n['image_path']))}</strong></td>
                    <td>
                        <div class="cmd-text"><code>{html.escape(str(n['command_line']))}</code></div>
                        {dec_html}
                    </td>
                    <td><span class="badge stage">{n.get('risk_score', 0)}/100</span></td>
                    <td>Line <code>{n['line_number']}</code><br><code class="hash">{html.escape(str(n['sha256_hash']))}</code></td>
                </tr>
                """)
            tree_cards_html.append(f"""
            <div class="card">
                <h3>Recursive Process Lineage Tree (Root PID: <code>{root_pid}</code>)</h3>
                <input type="text" class="search-input" onkeyup="filterTable(this)" placeholder="Filter process lineage tree...">
                <table>
                    <thead>
                        <tr>
                            <th>Depth</th>
                            <th>PID Lineage Path</th>
                            <th>Timestamp (UTC)</th>
                            <th>Process Hierarchy</th>
                            <th>Command Line & De-obfuscation</th>
                            <th>Risk</th>
                            <th>Line & SHA-256</th>
                        </tr>
                    </thead>
                    <tbody>{''.join(t_rows)}</tbody>
                </table>
            </div>
            """)

        # Baseline Deviations Section
        dev_rows_html: List[str] = []
        for d in deviations:
            dec_d = (
                f'<div class="decoded-box"><strong>DECODED:</strong> <code>{html.escape(str(d["decoded_payload"]))}</code></div>'
                if d.get("decoded_payload") else ""
            )
            dev_rows_html.append(f"""
            <tr>
                <td><code>{html.escape(str(d['timestamp_utc']))}</code></td>
                <td>{html.escape(str(d['metric']))}</td>
                <td>{html.escape(str(d['expected_baseline']))}</td>
                <td><code>{html.escape(str(d['actual_observed']))}</code></td>
                <td>
                    <div class="cmd-text"><code>{html.escape(str(d['command_line']))}</code></div>
                    {dec_d}
                    <div class="muted" style="margin-top:4px;">{html.escape(str(d['reason']))}</div>
                </td>
                <td>Line <code>{d['line_number']}</code><br><code class="hash">{html.escape(str(d['sha256_hash']))}</code></td>
            </tr>
            """)

        dev_section = f"""
        <div class="card">
            <h3>Statistical Baseline Deviations & Behavioral Anomalies</h3>
            <table>
                <thead>
                    <tr>
                        <th>First Seen (UTC)</th>
                        <th>Baseline Metric</th>
                        <th>Expected Baseline</th>
                        <th>Observed Deviation</th>
                        <th>Command Sample & Forensic Justification</th>
                        <th>Line & SHA-256</th>
                    </tr>
                </thead>
                <tbody>{''.join(dev_rows_html) if dev_rows_html else '<tr><td colspan="6">No statistical deviations detected.</td></tr>'}</tbody>
            </table>
        </div>
        """

        # Cross-Host Pivots Section
        pivot_rows_html: List[str] = []
        for p in pivots:
            pivot_rows_html.append(f"""
            <tr>
                <td><code>{html.escape(str(p['egress_time']))}</code> &rarr; <code>{html.escape(str(p['ingress_time']))}</code></td>
                <td><strong>{html.escape(str(p['source_host']))}</strong><br><code>{html.escape(str(p['pivot_src_ip']))}</code> ({html.escape(str(p['source_process']))})</td>
                <td><strong>{html.escape(str(p['target_host']))}</strong><br>User: <code>{html.escape(str(p['target_user']))}</code> | LogonId: <code>{html.escape(str(p['target_logon_id']))}</code></td>
                <td>{html.escape(str(p['proof']))}</td>
                <td>
                    <strong>Egress (L:{p['egress_line']}):</strong><br><code class="hash">{html.escape(str(p['egress_sha256']))}</code><br>
                    <strong>Ingress (L:{p['ingress_line']}):</strong><br><code class="hash">{html.escape(str(p['ingress_sha256']))}</code>
                </td>
            </tr>
            """)

        pivots_section = f"""
        <div class="card">
            <h3>Cross-Host Lateral Movement Proofs (Dual SHA-256 Verification)</h3>
            <table>
                <thead>
                    <tr>
                        <th>Pivot Window (UTC)</th>
                        <th>Source Host & Process</th>
                        <th>Target Host & Session</th>
                        <th>Deterministic Narrative Proof</th>
                        <th>Dual Cryptographic Hashes</th>
                    </tr>
                </thead>
                <tbody>{''.join(pivot_rows_html) if pivot_rows_html else '<tr><td colspan="5">No cross-host lateral movement pivots detected.</td></tr>'}</tbody>
            </table>
        </div>
        """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Log Story Studio — DFIR Workbench ({html.escape(host)})</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Ubuntu, monospace; background: #0b1120; color: #e2e8f0; margin: 0; padding: 24px; line-height: 1.5; }}
    h1, h2, h3 {{ color: #f8fafc; margin: 0 0 10px 0; }}
    .top-bar {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 20px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; }}
    .kpi-grid {{ display: flex; gap: 16px; flex-wrap: wrap; }}
    .kpi {{ background: #0f172a; border: 1px solid #334155; padding: 10px 18px; border-radius: 6px; text-align: center; }}
    .kpi .num {{ font-size: 22px; font-weight: bold; color: #38bdf8; }}
    .kpi .lbl {{ font-size: 11px; color: #94a3b8; text-transform: uppercase; }}
    .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 20px; margin-bottom: 24px; box-shadow: 0 4px 12px rgba(0,0,0,0.4); }}
    .card-header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 10px; margin-bottom: 12px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 12.5px; }}
    th, td {{ border: 1px solid #334155; padding: 10px; text-align: left; vertical-align: top; }}
    th {{ background: #0f172a; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 11px; }}
    tr:nth-child(even) {{ background: #192338; }}
    tr:hover {{ background: #263554; }}
    .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; margin: 2px 4px 2px 0; }}
    .crit {{ background: #dc2626; color: #ffffff; }}
    .stage {{ background: #2563eb; color: #ffffff; }}
    .mitre {{ background: #059669; color: #ffffff; }}
    .decoded-box {{ background: #451a03; border-left: 4px solid #f59e0b; padding: 8px 10px; margin-top: 6px; color: #fde68a; border-radius: 4px; word-break: break-all; }}
    .cmd-text {{ word-break: break-word; color: #f1f5f9; }}
    .hash {{ font-size: 11px; color: #38bdf8; word-break: break-all; display: inline-block; }}
    .muted {{ font-size: 11px; color: #94a3b8; }}
    .proof {{ background: #0f172a; padding: 12px; border-left: 4px solid #38bdf8; color: #cbd5e1; margin-bottom: 12px; border-radius: 4px; font-size: 13px; }}
    .search-input {{ width: 100%; box-sizing: border-box; padding: 10px 14px; background: #0f172a; border: 1px solid #475569; color: #f8fafc; border-radius: 6px; margin-bottom: 8px; font-size: 13px; }}
    .search-input:focus {{ outline: none; border-color: #38bdf8; }}
</style>
</head>
<body>
    <div class="top-bar">
        <div>
            <h1>Log Story Studio — Forensic Narrative Workbench</h1>
            <div class="muted">Strict Host-Centric Isolation &bull; Cryptographic SHA-256 Traceability &bull; Deterministic Causality</div>
        </div>
        <div class="kpi-grid">
            <div class="kpi"><div class="num">{html.escape(host)}</div><div class="lbl">Isolated Host</div></div>
            <div class="kpi"><div class="num">{len(findings)}</div><div class="lbl">Attack Chains</div></div>
            <div class="kpi"><div class="num">{len(process_trees)}</div><div class="lbl">Process Trees</div></div>
            <div class="kpi"><div class="num">{len(deviations)}</div><div class="lbl">Baseline Deviations</div></div>
            <div class="kpi"><div class="num">{len(pivots)}</div><div class="lbl">Cross-Host Pivots</div></div>
        </div>
    </div>

    {''.join(chain_cards_html) if chain_cards_html else '<div class="card"><h3>Attack Chains</h3><p>No multi-stage attack chains triggered on this host.</p></div>'}
    {''.join(tree_cards_html)}
    {dev_section}
    {pivots_section}

<script>
function filterTable(input) {{
    const filter = input.value.toUpperCase();
    const table = input.nextElementSibling;
    if (!table) return;
    const tr = table.getElementsByTagName("tr");
    for (let i = 1; i < tr.length; i++) {{
        const txt = tr[i].textContent || tr[i].innerText;
        tr[i].style.display = txt.toUpperCase().indexOf(filter) > -1 ? "" : "none";
    }}
}}
</script>
</body>
</html>"""
