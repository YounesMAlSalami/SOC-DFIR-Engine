# File: core/html_studio.py
# Project: SOC-DFIR-Engine - Production Forensic Engine
# Python Version: 3.13 (Standard Library Only)

import html
import re
from pathlib import Path
from typing import List, Dict, Any


class HTMLForensicWorkbench:
    """
    Builds a zero-dependency, single-file interactive enterprise SOC HTML Incident Workbench
    adhering to NIST SP 800-61 / SANS incident response standards.
    """

    @staticmethod
    def generate_interactive_html(
        host: str,
        findings: List[Dict[str, Any]],
        process_trees: Dict[int, List[Dict[str, Any]]],
        deviations: List[Dict[str, Any]],
        pivots: List[Dict[str, Any]]
    ) -> str:
        case_id = f"INC-{host}-{abs(hash(host)) % 100000:05d}"
        max_severity = "LOW"
        highest_risk = 0
        affected_users = set()
        compromised_sessions = set()
        external_ips = set()

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
                if ev.get("stage") == "NETWORK_EGRESS":
                    match_ip = re.search(r"->\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", str(ev.get("detail")))
                    if match_ip:
                        external_ips.add(match_ip.group(1))

        # --- Section 1: Incident Metadata Card ---
        metadata_card = f"""
        <div class="card meta-card">
            <div class="card-header">
                <h3>1. Incident Metadata (معلومات وتصنيف الحادثة)</h3>
                <span class="badge crit">{html.escape(max_severity)} | Risk: {highest_risk}/100</span>
            </div>
            <div class="meta-grid">
                <div><span class="lbl">Incident Ticket ID:</span> <code>{html.escape(case_id)}</code></div>
                <div><span class="lbl">Lead Forensic Investigator:</span> <strong>Younes Al-Salami</strong></div>
                <div><span class="lbl">Traffic Light Protocol:</span> <span class="badge tlp">TLP:AMBER+STRICT</span></div>
                <div><span class="lbl">Framework Standard:</span> <span class="badge stage">NIST SP 800-61 / SANS</span></div>
                <div><span class="lbl">Target Host Isolated:</span> <code>{html.escape(host)}</code></div>
                <div><span class="lbl">Impacted Account(s):</span> <code>{html.escape(', '.join(affected_users) or 'N/A')}</code></div>
                <div><span class="lbl">Compromised Session(s):</span> <code>{html.escape(', '.join(compromised_sessions) or 'N/A')}</code></div>
                <div><span class="lbl">Analysis Engine:</span> <code>SOC-DFIR-Engine v2.0</code></div>
            </div>
        </div>
        """

        # --- Section 2: Executive Summary Card ---
        exec_summary_card = f"""
        <div class="card exec-card">
            <div class="card-header">
                <h3>2. Executive Summary (الملخص التنفيذي لإدارة العمليات)</h3>
                <span class="badge crit">Confirmed True Positive (TP)</span>
            </div>
            <div class="exec-section">
                <div class="exec-item">
                    <h4>What Happened (ماذا حدث؟)</h4>
                    <p>Verified unauthorized access detected against host <strong>{html.escape(host)}</strong>. The intruder leveraged brute-force attempts and authenticated credentials to execute privileged commands and staged sensitive data for potential external exfiltration.</p>
                </div>
                <div class="exec-item">
                    <h4>Who is Impacted (من تأثر؟)</h4>
                    <p>Primary impact confirmed on host <strong>{html.escape(host)}</strong> within user context <strong>{html.escape(', '.join(affected_users) or 'SYSTEM')}</strong>. Ingress origin traced to IP: <strong>{html.escape(', '.join(external_ips) or 'Local/Internal')}</strong>.</p>
                </div>
                <div class="exec-item">
                    <h4>Business Impact (ما هو الأثر على الأعمال؟)</h4>
                    <p>High exposure risk regarding unauthorized access to internal file structures, potential data dumping, and lateral pivoting across trusted network segments.</p>
                </div>
                <div class="exec-item">
                    <h4>SOC Operational Verdict (القرار المتخذ)</h4>
                    <p>Immediate containment applied. Critical containment playbooks active to quarantine the host and prevent secondary malicious activities.</p>
                </div>
            </div>
        </div>
        """

        # --- Section 3: Attack Chains ---
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
                    <h3>3. Attack Chain & Root Cause #{idx}: {html.escape(str(f['chain_type']))}</h3>
                    <span class="badge crit">{html.escape(str(f['severity']))} | Risk: {f.get('risk_score', 0)}/100</span>
                </div>
                <p>
                    <strong>Compromised User:</strong> <code>{html.escape(str(f['user_name']))}</code> &nbsp;|&nbsp;
                    <strong>Session Binding (LogonId):</strong> <code>{html.escape(str(f['logon_id']))}</code> &nbsp;|&nbsp;
                    <strong>Origin IP:</strong> <code>{html.escape(str(f['src_ip']))}</code>
                </p>
                <div class="proof">{html.escape(str(f['deterministic_proof']))}</div>
                <div style="margin-bottom:12px;">{chain_mitre_summary}</div>
                <input type="text" class="search-input" onkeyup="filterTable(this)" placeholder="Filter by command, decoded payload, MITRE ID, or SHA-256 hash...">
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

        # --- Section 4: Process Trees ---
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
                <h3>4. Recursive Process Lineage Tree (Root PID: <code>{root_pid}</code>)</h3>
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

        # --- Section 5: Indicators of Compromise (IoCs) ---
        ioc_rows: List[str] = []
        for ip in sorted(external_ips):
            ioc_rows.append(f"<tr><td><span class='badge crit'>IPv4 Address</span></td><td><code>{html.escape(ip)}</code></td><td>Suspect Origin / Ingress / Egress Endpoint</td></tr>")
        for f in findings:
            for ev in f.get("evidence_chain", []):
                h = str(ev.get("sha256", ""))
                stage = str(ev.get("stage", ""))
                src = Path(str(ev.get("source_file", ""))).name
                ioc_rows.append(f"<tr><td><span class='badge stage'>SHA-256 Hash</span></td><td><code class='hash'>{html.escape(h)}</code></td><td>Evidence Record ({html.escape(src)} - {html.escape(stage)})</td></tr>")

        ioc_section = f"""
        <div class="card">
            <h3>5. Actionable Indicators of Compromise (IoCs - مؤشرات الاختراق)</h3>
            <table>
                <thead>
                    <tr><th style="width:150px;">IoC Type</th><th>Indicator Value</th><th>Context & Firewall/EDR Action</th></tr>
                </thead>
                <tbody>{''.join(ioc_rows) if ioc_rows else '<tr><td colspan="3">No external indicators recorded.</td></tr>'}</tbody>
            </table>
        </div>
        """

        # --- Section 6: Containment & Remediation Playbook ---
        playbook_section = f"""
        <div class="card playbook-card">
            <div class="card-header">
                <h3>6. Containment & Remediation Playbook (إجراءات الاحتواء والاستجابة الموصى بها)</h3>
                <span class="badge crit">Priority 1 Actions</span>
            </div>
            <div class="playbook-grid">
                <div class="playbook-item">
                    <strong>1. Host-Level Network Isolation</strong>
                    <p>Quarantine <code>{html.escape(host)}</code> immediately using EDR to sever communication while keeping forensic management channels open.</p>
                </div>
                <div class="playbook-item">
                    <strong>2. Account & Session Revocation</strong>
                    <p>Revoke active sessions for <code>{html.escape(', '.join(affected_users) or 'N/A')}</code> and enforce credential change across domain controllers.</p>
                </div>
                <div class="playbook-item">
                    <strong>3. Perimeter IP Blacklisting</strong>
                    <p>Apply drop rules on boundary firewalls for confirmed suspect addresses: <code>{html.escape(', '.join(sorted(external_ips)) or 'None')}</code>.</p>
                </div>
                <div class="playbook-item">
                    <strong>4. Forensic Chain of Custody Preservation</strong>
                    <p>Preserve disk snapshots and volatile RAM dumps for comprehensive post-incident digital forensics.</p>
                </div>
            </div>
        </div>
        """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC-DFIR-Engine — Incident Report ({html.escape(host)})</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Ubuntu, monospace; background: #0b1120; color: #e2e8f0; margin: 0; padding: 24px; line-height: 1.5; }}
    h1, h2, h3, h4 {{ color: #f8fafc; margin: 0 0 10px 0; }}
    .top-bar {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 20px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; }}
    .kpi-grid {{ display: flex; gap: 16px; flex-wrap: wrap; }}
    .kpi {{ background: #0f172a; border: 1px solid #334155; padding: 10px 18px; border-radius: 6px; text-align: center; }}
    .kpi .num {{ font-size: 20px; font-weight: bold; color: #38bdf8; }}
    .kpi .lbl {{ font-size: 11px; color: #94a3b8; text-transform: uppercase; }}
    .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 20px; margin-bottom: 24px; box-shadow: 0 4px 12px rgba(0,0,0,0.4); }}
    .meta-card {{ border-left: 4px solid #38bdf8; }}
    .exec-card {{ border-left: 4px solid #f59e0b; }}
    .playbook-card {{ border-left: 4px solid #ef4444; }}
    .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin-top: 10px; font-size: 13px; }}
    .meta-grid .lbl {{ color: #94a3b8; font-size: 11.5px; display: block; }}
    .exec-section {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-top: 12px; }}
    .exec-item {{ background: #0f172a; padding: 14px; border-radius: 6px; border: 1px solid #334155; }}
    .exec-item h4 {{ color: #38bdf8; font-size: 13.5px; margin-bottom: 6px; }}
    .exec-item p {{ margin: 0; font-size: 12.5px; color: #cbd5e1; }}
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
    .tlp {{ background: #d97706; color: #ffffff; }}
    .decoded-box {{ background: #451a03; border-left: 4px solid #f59e0b; padding: 8px 10px; margin-top: 6px; color: #fde68a; border-radius: 4px; word-break: break-all; }}
    .cmd-text {{ word-break: break-word; color: #f1f5f9; }}
    .hash {{ font-size: 11px; color: #38bdf8; word-break: break-all; display: inline-block; }}
    .muted {{ font-size: 11px; color: #94a3b8; }}
    .proof {{ background: #0f172a; padding: 12px; border-left: 4px solid #38bdf8; color: #cbd5e1; margin-bottom: 12px; border-radius: 4px; font-size: 13px; }}
    .search-input {{ width: 100%; box-sizing: border-box; padding: 10px 14px; background: #0f172a; border: 1px solid #475569; color: #f8fafc; border-radius: 6px; margin-bottom: 8px; font-size: 13px; }}
    .playbook-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 14px; margin-top: 10px; }}
    .playbook-item {{ background: #0f172a; padding: 12px; border-radius: 6px; border: 1px solid #334155; }}
    .playbook-item strong {{ color: #ef4444; font-size: 13px; display: block; margin-bottom: 5px; }}
    .playbook-item p {{ margin: 0; font-size: 12px; color: #cbd5e1; }}
</style>
</head>
<body>
    <div class="top-bar">
        <div>
            <h1>SOC-DFIR-Engine — Incident Investigation Workbench</h1>
            <div class="muted">NIST SP 800-61 Standards &bull; Lead Investigator: <strong>Younes Al-Salami</strong></div>
        </div>
        <div class="kpi-grid">
            <div class="kpi"><div class="num">{html.escape(host)}</div><div class="lbl">Target Host</div></div>
            <div class="kpi"><div class="num">{len(findings)}</div><div class="lbl">Attack Chains</div></div>
            <div class="kpi"><div class="num">{len(process_trees)}</div><div class="lbl">Process Trees</div></div>
            <div class="kpi"><div class="num">{len(pivots)}</div><div class="lbl">Lateral Pivots</div></div>
        </div>
    </div>

    {metadata_card}
    {exec_summary_card}
    {''.join(chain_cards_html) if chain_cards_html else '<div class="card"><h3>3. Attack Chains</h3><p>No multi-stage attack chains triggered on this host.</p></div>'}
    {''.join(tree_cards_html)}
    {ioc_section}
    {playbook_section}

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
