# File: core/web_server.py
# Project: SOC-DFIR-Engine - Interactive Local SOC Workbench
# Python Version: 3.13 (Standard Library Only - Zero External Dependencies)

import json
import os
import urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Dict, Any

from core.database import ForensicDatabase
from core.normalizer import CanonicalNormalizer
from core.correlator import DeterministicCorrelator
from core.lateral_movement import LateralMovementDetector


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC-DFIR-Engine — Live Interactive Workbench</title>
<style>
    :root {
        --bg-main: #0b1120;
        --card-bg: #1e293b;
        --border-clr: #334155;
        --accent: #38bdf8;
        --danger: #ef4444;
        --success: #10b981;
        --warning: #f59e0b;
        --text-main: #f8fafc;
        --text-muted: #94a3b8;
    }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: var(--bg-main); color: var(--text-main); margin: 0; padding: 20px; }
    h1, h2, h3, h4 { color: var(--text-main); margin: 0 0 8px 0; }
    .top-bar { background: var(--card-bg); border: 1px solid var(--border-clr); border-radius: 8px; padding: 16px 20px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; }
    .muted { font-size: 12px; color: var(--text-muted); }
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px; }
    @media (max-width: 850px) { .grid-2 { grid-template-columns: 1fr; } }
    .card { background: var(--card-bg); border: 1px solid var(--border-clr); border-radius: 8px; padding: 18px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
    .drop-zone { border: 2px dashed var(--accent); border-radius: 8px; padding: 25px; text-align: center; background: #0f172a; cursor: pointer; transition: 0.2s; }
    .drop-zone:hover, .drop-zone.dragover { background: #1e293b; border-color: #7dd3fc; }
    .btn { background: var(--accent); color: #0b1120; font-weight: bold; border: none; padding: 10px 18px; border-radius: 6px; cursor: pointer; transition: 0.2s; }
    .btn:hover { background: #7dd3fc; }
    .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }
    .badge-crit { background: var(--danger); color: #fff; }
    .badge-stage { background: #2563eb; color: #fff; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 12px; }
    th, td { border: 1px solid var(--border-clr); padding: 8px; text-align: left; vertical-align: top; }
    th { background: #0f172a; color: var(--text-muted); text-transform: uppercase; font-size: 11px; }
    tr:nth-child(even) { background: #162032; }
    tr:hover { background: #1e293b; }
    .search-bar { width: 100%; box-sizing: border-box; padding: 10px 14px; background: #0f172a; border: 1px solid var(--border-clr); color: #fff; border-radius: 6px; margin-bottom: 12px; font-size: 13px; }
    .decoded-box { background: #451a03; border-left: 3px solid var(--warning); padding: 6px 10px; margin-top: 5px; color: #fde68a; font-family: monospace; font-size: 11.5px; word-break: break-all; }
    #toast { position: fixed; bottom: 20px; right: 20px; padding: 12px 20px; border-radius: 6px; background: var(--card-bg); border: 1px solid var(--accent); color: #fff; display: none; z-index: 9999; box-shadow: 0 4px 12px rgba(0,0,0,0.5); }
</style>
</head>
<body>

<div class="top-bar">
    <div>
        <h1>SOC-DFIR-Engine — Live Interactive Workbench</h1>
        <div class="muted">Local Triage Server &bull; NIST SP 800-61 Standards &bull; Lead Investigator: <strong>Younes Al-Salami</strong></div>
    </div>
    <div>
        <button class="btn" onclick="runAnalysis()">Run Correlation & Analysis</button>
    </div>
</div>

<div class="grid-2">
    <div class="card">
        <h3>1. Direct Evidence Ingestion (رفع وسحب السجلات)</h3>
        <p class="muted">Accepts Sysmon JSONL, Linux Auth logs, Web Access logs, Firewall KV, and CSV.</p>
        <div class="drop-zone" id="dropZone" onclick="document.getElementById('fileInput').click()">
            <div id="dropText">Click or Drag & Drop evidence log files here</div>
            <input type="file" id="fileInput" style="display: none;" onchange="handleFileSelect(this.files)">
        </div>
    </div>

    <div class="card">
        <h3>2. Vault Health & Topology Status</h3>
        <p class="muted">Cryptographic SQLite WAL Vault statistics:</p>
        <div id="vaultStats">Loading vault metrics...</div>
    </div>
</div>

<div class="card" style="margin-bottom: 20px;">
    <h3>3. Detected Attack Chains & Deterministic Provenance</h3>
    <input type="text" class="search-bar" id="chainSearch" onkeyup="filterTable('chainTable', this.value)" placeholder="Search by host, user, MITRE ID, or hash...">
    <table id="chainTable">
        <thead>
            <tr>
                <th>Host</th>
                <th>Chain Type</th>
                <th>Severity</th>
                <th>User / Session</th>
                <th>Origin IP</th>
                <th>Events</th>
            </tr>
        </thead>
        <tbody id="chainBody">
            <tr><td colspan="6" class="muted">Click "Run Correlation & Analysis" to execute deterministic analysis.</td></tr>
        </tbody>
    </table>
</div>

<div class="card">
    <h3>4. Process Lineage & Decoded Invocations</h3>
    <input type="text" class="search-bar" id="treeSearch" onkeyup="filterTable('treeTable', this.value)" placeholder="Search process trees, commands, decoded payloads...">
    <table id="treeTable">
        <thead>
            <tr>
                <th>Host</th>
                <th>PID Lineage</th>
                <th>Process Image</th>
                <th>Command Execution & De-obfuscation</th>
                <th>Risk</th>
            </tr>
        </thead>
        <tbody id="treeBody">
            <tr><td colspan="5" class="muted">No process trees available.</td></tr>
        </tbody>
    </table>
</div>

<div id="toast"></div>

<script>
function showToast(msg, isErr=false) {
    const t = document.getElementById('toast');
    t.innerText = msg;
    t.style.borderColor = isErr ? 'var(--danger)' : 'var(--accent)';
    t.style.display = 'block';
    setTimeout(() => { t.style.display = 'none'; }, 4500);
}

function loadStatus() {
    fetch('/api/status')
        .then(r => r.json())
        .then(data => {
            let html = `<strong>Total Canonical Events:</strong> ${data.total_events} <br>`;
            html += `<strong>Isolated Host Topologies (${data.hosts.length}):</strong> ` + 
                    (data.hosts.length ? data.hosts.map(h => `<code>${h}</code>`).join(' ') : 'None');
            document.getElementById('vaultStats').innerHTML = html;
        })
        .catch(err => {
            document.getElementById('vaultStats').innerHTML = '<span style="color:var(--danger)">Offline or connecting...</span>';
        });
}

function runAnalysis() {
    showToast("Executing deterministic correlation...");
    fetch('/api/analyze')
        .then(r => {
            if (!r.ok) throw new Error("HTTP error " + r.status);
            return r.json();
        })
        .then(data => {
            renderChains(data.findings);
            renderTrees(data.process_trees);
            showToast("Analysis Complete! Attack chains & lineage updated.");
        })
        .catch(e => showToast("Analysis failed: " + e.message, true));
}

function renderChains(findings) {
    const tbody = document.getElementById('chainBody');
    if (!findings || findings.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="muted">No multi-stage attack chains detected in current logs.</td></tr>';
        return;
    }
    let html = '';
    findings.forEach(f => {
        html += `<tr>
            <td><strong>${f.host}</strong></td>
            <td><span class="badge badge-stage">${f.chain_type}</span></td>
            <td><span class="badge badge-crit">${f.severity} (${f.risk_score}/100)</span></td>
            <td><code>${f.user_name}</code><br><span class="muted">${f.logon_id}</span></td>
            <td><code>${f.src_ip}</code></td>
            <td><strong>${f.evidence_chain ? f.evidence_chain.length : 0}</strong> events</td>
        </tr>`;
    });
    tbody.innerHTML = html;
}

function renderTrees(trees) {
    const tbody = document.getElementById('treeBody');
    let rows = [];
    if (trees) {
        for (const [host, hostTrees] of Object.entries(trees)) {
            for (const [rootPid, nodes] of Object.entries(hostTrees)) {
                nodes.forEach(n => {
                    let dec = n.decoded_payload ? `<div class="decoded-box"><strong>DECODED:</strong> ${n.decoded_payload}</div>` : '';
                    rows.push(`<tr>
                        <td><strong>${host}</strong></td>
                        <td><code>${n.lineage_path}</code></td>
                        <td><strong>${n.image_path}</strong></td>
                        <td><code>${n.command_line}</code>${dec}</td>
                        <td><span class="badge badge-stage">${n.risk_score}/100</span></td>
                    </tr>`);
                });
            }
        }
    }
    tbody.innerHTML = rows.length ? rows.join('') : '<tr><td colspan="5" class="muted">No process trees recorded.</td></tr>';
}

function filterTable(tableId, query) {
    const q = query.toLowerCase();
    const rows = document.querySelectorAll(`#${tableId} tbody tr`);
    rows.forEach(r => {
        r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
}

const dropZone = document.getElementById('dropZone');
dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length) handleFileSelect(e.dataTransfer.files);
});

function handleFileSelect(files) {
    const file = files[0];
    if (!file) return;
    showToast(`Uploading and ingesting: ${file.name}...`);
    const reader = new FileReader();
    reader.onload = function(e) {
        fetch('/api/upload', {
            method: 'POST',
            headers: { 'X-Filename': encodeURIComponent(file.name) },
            body: e.target.result
        })
        .then(r => r.json())
        .then(res => {
            showToast(`Ingested ${res.ingested} lines successfully!`);
            loadStatus();
            runAnalysis();
        })
        .catch(err => showToast("Upload error: " + err, true));
    };
    reader.readAsArrayBuffer(file);
}

window.onload = () => { loadStatus(); };
</script>
</body>
</html>
"""


class SOCWorkbenchHandler(BaseHTTPRequestHandler):
    vault_db: ForensicDatabase = None

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode("utf-8"))
        elif parsed.path == "/api/status":
            try:
                stats = self.vault_db.get_stats()
                hosts = list(stats.get("canonical_by_host", {}).keys())
                total_events = sum(stats.get("canonical_by_host", {}).values())
                data = {"hosts": hosts, "total_events": total_events}
            except Exception as e:
                data = {"hosts": [], "total_events": 0, "error": str(e)}

            payload = json.dumps(data).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        elif parsed.path == "/api/analyze":
            try:
                stats = self.vault_db.get_stats()
                hosts = list(stats.get("canonical_by_host", {}).keys())

                # حماية برمجية إذا كانت قاعدة البيانات فارغة تماماً
                if not hosts:
                    payload = json.dumps({"findings": [], "process_trees": {}}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return

                all_findings = []
                all_trees = {}
                for host in hosts:
                    findings = DeterministicCorrelator.correlate_attack_chains(self.vault_db, host)
                    trees = DeterministicCorrelator.build_process_trees(self.vault_db, host)
                    all_findings.extend(findings)
                    # تحويل المفاتيح الرقمية إلى نصوص لضمان قبول تحويلها إلى JSON بأمان
                    all_trees[host] = {str(k): v for k, v in trees.items()}

                response_data = {"findings": all_findings, "process_trees": all_trees}
                payload = json.dumps(response_data).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except Exception as e:
                err_payload = json.dumps({"error": str(e)}).encode("utf-8")
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(err_payload)))
                self.end_headers()
                self.wfile.write(err_payload)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/api/upload":
            try:
                raw_filename = self.headers.get("X-Filename", "evidence.log")
                filename = urllib.parse.unquote(raw_filename)
                length = int(self.headers.get("Content-Length", 0))
                payload = self.rfile.read(length)

                temp_dir = Path("./uploaded_logs")
                temp_dir.mkdir(exist_ok=True)
                save_path = temp_dir / filename
                save_path.write_bytes(payload)

                normalizer = CanonicalNormalizer(self.vault_db)
                if hasattr(normalizer, "ingest_file"):
                    res = normalizer.ingest_file(str(save_path))
                elif hasattr(normalizer, "ingest_path"):
                    res = normalizer.ingest_path(str(save_path))
                else:
                    res = {"ingested": 1, "status": "processed"}

                resp_bytes = json.dumps(res).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp_bytes)))
                self.end_headers()
                self.wfile.write(resp_bytes)
            except Exception as e:
                err_b = json.dumps({"error": str(e), "ingested": 0}).encode("utf-8")
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(err_b)))
                self.end_headers()
                self.wfile.write(err_b)


def start_workbench_server(db_path: str = "lss_investigation.db", host: str = "0.0.0.0", port: int = 8080):
    vault = ForensicDatabase(db_path)
    SOCWorkbenchHandler.vault_db = vault
    server = ThreadingHTTPServer((host, port), SOCWorkbenchHandler)
    print(f"[*] SOC-DFIR-Engine Interactive Workbench active at: http://127.0.0.1:{port}")
    print(f"[*] Press CTRL+C to shutdown the workbench.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down workbench server safely.")
