
# SOC-DFIR-Engine: Deterministic Incident Narrative Platform

[![Python 3.13](https://img.shields.io/badge/Python-3.13-blue.svg)](https://www.python.org/)
[![C Standard](https://img.shields.io/badge/Language-C99%2FC11-orange.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Zero External Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Stdlib%20Only)-success.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An operational, deterministic Digital Forensics and Incident Response (DFIR) platform engineered to accelerate triage, eliminate alert fatigue, and automate root-cause reconstruction for Security Operations Centers (SOC).

Built with **Python 3.13 standard libraries** and high-throughput **C ingestion micro-utilities**, this platform transforms scattered, multi-source log lines into an irrefutable, cryptographically sealed attack narrative.

---

## The Operational Problem It Solves

Modern SOC teams and incident responders frequently struggle when investigating hundreds of disconnected log files across enterprise endpoints, servers, and perimeter appliances:

1. **Format Fragmentation:** Incompatible schemas across EVTX JSON, Linux Syslog, Web Access logs, Firewall key-values, and Database audit trails require custom parsers.
2. **Context Dissociation:** Single alerts do not convey the full attacker journey; related actions span across completely different systems and files.
3. **Chain-of-Custody Gaps:** Inability to immediately link an alert back to its physical line number, byte offset, and immutable raw payload on disk.
4. **Keyword Guesswork & Noise:** Heuristic keyword matching produces unmanageable alert volumes rather than identifying deterministic, multi-stage attack execution.

---

## Core Technical Pillars

* **Host-Centric Topology & Isolation:** Processes host artifacts as isolated operational fabrics, strictly forbidding cross-host correlation unless proven by dual network evidence.
* **Canonical Event Normalization:** Normalizes disparate inputs into a strict, unified SQLite schema documenting UTC timestamps, host identity, user contexts, process lineage, and confidence ratings.
* **Cryptographic Traceability (Chain of Custody):** Seals every ingested raw line with an immutable **SHA-256 digest**, byte offset, and physical line index:
  $$\text{Alert} \longrightarrow \text{Canonical Event} \longrightarrow \text{Source File} \longrightarrow \text{Line Number} \longrightarrow \text{Byte Offset} \longrightarrow \text{SHA-256}$$
* **Deterministic Correlation Engine:** Executes cycle-safe recursive Common Table Expressions (Recursive CTEs) to reconstruct hierarchical parent-child process execution trees without probabilistic guessing.
* **Multi-Stage Attack Chain Reconstruction:** Automatically correlates complex intrusion lifecycles:
  $$\text{Brute Force Failures} \longrightarrow \text{Valid Logon} \longrightarrow \text{Suspicious Execution} \longrightarrow \text{Data Staging / 7z} \longrightarrow \text{C2 / Egress}$$
* **Cross-Host Lateral Movement Proofs:** Binds source host egress telemetry to destination host authentication ingress events using dual-hash verification.
* **Automated De-obfuscation & MITRE ATT&CK Mapping:** Strips Windows caret masks (`^`), decodes nested Base64 payloads (UTF-16LE / UTF-8), unquotes multi-pass URL encodings, and dynamically assigns MITRE ATT&CK tactics and techniques.

---

## Output Modalities

The platform generates four operational deliverables from a single command:
1. **Interactive Single-File Offline HTML Workbench:** Self-contained visual workspace featuring live search, instant hash verification, decoded payload inspection, and MITRE badges (requires no web server or internet connection).
2. **Publication-Ready Markdown Reports:** Full incident case studies structured for stakeholders, including evidence matrices and chronological timelines.
3. **Mermaid.js Flowcharts:** Native code blocks ready for live rendering and presentation in GitHub/Notion.
4. **Draw.io XML Diagrams:** Structural `.drawio` files that open directly in diagrams.net with color-coded severity nodes and process links.

---

## System Architecture

```text
├── c_ingestor/
│   └── raw_pre_indexer.c          # High-throughput C99 pre-filter & byte-offset indexer
├── core/
│   ├── database.py                # SQLite WAL storage, schema enforcement & hash lookup
│   ├── deobfuscator.py            # Base64/URL/Caret decoder & dynamic MITRE ATT&CK mapper
│   ├── multi_parsers.py           # Web access, IIS W3C, KV firewall & CSV egress parsers
│   ├── normalizer.py              # Canonical event normalizer with C-bridge fallback
│   ├── correlator.py              # Recursive CTE process tree & deterministic chain engine
│   ├── lateral_movement.py        # Cross-host pivot detector with dual-hash proof
│   ├── storyteller.py             # Markdown, Mermaid, and Draw.io XML generator
│   └── html_studio.py             # Single-file interactive HTML DFIR Workbench builder
└── lss_cli.py                     # Unified CLI orchestrator & multi-vector lab generator

```
## Target Audience
 * **SOC Analysts (Tier 2 / Tier 3):** Rapid triage, alert verification, and automated root cause discovery without context switching.
 * **Incident Responders & DFIR Specialists:** Hardened digital forensics with tamper-evident chain of custody and instant artifact verification.
 * **Threat Hunters:** Behavioral baseline anomaly detection and hunt hypothesis testing across multi-source historical logs.
 * **Cybersecurity Researchers:** Developing and documenting reproducible attack case studies.
## Getting Started
### Prerequisites
 * **Python 3.13+** (Standard libraries only; zero third-party dependencies required).
 * **GCC / Clang** (Optional, only required if compiling the C pre-indexer for gigabyte-scale logs).
### Installation & Setup
 1. Clone the repository:
   ```bash
   git clone [https://github.com/YounesMAlSalami/SOC-DFIR-Engine.git](https://github.com/YounesMAlSalami/SOC-DFIR-Engine.git)
   cd SOC-DFIR-Engine
   
   ```
 2. Compile the high-speed C pre-indexer *(Optional)*:
   ```bash
   gcc -O3 -Wall -Wextra -pedantic c_ingestor/raw_pre_indexer.c -o c_ingestor/raw_pre_indexer
   
   ```
## Usage Workflow
### 1. Generate Realistic Multi-Host Test Evidence
To validate the full detection and correlation cycle without external datasets:
```bash
python3 lss_cli.py generate-lab --lab-dir ./sample_forensic_lab

```
This generates a multi-vector intrusion dataset across Windows Sysmon JSONL, Linux Auth logs, and Database CSV egress telemetry.
### 2. Ingest Evidence into the Cryptographic Vault
Ingest single files or entire evidence directories:
```bash
# Pure Python pipeline
python3 lss_cli.py ingest ./sample_forensic_lab

# Or accelerated via the C binary bridge
python3 lss_cli.py ingest ./sample_forensic_lab --c-binary ./c_ingestor/raw_pre_indexer

```
### 3. Check Vault Status
Review ingested host topologies and event distributions:
```bash
python3 lss_cli.py status

```
### 4. Execute Correlation & Generate Deliverables
Run deterministic correlation, process tree lineage extraction, and artifact generation:
```bash
python3 lss_cli.py analyze --output-dir ./forensic_reports

```
Inspect the generated artifacts in ./forensic_reports:
 * Workbench_<HOST>.html (Interactive triage UI)
 * Forensic_Report_<HOST>.md (Case study report)
 * AttackChain_<HOST>_<SESSION>.drawio (Visual architecture diagram)
### 5. Reverse Traceability Verification
Instantly verify any evidence record back to its physical storage coordinates using its SHA-256 digest:
```bash
python3 lss_cli.py verify-hash <SHA256_PREFIX>

```
## Author
**Younes Al-Salami**
Cybersecurity Specialist & SOC / DFIR Analyst
 * Portfolio: https://younes-alsalami.vercel.app
 * GitHub: @YounesMAlSalami
 * LinkedIn: https://www.linkedin.com/in/younes-al-salami
## License
This project is licensed under the MIT License.
```

