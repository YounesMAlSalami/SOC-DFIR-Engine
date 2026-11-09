# File: core/deobfuscator.py
# Project: Log Story Studio (LSS) - Production Forensic Engine
# Python Version: 3.13 (Standard Library Only)

import base64
import re
import urllib.parse
from typing import Dict, Any, List, Tuple

# Matches -e, -en, -enc, -encodedcommand, /e, etc. followed by Base64
POWERSHELL_ENC_REGEX = re.compile(
    r"(?:[-/]+(?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand))\s+['\"]?([A-Za-z0-9+/=]{12,})['\"]?",
    re.IGNORECASE
)

# Matches inline [System.Convert]::FromBase64String('...')
FROM_B64_REGEX = re.compile(
    r"FromBase64String\s*\(\s*['\"]([A-Za-z0-9+/=]{12,})['\"]\s*\)",
    re.IGNORECASE
)

# Matches Hex encoded payloads like \x77\x68\x6f\x61\x6d\x69 or 0x77686f616d69
HEX_ESCAPE_REGEX = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")


class ForensicDeobfuscator:
    """
    Deterministic command-line de-obfuscation and MITRE ATT&CK enrichment engine.
    """

    @staticmethod
    def strip_cmd_obfuscation(text: str) -> str:
        """Removes Windows CMD caret (^) and empty quote (\"\" or '') obfuscation."""
        if not text or text == "N/A":
            return ""
        cleaned = text.replace("^", "")
        cleaned = re.sub(r"(\"\")|('')", "", cleaned)
        return cleaned

    @staticmethod
    def _try_decode_b64_blob(b64_str: str) -> str:
        try:
            padded = b64_str.strip()
            missing_padding = len(padded) % 4
            if missing_padding:
                padded += "=" * (4 - missing_padding)
            raw_bytes = base64.b64decode(padded, validate=False)
            if not raw_bytes:
                return ""
            # PowerShell -EncodedCommand uses UTF-16LE (contains null bytes between ASCII chars)
            if b"\x00" in raw_bytes:
                decoded = raw_bytes.decode("utf-16le", errors="ignore").strip()
            else:
                decoded = raw_bytes.decode("utf-8", errors="ignore").strip()
            # Filter out non-printable garbage
            printable_ratio = sum(1 for c in decoded if c.isprintable() or c in "\r\n\t") / max(len(decoded), 1)
            return decoded if printable_ratio > 0.75 else ""
        except Exception:
            return ""

    @classmethod
    def decode_powershell_b64(cls, command_line: str) -> str:
        """Extracts and decodes Base64 payloads from PowerShell command lines."""
        if not command_line or command_line == "N/A":
            return ""

        decarated = cls.strip_cmd_obfuscation(command_line)
        decoded_segments: List[str] = []

        for regex in (POWERSHELL_ENC_REGEX, FROM_B64_REGEX):
            for match in regex.finditer(decarated):
                candidate = cls._try_decode_b64_blob(match.group(1))
                if candidate and candidate not in decoded_segments:
                    decoded_segments.append(candidate)

        return " | ".join(decoded_segments)

    @staticmethod
    def decode_url_and_hex(raw_input: str) -> str:
        """Decodes multi-layer URL encoding and hex escape sequences in web/DB logs."""
        if not raw_input or raw_input == "N/A":
            return ""

        results: List[str] = []

        # 1. Multi-pass URL decoding
        if "%" in raw_input or "+" in raw_input:
            pass1 = urllib.parse.unquote_plus(raw_input)
            pass2 = urllib.parse.unquote_plus(pass1)
            if pass2 != raw_input and any( tok in pass2.lower() for tok in ("select ", "../", "cmd", "exec", "powershell", "/etc/passwd", "<script", "eval(")):
                results.append(f"URL_DECODED: {pass2}")

        # 2. Hex escape decoding (\x41\x42...)
        for match in HEX_ESCAPE_REGEX.finditer(raw_input):
            hex_seq = match.group(0).replace("\\x", "")
            try:
                decoded_hex = bytes.fromhex(hex_seq).decode("utf-8", errors="ignore")
                if decoded_hex.isprintable():
                    results.append(f"HEX_DECODED: {decoded_hex}")
            except Exception:
                pass

        return " | ".join(results)

    @classmethod
    def deobfuscate_all(cls, command_line: str) -> str:
        """Master de-obfuscation routine returning a unified cleartext string."""
        if not command_line or command_line == "N/A":
            return ""

        parts: List[str] = []
        ps_clear = cls.decode_powershell_b64(command_line)
        if ps_clear:
            parts.append(f"[PS_B64]: {ps_clear}")

        url_hex_clear = cls.decode_url_and_hex(command_line)
        if url_hex_clear:
            parts.append(url_hex_clear)

        if "^" in command_line and command_line.count("^") >= 3:
            stripped = cls.strip_cmd_obfuscation(command_line)
            parts.append(f"[CMD_UNCARET]: {stripped}")

        return " || ".join(parts)

    @classmethod
    def enrich_and_map_mitre(cls, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Inspects canonical event fields alongside de-obfuscated payloads to assign
        deterministic MITRE ATT&CK techniques and calculate a normalized risk_score (0-100).
        """
        raw_cmd = str(event.get("command_line", ""))
        img = str(event.get("image_path", "")).lower()
        p_img = str(event.get("parent_image_path", "")).lower()
        cat = str(event.get("event_category", "")).upper()
        target_file = str(event.get("target_filename", "")).lower()
        src_ip = str(event.get("src_ip", "N/A"))
        dst_ip = str(event.get("dst_ip", "N/A"))

        decoded_payload = cls.deobfuscate_all(raw_cmd)
        inspect_surface = f"{raw_cmd.lower()} {decoded_payload.lower()} {img} {target_file}"

        mitre_tags: List[Dict[str, str]] = []
        risk_score = 5

        def add_mitre(tech_id: str, tactic: str, name: str, weight: int) -> None:
            nonlocal risk_score
            if not any(m["id"] == tech_id for m in mitre_tags):
                mitre_tags.append({"id": tech_id, "tactic": tactic, "name": name})
                risk_score = min(100, risk_score + weight)

        # 1. Credential Access & Authentication
        if cat == "AUTH_FAILED":
            add_mitre("T1110", "Credential Access", "Brute Force / Failed Authentication", 20)
        elif cat == "AUTH_SUCCESS" and src_ip not in ("127.0.0.1", "::1", "N/A", "-", "0.0.0.0"):
            add_mitre("T1078", "Initial Access / Lateral Movement", "Valid Accounts (Network Logon)", 15)

        # 2. Execution (PowerShell / Command Shell / Scripting)
        if any(p in inspect_surface for p in ("powershell", "pwsh", "iex(", "invoke-expression", "downloadstring")):
            add_mitre("T1059.001", "Execution", "Command and Scripting Interpreter: PowerShell", 35)
        elif any(s in img or s in inspect_surface for s in ("cmd.exe", "/bin/sh", "/bin/bash", "wscript.exe", "cscript.exe")):
            add_mitre("T1059", "Execution", "Command and Scripting Interpreter", 20)

        # 3. Defense Evasion (Obfuscation & LOLBins)
        if decoded_payload or any(k in inspect_surface for k in ("-enc", "frombase64string", "-w hidden", "-windowstyle hidden", "bypass")):
            add_mitre("T1027", "Defense Evasion", "Obfuscated Files or Information", 30)
        if any(lol in img or lol in inspect_surface for lol in ("certutil", "mshta", "rundll32", "regsvr32", "bitsadmin")):
            add_mitre("T1218", "Defense Evasion", "System Binary Proxy Execution (LOLBin)", 35)

        # 4. Web Shells & Public-Facing Application Exploits
        if any(w in p_img or w in img for w in ("w3wp.exe", "php-cgi", "httpd", "apache", "nginx", "tomcat")) and cat == "PROCESS_CREATE":
            add_mitre("T1505.003", "Persistence", "Server Software Component: Web Shell", 50)
        if cat == "WEB_EXPLOIT_ATTEMPT" or any(w in inspect_surface for w in ("union select", "xp_cmdshell", "../", "etc/passwd", "cmd=", "eval(")):
            add_mitre("T1190", "Initial Access", "Exploit Public-Facing Application", 45)

        # 5. Discovery & Credential Dumping
        if any(d in inspect_surface for d in ("whoami", "net user", "net group", "nltest", "ipconfig", "systeminfo", "id;")) and cat == "PROCESS_CREATE":
            add_mitre("T1033", "Discovery", "System Owner/User Discovery", 20)
        if any(c in inspect_surface for c in ("lsass", "sekurlsa", "mimikatz", "procdump", "comsvcs.dll", "/etc/shadow")):
            add_mitre("T1003", "Credential Access", "OS Credential Dumping", 60)

        # 6. Collection & Data Staging (Archiving)
        if any(a in inspect_surface for a in ("7z.exe", "7za", "rar.exe", "compress-archive", "tar -c", "zip -r")):
            add_mitre("T1560.001", "Collection", "Archive Collected Data: Archive via Utility", 40)

        # 7. Impact & Ransomware Precursors
        if any(r in inspect_surface for r in ("vssadmin", "shadowcopy", "wbadmin delete", "bcdedit /set")):
            add_mitre("T1490", "Impact", "Inhibit System Recovery", 65)

        # 8. Sensitive File Drops
        if cat == "FILE_CREATE" and any(target_file.endswith(ext) for ext in (".ps1", ".bat", ".vbs", ".exe", ".dll", ".php", ".aspx", ".jsp", ".7z", ".zip", ".rar", ".dmp")):
            add_mitre("T1105", "Command and Control / Collection", "Artifact Staging or Tool Drop", 30)

        # 9. Command & Control / Exfiltration
        if cat in ("NETWORK_CONNECT", "DB_QUERY_OR_EGRESS") and dst_ip not in ("127.0.0.1", "::1", "N/A", "-"):
            add_mitre("T1071", "Command and Control / Exfiltration", "External Network / Egress Channel", 30)

        return {
            "decoded_payload": decoded_payload,
            "mitre_mappings": mitre_tags,
            "risk_score": risk_score
        }
