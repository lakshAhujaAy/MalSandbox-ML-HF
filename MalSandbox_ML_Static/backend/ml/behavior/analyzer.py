"""
ML Model 2 — Behavior / Anomaly Classifier
===========================================
Processes sandbox logs (network requests, process events, file operations)
and scores them against a rule-based + statistical model.

In production this would be a trained Random Forest / XGBoost model
fed with feature vectors from sandbox telemetry. Here we implement the
full feature-engineering pipeline and a weighted rule classifier that
mirrors what a trained model learns.
"""
import re
from typing import Dict, Any, List


# ── Known-bad indicators ──────────────────────────────────────────────────────
BINARY_MIME_TYPES = {
    "application/octet-stream", "application/x-msdownload",
    "application/x-executable", "application/x-dosexec",
    "application/x-elf", "application/vnd.ms-cab-compressed",
}

MALWARE_EXTENSIONS = re.compile(
    r'\.(exe|dll|bat|cmd|ps1|vbs|jar|msi|scr|hta|wsf|pif|reg)(\?|$)',
    re.IGNORECASE
)

C2_PORTS = {4444, 8080, 1337, 6666, 9001, 8443, 31337, 2222}

SUSPICIOUS_PROCESSES = {
    "powershell", "cmd.exe", "wscript", "cscript",
    "mshta", "regsvr32", "rundll32", "certutil", "bitsadmin",
}

ENCODED_ARG_PATTERN = re.compile(r'-enc(odedcommand)?[\s]+[A-Za-z0-9+/=]{20,}', re.IGNORECASE)


class BehaviorAnalyzer:
    """
    Feature vector extraction + weighted rule classifier over sandbox telemetry.
    """

    def analyze(self, sandbox: Dict[str, Any]) -> Dict[str, Any]:
        features = self._extract_features(sandbox)
        score, reasoning = self._classify(features)

        threat_level = "safe"
        if score >= 0.70:
            threat_level = "malicious"
        elif score >= 0.40:
            threat_level = "suspicious"

        return {
            "model": "behavior",
            "score": round(score, 4),
            "confidence": round(min(0.55 + len(reasoning) * 0.07, 0.97), 4),
            "threat_level": threat_level,
            "features": {k: v for k, v in features.items() if not k.startswith("_")},
            "reasoning": reasoning,
        }

    # ── Feature extraction ────────────────────────────────────────────────────

    def _extract_features(self, s: Dict[str, Any]) -> Dict[str, Any]:
        net = s.get("network_requests", [])
        procs = s.get("process_events", [])
        files = s.get("file_operations", [])
        logs = s.get("logs", [])

        # Network features
        binary_downloads = [
            r for r in net
            if r.get("content_type", "") in BINARY_MIME_TYPES
            or MALWARE_EXTENSIONS.search(r.get("url", ""))
        ]

        unique_hosts = len({r.get("url", "").split("/")[2] for r in net if "//" in r.get("url", "")})
        suspicious_port_connections = [
            r for r in net
            if any(f":{p}" in r.get("url", "") for p in C2_PORTS)
        ]

        ip_connections = [
            r for r in net
            if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', r.get("url", ""))
        ]

        # Process features
        suspicious_proc_names = [
            p for p in procs
            if any(sp in p.get("name", "").lower() for sp in SUSPICIOUS_PROCESSES)
        ]

        encoded_args = [
            p for p in procs
            if ENCODED_ARG_PATTERN.search(" ".join(p.get("args", [])))
        ]

        child_process_count = len([p for p in procs if p.get("event") == "spawn"])

        # File features
        sensitive_writes = [
            f for f in files
            if f.get("operation") in ("write", "create")
            and any(path in f.get("path", "").lower()
                    for path in ("system32", "startup", "appdata\\roaming",
                                 "/etc/", "/bin/", "crontab"))
        ]

        # Log-level alerts
        alert_logs = [l for l in logs if l.get("level") == "alert"]
        password_form_detected = any(
            "password" in l.get("message", "").lower() for l in logs
        )

        return {
            "network_request_count": len(net),
            "unique_host_count": unique_hosts,
            "binary_download_count": len(binary_downloads),
            "binary_download_urls": [r["url"] for r in binary_downloads[:3]],
            "suspicious_port_count": len(suspicious_port_connections),
            "ip_connection_count": len(ip_connections),
            "suspicious_process_count": len(suspicious_proc_names),
            "suspicious_process_names": [p["name"] for p in suspicious_proc_names],
            "encoded_argument_count": len(encoded_args),
            "child_process_count": child_process_count,
            "sensitive_write_count": len(sensitive_writes),
            "alert_log_count": len(alert_logs),
            "password_form_detected": password_form_detected,
        }

    # ── Weighted rule classifier ──────────────────────────────────────────────

    def _classify(self, f: Dict[str, Any]):
        score = 0.0
        reasoning: List[str] = []

        def add(points: float, reason: str):
            nonlocal score
            score += points
            reasoning.append(reason)

        # Binary / file downloads
        if f["binary_download_count"] > 0:
            add(0.45, f"Binary file download detected ({f['binary_download_count']} files): "
                      + ", ".join(f["binary_download_urls"][:2]))

        # Direct IP connections
        if f["ip_connection_count"] > 0:
            add(0.25, f"Direct IP connection(s) bypassing DNS ({f['ip_connection_count']})")

        # Known C2 ports
        if f["suspicious_port_count"] > 0:
            add(0.30, f"Connection to known C2 port(s) ({f['suspicious_port_count']})")

        # Suspicious processes
        if f["suspicious_process_count"] > 0:
            names = ", ".join(set(f["suspicious_process_names"]))
            add(0.35, f"Suspicious process(es) spawned: {names}")

        # Encoded arguments (obfuscation)
        if f["encoded_argument_count"] > 0:
            add(0.40, f"Obfuscated encoded command-line argument detected — common malware technique")

        # Sensitive file writes
        if f["sensitive_write_count"] > 0:
            add(0.35, f"Write to sensitive system path ({f['sensitive_write_count']} operations)")

        # Password form
        if f["password_form_detected"]:
            add(0.20, "Password input field detected — potential credential harvesting page")

        # Alert-level log density
        if f["alert_log_count"] >= 3:
            add(0.15, f"High alert-log density ({f['alert_log_count']} alerts from sandbox)")

        # Lateral movement heuristic
        if f["unique_host_count"] > 8:
            add(0.10, f"Contacted unusually high number of hosts ({f['unique_host_count']})")

        if not reasoning:
            reasoning.append("No anomalous behavior patterns detected in sandbox telemetry")

        return min(score, 1.0), reasoning
