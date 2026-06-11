import random
import time
import threading

from normalizer import normalize_report
from database import insert_vulnerability


sample_live_vulnerabilities = [
    {
        "tool": "live-sensor",
        "host": "192.168.1.120",
        "port": 21,
        "service": "ftp",
        "vulnerability": "Anonymous FTP Access",
        "severity": "HIGH",
        "cve": "CVE-2021-3156",
        "cvss_score": 8.8
    },
    {
        "tool": "live-sensor",
        "host": "192.168.1.130",
        "port": 445,
        "service": "smb",
        "vulnerability": "SMB Misconfiguration",
        "severity": "CRITICAL",
        "cve": "CVE-2020-0796",
        "cvss_score": 10.0
    },
    {
        "tool": "live-sensor",
        "host": "192.168.1.140",
        "port": 8080,
        "service": "http",
        "vulnerability": "Exposed Admin Panel",
        "severity": "HIGH",
        "cve": "N/A",
        "cvss_score": 8.0
    }
]


def start_realtime_detection():
    def detector():
        while True:
            vuln = random.choice(sample_live_vulnerabilities)
            normalized = normalize_report(vuln)
            insert_vulnerability(normalized)
            time.sleep(10)

    thread = threading.Thread(target=detector, daemon=True)
    thread.start()