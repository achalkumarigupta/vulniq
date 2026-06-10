def normalize_report(report: dict):
    normalized = {
        "asset": report.get("host", "unknown"),
        "port": report.get("port", "unknown"),
        "service": report.get("service", "unknown"),
        "vulnerability_name": report.get("vulnerability", "unknown"),
        "severity": report.get("severity", "unknown").upper(),
        "source_tool": report.get("tool", "manual")
    }

    return normalized