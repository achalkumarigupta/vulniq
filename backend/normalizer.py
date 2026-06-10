def get_severity_from_cvss(cvss_score):
    if cvss_score >= 9.0:
        return "CRITICAL"
    elif cvss_score >= 7.0:
        return "HIGH"
    elif cvss_score >= 4.0:
        return "MEDIUM"
    elif cvss_score > 0:
        return "LOW"
    else:
        return "UNKNOWN"


def normalize_report(report: dict):
    cvss_score = float(report.get("cvss_score", 0.0))

    severity = report.get("severity", "")

    if severity:
        severity = severity.upper()
    else:
        severity = get_severity_from_cvss(cvss_score)

    normalized = {
        "asset": report.get("host", "unknown"),
        "port": report.get("port", 0),
        "service": report.get("service", "unknown"),
        "vulnerability_name": report.get("vulnerability", "unknown"),
        "severity": severity,
        "source_tool": report.get("tool", "manual"),
        "cve": report.get("cve", "N/A"),
        "cvss_score": cvss_score
    }

    return normalized