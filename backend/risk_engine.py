def calculate_risk(vulnerability):
    cvss_score = vulnerability.get("cvss_score", 0.0)

    if cvss_score and cvss_score > 0:
        return cvss_score

    severity = vulnerability["severity"]

    scores = {
        "LOW": 2,
        "MEDIUM": 5,
        "HIGH": 8,
        "CRITICAL": 10
    }

    return scores.get(severity, 0)