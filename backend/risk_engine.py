def calculate_risk(vulnerability):
    severity = vulnerability["severity"]

    scores = {
        "LOW": 2,
        "MEDIUM": 5,
        "HIGH": 8,
        "CRITICAL": 10
    }

    return scores.get(severity, 0)