def analyze_attack_paths(vulnerabilities):
    paths = []

    for vuln in vulnerabilities:
        severity = vuln["severity"]
        service = vuln["service"]
        asset = vuln["asset"]

        if severity in ["HIGH", "CRITICAL"]:
            path = {
                "asset": asset,
                "entry_point": service,
                "risk": severity,
                "reason": f"{service} service has {severity} severity vulnerability",
                "possible_attack_path": f"Attacker -> {asset}:{vuln['port']} ({service}) -> System compromise"
            }
            paths.append(path)

    return paths