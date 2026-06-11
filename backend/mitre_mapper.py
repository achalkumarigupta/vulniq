def map_mitre(vuln_name):

    vuln = vuln_name.lower()

    if "smb" in vuln:
        return {
            "technique": "T1021",
            "name": "Remote Services",
            "tactic": "Lateral Movement"
        }

    elif "ftp" in vuln:
        return {
            "technique": "T1078",
            "name": "Valid Accounts",
            "tactic": "Initial Access"
        }

    elif "ssl" in vuln:
        return {
            "technique": "T1190",
            "name": "Exploit Public-Facing Application",
            "tactic": "Initial Access"
        }

    elif "ssh" in vuln:
        return {
            "technique": "T1021.004",
            "name": "SSH",
            "tactic": "Lateral Movement"
        }

    elif "http" in vuln:
        return {
            "technique": "T1190",
            "name": "Public Facing Application",
            "tactic": "Initial Access"
        }

    return {
        "technique": "Unknown",
        "name": "Unknown",
        "tactic": "Unknown"
    }