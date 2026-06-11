def get_remediation(vuln_name):

    vuln = vuln_name.lower()

    if "smb" in vuln:
        return [
            "Disable SMBv1",
            "Enable SMB Signing",
            "Restrict internal SMB access",
            "Apply latest Microsoft patches"
        ]

    elif "ftp" in vuln:
        return [
            "Disable anonymous access",
            "Use SFTP instead of FTP",
            "Enforce authentication",
            "Restrict public exposure"
        ]

    elif "ssl" in vuln:
        return [
            "Disable weak ciphers",
            "Use TLS 1.2 or TLS 1.3",
            "Renew certificates",
            "Enable secure HTTPS configuration"
        ]

    elif "ssh" in vuln:
        return [
            "Disable root login",
            "Use SSH keys",
            "Enable MFA",
            "Restrict source IPs"
        ]

    elif "http" in vuln:
        return [
            "Apply web server patches",
            "Use HTTPS",
            "Enable WAF",
            "Restrict admin endpoints"
        ]

    return [
        "Review configuration",
        "Apply latest patches",
        "Perform security assessment"
    ]