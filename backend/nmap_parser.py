import xml.etree.ElementTree as ET


def parse_nmap_xml(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()

    reports = []

    for host in root.findall("host"):
        address_tag = host.find("address")
        if address_tag is None:
            continue

        ip = address_tag.get("addr", "unknown")

        ports = host.find("ports")
        if ports is None:
            continue

        for port in ports.findall("port"):
            port_id = int(port.get("portid", 0))

            service_tag = port.find("service")
            service = "unknown"

            if service_tag is not None:
                service = service_tag.get("name", "unknown")

            report = {
                "tool": "nmap",
                "host": ip,
                "port": port_id,
                "service": service,
                "vulnerability": f"Open {service} service detected",
                "severity": "MEDIUM",
                "cve": "N/A",
                "cvss_score": 5.0
            }

            reports.append(report)

    return reports