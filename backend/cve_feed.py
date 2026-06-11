import urllib.request
import json


def get_severity(score):
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "UNKNOWN"


def fetch_latest_cves():
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=10"

    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            data = json.loads(response.read().decode())

        results = []

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})

            cve_id = cve.get("id", "N/A")

            descriptions = cve.get("descriptions", [])
            description = "No description available"

            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value")
                    break

            score = 0.0

            metrics = cve.get("metrics", {})

            if "cvssMetricV31" in metrics:
                score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV30" in metrics:
                score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV2" in metrics:
                score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

            results.append({
                "cve_id": cve_id,
                "description": description,
                "cvss_score": score,
                "severity": get_severity(score),
                "recommendation": "Apply vendor patches, restrict exposure, and monitor affected systems."
            })

        return results

    except Exception as e:
        return [
            {
                "cve_id": "NVD-FEED-ERROR",
                "description": str(e),
                "cvss_score": 0,
                "severity": "UNKNOWN",
                "recommendation": "Check internet connection or try again later."
            }
        ]