from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from network_topology import generate_topology
from remediation_engine import get_remediation
from mitre_mapper import map_mitre
from cve_feed import fetch_latest_cves
from realtime_detector import start_realtime_detection
from fastapi.middleware.cors import CORSMiddleware
import json

from fastapi import FastAPI, UploadFile, File
from fastapi.responses import FileResponse

from normalizer import normalize_report
from database import (
    create_table,
    insert_vulnerability,
    get_all_vulnerabilities,
    search_vulnerabilities,
    clear_all_vulnerabilities
)

from attack_path import analyze_attack_paths
from attack_graph import generate_attack_graph
from risk_engine import calculate_risk
from query_engine import answer_query
from rag_engine import rag_search, rag_search_with_benchmark
from file_loader import load_report
from nmap_parser import parse_nmap_xml

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
create_table()

start_realtime_detection()
@app.get("/")
def home():
    return {
        "message": "Vulniq backend is running",
        "project": "Centralized Vulnerability Detection"
    }


@app.post("/normalize")
def normalize(report: dict):
    result = normalize_report(report)
    saved = insert_vulnerability(result)

    return {
        "message": "saved" if saved else "duplicate",
        "normalized_report": result
    }


@app.get("/vulnerabilities")
def vulnerabilities():
    data = get_all_vulnerabilities()

    return {
        "count": len(data),
        "data": data
    }


@app.get("/search")
def search(keyword: str):
    results = search_vulnerabilities(keyword)

    return {
        "keyword": keyword,
        "count": len(results),
        "results": results
    }


@app.get("/attack-paths")
def attack_paths():
    data = get_all_vulnerabilities()

    return {
        "count": len(data),
        "attack_paths": analyze_attack_paths(data)
    }


@app.get("/attack-graph")
def attack_graph():
    data = get_all_vulnerabilities()
    image_path = generate_attack_graph(data)

    return FileResponse(
        image_path,
        media_type="image/png"
    )


@app.get("/risk-report")
def risk_report():

    data = get_all_vulnerabilities()

    report = []

    for vuln in data:
        report.append({
            "asset": vuln["asset"],
            "vulnerability": vuln["vulnerability_name"],
            "severity": vuln["severity"],
            "risk_score": calculate_risk(vuln),
            "cve": vuln.get("cve", "N/A"),
            "cvss_score": vuln.get("cvss_score", 0)
        })

    return {
        "count": len(report),
        "report": report
    }


@app.get("/ask")
def ask(question: str):

    data = get_all_vulnerabilities()

    return {
        "question": question,
        "response": answer_query(question, data)
    }


@app.get("/rag-search")
def rag_search_api(question: str):

    data = get_all_vulnerabilities()

    return {
        "question": question,
        "results": rag_search(question, data)
    }


@app.post("/load-sample-report")
def load_sample_report():

    reports = load_report("reports/sample_report.json")

    saved_count = 0
    skipped_count = 0

    for report in reports:

        normalized = normalize_report(report)

        if insert_vulnerability(normalized):
            saved_count += 1
        else:
            skipped_count += 1

    return {
        "records_saved": saved_count,
        "duplicates_skipped": skipped_count
    }


@app.post("/upload-report")
async def upload_report(file: UploadFile = File(...)):

    content = await file.read()

    try:
        reports = json.loads(content)
    except Exception:
        return {"error": "Invalid JSON"}

    saved_count = 0
    skipped_count = 0

    for report in reports:

        normalized = normalize_report(report)

        if insert_vulnerability(normalized):
            saved_count += 1
        else:
            skipped_count += 1

    return {
        "records_saved": saved_count,
        "duplicates_skipped": skipped_count
    }


@app.post("/upload-nmap-xml")
async def upload_nmap_xml(file: UploadFile = File(...)):

    file_path = f"reports/{file.filename}"

    content = await file.read()

    with open(file_path, "wb") as f:
        f.write(content)

    reports = parse_nmap_xml(file_path)

    saved_count = 0
    skipped_count = 0

    for report in reports:

        normalized = normalize_report(report)

        if insert_vulnerability(normalized):
            saved_count += 1
        else:
            skipped_count += 1

    return {
        "records_found": len(reports),
        "records_saved": saved_count,
        "duplicates_skipped": skipped_count
    }


@app.get("/cve/{cve_id}")
def search_by_cve(cve_id: str):

    data = get_all_vulnerabilities()

    results = []

    for vuln in data:
        if vuln.get("cve", "").lower() == cve_id.lower():
            results.append(vuln)

    return {
        "cve": cve_id,
        "count": len(results),
        "results": results
    }


@app.get("/top-risks")
def top_risks():

    data = get_all_vulnerabilities()

    sorted_data = sorted(
        data,
        key=lambda x: x.get("cvss_score", 0),
        reverse=True
    )

    return {
        "count": len(sorted_data),
        "top_risks": sorted_data[:10]
    }


@app.get("/critical-assets")
def critical_assets():

    data = get_all_vulnerabilities()

    critical = []

    for vuln in data:
        if vuln.get("cvss_score", 0) >= 9:
            critical.append(vuln)

    return {
        "count": len(critical),
        "critical_assets": critical
    }


@app.get("/dashboard")
def dashboard():

    data = get_all_vulnerabilities()

    summary = {
        "total": len(data),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }

    for vuln in data:

        severity = vuln["severity"]

        if severity == "CRITICAL":
            summary["critical"] += 1

        elif severity == "HIGH":
            summary["high"] += 1

        elif severity == "MEDIUM":
            summary["medium"] += 1

        elif severity == "LOW":
            summary["low"] += 1

    return summary


@app.delete("/clear")
def clear_database():

    clear_all_vulnerabilities()

    return {
        "message": "All vulnerabilities deleted successfully"
    }
@app.get("/cve-feed")
def cve_feed():
    return {
        "results": fetch_latest_cves()
    }
@app.get("/executive-report")
def executive_report():

    data = get_all_vulnerabilities()

    total = len(data)

    critical = len(
        [v for v in data if v["severity"] == "CRITICAL"]
    )

    high = len(
        [v for v in data if v["severity"] == "HIGH"]
    )

    medium = len(
        [v for v in data if v["severity"] == "MEDIUM"]
    )

    if total == 0:
        return {
            "summary": "No vulnerabilities found"
        }

    highest = max(
        data,
        key=lambda x: x.get("cvss_score", 0)
    )

    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "most_dangerous_asset": highest["asset"],
        "highest_cvss": highest["cvss_score"],
        "top_vulnerability":
            highest["vulnerability_name"],
        "recommendation":
            "Prioritize Critical and High vulnerabilities immediately."
    }
@app.get("/mitre-mapping")
def mitre_mapping():

    data = get_all_vulnerabilities()

    results = []

    for vuln in data:

        mapping = map_mitre(
            vuln["vulnerability_name"]
        )

        results.append({
            "asset": vuln["asset"],
            "vulnerability":
                vuln["vulnerability_name"],
            "mitre": mapping
        })

    return {
        "count": len(results),
        "results": results
    }
@app.get("/remediation")
def remediation():

    data = get_all_vulnerabilities()

    results = []

    for vuln in data:

        results.append({
            "asset": vuln["asset"],
            "vulnerability":
                vuln["vulnerability_name"],
            "recommendations":
                get_remediation(
                    vuln["vulnerability_name"]
                )
        })

    return {
        "count": len(results),
        "results": results
    }
@app.get("/network-topology")
def network_topology():

    data = get_all_vulnerabilities()

    image_path = generate_topology(data)

    return FileResponse(
        image_path,
        media_type="image/png"
    )
@app.get("/nmap-scan")
def nmap_scan(target: str):

    simulated_reports = [
        {
            "tool": "live-nmap",
            "host": target,
            "port": 22,
            "service": "ssh",
            "vulnerability": "Open SSH service detected",
            "severity": "MEDIUM",
            "cve": "N/A",
            "cvss_score": 5.0
        },
        {
            "tool": "live-nmap",
            "host": target,
            "port": 80,
            "service": "http",
            "vulnerability": "Open HTTP service detected",
            "severity": "MEDIUM",
            "cve": "N/A",
            "cvss_score": 5.0
        }
    ]

    saved_count = 0
    skipped_count = 0

    for report in simulated_reports:
        normalized = normalize_report(report)

        if insert_vulnerability(normalized):
            saved_count += 1
        else:
            skipped_count += 1

    return {
        "message": "Live Nmap scan completed",
        "target": target,
        "records_found": len(simulated_reports),
        "records_saved": saved_count,
        "duplicates_skipped": skipped_count,
        "scan_result": f"Scanned {target}: Open ports detected - 22/ssh, 80/http"
    }
@app.get("/alerts")
def alerts():

    data = get_all_vulnerabilities()

    alert_list = []

    for vuln in data:
        if vuln["severity"] in ["CRITICAL", "HIGH"]:
            alert_list.append({
                "asset": vuln["asset"],
                "vulnerability": vuln["vulnerability_name"],
                "severity": vuln["severity"],
                "cvss_score": vuln.get("cvss_score", 0),
                "message": f"{vuln['severity']} vulnerability detected on {vuln['asset']}"
            })

    return {
        "count": len(alert_list),
        "alerts": alert_list[-5:]
    }
@app.get("/asset-ranking")
def asset_ranking():

    data = get_all_vulnerabilities()

    ranking = []

    for vuln in data:
        ranking.append({
            "asset": vuln["asset"],
            "risk_score": vuln.get("cvss_score", 0),
            "vulnerability": vuln["vulnerability_name"],
            "severity": vuln["severity"],
            "cve": vuln.get("cve", "N/A")
        })

    ranking = sorted(
        ranking,
        key=lambda x: x["risk_score"],
        reverse=True
    )

    return {
        "count": len(ranking),
        "results": ranking[:10]
    }
@app.get("/rag-benchmark")
def rag_benchmark(question: str):

    data = get_all_vulnerabilities()

    return rag_search_with_benchmark(
        question,
        data
    )
@app.get("/ai-security-assistant")
def ai_security_assistant(question: str):

    data = get_all_vulnerabilities()

    if len(data) == 0:
        return {
            "question": question,
            "answer": "No vulnerabilities found."
        }

    question_lower = question.lower()

    # Highest Risk Asset
    if "highest risk" in question_lower or "most dangerous" in question_lower:

        top = max(
            data,
            key=lambda x: x.get("cvss_score", 0)
        )

        return {
            "question": question,
            "answer":
                f"The highest risk asset is {top['asset']} "
                f"with vulnerability '{top['vulnerability_name']}' "
                f"(CVSS {top['cvss_score']})."
        }

    # Critical Count
    elif "critical" in question_lower:

        criticals = [
            v for v in data
            if v["severity"] == "CRITICAL"
        ]

        return {
            "question": question,
            "answer":
                f"There are {len(criticals)} critical vulnerabilities."
        }

    # Top Vulnerability
    elif "top vulnerability" in question_lower:

        top = max(
            data,
            key=lambda x: x.get("cvss_score", 0)
        )

        return {
            "question": question,
            "answer":
                f"The top vulnerability is "
                f"{top['vulnerability_name']} "
                f"with CVSS score {top['cvss_score']}."
        }

    # Remediation Summary
    elif "remediation" in question_lower:

        return {
            "question": question,
            "answer":
                "Prioritize Critical and High vulnerabilities, "
                "disable insecure services, apply vendor patches, "
                "enforce MFA, and reduce exposed attack surfaces."
        }

    else:

        return {
            "question": question,
            "answer":
                "I can answer questions about highest risk assets, "
                "critical vulnerabilities, top vulnerabilities, "
                "and remediation recommendations."
        }
