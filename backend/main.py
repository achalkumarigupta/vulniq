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
from risk_engine import calculate_risk
from query_engine import answer_query
from rag_engine import rag_search
from file_loader import load_report
from attack_graph import generate_attack_graph


app = FastAPI()

create_table()


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

    if saved:
        message = "Report normalized and saved successfully"
    else:
        message = "Duplicate report detected. Not saved again."

    return {
        "message": message,
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
    paths = analyze_attack_paths(data)

    return {
        "count": len(paths),
        "attack_paths": paths
    }


@app.get("/attack-graph")
def attack_graph():
    data = get_all_vulnerabilities()
    image_path = generate_attack_graph(data)

    return FileResponse(image_path, media_type="image/png")


@app.get("/risk-report")
def risk_report():
    data = get_all_vulnerabilities()

    report = []

    for vuln in data:
        report.append({
            "asset": vuln["asset"],
            "vulnerability": vuln["vulnerability_name"],
            "severity": vuln["severity"],
            "risk_score": calculate_risk(vuln)
        })

    return {
        "count": len(report),
        "report": report
    }


@app.get("/ask")
def ask(question: str):
    data = get_all_vulnerabilities()
    response = answer_query(question, data)

    return {
        "question": question,
        "response": response
    }


@app.get("/rag-search")
def rag_search_api(question: str):
    data = get_all_vulnerabilities()
    results = rag_search(question, data)

    return {
        "question": question,
        "results": results
    }


@app.post("/load-sample-report")
def load_sample_report():
    reports = load_report("reports/sample_report.json")

    saved_count = 0
    skipped_count = 0

    for report in reports:
        normalized = normalize_report(report)
        saved = insert_vulnerability(normalized)

        if saved:
            saved_count += 1
        else:
            skipped_count += 1

    return {
        "message": "Sample report processed successfully",
        "records_saved": saved_count,
        "duplicates_skipped": skipped_count
    }


@app.post("/upload-report")
async def upload_report(file: UploadFile = File(...)):
    if not file.filename.endswith(".json"):
        return {
            "error": "Only JSON files are supported"
        }

    content = await file.read()

    try:
        reports = json.loads(content)
    except Exception:
        return {
            "error": "Invalid JSON file"
        }

    if not isinstance(reports, list):
        return {
            "error": "JSON file must contain a list of vulnerability reports"
        }

    saved_count = 0
    skipped_count = 0

    for report in reports:
        normalized = normalize_report(report)
        saved = insert_vulnerability(normalized)

        if saved:
            saved_count += 1
        else:
            skipped_count += 1

    return {
        "message": "Report processed successfully",
        "records_saved": saved_count,
        "duplicates_skipped": skipped_count
    }


@app.delete("/clear")
def clear_database():
    clear_all_vulnerabilities()

    return {
        "message": "All vulnerabilities deleted successfully"
    }