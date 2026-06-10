import json
from file_loader import load_report
from rag_engine import rag_search
from query_engine import answer_query
from risk_engine import calculate_risk
from attack_path import analyze_attack_paths
from fastapi import FastAPI, UploadFile, File
from normalizer import normalize_report
from database import (
    create_table,
    insert_vulnerability,
    get_all_vulnerabilities,
    search_vulnerabilities,
      clear_all_vulnerabilities
)

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
    insert_vulnerability(result)

    return {
        "message": "Report normalized and saved successfully",
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
@app.delete("/clear")
def clear_database():
    clear_all_vulnerabilities()

    return {
        "message": "All vulnerabilities deleted successfully"
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

    for report in reports:
        normalized = normalize_report(report)
        insert_vulnerability(normalized)

    return {
        "message": "Sample report loaded successfully",
        "records_loaded": len(reports)
    }
@app.post("/upload-report")
async def upload_report(file: UploadFile = File(...)):

    content = await file.read()

    reports = json.loads(content)

    for report in reports:
        normalized = normalize_report(report)
        insert_vulnerability(normalized)

    return {
        "message": "Report uploaded successfully",
        "records_loaded": len(reports)
    }