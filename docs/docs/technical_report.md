# VulniQ: Centralized Vulnerability Detection & Intelligent Query Interface

## 1. Introduction

Modern organizations use multiple cybersecurity tools such as Nmap, OpenVAS, Nessus, and manual assessment reports to identify vulnerabilities. These tools often generate reports in different formats, making centralized analysis difficult.

VulniQ is a cybersecurity intelligence platform designed to collect, normalize, analyze, and visualize vulnerability data through a unified dashboard. The system provides intelligent search, risk prioritization, attack visualization, MITRE ATT&CK mapping, remediation guidance, and AI-powered security assistance.

---

# 2. Problem Statement

Security teams face several challenges:

* Vulnerability data scattered across multiple tools
* Lack of centralized visibility
* Difficulty prioritizing critical assets
* Limited understanding of attack paths
* Manual vulnerability investigation
* Lack of intelligent cybersecurity assistance

The objective of VulniQ is to provide a centralized platform capable of ingesting vulnerability reports, performing risk analysis, supporting intelligent search, and assisting security analysts with AI-powered recommendations.

---

# 3. System Architecture

The system follows a multi-layer architecture.

### Frontend Layer

Technologies:

* HTML
* CSS
* JavaScript
* Chart.js

Responsibilities:

* Dashboard visualization
* Report uploads
* Security Copilot interface
* Risk analytics display
* Attack graph visualization

### Backend Layer

Technologies:

* Python
* FastAPI

Responsibilities:

* API processing
* Vulnerability normalization
* Risk scoring
* MITRE mapping
* AI services

### Database Layer

Technology:

* SQLite

Stores:

* Assets
* Vulnerabilities
* CVE IDs
* CVSS Scores
* Risk Information

### AI Layer

Technologies:

* Sentence Transformers
* FAISS
* AI Security Copilot

Responsibilities:

* Semantic retrieval
* Intelligent search
* Security question answering

---

# 4. Methodology

## Data Ingestion

The platform accepts data from:

* JSON Vulnerability Reports
* Nmap XML Reports
* Simulated Live Scans

## Vulnerability Normalization

All imported records are converted into a common schema:

```json
{
  "asset": "192.168.1.130",
  "port": 445,
  "service": "smb",
  "vulnerability_name": "SMB Misconfiguration",
  "severity": "CRITICAL",
  "cve": "CVE-2020-0796",
  "cvss_score": 10.0
}
```

## Risk Analysis

Risk is calculated using:

* CVSS Score
* Severity
* Asset Exposure

The system automatically identifies high-risk assets and vulnerabilities.

---

# 5. AI and NLP Components

## RAG Search Engine

The platform uses:

* Sentence Transformers
* Vector Embeddings
* FAISS Similarity Search

Example queries:

* Which host has highest risk?
* Show SSH vulnerabilities
* Show critical vulnerabilities

## AI Security Copilot

The Security Copilot provides intelligent reasoning over vulnerability data.

Capabilities include:

* Highest-risk asset identification
* Critical vulnerability analysis
* Security posture summaries
* Remediation recommendations

## Benchmarking Framework

The platform measures:

* Embedding generation latency
* Index creation latency
* Vector retrieval latency
* Total query processing time

Sample Results:

* Embedding Time: 602.67 ms
* Search Time: 2.20 ms
* Total Time: 607.68 ms

---

# 6. Implemented Features

### Vulnerability Management

* Vulnerability Normalization
* Centralized Database
* JSON Report Upload
* Nmap XML Upload
* Simulated Live Scan

### Security Analytics

* Risk Scoring Engine
* Asset Risk Ranking
* Executive Security Reports
* Dashboard Analytics

### Intelligence & Visualization

* MITRE ATT&CK Mapping
* CVE Feed Integration
* Attack Graph Generation
* Network Topology Visualization
* Real-Time Alert Center

### AI Features

* RAG Search
* Security Copilot
* AI Remediation Recommendations
* Benchmarking Framework

---

# 7. Results

The platform successfully:

* Centralized vulnerability information
* Ranked assets by risk
* Generated attack graphs
* Mapped vulnerabilities to MITRE ATT&CK
* Performed semantic vulnerability search
* Answered security questions using AI Security Copilot

Sample Findings:

* Highest Risk Asset: 192.168.1.130
* Top Vulnerability: SMB Misconfiguration
* Highest CVSS Score: 10.0

---

# 8. Future Scope

Potential future improvements include:

* NVIDIA H200 Deployment
* GPU-Accelerated FAISS
* Local LLM Security Assistant
* Real Nmap Integration
* SIEM Integration
* Cloud Security Monitoring
* Multi-User Authentication
* Threat Intelligence Expansion

---

# 9. Conclusion

VulniQ provides a centralized cybersecurity intelligence platform capable of vulnerability management, risk prioritization, attack visualization, intelligent retrieval, and AI-powered decision support.

The project combines cybersecurity analytics, NLP-based semantic search, and AI-assisted reasoning to improve security operations and vulnerability management workflows.
