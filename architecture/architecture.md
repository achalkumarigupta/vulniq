# VulniQ System Architecture

```mermaid
flowchart TD

A[User / Security Analyst] --> B[Frontend Dashboard<br>HTML CSS JavaScript Chart.js]

B --> C[FastAPI Backend]

C --> D[SQLite Vulnerability Database]

C --> E[Vulnerability Normalization Engine]
C --> F[Risk Scoring Engine<br>CVSS Based]
C --> G[Asset Risk Ranking]
C --> H[Attack Path Analysis]
C --> I[Attack Graph Generator<br>NetworkX + Matplotlib]
C --> J[Network Topology Generator]
C --> K[MITRE ATT&CK Mapper]
C --> L[AI Remediation Engine]
C --> M[CVE Feed Engine<br>NVD API]
C --> N[RAG Search Engine<br>Sentence Transformers + FAISS]
C --> O[AI Security Copilot]
C --> P[RAG Benchmark Engine]

Q[JSON Reports] --> E
R[Nmap XML Reports] --> E
S[Simulated Live Nmap Scan] --> E

E --> D
D --> F
D --> G
D --> H
D --> I
D --> J
D --> K
D --> L
D --> N
D --> O
D --> P

N --> O
F --> O
K --> O
L --> O


