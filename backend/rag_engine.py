from sentence_transformers import SentenceTransformer
import faiss
import numpy as np
import time

model = SentenceTransformer("all-MiniLM-L6-v2")


def create_text(vuln):
    return (
        f"Asset {vuln['asset']} has {vuln['severity']} vulnerability "
        f"{vuln['vulnerability_name']} with CVE {vuln.get('cve', 'N/A')} "
        f"and CVSS score {vuln.get('cvss_score', 0.0)} "
        f"on port {vuln['port']} service {vuln['service']} "
        f"found by {vuln['source_tool']}."
    )


def rag_search(question, vulnerabilities):
    if len(vulnerabilities) == 0:
        return []

    texts = []

    for vuln in vulnerabilities:
        texts.append(create_text(vuln))

    embeddings = model.encode(texts)

    dimension = embeddings.shape[1]

    index = faiss.IndexFlatL2(dimension)

    index.add(
        np.array(embeddings).astype("float32")
    )

    question_embedding = model.encode([question])

    distances, indices = index.search(
        np.array(question_embedding).astype("float32"),
        3
    )

    results = []

    for idx in indices[0]:
        if idx < len(vulnerabilities):
            results.append({
                "matched_text": texts[idx],
                "vulnerability": vulnerabilities[idx]
            })

    return results


def rag_search_with_benchmark(question, vulnerabilities):
    if len(vulnerabilities) == 0:
        return {
            "question": question,
            "results": [],
            "benchmark": {
                "device": "cpu",
                "embedding_time_ms": 0,
                "index_build_time_ms": 0,
                "search_time_ms": 0,
                "total_time_ms": 0,
                "records_processed": 0
            }
        }

    start_total = time.time()

    texts = []

    for vuln in vulnerabilities:
        texts.append(create_text(vuln))

    start_embedding = time.time()
    embeddings = model.encode(texts)
    question_embedding = model.encode([question])
    end_embedding = time.time()

    start_index = time.time()

    dimension = embeddings.shape[1]
    index = faiss.IndexFlatL2(dimension)

    index.add(
        np.array(embeddings).astype("float32")
    )

    end_index = time.time()

    start_search = time.time()

    distances, indices = index.search(
        np.array(question_embedding).astype("float32"),
        3
    )

    end_search = time.time()
    end_total = time.time()

    results = []

    for idx in indices[0]:
        if idx < len(vulnerabilities):
            results.append({
                "matched_text": texts[idx],
                "vulnerability": vulnerabilities[idx]
            })

    return {
        "question": question,
        "results": results,
        "benchmark": {
            "device": "cpu",
            "embedding_time_ms": round((end_embedding - start_embedding) * 1000, 2),
            "index_build_time_ms": round((end_index - start_index) * 1000, 2),
            "search_time_ms": round((end_search - start_search) * 1000, 2),
            "total_time_ms": round((end_total - start_total) * 1000, 2),
            "records_processed": len(vulnerabilities)
        }
    }