from sentence_transformers import SentenceTransformer
import faiss
import numpy as np

model = SentenceTransformer("all-MiniLM-L6-v2")

def create_text(vuln):
    return (
        f"Asset {vuln['asset']} has {vuln['severity']} vulnerability "
        f"{vuln['vulnerability_name']} on port {vuln['port']} "
        f"service {vuln['service']} found by {vuln['source_tool']}."
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
    index.add(np.array(embeddings).astype("float32"))

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