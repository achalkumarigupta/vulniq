def answer_query(question, vulnerabilities):
    question = question.lower()

    if "critical" in question:
        results = []
        for vuln in vulnerabilities:
            if vuln["severity"] == "CRITICAL":
                results.append(vuln)

        return {
            "answer": "These are the critical vulnerabilities.",
            "results": results
        }

    if "high" in question:
        results = []
        for vuln in vulnerabilities:
            if vuln["severity"] == "HIGH":
                results.append(vuln)

        return {
            "answer": "These are the high severity vulnerabilities.",
            "results": results
        }

    if "ssh" in question:
        results = []
        for vuln in vulnerabilities:
            if vuln["service"] == "ssh":
                results.append(vuln)

        return {
            "answer": "These vulnerabilities are related to SSH service.",
            "results": results
        }

    if "http" in question or "web" in question:
        results = []
        for vuln in vulnerabilities:
            if vuln["service"] == "http":
                results.append(vuln)

        return {
            "answer": "These vulnerabilities are related to web/http service.",
            "results": results
        }

    return {
        "answer": "I could not understand the query. Try asking about critical, high, ssh, or web vulnerabilities.",
        "results": []
    }