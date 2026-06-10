import networkx as nx
import matplotlib.pyplot as plt


def generate_attack_graph(vulnerabilities):
    graph = nx.DiGraph()

    graph.add_node("Attacker")

    for vuln in vulnerabilities:
        asset = vuln["asset"]
        service = vuln["service"]
        severity = vuln["severity"]

        node_name = f"{asset}:{vuln['port']} ({service})"

        graph.add_node(node_name)

        if severity in ["HIGH", "CRITICAL"]:
            graph.add_edge("Attacker", node_name)

    plt.figure(figsize=(10, 6))
    pos = nx.spring_layout(graph)

    nx.draw(
        graph,
        pos,
        with_labels=True,
        node_size=3000,
        font_size=8,
        arrows=True
    )

    image_path = "attack_graph.png"
    plt.savefig(image_path)
    plt.close()

    return image_path