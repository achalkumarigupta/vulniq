import networkx as nx
import matplotlib.pyplot as plt


def generate_topology(vulnerabilities):

    G = nx.Graph()

    for vuln in vulnerabilities:

        asset = vuln["asset"]

        label = (
            asset +
            "\n" +
            vuln["service"]
        )

        G.add_node(label)

    nodes = list(G.nodes())

    for i in range(len(nodes) - 1):
        G.add_edge(
            nodes[i],
            nodes[i + 1]
        )

    plt.figure(figsize=(12, 4))

    pos = nx.spring_layout(
        G,
        seed=42,
        k=1.2
    )

    nx.draw(
        G,
        pos,
        with_labels=True,
        node_size=2500,
        node_color="#2563eb",
        font_size=8,
        font_color="white",
        edge_color="#60a5fa",
        width=2
    )

    plt.axis("off")

    plt.tight_layout()

    image_path = "network_topology.png"

    plt.savefig(
        image_path,
        bbox_inches="tight",
        pad_inches=0.1
    )

    plt.close()

    return image_path