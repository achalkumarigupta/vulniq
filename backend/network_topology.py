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

    plt.figure(figsize=(10, 6))

    nx.draw(
        G,
        with_labels=True,
        node_size=3500,
        font_size=8
    )

    image_path = "network_topology.png"

    plt.savefig(image_path)
    plt.close()

    return image_path