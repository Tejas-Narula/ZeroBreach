
import networkx as nx


def create_demo_network():
    graph = nx.DiGraph()

    devices = [
        {
            "id": "laptop_1",
            "name": "Employee Laptop",
            "type": "laptop",
            "criticality": 1,
            "zone": "employee",
        },
        {
            "id": "web_1",
            "name": "Web Server",
            "type": "server",
            "criticality": 3,
            "zone": "dmz",
        },
        {
            "id": "app_1",
            "name": "Application Server",
            "type": "server",
            "criticality": 4,
            "zone": "internal",
        },
        {
            "id": "db_1",
            "name": "Customer Database",
            "type": "database",
            "criticality": 5,
            "zone": "restricted",
        },
        {
            "id": "backup_1",
            "name": "Backup Server",
            "type": "server",
            "criticality": 4,
            "zone": "restricted",
        },
    ]

    connections = [
        ("laptop_1", "web_1", "HTTPS"),
        ("web_1", "app_1", "HTTPS"),
        ("app_1", "db_1", "SQL"),
        ("app_1", "backup_1", "SSH"),
        ("backup_1", "db_1", "SQL"),
    ]

    for device in devices:
        graph.add_node(device["id"], **device)

    for source, target, protocol in connections:
        graph.add_edge(
            source,
            target,
            allowed=True,
            protocol=protocol,
        )

    return graph
