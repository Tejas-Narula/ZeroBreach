from typing import Dict, Any, List, Optional
import networkx as nx


def create_demo_network() -> nx.DiGraph:
    """
    Creates and returns a fresh instance of the demo directed network.
    Node schema:
        id: str
        name: str
        type: str (laptop, server, database, etc.)
        criticality: int (1-5)
        zone: str (employee, dmz, internal, restricted, etc.)
    Edge schema:
        source: str
        target: str
        allowed: bool
        protocol: str (HTTPS, SQL, SSH, etc.)
        business_critical: bool (optional)
        disruption_cost: float (optional)
    """
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
        ("laptop_1", "web_1", "HTTPS", False, 1.0),
        ("web_1", "app_1", "HTTPS", True, 2.0),
        ("app_1", "db_1", "SQL", True, 3.0),
        ("app_1", "backup_1", "SSH", False, 1.5),
        ("backup_1", "db_1", "SQL", True, 2.5),
    ]

    for device in devices:
        validate_device_data(device)
        graph.add_node(device["id"], **device)

    for source, target, protocol, business_critical, disruption_cost in connections:
        graph.add_edge(
            source,
            target,
            allowed=True,
            protocol=protocol,
            business_critical=business_critical,
            disruption_cost=disruption_cost,
        )

    return graph


def validate_device_data(data: Dict[str, Any], check_id_present: bool = True) -> None:
    if check_id_present:
        device_id = data.get("id")
        if not device_id or not isinstance(device_id, str) or not device_id.strip():
            raise ValueError("Device 'id' must be a non-empty string.")

    if "criticality" in data:
        criticality = data["criticality"]
        if not isinstance(criticality, int) or criticality < 1 or criticality > 5:
            raise ValueError("Device 'criticality' must be an integer between 1 and 5.")

    if "name" in data and (not isinstance(data["name"], str) or not data["name"].strip()):
        raise ValueError("Device 'name' must be a non-empty string.")

    if "type" in data and (not isinstance(data["type"], str) or not data["type"].strip()):
        raise ValueError("Device 'type' must be a non-empty string.")

    if "zone" in data and (not isinstance(data["zone"], str) or not data["zone"].strip()):
        raise ValueError("Device 'zone' must be a non-empty string.")


def validate_connection_data(graph: nx.DiGraph, source: str, target: str, data: Optional[Dict[str, Any]] = None) -> None:
    if not source or not isinstance(source, str):
        raise ValueError("Connection 'source' must be a non-empty string.")
    if not target or not isinstance(target, str):
        raise ValueError("Connection 'target' must be a non-empty string.")
    if source == target:
        raise ValueError("Self-loop connections are not allowed in this network model.")

    if source not in graph:
        raise ValueError(f"Source device '{source}' does not exist in graph.")
    if target not in graph:
        raise ValueError(f"Target device '{target}' does not exist in graph.")

    if data:
        if "allowed" in data and not isinstance(data["allowed"], bool):
            raise ValueError("Edge 'allowed' must be a boolean.")
        if "protocol" in data and (not isinstance(data["protocol"], str) or not data["protocol"].strip()):
            raise ValueError("Edge 'protocol' must be a non-empty string.")
        if "disruption_cost" in data:
            cost = data["disruption_cost"]
            if not isinstance(cost, (int, float)) or cost < 0:
                raise ValueError("Edge 'disruption_cost' must be a non-negative number.")
        if "business_critical" in data and not isinstance(data["business_critical"], bool):
            raise ValueError("Edge 'business_critical' must be a boolean.")


def add_device_to_graph(graph: nx.DiGraph, device_data: Dict[str, Any]) -> Dict[str, Any]:
    validate_device_data(device_data, check_id_present=True)
    device_id = device_data["id"]

    if device_id in graph:
        raise ValueError(f"Device with id '{device_id}' already exists.")

    node_attrs = {
        "id": device_id,
        "name": device_data.get("name", device_id),
        "type": device_data.get("type", "generic"),
        "criticality": int(device_data.get("criticality", 1)),
        "zone": device_data.get("zone", "default"),
    }
    graph.add_node(device_id, **node_attrs)
    return node_attrs


def update_device_in_graph(graph: nx.DiGraph, device_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
    if device_id not in graph:
        raise ValueError(f"Device '{device_id}' does not exist.")

    validate_device_data(updates, check_id_present=False)

    for key in ["name", "type", "criticality", "zone"]:
        if key in updates and updates[key] is not None:
            graph.nodes[device_id][key] = updates[key]

    return dict(graph.nodes[device_id])


def remove_device_from_graph(graph: nx.DiGraph, device_id: str) -> None:
    if device_id not in graph:
        raise ValueError(f"Device '{device_id}' does not exist.")
    graph.remove_node(device_id)


def add_connection_to_graph(
    graph: nx.DiGraph,
    source: str,
    target: str,
    protocol: str = "TCP",
    allowed: bool = True,
    business_critical: bool = False,
    disruption_cost: float = 1.0,
) -> Dict[str, Any]:
    edge_data = {
        "protocol": protocol,
        "allowed": allowed,
        "business_critical": business_critical,
        "disruption_cost": disruption_cost,
    }
    validate_connection_data(graph, source, target, edge_data)

    if graph.has_edge(source, target):
        raise ValueError(f"Connection from '{source}' to '{target}' already exists.")

    graph.add_edge(source, target, **edge_data)
    return {
        "source": source,
        "target": target,
        **edge_data,
    }


def update_connection_in_graph(
    graph: nx.DiGraph,
    source: str,
    target: str,
    updates: Dict[str, Any],
) -> Dict[str, Any]:
    if not graph.has_edge(source, target):
        raise ValueError(f"Connection from '{source}' to '{target}' does not exist.")

    validate_connection_data(graph, source, target, updates)

    for key in ["protocol", "allowed", "business_critical", "disruption_cost"]:
        if key in updates and updates[key] is not None:
            graph.edges[source, target][key] = updates[key]

    return {
        "source": source,
        "target": target,
        **graph.edges[source, target],
    }


def remove_connection_from_graph(graph: nx.DiGraph, source: str, target: str) -> None:
    if not graph.has_edge(source, target):
        raise ValueError(f"Connection from '{source}' to '{target}' does not exist.")
    graph.remove_edge(source, target)


def serialize_network(graph: nx.DiGraph) -> Dict[str, List[Dict[str, Any]]]:
    nodes = [dict(data) for _, data in graph.nodes(data=True)]
    edges = [
        {
            "source": u,
            "target": v,
            **dict(data),
        }
        for u, v, data in graph.edges(data=True)
    ]
    return {
        "nodes": nodes,
        "edges": edges,
    }
