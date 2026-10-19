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
        if "observed" in data and data["observed"] is not None and not isinstance(data["observed"], bool):
            raise ValueError("Edge 'observed' must be a boolean.")
        if "port" in data and data["port"] is not None:
            port = data["port"]
            if not isinstance(port, int) or port < 1 or port > 65535:
                raise ValueError("Edge 'port' must be an integer between 1 and 65535.")
        if "count" in data and data["count"] is not None:
            count = data["count"]
            if not isinstance(count, int) or count < 0:
                raise ValueError("Edge 'count' must be a non-negative integer.")
        if "timestamp" in data and data["timestamp"] is not None and not isinstance(data["timestamp"], str):
            raise ValueError("Edge 'timestamp' must be a string.")
        if "metadata" in data and data["metadata"] is not None and not isinstance(data["metadata"], dict):
            raise ValueError("Edge 'metadata' must be a dictionary.")


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
    observed: bool = False,
    port: Optional[int] = None,
    count: Optional[int] = None,
    timestamp: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    edge_data = {
        "protocol": protocol,
        "allowed": allowed,
        "business_critical": business_critical,
        "disruption_cost": disruption_cost,
        "observed": observed,
    }
    if port is not None:
        edge_data["port"] = port
    if count is not None:
        edge_data["count"] = count
    if timestamp is not None:
        edge_data["timestamp"] = timestamp
    if metadata is not None:
        edge_data["metadata"] = metadata

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

    updatable_keys = [
        "protocol",
        "allowed",
        "business_critical",
        "disruption_cost",
        "observed",
        "port",
        "count",
        "timestamp",
        "metadata",
    ]
    for key in updatable_keys:
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


def build_network_from_records(
    nodes: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
) -> nx.DiGraph:
    """
    Constructs an isolated NetworkX DiGraph from structured node and edge records.
    Validates all devices and connections without mutating any global or active network state.
    """
    new_graph = nx.DiGraph()

    for node_data in nodes:
        add_device_to_graph(new_graph, node_data)

    for edge_data in edges:
        source = edge_data.get("source")
        target = edge_data.get("target")
        if not source or not target:
            raise ValueError("Each edge record must specify 'source' and 'target'.")

        kwargs = {
            "protocol": edge_data.get("protocol", "TCP"),
            "allowed": edge_data.get("allowed", True),
            "business_critical": edge_data.get("business_critical", False),
            "disruption_cost": float(edge_data.get("disruption_cost", 1.0)),
            "observed": edge_data.get("observed", False),
            "port": edge_data.get("port"),
            "count": edge_data.get("count"),
            "timestamp": edge_data.get("timestamp"),
            "metadata": edge_data.get("metadata"),
        }
        add_connection_to_graph(new_graph, source=source, target=target, **kwargs)

    return new_graph


def merge_network_records(
    base_graph: nx.DiGraph,
    new_nodes: List[Dict[str, Any]],
    new_edges: List[Dict[str, Any]],
    preserve_existing_nodes: bool = True,
) -> nx.DiGraph:
    """
    Creates a new nx.DiGraph by merging candidate nodes and edges into a copy of base_graph.
    - If preserve_existing_nodes is True, existing nodes retain their current name, type, criticality, and zone.
      New nodes are added.
    - If an edge already exists, its observation count is incremented, observed is set to True,
      and port/metadata are combined, preserving the existing policy permission ('allowed').
      New edges are added with their specified attributes.
    Does not mutate base_graph.
    """
    merged_graph = base_graph.copy()

    for node_data in new_nodes:
        node_id = node_data.get("id")
        if not node_id:
            continue
        if node_id in merged_graph:
            if not preserve_existing_nodes:
                update_device_in_graph(merged_graph, node_id, node_data)
        else:
            add_device_to_graph(merged_graph, node_data)

    for edge_data in new_edges:
        source = edge_data.get("source")
        target = edge_data.get("target")
        if not source or not target:
            continue

        if merged_graph.has_edge(source, target):
            # Edge exists: combine metadata and counts, preserve existing allowed & business_critical policies
            existing_attrs = merged_graph.edges[source, target]
            existing_count = existing_attrs.get("count") or 1
            added_count = edge_data.get("count") or 1
            existing_attrs["count"] = existing_count + added_count
            existing_attrs["observed"] = True

            if edge_data.get("timestamp"):
                existing_attrs["timestamp"] = edge_data["timestamp"]

            if not existing_attrs.get("port") and edge_data.get("port"):
                existing_attrs["port"] = edge_data["port"]

            existing_meta = existing_attrs.get("metadata")
            new_meta = edge_data.get("metadata")
            if isinstance(existing_meta, dict) and isinstance(new_meta, dict):
                for key in ["services", "ports", "protocols", "conn_states", "uids"]:
                    if key in new_meta:
                        merged_list = list(set(existing_meta.get(key, []) + new_meta.get(key, [])))
                        existing_meta[key] = merged_list
                existing_meta["total_orig_bytes"] = existing_meta.get("total_orig_bytes", 0) + new_meta.get("total_orig_bytes", 0)
                existing_meta["total_resp_bytes"] = existing_meta.get("total_resp_bytes", 0) + new_meta.get("total_resp_bytes", 0)
            elif isinstance(new_meta, dict):
                existing_attrs["metadata"] = new_meta
        else:
            # New edge
            kwargs = {
                "protocol": edge_data.get("protocol", "TCP"),
                "allowed": edge_data.get("allowed", False),
                "business_critical": edge_data.get("business_critical", False),
                "disruption_cost": float(edge_data.get("disruption_cost", 1.0)),
                "observed": edge_data.get("observed", True),
                "port": edge_data.get("port"),
                "count": edge_data.get("count", 1),
                "timestamp": edge_data.get("timestamp"),
                "metadata": edge_data.get("metadata"),
            }
            add_connection_to_graph(merged_graph, source=source, target=target, **kwargs)

    return merged_graph


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

