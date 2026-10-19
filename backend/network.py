from typing import Dict, Any, List, Optional
import networkx as nx
from criticality import normalize_device_type, recommend_device_criticality


def create_demo_network() -> nx.DiGraph:
    """
    Creates and returns a fresh instance of the demo directed network.
    Node schema:
        id: str
        name: str
        type: str (endpoint, server, database, network_device, firewall, etc.)
        criticality: int (1-5)
        zone: str (employee, dmz, internal, restricted, external, etc.)
        manual_override: bool
    Edge schema:
        source: str
        target: str
        allowed: bool
        policy_status: str (allowed, denied, unknown)
        protocol: str (HTTPS, SQL, SSH, etc.)
        business_critical: bool (optional)
        disruption_cost: float (optional)
    """
    graph = nx.DiGraph()

    devices = [
        {
            "id": "laptop_1",
            "name": "Employee Laptop",
            "type": "endpoint",
            "criticality": 1,
            "zone": "employee",
            "inferred_role": "Standard Workstation",
            "manual_override": True,
            "discovery_source": "demo",
        },
        {
            "id": "web_1",
            "name": "Web Server",
            "type": "server",
            "criticality": 3,
            "zone": "dmz",
            "inferred_role": "Public Web Frontend",
            "manual_override": True,
            "discovery_source": "demo",
        },
        {
            "id": "app_1",
            "name": "Application Server",
            "type": "server",
            "criticality": 4,
            "zone": "internal",
            "inferred_role": "Core API Server",
            "manual_override": True,
            "discovery_source": "demo",
        },
        {
            "id": "db_1",
            "name": "Customer Database",
            "type": "database",
            "criticality": 5,
            "zone": "restricted",
            "inferred_role": "Production Customer DB",
            "manual_override": True,
            "discovery_source": "demo",
        },
        {
            "id": "backup_1",
            "name": "Backup Server",
            "type": "server",
            "criticality": 4,
            "zone": "restricted",
            "inferred_role": "Secondary Backup Server",
            "manual_override": True,
            "discovery_source": "demo",
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
            policy_status="allowed",
            protocol=protocol,
            business_critical=business_critical,
            disruption_cost=disruption_cost,
            observed=True,
        )

    return graph


def validate_device_data(data: Dict[str, Any], check_id_present: bool = True) -> None:
    if check_id_present:
        device_id = data.get("id")
        if not device_id or not isinstance(device_id, str) or not device_id.strip():
            raise ValueError("Device 'id' must be a non-empty string.")

    if "criticality" in data and data["criticality"] is not None:
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
        if "policy_status" in data and data["policy_status"] is not None:
            if data["policy_status"] not in ["allowed", "denied", "unknown"]:
                raise ValueError("Edge 'policy_status' must be 'allowed', 'denied', or 'unknown'.")
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
        if "first_seen" in data and data["first_seen"] is not None and not isinstance(data["first_seen"], str):
            raise ValueError("Edge 'first_seen' must be a string.")
        if "last_seen" in data and data["last_seen"] is not None and not isinstance(data["last_seen"], str):
            raise ValueError("Edge 'last_seen' must be a string.")
        if "metadata" in data and data["metadata"] is not None and not isinstance(data["metadata"], dict):
            raise ValueError("Edge 'metadata' must be a dictionary.")


def add_device_to_graph(graph: nx.DiGraph, device_data: Dict[str, Any]) -> Dict[str, Any]:
    validate_device_data(device_data, check_id_present=True)
    device_id = device_data["id"]

    if device_id in graph:
        raise ValueError(f"Device with id '{device_id}' already exists.")

    norm_type = normalize_device_type(device_data.get("type", "unknown"))
    manual_override = bool(device_data.get("manual_override", False))

    criticality_val = device_data.get("criticality")
    if criticality_val is not None:
        crit = int(criticality_val)
        # If user explicitly supplied criticality, flag as manual override unless specified otherwise
        manual_override = device_data.get("manual_override", True)
    else:
        # Automatically recommend criticality
        temp_data = dict(device_data)
        temp_data["type"] = norm_type
        rec = recommend_device_criticality(temp_data, graph=graph)
        crit = rec["recommended_criticality"]
        manual_override = False

    node_attrs = {
        "id": device_id,
        "name": device_data.get("name", device_id),
        "type": norm_type,
        "criticality": max(1, min(5, crit)),
        "zone": device_data.get("zone", "internal"),
        "inferred_role": device_data.get("inferred_role"),
        "manual_override": manual_override,
        "ip_addresses": device_data.get("ip_addresses") or [],
        "hostname": device_data.get("hostname"),
        "discovery_source": device_data.get("discovery_source", "manual"),
        "first_seen": device_data.get("first_seen"),
        "last_seen": device_data.get("last_seen"),
        "metadata": device_data.get("metadata") or {},
    }
    graph.add_node(device_id, **node_attrs)
    return node_attrs


def update_device_in_graph(graph: nx.DiGraph, device_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
    if device_id not in graph:
        raise ValueError(f"Device '{device_id}' does not exist.")

    validate_device_data(updates, check_id_present=False)

    for key in ["name", "zone", "inferred_role", "hostname", "discovery_source", "first_seen", "last_seen"]:
        if key in updates and updates[key] is not None:
            graph.nodes[device_id][key] = updates[key]

    if "type" in updates and updates["type"] is not None:
        graph.nodes[device_id]["type"] = normalize_device_type(updates["type"])

    if "criticality" in updates and updates["criticality"] is not None:
        graph.nodes[device_id]["criticality"] = int(updates["criticality"])
        graph.nodes[device_id]["manual_override"] = True

    if "manual_override" in updates and updates["manual_override"] is not None:
        graph.nodes[device_id]["manual_override"] = bool(updates["manual_override"])

    if "ip_addresses" in updates and updates["ip_addresses"] is not None:
        existing_ips = set(graph.nodes[device_id].get("ip_addresses") or [])
        existing_ips.update(updates["ip_addresses"])
        graph.nodes[device_id]["ip_addresses"] = sorted(list(existing_ips))

    if "metadata" in updates and updates["metadata"] is not None:
        existing_meta = graph.nodes[device_id].get("metadata") or {}
        if isinstance(existing_meta, dict) and isinstance(updates["metadata"], dict):
            existing_meta.update(updates["metadata"])
            graph.nodes[device_id]["metadata"] = existing_meta
        else:
            graph.nodes[device_id]["metadata"] = updates["metadata"]

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
    policy_status: Optional[str] = None,
    business_critical: bool = False,
    disruption_cost: float = 1.0,
    observed: bool = False,
    port: Optional[int] = None,
    count: Optional[int] = None,
    timestamp: Optional[str] = None,
    first_seen: Optional[str] = None,
    last_seen: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    # Determine coherent policy status
    if policy_status is None:
        policy_status = "allowed" if allowed else "denied"
    else:
        policy_status = policy_status.strip().lower()

    # Synchronize allowed flag with policy status: only "allowed" permits traversal
    actual_allowed = (policy_status == "allowed") if policy_status in ["allowed", "denied"] else allowed

    edge_data = {
        "protocol": protocol,
        "allowed": actual_allowed,
        "policy_status": policy_status,
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
    if first_seen is not None:
        edge_data["first_seen"] = first_seen
    if last_seen is not None:
        edge_data["last_seen"] = last_seen
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
        "policy_status",
        "business_critical",
        "disruption_cost",
        "observed",
        "port",
        "count",
        "timestamp",
        "first_seen",
        "last_seen",
        "metadata",
    ]
    for key in updatable_keys:
        if key in updates and updates[key] is not None:
            graph.edges[source, target][key] = updates[key]

    # Keep allowed synchronized if policy_status updated
    if "policy_status" in updates and updates["policy_status"] is not None:
        ps = str(updates["policy_status"]).strip().lower()
        if ps == "allowed":
            graph.edges[source, target]["allowed"] = True
        elif ps == "denied":
            graph.edges[source, target]["allowed"] = False
    elif "allowed" in updates and updates["allowed"] is not None and "policy_status" not in updates:
        graph.edges[source, target]["policy_status"] = "allowed" if updates["allowed"] else "denied"

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
            "policy_status": edge_data.get("policy_status"),
            "business_critical": edge_data.get("business_critical", False),
            "disruption_cost": float(edge_data.get("disruption_cost", 1.0)),
            "observed": edge_data.get("observed", False),
            "port": edge_data.get("port"),
            "count": edge_data.get("count"),
            "timestamp": edge_data.get("timestamp"),
            "first_seen": edge_data.get("first_seen"),
            "last_seen": edge_data.get("last_seen"),
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
      Crucially, if a node had a manual criticality override (manual_override=True), it is strictly preserved.
      New nodes are added.
    - If an edge already exists, its observation count is incremented, observed is set to True,
      and port/metadata are combined, preserving the existing policy permission ('allowed' and 'policy_status').
      New edges are added with their specified attributes.
    Does not mutate base_graph.
    """
    merged_graph = base_graph.copy()

    for node_data in new_nodes:
        node_id = node_data.get("id")
        if not node_id:
            continue
        if node_id in merged_graph:
            existing_attrs = merged_graph.nodes[node_id]
            is_manual_override = existing_attrs.get("manual_override", False)
            if not preserve_existing_nodes:
                # If preserve_existing_nodes is false, update attributes but protect manual_override if present
                safe_updates = dict(node_data)
                if is_manual_override and "criticality" in safe_updates:
                    # Do not overwrite manually assigned criticality
                    safe_updates["criticality"] = existing_attrs.get("criticality")
                update_device_in_graph(merged_graph, node_id, safe_updates)
            else:
                # Preserve existing node attributes, but merge IP addresses / timestamps
                if node_data.get("ip_addresses"):
                    ips = set(existing_attrs.get("ip_addresses") or [])
                    ips.update(node_data["ip_addresses"])
                    existing_attrs["ip_addresses"] = sorted(list(ips))
                if node_data.get("last_seen"):
                    existing_attrs["last_seen"] = node_data["last_seen"]
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
            if edge_data.get("last_seen"):
                existing_attrs["last_seen"] = edge_data["last_seen"]

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
                "policy_status": edge_data.get("policy_status", "unknown"),
                "business_critical": edge_data.get("business_critical", False),
                "disruption_cost": float(edge_data.get("disruption_cost", 1.0)),
                "observed": edge_data.get("observed", True),
                "port": edge_data.get("port"),
                "count": edge_data.get("count", 1),
                "timestamp": edge_data.get("timestamp"),
                "first_seen": edge_data.get("first_seen"),
                "last_seen": edge_data.get("last_seen"),
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

