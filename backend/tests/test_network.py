import pytest
import networkx as nx

from network import (
    create_demo_network,
    add_device_to_graph,
    update_device_in_graph,
    remove_device_from_graph,
    add_connection_to_graph,
    update_connection_in_graph,
    build_network_from_records,
    merge_network_records,
    serialize_network,
)
from criticality import (
    VALID_DEVICE_TYPES,
    normalize_device_type,
    recommend_device_criticality,
)


def test_major_device_categories():
    """Validates the 11 major network device categories and alias normalizations."""
    expected_categories = {
        "endpoint",
        "server",
        "database",
        "network_device",
        "firewall",
        "wireless_access_point",
        "cloud_infrastructure",
        "security_system",
        "iot_device",
        "external",
        "unknown",
    }
    assert VALID_DEVICE_TYPES == expected_categories

    # Test alias mappings
    assert normalize_device_type("laptop") == "endpoint"
    assert normalize_device_type("workstation") == "endpoint"
    assert normalize_device_type("router") == "network_device"
    assert normalize_device_type("switch") == "network_device"
    assert normalize_device_type("wap") == "wireless_access_point"
    assert normalize_device_type("ids") == "security_system"
    assert normalize_device_type("camera") == "iot_device"
    assert normalize_device_type("internet") == "external"
    assert normalize_device_type("unknown") == "unknown"
    assert normalize_device_type("nonexistent_device") == "unknown"


def test_automatic_criticality_recommendation():
    """Validates explainable criticality rules across different device categories and evidence."""
    # 1. Endpoint baseline
    rec_endpoint = recommend_device_criticality({"id": "ep1", "type": "endpoint", "zone": "employee"})
    assert rec_endpoint["recommended_criticality"] == 1
    assert "endpoint" in rec_endpoint["explanation"]

    # 2. General server baseline
    rec_server = recommend_device_criticality({"id": "srv1", "type": "server", "zone": "internal"})
    assert rec_server["recommended_criticality"] == 3

    # 3. Database server in restricted zone with verified database role
    rec_db = recommend_device_criticality({
        "id": "db1",
        "type": "database",
        "zone": "restricted",
        "inferred_role": "Production PostgreSQL Cluster",
    })
    assert rec_db["recommended_criticality"] == 5
    assert "restricted" in rec_db["explanation"]

    # 4. Domain Controller / Auth Server
    rec_auth = recommend_device_criticality({
        "id": "dc1",
        "type": "server",
        "zone": "internal",
        "inferred_role": "Active Directory Domain Controller",
    })
    assert rec_auth["recommended_criticality"] == 5
    assert rec_auth["confidence"] == "high"
    assert "Active Directory" in rec_auth["explanation"]

    # 5. Unknown device conservative provisional rating
    rec_unknown = recommend_device_criticality({"id": "unk1", "type": "unknown", "zone": "internal"})
    assert rec_unknown["recommended_criticality"] == 2
    assert rec_unknown["confidence"] == "provisional"
    assert len(rec_unknown["missing_information"]) > 0

    # 6. External endpoint
    rec_ext = recommend_device_criticality({"id": "ext1", "type": "external", "zone": "external"})
    assert rec_ext["recommended_criticality"] == 1


def test_manual_criticality_override_and_persistence():
    """Validates that manual overrides take precedence and are never overwritten during merges."""
    graph = create_demo_network()
    # db_1 has manual_override=True, criticality=5
    assert graph.nodes["db_1"]["criticality"] == 5
    assert graph.nodes["db_1"]["manual_override"] is True

    # User manually lowers criticality of db_1 to 2
    update_device_in_graph(graph, "db_1", {"criticality": 2, "manual_override": True})
    assert graph.nodes["db_1"]["criticality"] == 2

    # Simulate importing/merging new Zeek records where db_1 is observed with database traffic
    incoming_nodes = [
        {
            "id": "db_1",
            "name": "Host 10.0.0.50",
            "type": "database",
            "criticality": 5, # incoming candidate says 5
            "zone": "restricted",
            "manual_override": False,
        }
    ]
    incoming_edges = []

    merged = merge_network_records(graph, incoming_nodes, incoming_edges, preserve_existing_nodes=True)
    # Must preserve the analyst's manual override of 2!
    assert merged.nodes["db_1"]["criticality"] == 2
    assert merged.nodes["db_1"]["manual_override"] is True

    # Even if preserve_existing_nodes=False, manual_override protects manual criticality
    merged_override_protected = merge_network_records(
        graph, incoming_nodes, incoming_edges, preserve_existing_nodes=False
    )
    assert merged_override_protected.nodes["db_1"]["criticality"] == 2


def test_connection_policy_status_distinction():
    """Validates that observed connections remain distinct from allowed vs denied vs unknown policies."""
    graph = nx.DiGraph()
    add_device_to_graph(graph, {"id": "dev_a", "name": "Device A", "type": "endpoint"})
    add_device_to_graph(graph, {"id": "dev_b", "name": "Device B", "type": "server"})

    # 1. Observed but policy unknown -> allowed should be False
    add_connection_to_graph(
        graph,
        source="dev_a",
        target="dev_b",
        protocol="TCP",
        allowed=False,
        policy_status="unknown",
        observed=True,
    )
    assert graph.edges["dev_a", "dev_b"]["observed"] is True
    assert graph.edges["dev_a", "dev_b"]["allowed"] is False
    assert graph.edges["dev_a", "dev_b"]["policy_status"] == "unknown"

    # 2. Update to explicitly allowed
    update_connection_in_graph(graph, "dev_a", "dev_b", {"policy_status": "allowed"})
    assert graph.edges["dev_a", "dev_b"]["allowed"] is True
    assert graph.edges["dev_a", "dev_b"]["policy_status"] == "allowed"

    # 3. Update to explicitly denied
    update_connection_in_graph(graph, "dev_a", "dev_b", {"policy_status": "denied"})
    assert graph.edges["dev_a", "dev_b"]["allowed"] is False
    assert graph.edges["dev_a", "dev_b"]["policy_status"] == "denied"


def test_demo_network_and_backward_compatibility():
    """Validates demo network integrity and compatibility with attack algorithms."""
    graph = create_demo_network()
    assert graph.number_of_nodes() == 5
    assert graph.number_of_edges() == 5

    # Check node categories
    assert graph.nodes["laptop_1"]["type"] == "endpoint"
    assert graph.nodes["web_1"]["type"] == "server"
    assert graph.nodes["db_1"]["type"] == "database"
    assert graph.nodes["db_1"]["criticality"] == 5

    serialized = serialize_network(graph)
    assert len(serialized["nodes"]) == 5
    assert len(serialized["edges"]) == 5
