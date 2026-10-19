import pytest
import networkx as nx
from network import create_demo_network, add_device_to_graph, add_connection_to_graph
from algorithms import (
    analyze_service_reachability,
    analyze_attack_paths,
    analyze_containment_impact,
)


def test_service_reachability_demo_network():
    """Verify that reachable services distinguish device reachability, ports, and vulnerabilities."""
    graph = create_demo_network()
    res = analyze_service_reachability(graph, "laptop_1")

    assert res["compromised_device"] == "laptop_1"
    assert res["total_services_exposed"] > 0
    assert res["services_with_vulnerabilities"] > 0

    services = res["reachable_services"]
    # Web server 443 should be reachable from laptop_1
    web_443 = next((s for s in services if s["target_device"] == "web_1" and s["port"] == 443), None)
    assert web_443 is not None
    assert web_443["reachable"] is True
    assert web_443["hops"] == 1
    # Check that vulnerabilities are correlated
    assert any("CVE-2022-41741" in v["id"] for v in web_443["vulnerabilities"])

    # backup_1 should be reachable via app_1
    backup_services = [s for s in services if s["target_device"] == "backup_1"]
    assert len(backup_services) > 0


def test_service_reachability_port_restriction():
    """Verify that when an inbound link specifies a specific port, other ports on that host are not reachable."""
    g = nx.DiGraph()
    add_device_to_graph(
        g,
        {
            "id": "client",
            "name": "Client",
            "type": "endpoint",
            "criticality": 1,
        }
    )
    add_device_to_graph(
        g,
        {
            "id": "target",
            "name": "Target Host",
            "type": "server",
            "criticality": 4,
            "services": [
                {"name": "HTTP", "port": 80, "protocol": "tcp"},
                {"name": "SSH", "port": 22, "protocol": "tcp"},
            ]
        }
    )
    # Allowed edge restricted specifically to port 80
    add_connection_to_graph(
        g,
        source="client",
        target="target",
        protocol="tcp",
        allowed=True,
        port=80,
    )

    res = analyze_service_reachability(g, "client")
    srv_80 = next(s for s in res["reachable_services"] if s["port"] == 80)
    srv_22 = next(s for s in res["reachable_services"] if s["port"] == 22)

    assert srv_80["reachable"] is True
    assert srv_22["reachable"] is False
    assert "restricting access to service port 22" in srv_22["status_explanation"]


def test_attack_paths_exploit_and_policy_evidence():
    """Verify attack path analysis calculates feasibility and flags uncertain policy evidence."""
    graph = create_demo_network()
    res = analyze_attack_paths(graph, "laptop_1", critical_threshold=4)

    assert res["compromised_device"] == "laptop_1"
    assert res["total_attack_paths"] >= 1
    assert "db_1" in res["critical_assets_reachable"]

    paths = res["attack_paths"]
    # Sort order should place highest threat / highest criticality first
    assert paths[0]["target_criticality"] >= 4
    assert paths[0]["feasibility_score"] > 0
    assert len(paths[0]["step_details"]) > 0

    # Test unknown policy penalty
    # Set web_1 -> app_1 edge policy_status to "unknown"
    graph["web_1"]["app_1"]["policy_status"] = "unknown"
    res_uncertain = analyze_attack_paths(graph, "laptop_1", critical_threshold=4)
    db_paths = [p for p in res_uncertain["attack_paths"] if p["target_device"] == "db_1"]
    assert len(db_paths) > 0
    db_path = db_paths[0]

    # Must contain missing/uncertain evidence flag
    assert any("Firewall policy status is unconfirmed" in ev for ev in db_path["missing_or_uncertain_evidence"])
    # Feasibility score should reflect penalty
    assert any(h["evidence_status"] == "speculative_policy_unknown" for h in db_path["step_details"])


def test_attack_paths_containment_impact():
    """Verify containment impact properly tracks attack paths before and after actions."""
    graph = create_demo_network()
    impact = analyze_containment_impact(graph, "laptop_1", critical_threshold=4)

    assert impact["original_attack_paths_count"] > 0
    # Recommended containment actions should eliminate or protect critical paths
    assert impact["remaining_attack_paths_count"] < impact["original_attack_paths_count"]
    assert impact["eliminated_attack_paths_count"] > 0
