import json
import pytest
import networkx as nx
from zeek_parser import (
    process_zeek_log_to_network,
    parse_zeek_tsv,
    parse_zeek_json,
    sanitize_device_id,
    extract_zeek_flow,
)
from network import (
    build_network_from_records,
    merge_network_records,
    create_demo_network,
    serialize_network,
)
from algorithms import (
    find_reachable_devices,
    find_path,
    calculate_risk_scores,
    recommend_containment,
)


SAMPLE_ZEEK_TSV = """#separator \\x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2023-10-15-10-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state
#types	time	string	addr	port	addr	port	string	string	interval	count	count	string
1697364000.123456	C12345abc	192.168.1.50	51234	10.0.0.10	443	tcp	ssl	1.50	1200	4500	SF
1697364002.654321	C12346def	10.0.0.10	49201	10.0.0.25	3306	tcp	mysql	0.05	300	1200	SF
1697364005.111222	C12347ghi	192.168.1.50	51235	10.0.0.10	80	tcp	http	0.10	150	600	SF
#close	2023-10-15-10-00-10
"""

SAMPLE_ZEEK_JSON = """{"ts": 1697364010.0, "uid": "C99901", "id.orig_h": "172.16.1.10", "id.orig_p": 44100, "id.resp_h": "172.16.1.20", "id.resp_p": 22, "proto": "tcp", "service": "ssh", "conn_state": "SF"}
{"ts": 1697364012.0, "uid": "C99902", "id.orig_h": "172.16.1.20", "id.orig_p": 50100, "id.resp_h": "172.16.1.30", "id.resp_p": 5432, "proto": "tcp", "service": "postgresql", "conn_state": "SF"}
"""


def test_zeek_tsv_parsing():
    res = process_zeek_log_to_network(SAMPLE_ZEEK_TSV)
    assert res["statistics"]["total_records"] == 3
    assert res["statistics"]["processed_records"] == 3
    assert len(res["nodes"]) == 3
    # 2 aggregated edges: 192.168.1.50 -> 10.0.0.10 and 10.0.0.10 -> 10.0.0.25
    assert len(res["edges"]) == 2

    edge_192_10 = next(e for e in res["edges"] if "192_168_1_50" in e["source"] and "10_0_0_10" in e["target"])
    assert edge_192_10["count"] == 2
    assert edge_192_10["observed"] is True
    assert edge_192_10["allowed"] is False  # Separated by default
    assert "ssl" in edge_192_10["metadata"]["services"]
    assert "http" in edge_192_10["metadata"]["services"]
    assert 443 in edge_192_10["metadata"]["ports"]
    assert 80 in edge_192_10["metadata"]["ports"]


def test_zeek_json_parsing():
    res = process_zeek_log_to_network(SAMPLE_ZEEK_JSON)
    assert res["statistics"]["processed_records"] == 2
    assert len(res["nodes"]) == 3
    assert len(res["edges"]) == 2

    # Verify deterministic IDs
    expected_ids = {"dev_172_16_1_10", "dev_172_16_1_20", "dev_172_16_1_30"}
    actual_ids = {n["id"] for n in res["nodes"]}
    assert actual_ids == expected_ids


def test_device_classification_and_overrides():
    overrides = {
        "10.0.0.10": {"name": "Primary Web Gateway", "criticality": 4, "type": "server", "zone": "dmz"}
    }
    res = process_zeek_log_to_network(SAMPLE_ZEEK_TSV, device_overrides=overrides)
    node_10 = next(n for n in res["nodes"] if n["id"] == "dev_10_0_0_10")
    assert node_10["name"] == "Primary Web Gateway"
    assert node_10["criticality"] == 4
    assert node_10["zone"] == "dmz"


def test_invalid_records_handling():
    invalid_log = """{"id.orig_h": "invalid.ip", "id.resp_h": "10.0.0.1", "proto": "tcp"}
{"id.orig_h": "10.0.0.2", "id.resp_h": "10.0.0.2", "proto": "tcp"}
{"id.orig_h": "10.0.0.3", "id.resp_h": "10.0.0.4", "proto": "tcp", "id.resp_p": 80}
"""
    res = process_zeek_log_to_network(invalid_log)
    # 1 invalid IP skipped, 1 self-loop skipped, 1 valid flow processed
    assert res["statistics"]["processed_records"] == 1
    assert res["statistics"]["skipped_records"] == 2
    assert len(res["nodes"]) == 2
    assert len(res["edges"]) == 1


def test_empty_or_malformed_file():
    with pytest.raises(ValueError, match="Log file is empty"):
        process_zeek_log_to_network("")

    with pytest.raises(ValueError):
        process_zeek_log_to_network("NOT_A_LOG_FORMAT\nRandom garbage words")


def test_build_network_from_records_isolation():
    res = process_zeek_log_to_network(SAMPLE_ZEEK_TSV)
    graph = build_network_from_records(res["nodes"], res["edges"])
    assert graph.number_of_nodes() == 3
    assert graph.number_of_edges() == 2

    # Ensure edge metadata is preserved
    edge_data = graph["dev_192_168_1_50"]["dev_10_0_0_10"]
    assert edge_data["observed"] is True
    assert edge_data["allowed"] is False
    assert edge_data["count"] == 2


def test_merge_network_records():
    demo = create_demo_network()
    initial_nodes = demo.number_of_nodes()
    initial_edges = demo.number_of_edges()

    # Import new traffic connecting laptop_1 to an external IP
    new_nodes = [
        {"id": "laptop_1", "name": "Overwritten Laptop", "type": "laptop", "criticality": 1, "zone": "employee"},
        {"id": "dev_8_8_8_8", "name": "Google DNS", "type": "server", "criticality": 3, "zone": "dmz"},
    ]
    new_edges = [
        {"source": "laptop_1", "target": "dev_8_8_8_8", "protocol": "UDP", "port": 53, "allowed": False, "observed": True}
    ]

    # Merging preserving existing
    merged = merge_network_records(demo, new_nodes, new_edges, preserve_existing_nodes=True)
    assert demo.number_of_nodes() == initial_nodes  # Base untouched
    assert merged.number_of_nodes() == initial_nodes + 1
    assert merged.number_of_edges() == initial_edges + 1
    assert merged.nodes["laptop_1"]["name"] == "Employee Laptop"  # Preserved original name
    assert merged.has_edge("laptop_1", "dev_8_8_8_8")


def test_existing_algorithms_with_observed_edges():
    # Construct graph with both permitted and blocked/unapproved observed traffic
    demo = create_demo_network()
    # Add an observed but not allowed edge
    demo.add_node("dev_ext_1", id="dev_ext_1", name="Ext Server", type="server", criticality=5, zone="restricted")
    demo.add_edge("laptop_1", "dev_ext_1", protocol="TCP", port=443, allowed=False, observed=True)

    # Attack simulation should NOT be able to reach dev_ext_1 because allowed=False
    reachable = find_reachable_devices(demo, "laptop_1")
    assert "dev_ext_1" not in reachable

    # Path finding should return None
    path = find_path(demo, "laptop_1", "dev_ext_1")
    assert path is None

    # Now permit the edge
    demo["laptop_1"]["dev_ext_1"]["allowed"] = True
    reachable_now = find_reachable_devices(demo, "laptop_1")
    assert "dev_ext_1" in reachable_now

    # Risk scoring works seamlessly with edge metadata present
    risks = calculate_risk_scores(demo, "laptop_1")
    ext_risk = next((r for r in risks if r["device_id"] == "dev_ext_1"), None)
    assert ext_risk is not None
    assert ext_risk["criticality"] == 5

    # Containment recommendation executes safely
    containment = recommend_containment(demo, "laptop_1", critical_threshold=4)
    assert "recommended_actions" in containment


@pytest.mark.anyio
async def test_api_zeek_import_logic():
    from main import import_zeek_logs, reset_network, get_network
    import io
    from fastapi import UploadFile

    reset_network()

    # 1. Preview mode
    file_tsv = UploadFile(
        filename="conn.log",
        file=io.BytesIO(SAMPLE_ZEEK_TSV.encode("utf-8")),
    )
    res_preview = await import_zeek_logs(
        file=file_tsv,
        mode="preview",
        default_criticality=3,
        default_zone="internal",
        allowed_default=False,
        preserve_existing_nodes=True,
    )
    assert res_preview["status"] == "success"
    assert res_preview["mode"] == "preview"
    assert res_preview["nodes_count"] == 3

    # Active network was untouched
    assert len(get_network()["nodes"]) == 5

    # 2. Replace mode
    file_json = UploadFile(
        filename="conn.json",
        file=io.BytesIO(SAMPLE_ZEEK_JSON.encode("utf-8")),
    )
    res_replace = await import_zeek_logs(
        file=file_json,
        mode="replace",
        default_criticality=2,
        default_zone="internal",
        allowed_default=False,
        preserve_existing_nodes=True,
    )
    assert res_replace["status"] == "success"
    assert res_replace["mode"] == "replace"
    assert res_replace["nodes_count"] == 3
    assert len(get_network()["nodes"]) == 3

    # 3. Validation failure
    file_bad = UploadFile(
        filename="bad.log",
        file=io.BytesIO(b"Not a zeek log"),
    )
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        await import_zeek_logs(file=file_bad, mode="replace")
    assert exc_info.value.status_code == 400

    # Active network remained 3 nodes
    assert len(get_network()["nodes"]) == 3

    # Reset back to demo state
    reset_network()

