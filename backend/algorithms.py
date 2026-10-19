from collections import deque
from typing import Dict, List, Set, Tuple, Optional, Any
import networkx as nx


def bfs_reachability_with_distances(
    graph: nx.DiGraph,
    start_device: str,
) -> Tuple[Dict[str, int], Dict[str, Optional[str]]]:
    """
    Internal reusable BFS traversal routine over allowed outgoing edges.
    Returns:
        distances: dict mapping reachable device_id -> shortest hop count from start_device
        parent: dict mapping reachable device_id -> predecessor device_id (start_device -> None)
    Raises:
        ValueError if start_device is not in graph.
    """
    if start_device not in graph:
        raise ValueError(f"Device '{start_device}' does not exist")

    distances: Dict[str, int] = {start_device: 0}
    parent: Dict[str, Optional[str]] = {start_device: None}
    queue: deque[str] = deque([start_device])

    while queue:
        current = queue.popleft()

        for neighbor in graph.successors(current):
            edge_data = graph[current][neighbor]

            # Traversal only respects allowed edges
            if not edge_data.get("allowed", False):
                continue

            if neighbor not in distances:
                distances[neighbor] = distances[current] + 1
                parent[neighbor] = current
                queue.append(neighbor)

    return distances, parent


def find_reachable_devices(graph: nx.DiGraph, start_device: str) -> Set[str]:
    """
    Returns the set of all device IDs reachable from start_device through allowed directed edges,
    including start_device itself.
    """
    distances, _ = bfs_reachability_with_distances(graph, start_device)
    return set(distances.keys())


def find_path(graph: nx.DiGraph, start_device: str, target_device: str) -> Optional[List[str]]:
    """
    Finds the shortest allowed directed path from start_device to target_device.
    Returns list of device IDs from start to target, or None if no path exists.
    Raises ValueError if either device does not exist in graph.
    """
    if start_device not in graph:
        raise ValueError(f"Device '{start_device}' does not exist")
    if target_device not in graph:
        raise ValueError(f"Device '{target_device}' does not exist")

    distances, parent = bfs_reachability_with_distances(graph, start_device)

    if target_device not in parent:
        return None

    path = []
    curr: Optional[str] = target_device
    while curr is not None:
        path.append(curr)
        curr = parent[curr]

    path.reverse()
    return path


def analyze_reachability_multi(
    graph: nx.DiGraph,
    compromised_devices: List[str],
) -> Dict[str, Any]:
    """
    Analyzes reachability from multiple compromised starting points.
    Computes union exposure while clearly separating compromised entry points from newly exposed devices.
    """
    if not compromised_devices:
        raise ValueError("At least one compromised device must be specified.")

    invalid = [dev for dev in compromised_devices if dev not in graph]
    if invalid:
        raise ValueError(f"Invalid device(s): {', '.join(invalid)}")

    compromised_set = set(compromised_devices)
    combined_reachable: Set[str] = set()
    per_device_analysis = {}

    for dev in compromised_devices:
        distances, _ = bfs_reachability_with_distances(graph, dev)
        reachable = set(distances.keys())
        combined_reachable.update(reachable)
        per_device_analysis[dev] = {
            "reachable_devices": sorted(reachable),
            "reachable_count": len(reachable) - 1,
        }

    # Newly exposed excludes the compromised starting devices
    newly_exposed = sorted(combined_reachable - compromised_set)

    return {
        "compromised_devices": compromised_devices,
        "combined_reachable_devices": sorted(combined_reachable),
        "total_reachable_count": len(combined_reachable),
        "newly_exposed_devices": newly_exposed,
        "newly_exposed_count": len(newly_exposed),
        "per_device": per_device_analysis,
    }


def find_critical_assets(
    graph: nx.DiGraph,
    start_device: str,
    threshold: int = 4,
) -> List[Dict[str, Any]]:
    """
    Identifies reachable critical assets (criticality >= threshold).
    For each asset reports:
        - device_id, name, criticality
        - shortest path, number of hops
        - whether it is reachable (True)
    """
    if start_device not in graph:
        raise ValueError(f"Device '{start_device}' does not exist")

    distances, parent = bfs_reachability_with_distances(graph, start_device)
    critical_assets = []

    for device_id, hops in distances.items():
        if device_id == start_device:
            continue

        node_data = graph.nodes[device_id]
        criticality = node_data.get("criticality", 1)

        if criticality >= threshold:
            # Reconstruct path
            path = []
            curr: Optional[str] = device_id
            while curr is not None:
                path.append(curr)
                curr = parent[curr]
            path.reverse()

            critical_assets.append({
                "device_id": device_id,
                "name": node_data.get("name", device_id),
                "criticality": criticality,
                "hops": hops,
                "path": path,
                "reachable": True,
            })

    critical_assets.sort(key=lambda x: (-x["criticality"], x["hops"]))
    return critical_assets


def calculate_risk_scores(
    graph: nx.DiGraph,
    start_device: str,
) -> List[Dict[str, Any]]:
    """
    Heuristic transparent risk scoring:
    Formula:
        base_criticality_factor = (criticality / 5.0) * 100
        hop_decay = 1.0 / hops
        risk_score = round(base_criticality_factor * hop_decay, 2)
    Ranges from 0 to 100. Deterministic, explainable.
    Starting device is excluded from ranking.
    """
    if start_device not in graph:
        raise ValueError(f"Device '{start_device}' does not exist")

    distances, parent = bfs_reachability_with_distances(graph, start_device)
    results = []

    for device_id, hops in distances.items():
        if device_id == start_device:
            continue

        node_data = graph.nodes[device_id]
        criticality = node_data.get("criticality", 1)

        # Hop distance >= 1
        base_criticality_pct = (criticality / 5.0) * 100.0
        hop_decay = 1.0 / max(1, hops)
        score = base_criticality_pct * hop_decay
        score_bounded = max(0.0, min(100.0, score))

        # Reconstruct path
        path = []
        curr: Optional[str] = device_id
        while curr is not None:
            path.append(curr)
            curr = parent[curr]
        path.reverse()

        results.append({
            "device_id": device_id,
            "name": node_data.get("name", device_id),
            "criticality": criticality,
            "hops": hops,
            "path": path,
            "risk_score": round(score_bounded, 2),
            "explanation": (
                f"Heuristic score {round(score_bounded, 2)} derived from criticality {criticality}/5 "
                f"at {hops} hop(s) distance (decay factor {round(hop_decay, 3)}). Not a calibrated attack probability."
            ),
        })

    results.sort(key=lambda d: d["risk_score"], reverse=True)
    return results


def recommend_containment(
    graph: nx.DiGraph,
    compromised_device: str,
    critical_threshold: int = 4,
) -> Dict[str, Any]:
    """
    Generates intelligent containment recommendations that account for alternative paths.
    Evaluates candidate containment actions:
    1. Blocking connections along attack paths to critical assets.
    2. Isolating intermediate hop nodes.
    Ranks actions by critical asset reduction per disruption cost.
    Simulates actions on graph copies so original graph remains untouched.
    """
    if compromised_device not in graph:
        raise ValueError(f"Device '{compromised_device}' does not exist")

    # Initial state
    init_distances, _ = bfs_reachability_with_distances(graph, compromised_device)
    init_reachable = set(init_distances.keys())

    init_critical = {
        node for node in init_reachable
        if node != compromised_device and graph.nodes[node].get("criticality", 1) >= critical_threshold
    }

    if not init_critical:
        return {
            "compromised_device": compromised_device,
            "recommended_actions": [],
            "message": "No critical assets currently exposed from this device.",
            "original_exposed_critical_count": 0,
            "remaining_exposed_critical_count": 0,
            "protected_critical_assets": [],
            "remaining_reachable_devices": sorted(init_reachable),
        }

    # Collect candidate actions: all active edges in reachable subgraph and intermediate nodes
    # We evaluate single edge cuts and multi-edge cuts, or greedy containment
    candidate_actions = []

    # 1. Edge actions (block edge)
    for u in init_reachable:
        for v in graph.successors(u):
            if not graph[u][v].get("allowed", False):
                continue
            cost = float(graph[u][v].get("disruption_cost", 1.0))
            is_bc = bool(graph[u][v].get("business_critical", False))
            if is_bc:
                cost += 3.0  # Business critical penalty

            candidate_actions.append({
                "action_type": "block_connection",
                "source": u,
                "target": v,
                "target_device": None,
                "cost": cost,
                "description": f"Block connection {u} -> {v} ({graph[u][v].get('protocol', 'TCP')})",
            })

    # 2. Node isolation actions (isolate intermediate node)
    for node in init_reachable:
        if node == compromised_device:
            # We can also consider isolating the compromised device itself
            candidate_actions.append({
                "action_type": "isolate_device",
                "source": None,
                "target": None,
                "target_device": node,
                "cost": 1.0,  # Isolating patient zero has low disruption cost vs company wide exposure
                "description": f"Isolate compromised device {node}",
            })
        elif node not in init_critical:
            # Isolating an intermediate relay server
            node_criticality = graph.nodes[node].get("criticality", 1)
            candidate_actions.append({
                "action_type": "isolate_device",
                "source": None,
                "target": None,
                "target_device": node,
                "cost": float(node_criticality * 1.5),
                "description": f"Isolate intermediate relay device {node} ({graph.nodes[node].get('name', node)})",
            })

    # Helper to simulate an action on a graph copy
    def apply_action(g: nx.DiGraph, act: Dict[str, Any]):
        if act["action_type"] == "block_connection":
            if g.has_edge(act["source"], act["target"]):
                g[act["source"]][act["target"]]["allowed"] = False
        elif act["action_type"] == "isolate_device":
            node = act["target_device"]
            if node in g:
                for pred in list(g.predecessors(node)):
                    g[pred][node]["allowed"] = False
                for succ in list(g.successors(node)):
                    g[node][succ]["allowed"] = False

    # Greedy selection of actions to protect maximum critical assets with minimum cost
    simulated_graph = graph.copy()
    current_critical = set(init_critical)
    chosen_actions = []
    remaining_candidates = list(candidate_actions)

    while current_critical and remaining_candidates:
        best_candidate = None
        best_protected_count = 0
        best_efficiency = -1.0
        best_new_critical = None

        for cand in remaining_candidates:
            # Test candidate on a scratch copy of the currently simulated graph
            test_g = simulated_graph.copy()
            apply_action(test_g, cand)

            test_dist, _ = bfs_reachability_with_distances(test_g, compromised_device)
            test_reachable = set(test_dist.keys())
            test_critical = {
                n for n in test_reachable
                if n != compromised_device and test_g.nodes[n].get("criticality", 1) >= critical_threshold
            }

            protected_critical = current_critical - test_critical
            protected_count = len(protected_critical)

            if protected_count > 0:
                # efficiency = protected_count / cost
                efficiency = protected_count / max(0.1, cand["cost"])
                if efficiency > best_efficiency:
                    best_efficiency = efficiency
                    best_candidate = cand
                    best_protected_count = protected_count
                    best_new_critical = test_critical

        if best_candidate and best_protected_count > 0:
            apply_action(simulated_graph, best_candidate)
            protected_now = current_critical - best_new_critical
            best_candidate["protected_assets"] = sorted(list(protected_now))
            best_candidate["efficiency_score"] = round(best_efficiency, 2)
            chosen_actions.append(best_candidate)
            remaining_candidates.remove(best_candidate)
            current_critical = best_new_critical
        else:
            # No single remaining action can reduce critical asset exposure further
            break

    # Final verification on simulated graph
    final_dist, _ = bfs_reachability_with_distances(simulated_graph, compromised_device)
    final_reachable = set(final_dist.keys())
    remaining_critical = {
        n for n in final_reachable
        if n != compromised_device and simulated_graph.nodes[n].get("criticality", 1) >= critical_threshold
    }
    protected_critical_assets = sorted(list(init_critical - remaining_critical))

    return {
        "compromised_device": compromised_device,
        "original_exposed_critical_count": len(init_critical),
        "remaining_exposed_critical_count": len(remaining_critical),
        "protected_critical_assets": protected_critical_assets,
        "remaining_exposed_critical_assets": sorted(list(remaining_critical)),
        "remaining_reachable_devices": sorted(list(final_reachable)),
        "recommended_actions": chosen_actions,
        "explanation": (
            f"Recommended {len(chosen_actions)} containment action(s). "
            f"Successfully protected {len(protected_critical_assets)} out of {len(init_critical)} critical asset(s) "
            f"while evaluating alternative paths and disruption costs."
        ),
    }


def analyze_containment_impact(
    graph: nx.DiGraph,
    compromised_device: str,
    critical_threshold: int = 4,
    actions_to_apply: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Compares network exposure before and after simulated containment.
    Does NOT mutate the input graph.
    """
    if compromised_device not in graph:
        raise ValueError(f"Device '{compromised_device}' does not exist")

    # 1. Before stats
    before_risk = calculate_risk_scores(graph, compromised_device)
    before_reach_dist, _ = bfs_reachability_with_distances(graph, compromised_device)
    before_reachable = sorted(list(before_reach_dist.keys()))
    before_critical = [
        r["device_id"] for r in before_risk if r["criticality"] >= critical_threshold
    ]
    before_total_risk = round(sum(r["risk_score"] for r in before_risk), 2)

    before_ap_analysis = analyze_attack_paths(graph, compromised_device, critical_threshold=critical_threshold)
    before_attack_paths = before_ap_analysis.get("attack_paths", [])

    # 2. Determine actions
    if actions_to_apply is None:
        containment_rec = recommend_containment(graph, compromised_device, critical_threshold)
        actions_to_apply = containment_rec["recommended_actions"]
    else:
        containment_rec = None

    # 3. Simulate containment on a fresh copy
    sim_graph = graph.copy()
    disruption_cost_total = 0.0

    for act in actions_to_apply:
        action_type = act.get("action_type")
        cost = float(act.get("cost", 1.0))
        disruption_cost_total += cost

        if action_type == "block_connection":
            src = act.get("source")
            tgt = act.get("target")
            if src and tgt and sim_graph.has_edge(src, tgt):
                sim_graph[src][tgt]["allowed"] = False
        elif action_type == "isolate_device":
            node = act.get("target_device")
            if node and node in sim_graph:
                for pred in list(sim_graph.predecessors(node)):
                    sim_graph[pred][node]["allowed"] = False
                for succ in list(sim_graph.successors(node)):
                    sim_graph[node][succ]["allowed"] = False

    # 4. After stats
    after_reach_dist, _ = bfs_reachability_with_distances(sim_graph, compromised_device)
    after_reachable = sorted(list(after_reach_dist.keys()))
    after_risk = calculate_risk_scores(sim_graph, compromised_device)
    after_critical = [
        r["device_id"] for r in after_risk if r["criticality"] >= critical_threshold
    ]
    after_total_risk = round(sum(r["risk_score"] for r in after_risk), 2)

    after_ap_analysis = analyze_attack_paths(sim_graph, compromised_device, critical_threshold=critical_threshold)
    after_attack_paths = after_ap_analysis.get("attack_paths", [])

    no_longer_reachable = sorted(list(set(before_reachable) - set(after_reachable)))
    protected_critical = sorted(list(set(before_critical) - set(after_critical)))

    risk_reduction_abs = round(max(0.0, before_total_risk - after_total_risk), 2)
    if before_total_risk > 0:
        risk_reduction_pct = round((risk_reduction_abs / before_total_risk) * 100.0, 2)
    else:
        risk_reduction_pct = 0.0

    return {
        "compromised_device": compromised_device,
        "original_reachable_devices": before_reachable,
        "remaining_reachable_devices": after_reachable,
        "original_exposed_critical_assets": before_critical,
        "remaining_exposed_critical_assets": after_critical,
        "assets_no_longer_reachable": no_longer_reachable,
        "protected_critical_assets": protected_critical,
        "original_total_risk_score": before_total_risk,
        "remaining_total_risk_score": after_total_risk,
        "absolute_risk_reduction": risk_reduction_abs,
        "percentage_risk_reduction": risk_reduction_pct,
        "containment_actions_applied": actions_to_apply,
        "total_disruption_cost": round(disruption_cost_total, 2),
        "residual_critical_exposed": after_critical,
        # Service & Attack Path Impact context
        "original_attack_paths_count": len(before_attack_paths),
        "remaining_attack_paths_count": len(after_attack_paths),
        "eliminated_attack_paths_count": max(0, len(before_attack_paths) - len(after_attack_paths)),
    }


# -------------------------------------------------------------------------
# Service Reachability & Vulnerability Attack Path Analysis
# -------------------------------------------------------------------------

def analyze_service_reachability(
    graph: nx.DiGraph,
    compromised_device: str,
) -> Dict[str, Any]:
    """
    Evaluates potential reachability to all services configured across network devices
    starting from the compromised_device via allowed network paths.

    Separates:
      - Device reachability (topology traversal)
      - Port/Protocol exposure (inbound edge policy and port alignment)
      - Policy status ('allowed', 'unknown', 'denied')
      - Traffic observation (observed vs permitted)
      - Vulnerability evidence (never assumed solely from reachability)
    """
    if compromised_device not in graph:
        raise ValueError(f"Device '{compromised_device}' does not exist")

    distances, parent = bfs_reachability_with_distances(graph, compromised_device)

    reachable_services: List[Dict[str, Any]] = []
    total_services_exposed = 0
    services_with_vulns = 0

    for dev_id in sorted(graph.nodes):
        if dev_id == compromised_device:
            continue

        dev_data = graph.nodes[dev_id]
        services = dev_data.get("services", []) or []
        dev_vulns = dev_data.get("vulnerabilities", []) or []

        is_dev_reachable = dev_id in distances

        # Build path to device if reachable
        path_to_dev: List[str] = []
        hops = distances.get(dev_id, 0)
        if is_dev_reachable:
            curr: Optional[str] = dev_id
            while curr is not None:
                path_to_dev.append(curr)
                curr = parent.get(curr)
            path_to_dev.reverse()

        # Inbound edge policy on the final hop (if reachable)
        final_edge_policy = "denied"
        final_edge_observed = False
        final_edge_port = None
        if is_dev_reachable and len(path_to_dev) >= 2:
            pred = path_to_dev[-2]
            if graph.has_edge(pred, dev_id):
                edge_d = graph[pred][dev_id]
                final_edge_policy = edge_d.get("policy_status", "allowed" if edge_d.get("allowed", False) else "denied")
                final_edge_observed = bool(edge_d.get("observed", False))
                final_edge_port = edge_d.get("port")

        for s in services:
            s_name = s.get("name", "unknown")
            s_port = int(s.get("port", 0))
            s_proto = str(s.get("protocol", "tcp")).lower()
            s_ver = s.get("version")

            # Determine whether inbound link permits this specific service port
            # If inbound link specifies a port and it does not match, service is restricted at network layer
            port_matches = True
            if final_edge_port is not None and final_edge_port != s_port:
                port_matches = False

            service_reachable = is_dev_reachable and port_matches

            # Correlate vulnerabilities matching this service port or general device
            matching_vulns = [
                v for v in dev_vulns
                if v.get("service_port") is None or v.get("service_port") == s_port
            ]

            # Explanation
            if not is_dev_reachable:
                explanation = f"Target host {dev_id} is not reachable via any allowed path from {compromised_device}."
            elif not port_matches:
                explanation = (
                    f"Host {dev_id} is reachable via path {' -> '.join(path_to_dev)}, but the inbound link from "
                    f"{path_to_dev[-2]} specifies port {final_edge_port}, restricting access to service port {s_port}."
                )
            else:
                obs_note = " historically observed in traffic logs" if final_edge_observed else " not observed in captured traffic"
                pol_note = f"policy status: '{final_edge_policy}'"
                explanation = (
                    f"Service '{s_name}' on port {s_port}/{s_proto} is reachable via {' -> '.join(path_to_dev)} "
                    f"({hops} hop(s), {pol_note},{obs_note})."
                )

            item = {
                "target_device": dev_id,
                "target_device_name": dev_data.get("name", dev_id),
                "service_name": s_name,
                "port": s_port,
                "protocol": s_proto,
                "version": s_ver,
                "hops": hops if service_reachable else -1,
                "path": path_to_dev if service_reachable else [],
                "reachable": service_reachable,
                "connection_policy_status": final_edge_policy if service_reachable else "denied",
                "connection_observed": final_edge_observed if service_reachable else False,
                "status_explanation": explanation,
                "vulnerabilities": matching_vulns,
            }

            reachable_services.append(item)
            if service_reachable:
                total_services_exposed += 1
                if matching_vulns:
                    services_with_vulns += 1

    return {
        "compromised_device": compromised_device,
        "reachable_services": reachable_services,
        "total_services_exposed": total_services_exposed,
        "services_with_vulnerabilities": services_with_vulns,
    }


def find_all_allowed_simple_paths(
    graph: nx.DiGraph,
    source: str,
    target: str,
    max_hops: int = 6,
) -> List[List[str]]:
    """
    Finds simple directed paths from source to target where every edge has allowed == True.
    Bounded by max_hops to avoid exponential path explosions.
    """
    allowed_subgraph = nx.DiGraph()
    for u, v, data in graph.edges(data=True):
        if data.get("allowed", False):
            allowed_subgraph.add_edge(u, v, **data)

    for node, data in graph.nodes(data=True):
        if node not in allowed_subgraph:
            allowed_subgraph.add_node(node, **data)

    if not allowed_subgraph.has_node(source) or not allowed_subgraph.has_node(target):
        return []

    try:
        paths = list(nx.all_simple_paths(allowed_subgraph, source=source, target=target, cutoff=max_hops))
        # Sort paths by length (shortest first)
        paths.sort(key=lambda p: len(p))
        return paths
    except Exception:
        return []


def analyze_attack_paths(
    graph: nx.DiGraph,
    compromised_device: str,
    critical_threshold: int = 4,
    max_hops: int = 6,
) -> Dict[str, Any]:
    """
    Discovers, evaluates, and ranks potential attack paths from the compromised_device
    to all critical assets (criticality >= critical_threshold).

    Combines:
      - Network topology reachability (allowed simple paths)
      - Service exposure along each hop
      - Vulnerability evidence (CVSS, known exploits, confidence)
      - Policy certainty (flags unknown policies as speculative)
      - Transparent explainability for each step and path
    """
    if compromised_device not in graph:
        raise ValueError(f"Device '{compromised_device}' does not exist")

    # 1. Identify critical targets
    critical_targets = [
        node for node, data in graph.nodes(data=True)
        if node != compromised_device and data.get("criticality", 1) >= critical_threshold
    ]

    all_path_results: List[Dict[str, Any]] = []
    reachable_critical_assets: Set[str] = set()

    path_counter = 1

    for target in sorted(critical_targets):
        candidate_paths = find_all_allowed_simple_paths(graph, compromised_device, target, max_hops=max_hops)

        for path in candidate_paths:
            reachable_critical_assets.add(target)
            target_data = graph.nodes[target]

            step_details: List[Dict[str, Any]] = []
            vulns_along_path: List[Dict[str, Any]] = []
            missing_or_uncertain_evidence: List[str] = []

            # Scoring factors
            path_feasible = True
            feasibility_penalty = 0.0
            high_confidence_exploit_count = 0

            for i in range(len(path) - 1):
                u = path[i]
                v = path[i + 1]
                edge_data = graph[u][v]
                v_data = graph.nodes[v]

                pol_status = edge_data.get("policy_status", "allowed" if edge_data.get("allowed", False) else "denied")
                observed = bool(edge_data.get("observed", False))
                proto = edge_data.get("protocol", "tcp")
                port = edge_data.get("port")

                # Inspect services and vulnerabilities on the destination node of this hop
                services = v_data.get("services", []) or []
                vulns = v_data.get("vulnerabilities", []) or []

                # Find relevant service
                target_service = None
                if port is not None:
                    target_service = next((s for s in services if s.get("port") == port), None)
                elif services:
                    target_service = services[0]

                # Match vulnerabilities applicable to this service/port
                relevant_vulns = []
                for vuln in vulns:
                    v_port = vuln.get("service_port")
                    if v_port is None or (port is not None and v_port == port) or (target_service and v_port == target_service.get("port")):
                        relevant_vulns.append(vuln)

                # Determine action type, vulnerability used, and evidence status
                best_vuln = None
                if relevant_vulns:
                    # Pick most severe vulnerability
                    best_vuln = max(
                        relevant_vulns,
                        key=lambda x: (
                            1 if x.get("exploit_available") else 0,
                            float(x.get("cvss_score") or 0.0)
                        )
                    )
                    vulns_along_path.append(best_vuln)

                # Determine evidence and feasibility penalty
                if pol_status == "unknown":
                    evidence_status = "speculative_policy_unknown"
                    feasibility_penalty += 20.0
                    missing_or_uncertain_evidence.append(
                        f"Hop {u} -> {v}: Firewall policy status is unconfirmed ('unknown')."
                    )
                elif not observed:
                    evidence_status = "probable"
                    missing_or_uncertain_evidence.append(
                        f"Hop {u} -> {v}: Connection is permitted by policy but has no observed traffic in Zeek logs."
                    )
                else:
                    evidence_status = "confirmed"

                if best_vuln:
                    if best_vuln.get("exploit_available"):
                        action_type = "service_exploit"
                        high_confidence_exploit_count += 1
                        rationale = (
                            f"Adversary exploits {best_vuln.get('id', 'vulnerability')} ({best_vuln.get('title')}) "
                            f"on {v} ({target_service.get('name', 'service') if target_service else 'port ' + str(port)}). "
                            f"Public exploit is verified available."
                        )
                    else:
                        action_type = "potential_exploit"
                        feasibility_penalty += 10.0
                        rationale = (
                            f"Known vulnerability {best_vuln.get('id')} exists on {v}, but public exploit is not confirmed. "
                            f"Compromise may require custom weaponization or credential reuse."
                        )
                        missing_or_uncertain_evidence.append(
                            f"Hop {u} -> {v}: {best_vuln.get('id')} has no confirmed public exploit evidence."
                        )
                else:
                    action_type = "lateral_traversal"
                    feasibility_penalty += 15.0
                    rationale = (
                        f"Adversary traverses allowed link {u} -> {v} via {proto}"
                        + (f":{port}" if port else "")
                        + ". No specific CVE documented; lateral movement relies on stolen credentials or configuration weakness."
                    )
                    missing_or_uncertain_evidence.append(
                        f"Hop {u} -> {v}: No specific vulnerability finding registered on target service; attack assumes credential or protocol abuse."
                    )

                hop_detail = {
                    "from_device": u,
                    "to_device": v,
                    "via_protocol": proto,
                    "via_port": port,
                    "policy_status": pol_status,
                    "observed": observed,
                    "action_type": action_type,
                    "vulnerability_used": best_vuln,
                    "rationale": rationale,
                    "evidence_status": evidence_status,
                }
                step_details.append(hop_detail)

            # Compute feasibility score: base 100 minus length decay and penalties
            hop_decay = (len(path) - 1) * 5.0
            calculated_score = max(5.0, 100.0 - hop_decay - feasibility_penalty + (high_confidence_exploit_count * 5.0))
            calculated_score = min(98.0, round(calculated_score, 1))

            if calculated_score >= 70.0:
                feasibility_level = "high"
            elif calculated_score >= 45.0:
                feasibility_level = "medium"
            elif calculated_score >= 20.0:
                feasibility_level = "low"
            else:
                feasibility_level = "unlikely"

            # Construct transparent why_possible narrative
            why_possible_parts = [
                f"Path involves {len(path) - 1} network hop(s) over permitted connections ({' -> '.join(path)})."
            ]
            if high_confidence_exploit_count > 0:
                why_possible_parts.append(
                    f"{high_confidence_exploit_count} hop(s) correlate with high-confidence exploitable vulnerabilities."
                )
            if any(h["evidence_status"] == "speculative_policy_unknown" for h in step_details):
                why_possible_parts.append("Contains unverified firewall policies that require confirmation.")
            why_possible = " ".join(why_possible_parts)

            path_id = f"path-{compromised_device}-to-{target}-{path_counter}"
            path_counter += 1

            all_path_results.append({
                "path_id": path_id,
                "target_device": target,
                "target_device_name": target_data.get("name", target),
                "target_criticality": target_data.get("criticality", 1),
                "path": path,
                "hops_count": len(path) - 1,
                "feasible": path_feasible,
                "feasibility_score": calculated_score,
                "feasibility_level": feasibility_level,
                "vulnerabilities_exploitable_count": high_confidence_exploit_count,
                "vulnerabilities_along_path": vulns_along_path,
                "step_details": step_details,
                "why_possible": why_possible,
                "missing_or_uncertain_evidence": missing_or_uncertain_evidence,
            })

    # Sort attack paths by feasibility score (highest threat first) and target criticality
    all_path_results.sort(
        key=lambda p: (
            -p["target_criticality"],
            -p["feasibility_score"],
            p["hops_count"]
        )
    )

    summary_text = (
        f"Identified {len(all_path_results)} potential attack path(s) originating from '{compromised_device}' "
        f"to {len(reachable_critical_assets)} critical asset(s) (criticality >= {critical_threshold})."
    )

    return {
        "compromised_device": compromised_device,
        "critical_threshold": critical_threshold,
        "attack_paths": all_path_results,
        "total_attack_paths": len(all_path_results),
        "critical_assets_reachable": sorted(list(reachable_critical_assets)),
        "summary": summary_text,
    }