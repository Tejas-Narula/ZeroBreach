from fastapi import FastAPI, HTTPException, Query, status
from typing import Optional, List
import networkx as nx

from network import (
    create_demo_network,
    serialize_network,
    add_device_to_graph,
    update_device_in_graph,
    remove_device_from_graph,
    add_connection_to_graph,
    update_connection_in_graph,
    remove_connection_from_graph,
)
from algorithms import (
    find_reachable_devices,
    find_path,
    calculate_risk_scores,
    analyze_reachability_multi,
    find_critical_assets,
    recommend_containment,
    analyze_containment_impact,
)
from schemas import (
    DeviceCreateRequest,
    DeviceUpdateRequest,
    ConnectionCreateRequest,
    ConnectionUpdateRequest,
    MultiDeviceAnalysisRequest,
    ContainmentSimulationRequest,
)

app = FastAPI(
    title="Network Attack Impact Analyzer API",
    description="Defensive network simulation tool modeling attack blast radius, risk ranking, containment recommendations, and before/after impact comparison.",
    version="1.0.0",
)

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory graph state initialized on application start
graph = create_demo_network()


# -------------------------------------------------------------------------
# Health & Network Inspection
# -------------------------------------------------------------------------

@app.get("/", tags=["General"])
def home():
    return {
        "message": "Network Attack Impact Analyzer API is running",
        "version": "1.0.0",
        "endpoints": {
            "health": "/health",
            "network": "/network",
            "docs": "/docs",
        },
    }


@app.get("/health", tags=["General"])
def health():
    return {
        "status": "ok",
        "nodes_count": graph.number_of_nodes(),
        "edges_count": graph.number_of_edges(),
    }


@app.get("/network", tags=["Network Model"])
def get_network():
    """Returns the current state of devices and connections."""
    return serialize_network(graph)


@app.post("/network/reset", tags=["Network Model"])
def reset_network():
    """Resets the network back to the original clean demo state."""
    global graph
    graph = create_demo_network()
    return {
        "message": "Network reset to demo state successfully",
        "network": serialize_network(graph),
    }


@app.post("/network/clear", tags=["Network Model"])
def clear_network():
    """Clears all nodes and edges from the network, providing a genuinely empty network."""
    global graph
    graph = nx.DiGraph()
    return {
        "message": "Network cleared successfully",
        "network": serialize_network(graph),
    }


# -------------------------------------------------------------------------
# Network Modification (CRUD)
# -------------------------------------------------------------------------

@app.post("/network/devices", status_code=status.HTTP_201_CREATED, tags=["Network Model"])
def add_device(payload: DeviceCreateRequest):
    try:
        device_data = payload.model_dump()
        added = add_device_to_graph(graph, device_data)
        return {"message": "Device added successfully", "device": added}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@app.patch("/network/devices/{device_id}", tags=["Network Model"])
def update_device(device_id: str, payload: DeviceUpdateRequest):
    try:
        updates = payload.model_dump(exclude_unset=True)
        updated = update_device_in_graph(graph, device_id, updates)
        return {"message": "Device updated successfully", "device": updated}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND if "does not exist" in str(e) else status.HTTP_400_BAD_REQUEST, detail=str(e))


@app.delete("/network/devices/{device_id}", tags=["Network Model"])
def delete_device(device_id: str):
    try:
        remove_device_from_graph(graph, device_id)
        return {"message": f"Device '{device_id}' deleted successfully"}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@app.post("/network/connections", status_code=status.HTTP_201_CREATED, tags=["Network Model"])
def add_connection(payload: ConnectionCreateRequest):
    try:
        data = payload.model_dump()
        added = add_connection_to_graph(
            graph,
            source=data["source"],
            target=data["target"],
            protocol=data["protocol"],
            allowed=data["allowed"],
            business_critical=data["business_critical"],
            disruption_cost=data["disruption_cost"],
        )
        return {"message": "Connection added successfully", "connection": added}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@app.patch("/network/connections/{source}/{target}", tags=["Network Model"])
def update_connection(source: str, target: str, payload: ConnectionUpdateRequest):
    try:
        updates = payload.model_dump(exclude_unset=True)
        updated = update_connection_in_graph(graph, source, target, updates)
        return {"message": "Connection updated successfully", "connection": updated}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND if "does not exist" in str(e) else status.HTTP_400_BAD_REQUEST, detail=str(e))


@app.delete("/network/connections/{source}/{target}", tags=["Network Model"])
def delete_connection(source: str, target: str):
    try:
        remove_connection_from_graph(graph, source, target)
        return {"message": f"Connection from '{source}' to '{target}' deleted successfully"}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


# -------------------------------------------------------------------------
# Analysis & Traversal Endpoints
# -------------------------------------------------------------------------

@app.get("/analyze/{device_id}", tags=["Analysis"])
def analyze_device(device_id: str):
    """Calculates all devices reachable via allowed directed connections from a compromised starting device."""
    try:
        reachable = find_reachable_devices(graph, device_id)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))

    return {
        "compromised_device": device_id,
        "reachable_devices": sorted(reachable),
        "reachable_count": len(reachable) - 1,
    }


@app.post("/analyze/multi", tags=["Analysis"])
def analyze_multiple_devices(payload: MultiDeviceAnalysisRequest):
    """Calculates blast radius exposure when multiple devices are simultaneously compromised."""
    try:
        analysis = analyze_reachability_multi(graph, payload.compromised_devices)
        return analysis
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))


@app.get("/path/{source}/{target}", tags=["Analysis"])
def get_path(source: str, target: str):
    """Finds the shortest allowed directed path between two devices."""
    try:
        path = find_path(graph, source, target)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))

    if path is None:
        return {
            "source": source,
            "target": target,
            "reachable": False,
            "path": [],
            "hops": 0,
        }

    return {
        "source": source,
        "target": target,
        "reachable": True,
        "path": path,
        "hops": len(path) - 1,
    }


@app.get("/risk/{device_id}", tags=["Analysis"])
def get_risk_scores(device_id: str):
    """Calculates deterministic, explainable risk ranking for assets exposed from a compromised device."""
    try:
        results = calculate_risk_scores(graph, device_id)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))

    return {
        "compromised_device": device_id,
        "results": results,
    }


@app.get("/critical-assets/{device_id}", tags=["Analysis"])
def get_critical_assets(
    device_id: str,
    threshold: int = Query(default=4, ge=1, le=5, description="Criticality threshold (default 4)"),
):
    """Identifies critical assets exposed from the compromised device with shortest paths and hop counts."""
    thresh_val = threshold.default if hasattr(threshold, "default") else threshold
    thresh_val = int(thresh_val)
    try:
        assets = find_critical_assets(graph, device_id, threshold=thresh_val)
        return {
            "compromised_device": device_id,
            "threshold": thresh_val,
            "critical_assets": assets,
            "count": len(assets),
        }
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))


# -------------------------------------------------------------------------
# Containment & Impact Analysis Endpoints
# -------------------------------------------------------------------------

@app.get("/containment/{device_id}", tags=["Containment"])
def get_containment_recommendation(
    device_id: str,
    critical_threshold: int = Query(default=4, ge=1, le=5, description="Asset criticality threshold"),
):
    """
    Evaluates attack blast radius, considers alternative paths, and recommends
    cost-effective containment actions (connection blocks or device isolation) to protect critical assets.
    """
    thresh_val = critical_threshold.default if hasattr(critical_threshold, "default") else critical_threshold
    thresh_val = int(thresh_val)
    try:
        recommendations = recommend_containment(graph, device_id, critical_threshold=thresh_val)
        return recommendations
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))


@app.post("/containment/simulate", tags=["Containment"])
def simulate_containment_impact(payload: ContainmentSimulationRequest):
    """
    Simulates containment actions on a graph copy and provides before-and-after impact analysis.
    Does not mutate the active network.
    """
    try:
        impact = analyze_containment_impact(
            graph,
            compromised_device=payload.compromised_device,
            critical_threshold=int(payload.critical_threshold),
            actions_to_apply=payload.custom_actions,
        )
        return impact
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))


@app.get("/containment/impact/{device_id}", tags=["Containment"])
def get_containment_impact(
    device_id: str,
    critical_threshold: int = Query(default=4, ge=1, le=5, description="Asset criticality threshold"),
):
    """
    Convenience GET endpoint providing before-and-after impact comparison using the recommended containment actions.
    """
    thresh_val = critical_threshold.default if hasattr(critical_threshold, "default") else critical_threshold
    thresh_val = int(thresh_val)
    try:
        impact = analyze_containment_impact(
            graph,
            compromised_device=device_id,
            critical_threshold=thresh_val,
        )
        return impact
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))
