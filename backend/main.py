
from fastapi import FastAPI
from network import create_demo_network

from algorithms import find_reachable_devices

app = FastAPI(title="Network Attack Impact Analyzer")

graph = create_demo_network()


@app.get("/")
def home():
    return {"message": "Network Attack Impact Analyzer API is running"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/network")
def get_network():
    return {
        "nodes": [
            data for _, data in graph.nodes(data=True)
        ],
        "edges": [
            {
                "source": source,
                "target": target,
                **data,
            }
            for source, target, data in graph.edges(data=True)
        ],
    }


@app.get("/analyze/{device_id}")
def analyze_device(device_id: str):
    try:
        reachable = find_reachable_devices(graph, device_id)
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error))

    return {
        "compromised_device": device_id,
        "reachable_devices": sorted(reachable),
        "reachable_count": len(reachable) - 1,
    }