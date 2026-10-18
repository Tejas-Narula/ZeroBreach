# Network Attack Impact Analyzer (NAIA)

A defensive network simulation and graph analytics engine built with **FastAPI**, **NetworkX**, and **Python**.

The tool models enterprise network topology as a directed graph, simulates compromised entry points (patient zero), traces attack blast radii, evaluates alternative attack paths, ranks exposed assets by deterministic risk heuristic, and recommends cost-effective containment actions while minimizing business disruption.

---

## Features

- **Directed Network Modeling**: Represents nodes with attributes (`id`, `name`, `type`, `criticality` 1–5, `zone`) and directed links (`protocol`, `allowed`, `business_critical`, `disruption_cost`).
- **Blast Radius Reachability (BFS)**: Computes all reachable downstream assets across allowed directed connections.
- **Multi-Compromise Analysis**: Analyzes simultaneous compromises across multiple entry points, accurately separating starting points from newly exposed downstream assets.
- **Shortest Attack Paths & Critical Asset Detection**: Identifies paths to high-value assets (criticality $\ge$ threshold) with hop counts.
- **Explainable Risk Scoring**: Deterministic, transparent heuristic scoring ($0 - 100$) combining asset criticality and hop distance decay ($R = \frac{\text{criticality}}{5} \times \frac{100}{\text{hops}}$).
- **Intelligent Containment Recommendation**:
  - Evaluates both edge blocking and device isolation actions.
  - Accounts for alternative pathways (an asset is only considered protected if **all** valid attack paths from the compromised node are severed).
  - Evaluates business disruption costs to prevent unnecessary or overly disruptive isolation.
- **Before-and-After Impact Simulation**: Compares original vs. contained state on graph copies (immutable network state), reporting risk reduction percentage and protected vs. residual exposed assets.
- **Dynamic Network Modification (CRUD)**: Endpoints to add, update, and remove devices and connections, plus a one-click reset to the clean demo network.

---

## Project Structure

```
DSA/
├── backend/
│   ├── algorithms.py       # BFS traversals, pathfinding, risk ranking, containment engine
│   ├── main.py             # FastAPI routes, error handling, state management
│   ├── network.py          # Demo network topology, graph validation, CRUD & serialization
│   ├── requirements.txt    # Python dependencies
│   ├── schemas.py          # Pydantic request and response models
│   ├── tests/
│   │   ├── test_algorithms.py
│   │   └── test_network.py
│   └── venv/               # Python virtual environment
├── frontend/               # React + Vite application (UI layer)
└── README.md               # Documentation
```

---

## Getting Started

### 1. Prerequisites
- Python 3.10+ (tested on Python 3.13)
- PowerShell or bash terminal

### 2. Setup Virtual Environment
From the project root:
```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 3. Run the Backend Server
```powershell
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```
- API Base URL: `http://127.0.0.1:8000`
- Interactive OpenAPI Docs (Swagger UI): `http://127.0.0.1:8000/docs`
- Alternative Docs (ReDoc): `http://127.0.0.1:8000/redoc`

### 4. Run the Test Suite
```powershell
python -m pytest
```

---

## Demo Network Topology

The built-in demo topology represents an enterprise segmentation scenario:

```
[laptop_1] (Criticality: 1, Zone: employee)
    │ (HTTPS, cost: 1.0)
    ▼
 [web_1]   (Criticality: 3, Zone: dmz)
    │ (HTTPS, cost: 2.0, business_critical: True)
    ▼
 [app_1]   (Criticality: 4, Zone: internal)
   ├───(SQL, cost: 3.0, business_critical: True)───► [db_1] (Criticality: 5, Zone: restricted)
   │                                                   ▲
   └───(SSH, cost: 1.5)───► [backup_1] (Crit: 4)───────┘ (SQL, cost: 2.5, business_critical: True)
```

---

## API Reference

### Health & Topology Inspection

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | API status and links |
| `GET` | `/health` | Healthcheck, total active node & edge count |
| `GET` | `/network` | Complete graph topology serialized as JSON `{nodes: [...], edges: [...]}` |
| `POST` | `/network/reset` | Resets graph back to the default 5-node demo network |

### Network Modification (CRUD)

| Method | Endpoint | Request Body | Description |
|---|---|---|---|
| `POST` | `/network/devices` | `DeviceCreateRequest` | Adds a new device to the network |
| `PATCH` | `/network/devices/{device_id}` | `DeviceUpdateRequest` | Modifies name, type, criticality, or zone |
| `DELETE` | `/network/devices/{device_id}` | None | Removes a device and incident connections |
| `POST` | `/network/connections` | `ConnectionCreateRequest` | Adds a directed connection |
| `PATCH` | `/network/connections/{source}/{target}` | `ConnectionUpdateRequest` | Modifies protocol, allowed, cost, etc. |
| `DELETE` | `/network/connections/{source}/{target}` | None | Deletes a directed connection |

#### Example: Add Device Payload
```json
{
  "id": "bastion_1",
  "name": "Jump Host Bastion",
  "type": "server",
  "criticality": 4,
  "zone": "dmz"
}
```

### Attack Blast Radius & Risk Analysis

| Method | Endpoint | Query / Body | Description |
|---|---|---|---|
| `GET` | `/analyze/{device_id}` | — | Reachable devices from compromised device |
| `POST` | `/analyze/multi` | `{"compromised_devices": [...]}` | Blast radius from multiple entry points |
| `GET` | `/path/{source}/{target}` | — | Shortest allowed directed path with hop count |
| `GET` | `/risk/{device_id}` | — | Ranked risk scores for reachable assets |
| `GET` | `/critical-assets/{device_id}` | `?threshold=4` | High-value reachable assets with paths |

#### Example: Multi-Device Analysis Request
```json
POST /analyze/multi
{
  "compromised_devices": ["laptop_1", "backup_1"]
}
```
**Response:**
```json
{
  "compromised_devices": ["laptop_1", "backup_1"],
  "combined_reachable_devices": ["app_1", "backup_1", "db_1", "laptop_1", "web_1"],
  "total_reachable_count": 5,
  "newly_exposed_devices": ["app_1", "db_1", "web_1"],
  "newly_exposed_count": 3,
  "per_device": {
    "laptop_1": {"reachable_devices": ["app_1", "backup_1", "db_1", "laptop_1", "web_1"], "reachable_count": 4},
    "backup_1": {"reachable_devices": ["backup_1", "db_1"], "reachable_count": 1}
  }
}
```

### Containment & Impact Simulation

| Method | Endpoint | Query / Body | Description |
|---|---|---|---|
| `GET` | `/containment/{device_id}` | `?critical_threshold=4` | Intelligent containment recommendations |
| `GET` | `/containment/impact/{device_id}` | `?critical_threshold=4` | Before vs. after impact analysis using recommended actions |
| `POST` | `/containment/simulate` | `ContainmentSimulationRequest` | Custom containment simulation without mutating the original network |

#### Example: Containment Impact Output
```json
GET /containment/impact/laptop_1
{
  "compromised_device": "laptop_1",
  "original_reachable_devices": ["app_1", "backup_1", "db_1", "laptop_1", "web_1"],
  "remaining_reachable_devices": ["laptop_1"],
  "original_exposed_critical_assets": ["app_1", "db_1", "backup_1"],
  "remaining_exposed_critical_assets": [],
  "assets_no_longer_reachable": ["app_1", "backup_1", "db_1", "web_1"],
  "protected_critical_assets": ["app_1", "backup_1", "db_1"],
  "original_total_risk_score": 160.0,
  "remaining_total_risk_score": 0.0,
  "absolute_risk_reduction": 160.0,
  "percentage_risk_reduction": 100.0,
  "containment_actions_applied": [
    {
      "action_type": "block_connection",
      "source": "laptop_1",
      "target": "web_1",
      "cost": 1.0,
      "description": "Block connection laptop_1 -> web_1 (HTTPS)",
      "protected_assets": ["app_1", "backup_1", "db_1"],
      "efficiency_score": 3.0
    }
  ],
  "total_disruption_cost": 1.0,
  "residual_critical_exposed": []
}
```

---

## Design Principles

1. **Defensive Network Simulation**: Graph mutations during containment calculations and simulations operate strictly on graph copies (`graph.copy()`), ensuring simulations are side-effect free.
2. **Deterministic & Explainable**: No opaque black-box machine learning models or arbitrary probabilistic claims. Risk scoring uses deterministic graph distance and asset criticality.
3. **Alternative Path Resilience**: Containment verification recalculates BFS reachability from patient zero to critical assets after each simulated action, preventing false claims of protection when secondary paths exist.
