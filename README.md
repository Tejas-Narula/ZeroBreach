# Network Attack Impact Analyzer (NAIA)

A defensive network simulation, topology analytics, and attack path engine built with **FastAPI**, **NetworkX**, and **React (Cytoscape.js)**.

NAIA models enterprise network topology as a directed graph, simulates compromised entry points (patient zero), traces network blast radii, evaluates service exposure and known vulnerability findings, calculates attack path feasibility, and recommends cost-effective containment actions while minimizing business disruption.

---

## Key Capabilities

- **Realistic Network Device & Topology Modeling**:
  - Major device categories: `endpoint`, `server`, `database`, `network_device`, `firewall`, `wireless_access_point`, `cloud_infrastructure`, `security_system`, `iot_device`, `external`, and `unknown`.
  - Rich node attributes: `id`, `name`, `type`, `criticality` (1–5 scale), `zone`, `inferred_role`, `hostname`, `ip_addresses`, `services`, `vulnerabilities`, `manual_override`, `discovery_source`.
  - Directed links with protocol, port, policy status (`allowed`, `denied`, `unknown`), observation state, business criticality, and disruption cost.

- **Automatic Criticality Recommendation**:
  - Transparent, explainable 1–5 asset criticality scoring based on device category, network zone, operational role, exposure, and topology depth.
  - Generates clear rationale, confidence level (`high`, `medium`, `low`, `provisional`), and explicit missing-information checklists.
  - Respects manual override locks so operator decisions are never overwritten unexpectedly.

- **Service-Aware Reachability**:
  - Models listening services on devices (`name`, `port`, `protocol`, `version`, `banner`, `status`).
  - Evaluates host-to-service reachability across allowed directed paths, enforcing network-layer port restrictions when inbound edges specify particular destination ports.
  - Distinctly decouples *permitted policy*, *observed traffic*, *service exposure*, and *vulnerability presence* (never assumes reachability implies vulnerability or observed traffic implies authorization).

- **Vulnerability-Based Attack Path Analysis**:
  - Discovers and evaluates multi-hop attack paths from patient zero to critical assets.
  - Correlates vulnerabilities (CVE, severity, CVSS, exploit availability, evidence confidence, CWE) to exposed services along each hop.
  - Computes transparent **Feasibility Scores** ($0 - 100\%$) and classifies paths into `high`, `medium`, `low`, or `unlikely`.
  - Differentiates confirmed exploits (`service_exploit`), potential exploits, and credentialed lateral movement (`lateral_traversal`).
  - Penalizes and explicitly flags uncertain firewall policies (`policy_status == "unknown"` $\rightarrow$ `speculative_policy_unknown`) and unobserved links.

- **Intelligent Containment & Impact Simulation**:
  - Evaluates edge blocking (`block_connection`) and device isolation (`isolate_device`).
  - Alternative path resilience: ensures all alternative pathways to critical assets are eliminated before declaring an asset protected.
  - Weighs business disruption costs to prevent disproportionate operational outages.
  - Side-effect-free before/after comparison on immutable graph copies, reporting percentage risk reduction, protected assets, and eliminated attack paths.

- **Zeek Connection Log Ingestion**:
  - Ingests Zeek `conn.log` files in TSV (with `#fields` header) or JSON format up to 50 MB / 50,000 records.
  - Validates IP addresses, normalizes protocols/ports, tentative device inference from service/port heuristics, and connection traffic counts.
  - Supports dry-run preview, non-destructive merging with existing networks, and clean network replacement.

- **Interactive Cytoscape.js Web Interface**:
  - Canvas drag-and-drop node palette, 2-click edge creation, and inline device/connection editors.
  - Real-time visual security badges: warning indicators (`⚠️`) with vulnerability counts and service gears (`⚙`).
  - Attack path highlighting: clicking an attack path highlights the complete multi-hop route on the canvas.
  - Interactive containment simulation toggles for testing operational mitigations.

---

## Architecture & Project Structure

```
DSA/
├── backend/
│   ├── algorithms.py         # BFS reachability, shortest paths, multi-hop attack paths,
│   │                         # service exposure analysis, risk scoring, containment engine
│   ├── criticality.py        # Explainable asset criticality recommendation engine
│   ├── network.py            # Graph models, demo network, node/edge CRUD, validation, serialization
│   ├── zeek_parser.py        # Zeek conn.log parser (TSV & JSON), aggregation, candidate graph builder
│   ├── schemas.py            # Pydantic models for devices, connections, services, vulnerabilities,
│   │                         # attack paths, containment, and Zeek import
│   ├── main.py               # FastAPI application, route handlers, error handling, CORS
│   ├── requirements.txt      # Python dependencies (FastAPI, NetworkX, Uvicorn, Pytest)
│   ├── tests/
│   │   ├── test_algorithms.py      # Traversal, multi-compromise, and risk ranking tests
│   │   ├── test_attack_paths.py    # Service reachability, port restrictions, attack paths, containment tests
│   │   ├── test_network.py         # Network CRUD, validation, and demo graph tests
│   │   └── test_zeek_ingestion.py  # Zeek parser, TSV/JSON import, preview, and merge tests
│   └── venv/                 # Python virtual environment
├── frontend/                 # React 18 + Vite SPA
│   ├── src/
│   │   ├── api.js                     # REST API client
│   │   ├── App.jsx                    # Root state management, canvas workspace, and sidebars
│   │   ├── components/
│   │   │   ├── NetworkGraph.jsx       # Cytoscape.js interactive topology renderer
│   │   │   ├── NetworkEditor.jsx      # Device/Connection editor with services & CVE managers
│   │   │   ├── ResultsPanel.jsx       # Attack paths, exposed services, and risk ranking
│   │   │   ├── ContainmentPanel.jsx   # Recommended actions, toggles, and impact simulation
│   │   │   ├── AnalysisStatsSidebar.jsx # Blast radius, aggregate risk, and attack path metrics
│   │   │   ├── DevicePalette.jsx      # Drag-and-drop device template drawer
│   │   │   ├── ZeekImportModal.jsx    # Log upload, preview, and merge modal
│   │   │   └── ui.jsx                 # Reusable UI primitives (tables, badges, cards)
│   │   └── index.css
│   ├── package.json
│   └── vite.config.js
├── ZEEK_INGESTION_GUIDE.md   # Practical guide for importing Zeek conn.log files
└── README.md                 # Project documentation
```

---

## Getting Started

### 1. Prerequisites
- **Python 3.10+** (tested on Python 3.13)
- **Node.js 18+** & **npm**

---

### 2. Backend Setup

From the repository root:

```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1    # On Linux/macOS: source venv/bin/activate
pip install -r requirements.txt
```

#### Run the Backend Server
```powershell
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```
- API Base URL: `http://127.0.0.1:8000`
- Interactive OpenAPI Docs (Swagger UI): `http://127.0.0.1:8000/docs`
- Alternative API Documentation (ReDoc): `http://127.0.0.1:8000/redoc`

#### Run the Backend Test Suite
```powershell
python -m pytest tests
```

---

### 3. Frontend Setup

In a new terminal window:

```powershell
cd frontend
npm install
npm run dev
```

- Web UI: `http://localhost:5173`

To build the production bundle:
```powershell
npm run build
```

---

## Demo Network Topology

The built-in demo topology represents an enterprise DMZ and internal segment:

```
[laptop_1] (Endpoint · Criticality: 1 · Zone: employee)
    │ (HTTPS / 443, allowed: True)
    ▼
  [web_1]   (Server · Criticality: 3 · Zone: dmz)
            • Services: HTTPS :443 (nginx/1.22.0), HTTP :80
            • Vulns: CVE-2022-41741 (CVSS 7.8, Exploit: Yes)
    │ (HTTPS / 8443, allowed: True, business_critical: True)
    ▼
  [app_1]   (Server · Criticality: 4 · Zone: internal)
            • Services: HTTPS :8443 (Express API), SSH :22
            • Vulns: CVE-2023-38606 (CVSS 9.8, Exploit: Yes)
    ├───(SQL / 3306, allowed: True, business_critical: True)───► [db_1] (Database · Crit: 5 · Zone: restricted)
    │                                                              • Services: MySQL :3306 (8.0.32)
    │                                                              • Vulns: CVE-2023-21980 (CVSS 7.5)
    └───(SSH / 22, allowed: True)───► [backup_1] (Server · Crit: 4)─┘ (SQL / 3306, allowed: True)
```

---

## API Reference Overview

### Network Model & Lifecycle

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Health check, active node and edge counts |
| `GET` | `/network` | Full serialized graph topology with node services and vulnerabilities |
| `POST` | `/network/reset` | Resets graph back to the default demo network |
| `POST` | `/network/clear` | Clears all nodes and connections |
| `POST` | `/network/preview` | Dry-run validation of candidate records without mutating state |
| `POST` | `/network/replace` | Replaces active graph with validated candidate nodes and edges |
| `POST` | `/network/import/zeek` | Ingests Zeek `conn.log` file (TSV or JSON) with preview or replace |

### Device & Connection CRUD

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/network/devices` | Adds a device with services, vulnerabilities, and criticality |
| `PATCH` | `/network/devices/{device_id}` | Updates device attributes, services, or vulnerabilities |
| `DELETE` | `/network/devices/{device_id}` | Removes device and all incident connections |
| `GET` | `/network/devices/{device_id}/criticality-recommendation` | Returns automatic criticality suggestion with explanation |
| `POST` | `/network/connections` | Adds a directed connection with protocol, port, and policy status |
| `PATCH` | `/network/connections/{source}/{target}` | Updates connection policy, allowed flag, or cost |
| `DELETE` | `/network/connections/{source}/{target}` | Deletes connection |

### Analysis & Attack Paths

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/analyze/{device_id}` | Reachable devices from patient zero via allowed connections |
| `POST` | `/analyze/multi` | Blast radius from multiple simultaneous compromised devices |
| `GET` | `/path/{source}/{target}` | Shortest allowed directed path with hop count |
| `GET` | `/risk/{device_id}` | Heuristic risk ranking for exposed assets |
| `GET` | `/critical-assets/{device_id}` | Exposed assets at or above criticality threshold |
| `GET` | `/analyze/services/{device_id}` | Evaluates device-to-service reachability and port exposure |
| `GET` | `/analyze/attack-paths/{device_id}` | Discovers multi-hop attack paths to critical assets with CVE correlation and feasibility scores |

### Containment & Simulation

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/containment/{device_id}` | Recommended connection blocks and device isolations |
| `GET` | `/containment/impact/{device_id}` | Before vs. after impact analysis using recommended actions |
| `POST` | `/containment/simulate` | Custom simulation of user-selected containment actions on graph copy |

---

## Core Algorithms & Math

1. **Breadth-First Search (BFS) Reachability**:
   $$\text{Distances}, \text{Predecessors} = \text{BFS}(G_{\text{allowed}}, \text{start\_device})$$
   Traverses only edges where `allowed == True` and `policy_status == "allowed"`.

2. **Transparent Risk Scoring**:
   $$\text{Risk}(v) = \text{round}\left( \frac{\text{criticality}(v)}{5.0} \times \frac{100}{\text{hops}(\text{start}, v)}, 2 \right)$$
   Bounded between 0 and 100. Purely deterministic and explainable without arbitrary black-box weights.

3. **Attack Path Feasibility Scoring**:
   $$\text{Score} = \min\left(98.0, \max\left(5.0, 100 - (\text{hops} \times 5.0) - P_{\text{penalty}} + (E_{\text{exploits}} \times 5.0)\right)\right)$$
   Where penalties apply for unverified firewall policies ($P_{\text{unknown}} = 20$), missing exploits ($P_{\text{unarmed}} = 10$), and lateral movement without vulnerability findings ($P_{\text{lateral}} = 15$).

4. **Containment Impact Evaluation**:
   $$\text{Risk Reduction \%} = \frac{\text{TotalRisk}_{\text{before}} - \text{TotalRisk}_{\text{after}}}{\text{TotalRisk}_{\text{before}}} \times 100$$
   Guarantees simulation safety via NetworkX graph duplication (`graph.copy()`).

---

## License

Academic / Educational Open Source (MIT License).
