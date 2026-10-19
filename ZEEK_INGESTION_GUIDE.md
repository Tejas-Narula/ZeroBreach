# Zeek Log Ingestion & Graph Analysis Guide

The Network Attack Impact Analyzer features an ingestion pipeline that imports Zeek (formerly Bro) network connection logs (`conn.log`) in both **TSV** and **JSON** formats, converting real-world telemetry into an attack graph for blast radius analysis and containment simulation.

---

## 1. Supported Formats & Required Fields

### TSV Logs
Standard Zeek tab-separated files with `#fields`, `#types`, and `#separator` directives:
```tsv
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2023-10-15-10-00-00
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state
#types	time	string	addr	port	addr	port	string	string	interval	count	count	string
1697364000.123456	C12345abc	192.168.1.50	51234	10.0.0.10	443	tcp	ssl	1.50	1200	4500	SF
1697364002.654321	C12346def	10.0.0.10	49201	10.0.0.25	3306	tcp	mysql	0.05	300	1200	SF
#close	2023-10-15-10-00-10
```

### JSON Logs
Accepts either newline-delimited JSON objects or a JSON array of record dictionaries:
```json
{"ts": 1697364010.0, "uid": "C99901", "id.orig_h": "172.16.1.10", "id.orig_p": 44100, "id.resp_h": "172.16.1.20", "id.resp_p": 22, "proto": "tcp", "service": "ssh", "conn_state": "SF"}
{"ts": 1697364012.0, "uid": "C99902", "id.orig_h": "172.16.1.20", "id.orig_p": 50100, "id.resp_h": "172.16.1.30", "id.resp_p": 5432, "proto": "tcp", "service": "postgresql", "conn_state": "SF"}
```
*(Nested `{"id": {"orig_h": ..., "resp_h": ...}}` formats are also supported).*

### Required Fields
- Source IP: `id.orig_h` (must be a valid IPv4 or IPv6 address).
- Destination IP: `id.resp_h` (must be a valid IPv4 or IPv6 address).

### Optional Fields & Defaults
- `id.resp_p`: Destination port (1–65535).
- `proto`: Transport protocol (`tcp`, `udp`, `icmp`).
- `service`: Detected application service (`http`, `ssl`, `ssh`, `dns`, `mysql`, etc.).
- `conn_state`: Zeek connection state (`SF`, `S0`, `REJ`, etc.).
- `ts`: Epoch timestamp of observation.
- `uid`: Unique Zeek flow identifier.
- `orig_bytes`, `resp_bytes`, `duration`: Network traffic volume and connection duration.

---

## 2. Device Classification & Deterministic IDs

- **Device IDs:** Generated deterministically from IP addresses (`sanitize_device_id("192.168.1.50")` -> `dev_192_168_1_50`). Repeated imports reference the same node.
- **Classification Defaults:** Discovered devices receive a configurable default criticality rating (1–5) and network zone.
- **Service/Port Inferred Roles:** If a device is repeatedly contacted on ports 80/443/22/3306/5432 or provides services, it is tentatively tagged as a `server` or `database`; otherwise, pure outbound flow endpoints are tagged as `workstation`.
- **IP Zone Inference:** Private RFC 1918 addresses map to `internal` by default, whereas global public routable IPs map to `dmz`.

---

## 3. Connection Normalization & nx.DiGraph Aggregation

### Directed Edge Constraints
`NetworkX DiGraph` permits only one directed edge for any ordered pair $(u, v)$. In real networks, multiple connections occur between the same source and destination on different ports or at different times.

### Deterministic Aggregation Strategy
- **Count:** Total number of observed flows between source and destination is aggregated (`count: N`).
- **Separation of Observed vs Allowed:** All parsed connections receive `observed: True`. However, `allowed: False` is maintained by default so that historical passive logs do not immediately grant lateral movement authorization unless explicitly configured (`allowed_default=True`).
- **Metadata Provenance:** The edge `metadata` dictionary records the full set of observed `ports`, `services`, `protocols`, `conn_states`, `uids`, `total_orig_bytes`, and `total_resp_bytes`.
- **Primary Attributes:** Primary `port` and `protocol` reflect the initial service flow, with the latest observation updating `timestamp`.

---

## 4. API Specification

### Endpoint
`POST /network/import/zeek`

### Request (Multipart Form-Data)
- `file`: Uploaded `.log`, `.tsv`, or `.json` file (max 10MB).
- `mode`: `"preview"` | `"replace"` | `"merge"`.
- `default_criticality`: Integer 1 to 5 (default: `2`).
- `default_zone`: String (default: `"internal"`).
- `allowed_default`: Boolean (default: `false`).
- `preserve_existing_nodes`: Boolean (default: `true`, applied in merge mode).
- `device_overrides`: Optional JSON dictionary mapping IPs or device IDs to specific attributes.

### Response
```json
{
  "status": "success",
  "mode": "replace",
  "message": "Network successfully replaced with 3 devices and 2 connections.",
  "statistics": {
    "total_records": 3,
    "processed_records": 3,
    "skipped_records": 0,
    "nodes_discovered": 3,
    "connections_aggregated": 2
  },
  "warnings": [],
  "nodes_count": 3,
  "edges_count": 2,
  "network": {
    "nodes": [...],
    "edges": [...]
  }
}
```

---

## 5. Merge vs. Replace Semantics

- **Replace Mode (`mode=replace`):** Validates and constructs the imported graph in isolation. Upon successful verification, atomic replacement occurs. If any parsing or validation error arises, the previous active network is preserved.
- **Merge Mode (`mode=merge`):** Combines parsed devices and edges with the active network. When `preserve_existing_nodes=true`, existing device names, criticality, and security zones are preserved. Existing connections have their observation count and traffic metadata updated while retaining existing policy authorization (`allowed`).

---

## 6. How to Run the Application & Tests

### Backend Tests
```powershell
cd backend
$env:PYTHONPATH='.'
.\venv\Scripts\python -m pytest tests/test_zeek_ingestion.py tests/test_algorithms.py
```

### Running Backend Server
```powershell
cd backend
.\venv\Scripts\uvicorn main:app --reload --port 8000
```

### Running Frontend
```powershell
cd frontend
npm run dev
```

### Importing via UI
1. Click the **"Import Zeek"** button in the top navigation bar.
2. Drag and drop any `conn.log` or `.json` file into the modal dropzone.
3. Configure the desired **Import Mode** (`Replace` or `Merge`), default criticality, and policy setting.
4. Click **"Preview Network"** to dry-run validation and inspect discovered device counts.
5. Click **"Replace Network"** or **"Merge Network"** to apply the candidate graph to the canvas.
