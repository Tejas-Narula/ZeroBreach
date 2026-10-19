"""
Zeek Connection Log Parser & Graph Aggregator

Supports both JSON and TSV (with Zeek headers/directives) log formats.
Extracts network flows, validates IP addresses, normalizes protocols and ports,
infers tentative device profiles, aggregates connections between endpoint pairs,
and builds structured records ready for candidate graph generation.
"""

import ipaddress
import json
from typing import Dict, Any, List, Optional, Tuple, Set


MAX_FILE_BYTES = 50 * 1024 * 1024  # 10 MB upload limit
MAX_RECORDS = 50_000               # 50,000 log records limit


# Common service hints mapped to major device category and inferred role
SERVICE_TYPE_HINTS = {
    "http": ("server", "Web Server"),
    "ssl": ("server", "Secure Web/TLS Service"),
    "https": ("server", "Web Server"),
    "ssh": ("server", "SSH Remote Management"),
    "dns": ("server", "Domain Name Service"),
    "dhcp": ("network_device", "DHCP Server / Gateway"),
    "smb": ("server", "File Sharing / SMB"),
    "mysql": ("database", "MySQL Database"),
    "postgresql": ("database", "PostgreSQL Database"),
    "oracle": ("database", "Oracle Database"),
    "rdp": ("endpoint", "Remote Desktop Workstation"),
    "ftp": ("server", "File Transfer Server"),
    "smtp": ("server", "Mail Transfer Server"),
    "imap": ("server", "Mail Delivery Server"),
    "ldap": ("server", "Directory & Authentication Service"),
    "kerberos": ("server", "Kerberos Authentication Server"),
    "snmp": ("network_device", "Network Management Agent"),
    "mqtt": ("iot_device", "IoT Telemetry Broker"),
    "coap": ("iot_device", "IoT Sensor Interface"),
    "rtsp": ("iot_device", "Streaming Camera"),
}

# Common destination ports mapped to major device categories and inferred roles
PORT_TYPE_HINTS = {
    80: ("server", "HTTP Web Server"),
    443: ("server", "HTTPS Web Server"),
    8080: ("server", "HTTP Proxy / App Server"),
    8443: ("server", "HTTPS App Server"),
    22: ("server", "SSH Server"),
    53: ("server", "DNS Server"),
    389: ("server", "LDAP Authentication Server"),
    88: ("server", "Kerberos Authentication Server"),
    3306: ("database", "MySQL Database Server"),
    5432: ("database", "PostgreSQL Database Server"),
    1521: ("database", "Oracle Database Server"),
    1433: ("database", "Microsoft SQL Server"),
    27017: ("database", "MongoDB Server"),
    6379: ("database", "Redis Cache / DB"),
    3389: ("endpoint", "RDP Workstation / Endpoint"),
    445: ("server", "SMB / File Server"),
    161: ("network_device", "SNMP Managed Switch / Router"),
    162: ("network_device", "SNMP Trap Receiver"),
    1883: ("iot_device", "MQTT IoT Broker"),
    8883: ("iot_device", "Secure MQTT IoT Broker"),
    554: ("iot_device", "RTSP IP Camera"),
}


def normalize_ip(ip_str: Any) -> Optional[str]:
    """Validates and returns normalized IP string (IPv4 or IPv6) or None if invalid."""
    if not ip_str or not isinstance(ip_str, str):
        return None
    ip_clean = ip_str.strip()
    try:
        addr = ipaddress.ip_address(ip_clean)
        return str(addr)
    except ValueError:
        return None


def sanitize_device_id(ip_str: str) -> str:
    """Creates a deterministic, CSS/Cytoscape/URL-safe device ID for an IP address."""
    # IPv4 stays as x_x_x_x; IPv6 colons become underscores
    return f"dev_{ip_str.replace('.', '_').replace(':', '_')}"


def infer_ip_zone(ip_str: str, default_zone: str = "internal") -> str:
    """Tentatively infers security zone based on IP address space."""
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr.is_loopback:
            return "internal"
        if addr.is_private:
            # Check 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            return default_zone
        if addr.is_global:
            return "dmz"
    except ValueError:
        pass
    return default_zone


def parse_zeek_tsv(text: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Parses a Zeek TSV log with directives (#separator, #fields, #types, etc.).
    Returns (records, warnings).
    """
    records = []
    warnings = []
    lines = text.splitlines()

    separator = "\t"
    fields: Optional[List[str]] = None
    unset_field = "-"
    empty_field = "(empty)"

    for line_idx, raw_line in enumerate(lines, start=1):
        line = raw_line.rstrip("\r\n")
        if not line:
            continue

        if line.startswith("#"):
            parts = line.split()
            if not parts:
                continue
            directive = parts[0].lower()
            if directive == "#separator":
                # Zeek specifies separator as hex escape like \x09 or literal
                sep_val = line[len(parts[0]):].strip()
                if "\\x09" in sep_val:
                    separator = "\t"
                elif sep_val:
                    # e.g. #separator \x20 for space
                    try:
                        separator = bytes.fromhex(sep_val.replace("\\x", "")).decode("latin-1")
                    except Exception:
                        separator = "\t"
            elif directive == "#fields":
                fields = line[len(parts[0]):].strip().split(separator)
            elif directive == "#unset_field":
                unset_field = line[len(parts[0]):].strip()
            elif directive == "#empty_field":
                empty_field = line[len(parts[0]):].strip()
            continue

        if not fields:
            warnings.append(f"Line {line_idx}: Data row encountered before #fields directive. Skipped.")
            continue

        values = line.split(separator)
        if len(values) != len(fields):
            warnings.append(
                f"Line {line_idx}: Column count mismatch (expected {len(fields)}, got {len(values)}). Skipped."
            )
            continue

        rec: Dict[str, Any] = {}
        for k, v in zip(fields, values):
            val = v.strip()
            if val == unset_field or val == empty_field:
                rec[k] = None
            else:
                rec[k] = val

        records.append(rec)
        if len(records) >= MAX_RECORDS:
            warnings.append(f"Maximum record count limit reached ({MAX_RECORDS}). Parsing stopped.")
            break

    return records, warnings


def parse_zeek_json(text: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Parses Zeek JSON logs (one JSON object per line, or a single JSON array).
    Returns (records, warnings).
    """
    records = []
    warnings = []
    stripped = text.strip()

    if stripped.startswith("[") and stripped.endswith("]"):
        try:
            raw_list = json.loads(stripped)
            if not isinstance(raw_list, list):
                raise ValueError("Expected a JSON array of connection records.")
            for idx, item in enumerate(raw_list, start=1):
                if isinstance(item, dict):
                    records.append(item)
                else:
                    warnings.append(f"Array element {idx} is not a valid JSON object. Skipped.")
                if len(records) >= MAX_RECORDS:
                    warnings.append(f"Maximum record count limit reached ({MAX_RECORDS}). Parsing stopped.")
                    break
            return records, warnings
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON array: {str(e)}")

    # Otherwise newline-delimited JSON
    for line_idx, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                records.append(obj)
            else:
                warnings.append(f"Line {line_idx}: Record is not a JSON object. Skipped.")
        except json.JSONDecodeError:
            warnings.append(f"Line {line_idx}: Malformed JSON syntax. Skipped.")

        if len(records) >= MAX_RECORDS:
            warnings.append(f"Maximum record count limit reached ({MAX_RECORDS}). Parsing stopped.")
            break

    return records, warnings


def parse_zeek_content(raw_text: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Detects whether content is Zeek TSV or JSON, and parses into normalized dict records.
    """
    if not raw_text or not raw_text.strip():
        raise ValueError("Log file is empty.")

    stripped = raw_text.lstrip()
    if stripped.startswith("#"):
        return parse_zeek_tsv(raw_text)
    elif stripped.startswith("{") or stripped.startswith("["):
        return parse_zeek_json(raw_text)
    else:
        # Check first line for tab delimiters
        first_line = stripped.splitlines()[0]
        if "\t" in first_line:
            return parse_zeek_tsv(raw_text)
        raise ValueError(
            "Unsupported Zeek log format. Expected Zeek TSV (starting with #separator / #fields) or JSON format."
        )


def extract_zeek_flow(record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Extracts and standardizes network flow attributes from a single parsed Zeek record.
    Supports both dotted key notation ('id.orig_h') and nested dicts ({'id': {'orig_h': ...}}).
    """
    def get_field(key: str, nested_parent: Optional[str] = None, nested_child: Optional[str] = None) -> Any:
        if key in record and record[key] is not None:
            return record[key]
        if nested_parent and nested_child and isinstance(record.get(nested_parent), dict):
            return record[nested_parent].get(nested_child)
        return None

    orig_h_raw = get_field("id.orig_h", "id", "orig_h")
    resp_h_raw = get_field("id.resp_h", "id", "resp_h")

    orig_h = normalize_ip(orig_h_raw)
    resp_h = normalize_ip(resp_h_raw)

    if not orig_h or not resp_h or orig_h == resp_h:
        return None

    # Destination port
    resp_p_raw = get_field("id.resp_p", "id", "resp_p")
    port = None
    if resp_p_raw is not None:
        try:
            p_val = int(resp_p_raw)
            if 1 <= p_val <= 65535:
                port = p_val
        except (ValueError, TypeError):
            pass

    # Source port (for provenance)
    orig_p_raw = get_field("id.orig_p", "id", "orig_p")
    orig_p = None
    if orig_p_raw is not None:
        try:
            orig_p = int(orig_p_raw)
        except (ValueError, TypeError):
            pass

    # Protocol
    proto_raw = get_field("proto")
    protocol = "TCP"
    if proto_raw and isinstance(proto_raw, str):
        proto_clean = proto_raw.strip().upper()
        if proto_clean in ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "SSH", "DNS", "SQL"]:
            protocol = proto_clean
        elif proto_clean:
            protocol = proto_clean

    service_raw = get_field("service")
    service = str(service_raw).strip().lower() if service_raw and str(service_raw).strip() != "-" else None

    # Connection state
    conn_state_raw = get_field("conn_state")
    conn_state = str(conn_state_raw).strip() if conn_state_raw and str(conn_state_raw).strip() != "-" else None

    # Timestamp
    ts_raw = get_field("ts")
    ts_str = str(ts_raw).strip() if ts_raw is not None else None

    # UID
    uid_raw = get_field("uid")
    uid = str(uid_raw).strip() if uid_raw and str(uid_raw).strip() != "-" else None

    # Optional metrics
    duration = None
    try:
        dur_raw = get_field("duration")
        if dur_raw is not None and str(dur_raw) != "-":
            duration = float(dur_raw)
    except (ValueError, TypeError):
        pass

    orig_bytes = None
    try:
        ob_raw = get_field("orig_bytes")
        if ob_raw is not None and str(ob_raw) != "-":
            orig_bytes = int(ob_raw)
    except (ValueError, TypeError):
        pass

    resp_bytes = None
    try:
        rb_raw = get_field("resp_bytes")
        if rb_raw is not None and str(rb_raw) != "-":
            resp_bytes = int(rb_raw)
    except (ValueError, TypeError):
        pass

    return {
        "orig_h": orig_h,
        "resp_h": resp_h,
        "port": port,
        "orig_p": orig_p,
        "protocol": protocol,
        "service": service,
        "conn_state": conn_state,
        "ts": ts_str,
        "uid": uid,
        "duration": duration,
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
    }


def process_zeek_log_to_network(
    raw_text: str,
    default_criticality: int = 2,
    default_zone: str = "internal",
    allowed_default: bool = False,
    device_overrides: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Full pipeline:
    1. Parses raw log text (TSV or JSON)
    2. Extracts and validates flows
    3. Infers deterministic device nodes
    4. Aggregates directed connections between (source, target) endpoint pairs
    5. Returns structured nodes, edges, warnings, and processing statistics
    """
    records, parse_warnings = parse_zeek_content(raw_text)
    device_overrides = device_overrides or {}

    total_records = len(records)
    processed_count = 0
    skipped_count = 0
    flow_records: List[Dict[str, Any]] = []

    for idx, rec in enumerate(records, start=1):
        flow = extract_zeek_flow(rec)
        if not flow:
            skipped_count += 1
            continue
        flow_records.append(flow)
        processed_count += 1

    if not flow_records:
        raise ValueError(
            f"No valid connection flows could be extracted from {total_records} records. "
            "Verify that source (id.orig_h) and destination (id.resp_h) IP addresses exist."
        )

    # 1. Discover and Classify Devices
    discovered_ips: Set[str] = set()
    ip_services: Dict[str, Set[str]] = {}
    ip_ports: Dict[str, Set[int]] = {}
    ip_as_resp_count: Dict[str, int] = {}

    for flow in flow_records:
        src = flow["orig_h"]
        dst = flow["resp_h"]
        discovered_ips.add(src)
        discovered_ips.add(dst)

        ip_as_resp_count[dst] = ip_as_resp_count.get(dst, 0) + 1
        if flow["service"]:
            ip_services.setdefault(dst, set()).add(flow["service"])
        if flow["port"]:
            ip_ports.setdefault(dst, set()).add(flow["port"])

    nodes: List[Dict[str, Any]] = []
    from criticality import recommend_device_criticality, normalize_device_type

    for ip in sorted(discovered_ips):
        device_id = sanitize_device_id(ip)

        # Check user-supplied override first
        override = device_overrides.get(ip) or device_overrides.get(device_id) or {}
        has_manual_override = bool(override)

        # Tentative classification heuristics (conservative & honest)
        inferred_type = "unknown"
        inferred_role = None
        services = ip_services.get(ip, set())
        ports = ip_ports.get(ip, set())

        # Check service hints
        for s in sorted(services):
            if s in SERVICE_TYPE_HINTS:
                inferred_type, inferred_role = SERVICE_TYPE_HINTS[s]
                break

        # Check port hints if still unknown
        if inferred_type == "unknown":
            for p in sorted(ports):
                if p in PORT_TYPE_HINTS:
                    inferred_type, inferred_role = PORT_TYPE_HINTS[p]
                    break

        # Check if external public IP
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_global and inferred_type == "unknown":
                inferred_type = "external"
                inferred_role = "External Internet Endpoint"
        except ValueError:
            pass

        # If no server indicators, strictly private IP, and only observed as originator
        if inferred_type == "unknown":
            if ip_as_resp_count.get(ip, 0) == 0:
                inferred_type = "endpoint"
                inferred_role = "Client Workstation"
            else:
                inferred_type = "server"
                inferred_role = "General Internal Server"

        # Apply override if specified
        final_type = normalize_device_type(override.get("type", inferred_type))
        final_name = override.get("name", f"Host {ip}")
        final_zone = override.get("zone", infer_ip_zone(ip, default_zone))
        final_role = override.get("inferred_role", inferred_role)

        # Build candidate device structure
        candidate_device = {
            "id": device_id,
            "name": final_name,
            "type": final_type,
            "zone": final_zone,
            "inferred_role": final_role,
            "manual_override": has_manual_override and ("criticality" in override),
            "ip_addresses": [ip],
            "hostname": override.get("hostname"),
            "discovery_source": "zeek",
            "metadata": {
                "observed_services": sorted(list(services)),
                "observed_ports": sorted(list(ports)),
                "inbound_flows": ip_as_resp_count.get(ip, 0),
            },
        }

        # Determine criticality: either user manual override or recommendation engine
        if "criticality" in override and override["criticality"] is not None:
            crit = int(override["criticality"])
            candidate_device["criticality"] = max(1, min(5, crit))
            candidate_device["manual_override"] = True
        else:
            rec = recommend_device_criticality(candidate_device)
            candidate_device["criticality"] = rec["recommended_criticality"]
            candidate_device["manual_override"] = False
            candidate_device["metadata"]["criticality_recommendation"] = rec

        nodes.append(candidate_device)

    # 2. Connection Normalization and Aggregation
    # In nx.DiGraph, an ordered pair (u, v) can only hold one edge attribute dict.
    # We aggregate multiple log records between (source, target):
    # - Protocol: Primary protocol (or list of observed protocols stored in metadata)
    # - Port: Primary destination port (and distinct ports recorded in metadata)
    # - Count: Total connection count
    # - Observed: Always True
    # - Allowed: Configurable policy default (default False)
    # - Policy Status: 'unknown' (distinct from allowed/denied), or 'allowed' if allowed_default is True
    # - Timestamp: Latest observation timestamp
    # - Metadata: Detailed breakdown of UIDs, services, ports, connection states
    edge_map: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for flow in flow_records:
        src_id = sanitize_device_id(flow["orig_h"])
        dst_id = sanitize_device_id(flow["resp_h"])

        if src_id == dst_id:
            # Self-loops not allowed in this network model
            skipped_count += 1
            continue

        pair_key = (src_id, dst_id)
        if pair_key not in edge_map:
            edge_map[pair_key] = {
                "source": src_id,
                "target": dst_id,
                "protocol": flow["protocol"],
                "allowed": allowed_default,
                "policy_status": "allowed" if allowed_default else "unknown",
                "business_critical": False,
                "disruption_cost": 1.0,
                "observed": True,
                "port": flow["port"],
                "count": 1,
                "timestamp": flow["ts"],
                "first_seen": flow["ts"],
                "last_seen": flow["ts"],
                "metadata": {
                    "source_ip": flow["orig_h"],
                    "target_ip": flow["resp_h"],
                    "services": [flow["service"]] if flow["service"] else [],
                    "ports": [flow["port"]] if flow["port"] else [],
                    "protocols": [flow["protocol"]],
                    "conn_states": [flow["conn_state"]] if flow["conn_state"] else [],
                    "uids": [flow["uid"]] if flow["uid"] else [],
                    "total_orig_bytes": flow["orig_bytes"] or 0,
                    "total_resp_bytes": flow["resp_bytes"] or 0,
                    "sample_records": 1,
                },
            }
        else:
            edge = edge_map[pair_key]
            edge["count"] += 1
            meta = edge["metadata"]
            meta["sample_records"] += 1

            if flow["orig_bytes"]:
                meta["total_orig_bytes"] = meta.get("total_orig_bytes", 0) + flow["orig_bytes"]
            if flow["resp_bytes"]:
                meta["total_resp_bytes"] = meta.get("total_resp_bytes", 0) + flow["resp_bytes"]

            if flow["service"] and flow["service"] not in meta["services"]:
                meta["services"].append(flow["service"])

            if flow["port"] and flow["port"] not in meta["ports"]:
                meta["ports"].append(flow["port"])

            if flow["protocol"] and flow["protocol"] not in meta["protocols"]:
                meta["protocols"].append(flow["protocol"])

            if flow["conn_state"] and flow["conn_state"] not in meta["conn_states"]:
                meta["conn_states"].append(flow["conn_state"])

            if flow["uid"] and len(meta["uids"]) < 25 and flow["uid"] not in meta["uids"]:
                meta["uids"].append(flow["uid"])

            # Update latest timestamp if provided
            if flow["ts"]:
                edge["timestamp"] = flow["ts"]

            # If current port is None, adopt this flow's port
            if edge["port"] is None and flow["port"] is not None:
                edge["port"] = flow["port"]

    edges = list(edge_map.values())

    return {
        "nodes": nodes,
        "edges": edges,
        "statistics": {
            "total_records": total_records,
            "processed_records": processed_count,
            "skipped_records": skipped_count,
            "nodes_discovered": len(nodes),
            "connections_aggregated": len(edges),
        },
        "warnings": parse_warnings,
    }
