"""
Deterministic, explainable criticality recommendation system for network devices.
Scale: 1 (low) to 5 (mission critical).

Principles:
- Deterministic and rule-based: explainable step-by-step reasoning.
- Separates device type, inferred role, exposure, and network zone.
- Does not assign criticality solely from a port number, connection count, or device type.
- Distinguishes provisional/inferred status from verified business importance.
- Returns:
    - recommended_criticality (1-5)
    - explanation (short human-readable summary of rationale)
    - confidence ('low', 'medium', 'high', 'provisional')
    - missing_information (list of evidence that could improve confidence)
    - evidence (key factors used in calculation)
"""

from typing import Dict, Any, List, Optional
import networkx as nx

# Canonical major device categories
VALID_DEVICE_TYPES = {
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

# Normalization alias mapping for backwards compatibility
DEVICE_TYPE_ALIASES = {
    "laptop": "endpoint",
    "workstation": "endpoint",
    "desktop": "endpoint",
    "computer": "endpoint",
    "pc": "endpoint",
    "host": "unknown",
    "generic": "unknown",
    "router": "network_device",
    "switch": "network_device",
    "hub": "network_device",
    "ap": "wireless_access_point",
    "wap": "wireless_access_point",
    "access_point": "wireless_access_point",
    "cloud": "cloud_infrastructure",
    "ids": "security_system",
    "ips": "security_system",
    "siem": "security_system",
    "sensor": "security_system",
    "iot": "iot_device",
    "camera": "iot_device",
    "printer": "iot_device",
    "internet": "external",
    "public": "external",
}


def normalize_device_type(raw_type: Optional[str]) -> str:
    """Normalizes any legacy or freeform device type into one of the 11 major categories."""
    if not raw_type or not isinstance(raw_type, str):
        return "unknown"
    cleaned = raw_type.strip().lower().replace("-", "_").replace(" ", "_")
    if cleaned in VALID_DEVICE_TYPES:
        return cleaned
    if cleaned in DEVICE_TYPE_ALIASES:
        return DEVICE_TYPE_ALIASES[cleaned]
    return "unknown"


def recommend_device_criticality(
    device_data: Dict[str, Any],
    graph: Optional[nx.DiGraph] = None,
) -> Dict[str, Any]:
    """
    Evaluates available evidence to suggest an explainable criticality score (1-5).

    Evidence evaluated:
    1. Device type & inferred role
    2. Provision of important services (e.g. authentication, database, security)
    3. Structural topology / fan-in from other nodes / relationship with critical assets
    4. External exposure / zone
    5. Explicit business importance metadata
    """
    dev_id = device_data.get("id", "")
    dev_type = normalize_device_type(device_data.get("type", "unknown"))
    zone = str(device_data.get("zone", "internal")).strip().lower()
    inferred_role = device_data.get("inferred_role") or ""
    metadata = device_data.get("metadata") or {}
    business_importance = device_data.get("business_importance") or metadata.get("business_importance")

    reasons: List[str] = []
    missing_info: List[str] = []
    confidence = "medium"

    # Base baseline criticality by device category
    # Ordinary endpoints: 1
    # Unknown: 2 (conservative provisional)
    # IoT: 2
    # External: 1 (risk is external, not internal asset value)
    # Server: 3 (moderate)
    # Wireless AP: 2
    # Network Device: 3
    # Cloud Infrastructure: 3
    # Firewall: 4
    # Security System: 4
    # Database: 4
    category_baselines = {
        "endpoint": 1,
        "unknown": 2,
        "iot_device": 2,
        "external": 1,
        "wireless_access_point": 2,
        "server": 3,
        "network_device": 3,
        "cloud_infrastructure": 3,
        "firewall": 4,
        "security_system": 4,
        "database": 4,
    }

    base = category_baselines.get(dev_type, 2)
    score = base
    reasons.append(f"Base rating for {dev_type.replace('_', ' ')} is {base}/5")

    if dev_type == "unknown":
        confidence = "provisional"
        missing_info.append("Host identification and active service fingerprinting needed to classify device type.")
    elif dev_type == "endpoint":
        confidence = "medium"
        missing_info.append("User identity and workstation sensitivity (e.g. executive/admin workstation) not verified.")
    elif dev_type in ["database", "server"]:
        missing_info.append("Application data classification (e.g. PII, financial, non-sensitive) not verified.")

    # 1. Inspect Inferred Role / Service Evidence
    # High-impact roles: authentication/identity (LDAP/AD/Kerberos), core database, domain controller
    role_str = f"{inferred_role} {metadata.get('services', '')}".lower()
    if any(k in role_str for k in ["domain controller", "active directory", "ldap", "kerberos", "auth"]):
        score = max(score, 5)
        confidence = "high"
        reasons.append("Provides identity & authentication services (Active Directory / LDAP / Kerberos)")
    elif any(k in role_str for k in ["database", "db_master", "sql", "postgres", "oracle", "mysql"]) and dev_type == "database":
        # Database server with verified database service role
        score = max(score, 5 if zone == "restricted" else 4)
        reasons.append(f"Houses relational or core transactional database services in {zone} zone")

    # 2. Inspect Network Zone & Exposure
    if zone == "restricted":
        if dev_type in ["server", "database", "security_system", "cloud_infrastructure"]:
            score = min(5, score + 1)
            reasons.append("Located in high-security restricted segment")
    elif zone in ["dmz", "external"]:
        if dev_type == "external":
            reasons.append("External internet endpoint (low internal asset value, tracked for external blast radius)")
        elif dev_type in ["server", "firewall"]:
            reasons.append("Perimeter/DMZ presence handles inbound untrusted traffic")

    # 3. Inspect Graph Structure (if graph provided and node exists)
    if graph and dev_id in graph:
        in_degree = graph.in_degree(dev_id)
        out_degree = graph.out_degree(dev_id)

        # How many other nodes depend on / connect to this device?
        if in_degree >= 4:
            if dev_type in ["server", "network_device", "firewall", "cloud_infrastructure"]:
                score = min(5, score + 1)
                reasons.append(f"High network dependency: {in_degree} distinct devices connect to this service")

        # Does this device route to high-criticality assets?
        successors = list(graph.successors(dev_id))
        high_crit_downstream = [
            s for s in successors
            if graph.nodes[s].get("criticality", 1) >= 4 and graph[dev_id][s].get("allowed", False)
        ]
        if high_crit_downstream and dev_type in ["network_device", "firewall", "wireless_access_point"]:
            score = max(score, 4)
            reasons.append(f"Direct allowed pathway to {len(high_crit_downstream)} critical downstream asset(s)")

    # 4. Explicit Business Importance override/indication
    if business_importance:
        b_clean = str(business_importance).strip().lower()
        if b_clean in ["high", "mission_critical", "critical", "tier1", "tier_1"]:
            score = max(score, 5)
            confidence = "high"
            reasons.append(f"Explicit business importance: {business_importance}")
        elif b_clean in ["medium", "standard", "tier2", "tier_2"]:
            score = max(score, 3)
            confidence = "high"
            reasons.append(f"Explicit business importance: {business_importance}")
        elif b_clean in ["low", "tier3", "tier_3", "ephemeral"]:
            score = min(score, 2)
            confidence = "high"
            reasons.append(f"Explicit business importance: {business_importance}")

    final_score = max(1, min(5, score))

    return {
        "device_id": dev_id,
        "recommended_criticality": final_score,
        "confidence": confidence,
        "explanation": " · ".join(reasons),
        "missing_information": missing_info,
        "evidence": {
            "device_type": dev_type,
            "network_zone": zone,
            "inferred_role": inferred_role or None,
            "business_importance": business_importance or None,
        },
    }
