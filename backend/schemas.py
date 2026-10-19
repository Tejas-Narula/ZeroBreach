from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ServiceModel(BaseModel):
    name: str = Field(..., description="Service name, e.g. http, ssh, mysql, redis", min_length=1)
    port: int = Field(..., ge=1, le=65535, description="Service listening port")
    protocol: str = Field("TCP", description="Transport protocol, e.g. TCP, UDP")
    version: Optional[str] = Field(None, description="Software version string if known")
    banner: Optional[str] = Field(None, description="Service banner or fingerprint info")
    status: Optional[str] = Field("active", description="Service status: active, disabled, filtered")


class VulnerabilityModel(BaseModel):
    id: str = Field(..., description="CVE or unique vulnerability ID, e.g. CVE-2023-38606", min_length=1)
    title: str = Field(..., description="Vulnerability title or description", min_length=1)
    severity: str = Field(..., description="Severity level: critical, high, medium, low, info")
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0, description="CVSS base score (0.0 to 10.0)")
    service_port: Optional[int] = Field(None, ge=1, le=65535, description="Port of associated service if service-specific")
    service_name: Optional[str] = Field(None, description="Name of associated service if known")
    exploit_available: bool = Field(False, description="Whether public or functional exploit is known")
    confidence: str = Field("medium", description="Assessment confidence: confirmed, high, medium, provisional, inferred")
    evidence: Optional[str] = Field(None, description="Concrete evidence (e.g. version match, banner match, scanner finding)")
    cwe: Optional[str] = Field(None, description="CWE category identifier")


# Network Models
class DeviceCreateRequest(BaseModel):
    id: str = Field(..., description="Unique device ID", min_length=1)
    name: str = Field(..., description="Human readable device name", min_length=1)
    type: str = Field(..., description="Device category (endpoint, server, database, network_device, firewall, wireless_access_point, cloud_infrastructure, security_system, iot_device, external, unknown)")
    criticality: Optional[int] = Field(None, ge=1, le=5, description="Asset criticality from 1 (low) to 5 (mission critical). If omitted, automatically recommended.")
    zone: str = Field("internal", description="Network security zone (employee, dmz, internal, restricted, external, etc.)")
    inferred_role: Optional[str] = Field(None, description="Inferred functional role (e.g. Domain Controller, Core Web Gateway, SQL Master)")
    manual_override: Optional[bool] = Field(False, description="Whether criticality was manually locked/overridden by an analyst")
    ip_addresses: Optional[List[str]] = Field(None, description="Known IP addresses associated with device")
    hostname: Optional[str] = Field(None, description="Verified or PTR hostname")
    discovery_source: Optional[str] = Field("manual", description="Source of device discovery (manual, zeek, import)")
    first_seen: Optional[str] = Field(None, description="First-seen timestamp")
    last_seen: Optional[str] = Field(None, description="Last-seen timestamp")
    services: Optional[List[ServiceModel]] = Field(default_factory=list, description="Services hosted on this device")
    vulnerabilities: Optional[List[VulnerabilityModel]] = Field(default_factory=list, description="Vulnerabilities identified on this device or its services")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional provenance or business metadata")


class DeviceUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1)
    type: Optional[str] = None
    criticality: Optional[int] = Field(None, ge=1, le=5)
    zone: Optional[str] = None
    inferred_role: Optional[str] = None
    manual_override: Optional[bool] = None
    ip_addresses: Optional[List[str]] = None
    hostname: Optional[str] = None
    discovery_source: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    services: Optional[List[ServiceModel]] = None
    vulnerabilities: Optional[List[VulnerabilityModel]] = None
    metadata: Optional[Dict[str, Any]] = None


class CriticalityRecommendationResponse(BaseModel):
    device_id: str
    recommended_criticality: int = Field(..., ge=1, le=5)
    confidence: str
    explanation: str
    missing_information: List[str]
    evidence: Dict[str, Any]


class ConnectionCreateRequest(BaseModel):
    source: str = Field(..., description="Source device ID")
    target: str = Field(..., description="Target device ID")
    protocol: str = Field("TCP", description="Network protocol (HTTPS, SSH, SQL, etc.)")
    allowed: bool = Field(True, description="Whether traffic is permitted by network policy")
    policy_status: Optional[str] = Field("unknown", description="Policy status: 'allowed', 'denied', or 'unknown'")
    business_critical: bool = Field(False, description="Whether this link is critical for business operations")
    disruption_cost: float = Field(1.0, ge=0.0, description="Cost penalty if this link is blocked")
    observed: Optional[bool] = Field(False, description="Whether this connection was historically observed in traffic logs")
    port: Optional[int] = Field(None, ge=1, le=65535, description="Destination or service port")
    count: Optional[int] = Field(None, ge=0, description="Observation or connection count")
    timestamp: Optional[str] = Field(None, description="ISO timestamp or record time of observation")
    first_seen: Optional[str] = Field(None, description="First observed timestamp")
    last_seen: Optional[str] = Field(None, description="Last observed timestamp")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Arbitrary provenance and log metadata")


class ConnectionUpdateRequest(BaseModel):
    protocol: Optional[str] = None
    allowed: Optional[bool] = None
    policy_status: Optional[str] = None
    business_critical: Optional[bool] = None
    disruption_cost: Optional[float] = Field(None, ge=0.0)
    observed: Optional[bool] = None
    port: Optional[int] = Field(None, ge=1, le=65535)
    count: Optional[int] = Field(None, ge=0)
    timestamp: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class NetworkPreviewRequest(BaseModel):
    nodes: List[DeviceCreateRequest] = Field(default_factory=list, description="Candidate network devices")
    edges: List[ConnectionCreateRequest] = Field(default_factory=list, description="Candidate network connections")


# Analysis Models
class MultiDeviceAnalysisRequest(BaseModel):
    compromised_devices: List[str] = Field(..., min_length=1, description="List of compromised device IDs")


class ContainmentSimulationRequest(BaseModel):
    compromised_device: str = Field(..., description="Compromised device ID")
    critical_threshold: int = Field(4, ge=1, le=5, description="Threshold above which devices are considered critical")
    custom_actions: Optional[List[Dict[str, Any]]] = Field(
        None,
        description="Optional list of manual containment actions to simulate instead of automatic engine"
    )


# Zeek Ingestion Models
class ZeekImportResponse(BaseModel):
    status: str
    mode: str
    message: str
    statistics: Dict[str, Any]
    warnings: List[str]
    nodes_count: int
    edges_count: int
    network: Optional[Dict[str, Any]] = None


# Service & Attack Path Analysis Models
class ServiceReachabilityItem(BaseModel):
    target_device: str
    target_device_name: str
    service_name: str
    port: int
    protocol: str
    version: Optional[str] = None
    hops: int
    path: List[str]
    reachable: bool
    connection_policy_status: str  # allowed, unknown, denied
    connection_observed: bool
    status_explanation: str
    vulnerabilities: List[VulnerabilityModel] = Field(default_factory=list)


class ServiceReachabilityResponse(BaseModel):
    compromised_device: str
    reachable_services: List[ServiceReachabilityItem]
    total_services_exposed: int
    services_with_vulnerabilities: int


class AttackPathHop(BaseModel):
    from_device: str
    to_device: str
    via_protocol: str
    via_port: Optional[int] = None
    policy_status: str
    observed: bool
    action_type: str  # e.g. "lateral_traversal", "service_exploit", "unauthenticated_pivot"
    vulnerability_used: Optional[VulnerabilityModel] = None
    rationale: str
    evidence_status: str  # "confirmed", "probable", "speculative_policy_unknown", "weak_evidence"


class AttackPathResult(BaseModel):
    path_id: str
    target_device: str
    target_device_name: str
    target_criticality: int
    path: List[str]
    hops_count: int
    feasible: bool
    feasibility_score: float  # 0.0 to 100.0
    feasibility_level: str  # "high", "medium", "low", "unlikely"
    vulnerabilities_exploitable_count: int
    vulnerabilities_along_path: List[VulnerabilityModel]
    step_details: List[AttackPathHop]
    why_possible: str
    missing_or_uncertain_evidence: List[str]


class AttackPathsAnalysisResponse(BaseModel):
    compromised_device: str
    critical_threshold: int
    attack_paths: List[AttackPathResult]
    total_attack_paths: int
    critical_assets_reachable: List[str]
    summary: str
