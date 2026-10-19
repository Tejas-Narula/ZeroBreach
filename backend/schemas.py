from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


# Network Models
class DeviceCreateRequest(BaseModel):
    id: str = Field(..., description="Unique device ID", min_length=1)
    name: str = Field(..., description="Human readable device name", min_length=1)
    type: str = Field(..., description="Device type (laptop, server, database, firewall, etc.)")
    criticality: int = Field(..., ge=1, le=5, description="Asset criticality from 1 (low) to 5 (mission critical)")
    zone: str = Field(..., description="Network security zone (employee, dmz, internal, restricted, etc.)")


class DeviceUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1)
    type: Optional[str] = None
    criticality: Optional[int] = Field(None, ge=1, le=5)
    zone: Optional[str] = None


class ConnectionCreateRequest(BaseModel):
    source: str = Field(..., description="Source device ID")
    target: str = Field(..., description="Target device ID")
    protocol: str = Field("TCP", description="Network protocol (HTTPS, SSH, SQL, etc.)")
    allowed: bool = Field(True, description="Whether traffic is permitted by network policy")
    business_critical: bool = Field(False, description="Whether this link is critical for business operations")
    disruption_cost: float = Field(1.0, ge=0.0, description="Cost penalty if this link is blocked")
    observed: Optional[bool] = Field(False, description="Whether this connection was historically observed in traffic logs")
    port: Optional[int] = Field(None, ge=1, le=65535, description="Destination or service port")
    count: Optional[int] = Field(None, ge=0, description="Observation or connection count")
    timestamp: Optional[str] = Field(None, description="ISO timestamp or record time of observation")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Arbitrary provenance and log metadata")


class ConnectionUpdateRequest(BaseModel):
    protocol: Optional[str] = None
    allowed: Optional[bool] = None
    business_critical: Optional[bool] = None
    disruption_cost: Optional[float] = Field(None, ge=0.0)
    observed: Optional[bool] = None
    port: Optional[int] = Field(None, ge=1, le=65535)
    count: Optional[int] = Field(None, ge=0)
    timestamp: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class NetworkPreviewRequest(BaseModel):
    nodes: List[DeviceCreateRequest] = Field(default_factory=list, description="Candidate network devices")
    edges: List[ConnectionCreateRequest] = Field(default_factory=list, description="Candidate network connections")


# Analysis Models
class MultiDeviceAnalysisRequest(BaseModel):
    compromised_devices: List[str] = Field(..., min_items=1, description="List of compromised device IDs")


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
