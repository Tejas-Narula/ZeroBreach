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
    allowed: bool = Field(True, description="Whether traffic is permitted")
    business_critical: bool = Field(False, description="Whether this link is critical for business operations")
    disruption_cost: float = Field(1.0, ge=0.0, description="Cost penalty if this link is blocked")


class ConnectionUpdateRequest(BaseModel):
    protocol: Optional[str] = None
    allowed: Optional[bool] = None
    business_critical: Optional[bool] = None
    disruption_cost: Optional[float] = Field(None, ge=0.0)


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
