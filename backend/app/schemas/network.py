from typing import List, Optional
from pydantic import BaseModel, Field


class NetworkInterface(BaseModel):
    """Network interface details."""

    name: str = Field(..., description="Interface name/identifier")
    ipv4_address: Optional[str] = Field(None, description="Primary IPv4 address if assigned")
    mac_address: Optional[str] = Field(None, description="Physical MAC address if available")
    is_up: Optional[bool] = Field(None, description="Operational status: True if up/connected")
    speed_mbps: Optional[int] = Field(None, description="NIC speed in Mbps if reported by OS")
    subnet_cidr: Optional[str] = Field(None, description="Discovered subnet CIDR e.g. 192.168.1.0/24")
    gateway: Optional[str] = Field(None, description="Default gateway IPv4 if routed")
    ipv6_address: Optional[str] = Field(None, description="Primary IPv6 address if assigned")
    interface_type: Optional[str] = Field("unknown", description="Interface category: physical, virtual, loopback, vpn")


class NetworkInterfacesData(BaseModel):
    """Network interfaces collection."""

    total_interfaces: int = Field(..., description="Total count of discovered interfaces")
    interfaces: List[NetworkInterface] = Field(..., description="List of network interfaces")


class NetworkSummaryData(BaseModel):
    """Network traffic summary counters."""

    bytes_sent: int = Field(..., description="Total bytes transmitted")
    bytes_recv: int = Field(..., description="Total bytes received")
    packets_sent: int = Field(..., description="Total packets transmitted")
    packets_recv: int = Field(..., description="Total packets received")
    errin: int = Field(0, description="Total errors while receiving")
    errout: int = Field(0, description="Total errors while sending")
    dropin: int = Field(0, description="Total incoming packets dropped")
    dropout: int = Field(0, description="Total outgoing packets dropped")

