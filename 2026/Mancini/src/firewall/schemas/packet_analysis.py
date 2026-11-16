from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from firewall.schemas.packet import IPVersion, TransportProtocol

# range for port numbers
PortRange = Literal["RESERVED", "SYSTEM", "REGISTERED", "DYNAMIC"]

# --- CHECK RESULTS ---

class CheckStatus(StrEnum):
    VALID = "VALID"
    INVALID = "INVALID"
    INCOMPLETE = "INCOMPLETE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_CHECKED = "NOT_CHECKED"


@dataclass(frozen=True, slots=True)
class CheckResult:
    status: CheckStatus
    reason: str | None = None


# --- PACKET INFO ---

@dataclass(frozen=True, slots=True)
class PacketInfo:
    timestamp: float | None
    captured_length: int
    packet_length: int | None
    payload_length: int | None

# --- NETWORK LEVEL ---

@dataclass(frozen=True, slots=True)
class NetworkInfo:
    src_mac: str | None = None
    dst_mac: str | None = None

    ip_version: IPVersion | None = None
    src_ip: str | None = None
    dst_ip: str | None = None

    ip_next_header: int | None = None

    ip_header_length: int | None = None
    ip_total_length: int | None = None     # IPv4
    ip_payload_length: int | None = None   # IPv6
    ip_extension_headers_length: int | None = None  # IPv6
    ip_last_next_header: int | None = None  # IPv6

    ip_fragment_offset: int | None = None  # 8-byte units
    ip_more_fragments: bool | None = None
    ip_fragment_header_present: bool | None = None  # IPv6
    link_header_length: int | None = None

# --- TRANSPORT LEVEL ---

@dataclass(frozen=True, slots=True)
class TCPInfo:
    src_port: int | None
    dst_port: int | None

    flags: frozenset[str]
    header_length: int | None

    sequence_number: int | None
    ack_number: int | None

    src_port_range: PortRange | None = None
    dst_port_range: PortRange | None = None


@dataclass(frozen=True, slots=True)
class UDPInfo:
    src_port: int | None
    dst_port: int | None

    length: int | None

    src_port_range: PortRange | None = None
    dst_port_range: PortRange | None = None


@dataclass(frozen=True, slots=True)
class ICMPInfo:
    type: int | None
    code: int | None


@dataclass(frozen=True, slots=True)
class OtherTransportInfo:
    protocol_number: int | None


# --- ANALYSIS OUTPUT ---

@dataclass(frozen=True, slots=True)
class PacketAnalysis:
    protocol: TransportProtocol
    packet: PacketInfo
    network: NetworkInfo
    transport: TCPInfo | UDPInfo | ICMPInfo | OtherTransportInfo | None
    checks: dict[str, CheckResult]
    characteristics: frozenset[str]
