from dataclasses import dataclass
from typing import Literal

IPVersion = Literal[4, 6]

TransportProtocol = Literal[
    "TCP", "UDP", "ICMP", "ICMPv6", "OTHER"
]

# --- PACKET DATA ---

@dataclass(frozen=True, slots=True)
class Packet:

    timestamp: float
    packet_length: int

    captured_length: int

    # data layer
    src_mac: str | None = None
    dst_mac: str | None = None

    # IP level
    ip_version: IPVersion | None = None
    src_ip: str | None = None
    dst_ip: str | None = None

    ip_next_header: int | None = None

    ip_header_length: int | None = None
    ip_total_length: int | None = None  # IPv4
    
    ip_payload_length: int | None = None  # IPv6
    ip_extension_headers_length: int | None = None  # IPv6
    ip_last_next_header: int | None = None  # IPv6, Next Header of the last extension header

    # IP fragmentation
    ip_fragment_offset: int | None = None
    ip_more_fragments: bool | None = None
    ip_fragment_header_present: bool | None = None  # IPv6 Fragment header, including atomic packets

    # transport level
    transport_protocol: TransportProtocol = "OTHER"

    # TCP
    tcp_flags: str | None = None
    tcp_header_length: int | None = None
    tcp_sequence_number: int | None = None
    tcp_ack_number: int | None = None

    # UDP
    udp_length: int | None = None

    # payload
    payload_length: int | None = None

    src_port: int | None = None
    dst_port: int | None = None

    # ICMP/ICMPv6
    icmp_type: int | None = None
    icmp_code: int | None = None
    link_header_length: int | None = None  # observed bytes before the outer IP header
