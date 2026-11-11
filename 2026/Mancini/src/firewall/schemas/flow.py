from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from firewall.analysis.util import TCP_FLAGS, tcp_flag_names

from firewall.schemas.packet import IPVersion, Packet, TransportProtocol

FlowDirection = Literal["A_TO_B", "B_TO_A"]


class TCPState(StrEnum):
    NEW = "NEW"
    UNKNOWN = "UNKNOWN"
    SYN_SENT = "SYN_SENT"
    SYN_ACK_SEEN = "SYN_ACK_SEEN"
    ESTABLISHED = "ESTABLISHED"

# --- FLOW DATA ---

@dataclass(frozen=True, slots=True)
class Endpoint:
    ip: str  # normalized with ipaddress
    port: int | None


@dataclass(frozen=True, slots=True)
class FlowKey:
    ip_version: IPVersion
    ip_protocol_number: int
    transport_protocol: TransportProtocol
    endpoint_a: Endpoint
    endpoint_b: Endpoint

@dataclass(slots=True)
class Flow:

    # identity
    key: FlowKey
    flow_id: int

    # time
    first_seen: float | None = None
    last_seen: float | None = None
    previous_timestamp: float | None = None

    # volumes
    packet_count: int = 0
    byte_count: int = 0

    # directions
    packets_a_to_b: int = 0
    packets_b_to_a: int = 0
    bytes_a_to_b: int = 0
    bytes_b_to_a: int = 0

    # packet sizes
    min_packet_size: int | None = None
    max_packet_size: int | None = None

    # inter-packet intervals
    interval_sum: float = 0.0
    interval_sq_sum: float = 0.0
    interval_count: int = 0

    # TCP behavior
    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    tcp_state: TCPState = TCPState.NEW
    tcp_initiator: FlowDirection | None = None
    tcp_state_anomalies: int = 0
    handshake_observed: bool = False
    tcp_reset_observed: bool = False

    def update_tcp_state(self, packet: Packet, direction: FlowDirection) -> None:
        """Track flags and direction only; sequence numbers are not validated."""
        if self.key.transport_protocol != "TCP":
            return
        raw = packet.tcp_flags
        if not isinstance(raw, str) or any(flag not in TCP_FLAGS for flag in raw):
            if not self.handshake_observed:
                self.tcp_state = TCPState.UNKNOWN
            return
        flags = tcp_flag_names(raw)
        if "RST" in flags:
            self.tcp_reset_observed = True
            self.tcp_state = TCPState.UNKNOWN
            return
        if self.tcp_reset_observed or self.tcp_state == TCPState.UNKNOWN:
            return
        if self.tcp_state == TCPState.NEW:
            if "SYN" in flags and not flags & {"ACK", "FIN"}:
                self.tcp_initiator = direction
                self.tcp_state = TCPState.SYN_SENT
            else:
                self.tcp_state = TCPState.UNKNOWN
            return
        if self.tcp_state == TCPState.ESTABLISHED or "FIN" in flags:
            return
        if "SYN" in flags:
            if "ACK" in flags:
                if direction == self.tcp_initiator:
                    self.tcp_state_anomalies += 1
                else:
                    self.tcp_state = TCPState.SYN_ACK_SEEN
            elif direction != self.tcp_initiator:
                # Simultaneous open is outside this minimal model.
                self.tcp_state = TCPState.UNKNOWN
            return
        if (self.tcp_state == TCPState.SYN_ACK_SEEN
                and "ACK" in flags and direction == self.tcp_initiator):
            self.tcp_state = TCPState.ESTABLISHED
            self.handshake_observed = True
