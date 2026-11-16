from collections import deque
from dataclasses import dataclass, field
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
    RESET = "RESET"


@dataclass(frozen=True, slots=True)
class TCPStateAnomaly:
    anomaly_type: str
    state_before: TCPState
    observed_direction: FlowDirection
    expected_direction: FlowDirection
    packet_flags: str
    packet_number_in_flow: int


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
    first_tcp_state_anomaly: TCPStateAnomaly | None = None

    packet_rate_window: deque[float] = field(default_factory=deque)
    peak_window_packets: int = 0

    def update_tcp_state(self, packet: Packet, direction: FlowDirection) -> None:
        """Track the observed handshake using TCP flags and endpoint direction."""
        if self.key.transport_protocol != "TCP" or self.tcp_reset_observed:
            return

        raw = packet.tcp_flags
        if not isinstance(raw, str) or any(flag not in TCP_FLAGS for flag in raw):
            if not self.handshake_observed:
                self.tcp_state = TCPState.UNKNOWN
            return

        flags = tcp_flag_names(raw)
        syn = "SYN" in flags
        ack = "ACK" in flags
        fin = "FIN" in flags

        if "RST" in flags:
            if not syn and not fin:
                self.tcp_reset_observed = True
                self.tcp_state = TCPState.RESET
            elif self.tcp_state == TCPState.NEW:
                self.tcp_state = TCPState.UNKNOWN
            return

        if self.tcp_state in (TCPState.UNKNOWN, TCPState.ESTABLISHED):
            return
        if self.tcp_state == TCPState.NEW:
            if syn and not ack and not fin and self.key.endpoint_a != self.key.endpoint_b:
                self.tcp_initiator = direction
                self.tcp_state = TCPState.SYN_SENT
            else:
                self.tcp_state = TCPState.UNKNOWN
            return
        if fin:
            return

        from_initiator = direction == self.tcp_initiator
        if syn and not ack:
            # A SYN from the initiator can be a retransmission in either pending state.
            if not from_initiator:
                # Simultaneous open is outside the model.
                self.tcp_state = TCPState.UNKNOWN
        elif syn and ack:
            if from_initiator:
                self.tcp_state_anomalies += 1
                if self.first_tcp_state_anomaly is None:
                    self.first_tcp_state_anomaly = TCPStateAnomaly(
                        anomaly_type="SYN_ACK_WRONG_DIRECTION",
                        state_before=self.tcp_state,
                        observed_direction=direction,
                        expected_direction="B_TO_A" if direction == "A_TO_B" else "A_TO_B",
                        packet_flags=raw,
                        packet_number_in_flow=self.packet_count,
                    )
            else:
                self.tcp_state = TCPState.SYN_ACK_SEEN
        elif ack and from_initiator and self.tcp_state == TCPState.SYN_ACK_SEEN:
            self.tcp_state = TCPState.ESTABLISHED
            self.handshake_observed = True
