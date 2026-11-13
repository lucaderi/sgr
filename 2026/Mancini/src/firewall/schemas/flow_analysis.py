from dataclasses import asdict, dataclass
from enum import StrEnum

from firewall.schemas.flow import FlowDirection, FlowKey, TCPState, TCPStateAnomaly
from firewall.schemas.packet_analysis import CheckResult

PEAK_PACKET_RATE_WINDOW_SECONDS = 1.0

# --- FLOW FINALIZATION ---

class FinalizationReason(StrEnum):
    TIMEOUT = "TIMEOUT"
    END_OF_CAPTURE = "END_OF_CAPTURE"

class TCPHandshakeStatus(StrEnum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    NOT_EVALUABLE = "NOT_EVALUABLE"
    RESET_OBSERVED = "RESET_OBSERVED"


# --- FLOW ANALYSIS ---

@dataclass(frozen=True, slots=True)
class FlowAnalysis:
    flow_id: int
    key: FlowKey

    first_seen: float | None
    last_seen: float | None
    duration: float | None
    finalized_at: float | None

    packet_count: int
    byte_count: int

    packets_a_to_b: int
    packets_b_to_a: int
    bytes_a_to_b: int
    bytes_b_to_a: int

    min_packet_size: int | None
    max_packet_size: int | None
    mean_packet_size: float | None

    mean_inter_packet_interval: float | None
    std_inter_packet_interval: float | None

    packets_per_second: float | None
    bytes_per_second: float | None

    syn_count: int
    fin_count: int
    rst_count: int

    finalization_reason: FinalizationReason

    # packet_count_consistency, byte_count_consistency, duration_validity
    checks: dict[str, CheckResult]
    tcp_state: TCPState = TCPState.NEW
    tcp_initiator: FlowDirection | None = None
    tcp_state_anomalies: int = 0
    handshake_observed: bool = False
    tcp_reset_observed: bool = False
    first_tcp_state_anomaly: TCPStateAnomaly | None = None
    peak_packets_per_second: float | None = None

    @property
    def tcp_handshake_status(self) -> TCPHandshakeStatus:
        if self.handshake_observed:
            return TCPHandshakeStatus.COMPLETE
        if self.tcp_reset_observed and self.tcp_initiator is not None:
            return TCPHandshakeStatus.RESET_OBSERVED
        if self.tcp_state in (TCPState.SYN_SENT, TCPState.SYN_ACK_SEEN):
            return TCPHandshakeStatus.INCOMPLETE
        return TCPHandshakeStatus.NOT_EVALUABLE

    def tcp_diagnostics(self) -> dict[str, object]:
        evidence: dict[str, object] = {
            "tcp_state": self.tcp_state.value,
            "tcp_handshake_status": self.tcp_handshake_status.value,
            "tcp_initiator": self.tcp_initiator,
            "handshake_observed": self.handshake_observed,
            "tcp_reset_observed": self.tcp_reset_observed,
            "tcp_state_anomalies": self.tcp_state_anomalies,
        }
        if self.first_tcp_state_anomaly is not None:
            evidence["first_tcp_state_anomaly"] = asdict(self.first_tcp_state_anomaly)
        return evidence
