from dataclasses import dataclass
from enum import StrEnum

from firewall.schemas.flow import FlowDirection, FlowKey, TCPState
from firewall.schemas.packet_analysis import CheckResult

# --- FLOW FINALIZATION ---

class FinalizationReason(StrEnum):
    TIMEOUT = "TIMEOUT"
    END_OF_CAPTURE = "END_OF_CAPTURE"

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
