from collections.abc import Iterable
from ipaddress import ip_address
from math import isfinite, sqrt
from typing import Literal

from firewall.analysis.util import is_int, tcp_flag_names, valid_timestamp
from firewall.schemas.flow import Endpoint, Flow, FlowKey
from firewall.schemas.flow_analysis import FinalizationReason, FlowAnalysis
from firewall.schemas.flow_process_result import FlowExclusionReason, FlowProcessResult
from firewall.schemas.packet import IPVersion, Packet
from firewall.schemas.packet_analysis import CheckResult, CheckStatus

# --- CONSTANTS ---

MAX_PORT = 65535

PORT_BASED_PROTOCOLS = {"TCP", "UDP"}

# IANA protocol numbers for the interpreted transports
PROTOCOL_NUMBERS = {
    "ICMP": 1,
    "TCP": 6,
    "UDP": 17,
    "ICMPv6": 58,
}

MAX_PROTOCOL_NUMBER = 255

Direction = Literal["A_TO_B", "B_TO_A"]

def is_finite_positive(value: object) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False

    try:
        return isfinite(value) and value > 0
    except OverflowError:
        # integers too large
        return False


def protocol_number(packet: Packet) -> int | None:
    # known transports keep a stable number even with IPv6 extension headers
    number = PROTOCOL_NUMBERS.get(packet.transport_protocol)

    if number is not None:
        return number

    number = packet.ip_next_header

    if (packet.ip_version == 6 and is_int(packet.ip_extension_headers_length) and packet.ip_extension_headers_length > 0):
        number = packet.ip_last_next_header

    if is_int(number) and 0 <= number <= MAX_PROTOCOL_NUMBER:
        return number

    return None


# --- FLOW KEY BUILDING ---

def build_endpoint(address: object, port: object) -> Endpoint | None:
    if not isinstance(address, str):
        return None

    try:
        parsed = ip_address(address)
    except ValueError:
        return None

    if port is not None and (not is_int(port) or not 0 <= port <= MAX_PORT):
        return None

    return Endpoint(ip=str(parsed), port=port)


def endpoint_sort_key(endpoint: Endpoint) -> tuple[int, bool, int]:
    return (int(ip_address(endpoint.ip)), endpoint.port is None, endpoint.port if endpoint.port is not None else 0,)


def build_key(packet: Packet) -> FlowKey | None:
    uses_ports = packet.transport_protocol in PORT_BASED_PROTOCOLS

    number = protocol_number(packet)

    if number is None:
        return None

    endpoint_a = build_endpoint(
        packet.src_ip,
        packet.src_port if uses_ports else None,
    )
    endpoint_b = build_endpoint(
        packet.dst_ip,
        packet.dst_port if uses_ports else None,
    )

    if endpoint_a is None or endpoint_b is None:
        return None

    if uses_ports and (endpoint_a.port is None or endpoint_b.port is None):
        return None

    parsed_a = ip_address(endpoint_a.ip)
    parsed_b = ip_address(endpoint_b.ip)

    if packet.ip_version != parsed_a.version:
        return None

    if parsed_a.version != parsed_b.version:
        return None

    if endpoint_sort_key(endpoint_b) < endpoint_sort_key(endpoint_a):
        endpoint_a, endpoint_b = endpoint_b, endpoint_a

    ip_version: IPVersion = 4 if parsed_a.version == 4 else 6

    return FlowKey(
        ip_version=ip_version,
        ip_protocol_number=number,
        transport_protocol=packet.transport_protocol,
        endpoint_a=endpoint_a,
        endpoint_b=endpoint_b,
    )


# --- FLOW ANALYZER ---

class FlowInvariantError(RuntimeError):
    pass

class FlowAnalyzer:

    def __init__(
        self,
        inactivity_timeout: float | None = 180.0,
        sweep_interval: float = 60.0,
    ) -> None:

        if (inactivity_timeout is not None and not is_finite_positive(inactivity_timeout)):
            raise ValueError("inactivity_timeout must be None or a finite positive number")

        if not is_finite_positive(sweep_interval):
            raise ValueError("sweep_interval must be a finite positive number")

        self.inactivity_timeout: float | None = inactivity_timeout
        self.sweep_interval = sweep_interval
        self.reset()

    def reset(self) -> None:
        self.active_flows: dict[FlowKey, Flow] = {}
        self.completed: list[FlowAnalysis] = []
        self.next_flow_id = 1
        self.last_sweep: float | None = None
        self.last_observed_timestamp: float | None = None

    def analyze(self, packets: Iterable[Packet]) -> list[FlowAnalysis]:

        self.reset()

        for packet in packets:
            self.process(packet)

        self.finalize_all()

        return list(self.completed)

    def build_key(self, packet: Packet) -> FlowKey | None:
        return build_key(packet)

    def direction(self, packet: Packet, key: FlowKey) -> Direction | None:
        uses_ports = key.transport_protocol in PORT_BASED_PROTOCOLS

        source = build_endpoint(packet.src_ip, packet.src_port if uses_ports else None)
        destination = build_endpoint(packet.dst_ip, packet.dst_port if uses_ports else None)

        if source is None:
            return None

        if (source == key.endpoint_a and destination == key.endpoint_b):
            return "A_TO_B"

        if (source == key.endpoint_b and destination == key.endpoint_a):
            return "B_TO_A"

        return None

    def should_sweep(self, timestamp: float) -> bool:
        if self.inactivity_timeout is None:
            return False

        return (self.last_sweep is None or timestamp - self.last_sweep >= self.sweep_interval)

    def sweep_expired_flows(self, current_timestamp: float) -> None:
        timeout = self.inactivity_timeout

        if timeout is None:
            return

        expired_keys = [key for key, flow in self.active_flows.items()
                        if (flow.last_seen is not None and current_timestamp - flow.last_seen >= timeout)]

        # only expired keys
        for key in expired_keys:

            self._close_flow(key, FinalizationReason.TIMEOUT, current_timestamp)

        self.last_sweep = current_timestamp

    def process(self, packet: Packet) -> FlowProcessResult:
        timestamp = valid_timestamp(packet.timestamp)

        if timestamp is None:
            return FlowProcessResult(flow_id=None, exclusion_reason=FlowExclusionReason.INVALID_TIMESTAMP)

        if (self.last_observed_timestamp is not None and timestamp < self.last_observed_timestamp):
            raise ValueError("packets must be processed in chronological order")

        self.last_observed_timestamp = timestamp

        if self.should_sweep(timestamp):
            self.sweep_expired_flows(timestamp)

        # no transport attribution or fragment correlation without reassembly
        if is_int(packet.ip_fragment_offset) and packet.ip_fragment_offset > 0:
            return FlowProcessResult(flow_id=None, exclusion_reason=FlowExclusionReason.NON_INITIAL_FRAGMENT)

        if (packet.ip_more_fragments is True and packet.transport_protocol == "OTHER" and protocol_number(packet) in (6, 17)):
            return FlowProcessResult(flow_id=None, exclusion_reason=FlowExclusionReason.INVALID_FLOW_KEY)

        key = self.build_key(packet)

        if key is None:
            return FlowProcessResult(flow_id=None, exclusion_reason=FlowExclusionReason.INVALID_FLOW_KEY)

        size = self.packet_size(packet)

        if size is None:
            return FlowProcessResult(flow_id=None, exclusion_reason=FlowExclusionReason.INVALID_PACKET_SIZE)

        flow = self.active_flows.get(key)

        # separate two instances of the same key expired between two sweeps
        if (self.inactivity_timeout is not None and flow is not None and flow.last_seen is not None and timestamp - flow.last_seen >= self.inactivity_timeout):
            self._close_flow(key, FinalizationReason.TIMEOUT, timestamp)

            flow = None

        if flow is None:
            flow = self.new_flow(key)
            self.active_flows[key] = flow

        self.update_flow(flow, packet, timestamp, size)

        return FlowProcessResult(flow_id=flow.flow_id)

    def new_flow(self, key: FlowKey) -> Flow:

        flow = Flow(key=key, flow_id=self.next_flow_id)
        self.next_flow_id += 1

        return flow

    def packet_size(self, packet: Packet) -> int | None:
        size = packet.packet_length

        if not is_int(size) or size <= 0:
            return None

        return size

    def update_flow(self, flow: Flow, packet: Packet, timestamp: float, size: int) -> None:
        if packet.transport_protocol != flow.key.transport_protocol:
            raise FlowInvariantError("packet protocol does not match the flow protocol")

        direction = self.direction(packet, flow.key)

        if direction is None:
            raise FlowInvariantError("packet source does not match either flow endpoint")

        flow.packet_count += 1
        flow.byte_count += size

        if direction == "A_TO_B":
            flow.packets_a_to_b += 1
            flow.bytes_a_to_b += size
        else:
            flow.packets_b_to_a += 1
            flow.bytes_b_to_a += size

        if flow.min_packet_size is None or size < flow.min_packet_size:
            flow.min_packet_size = size

        if flow.max_packet_size is None or size > flow.max_packet_size:
            flow.max_packet_size = size

        if flow.first_seen is None:
            flow.first_seen = timestamp

        if flow.previous_timestamp is not None:
            delta = timestamp - flow.previous_timestamp

            if delta < 0:
                raise FlowInvariantError("flow timestamps must be non-decreasing")

            flow.interval_count += 1
            flow.interval_sum += delta
            flow.interval_sq_sum += delta * delta

        flow.last_seen = timestamp
        flow.previous_timestamp = timestamp

        if flow.key.transport_protocol == "TCP":
            flow.update_tcp_state(packet, direction)
            flags = tcp_flag_names(packet.tcp_flags)

            if "SYN" in flags:
                flow.syn_count += 1

            if "FIN" in flags:
                flow.fin_count += 1

            if "RST" in flags:
                flow.rst_count += 1

    def _finalize_flow(self, flow: Flow, reason: FinalizationReason, finalized_at: float | None) -> None:
        
        if flow.first_seen is not None and flow.last_seen is not None:
            duration = flow.last_seen - flow.first_seen
        else:
            duration = None

        if flow.packet_count > 0:
            mean_packet_size = flow.byte_count / flow.packet_count
        else:
            mean_packet_size = None

        if flow.interval_count > 0:
            mean_interval = flow.interval_sum / flow.interval_count

            variance = flow.interval_sq_sum / flow.interval_count - mean_interval**2

            std_interval = sqrt(max(0.0, variance))
            
        else:
            mean_interval = None
            std_interval = None

        if duration is not None and duration > 0:
            packets_per_second = flow.packet_count / duration
            bytes_per_second = flow.byte_count / duration
        else:
            packets_per_second = None
            bytes_per_second = None

        self.completed.append(
            FlowAnalysis(
                flow_id=flow.flow_id,
                key=flow.key,
                first_seen=flow.first_seen,
                last_seen=flow.last_seen,
                duration=duration,
                finalized_at=finalized_at,
                packet_count=flow.packet_count,
                byte_count=flow.byte_count,
                packets_a_to_b=flow.packets_a_to_b,
                packets_b_to_a=flow.packets_b_to_a,
                bytes_a_to_b=flow.bytes_a_to_b,
                bytes_b_to_a=flow.bytes_b_to_a,
                min_packet_size=flow.min_packet_size,
                max_packet_size=flow.max_packet_size,
                mean_packet_size=mean_packet_size,
                mean_inter_packet_interval=mean_interval,
                std_inter_packet_interval=std_interval,
                packets_per_second=packets_per_second,
                bytes_per_second=bytes_per_second,
                syn_count=flow.syn_count,
                fin_count=flow.fin_count,
                rst_count=flow.rst_count,
                tcp_state=flow.tcp_state,
                tcp_initiator=flow.tcp_initiator,
                tcp_state_anomalies=flow.tcp_state_anomalies,
                handshake_observed=flow.handshake_observed,
                tcp_reset_observed=flow.tcp_reset_observed,
                finalization_reason=reason,
                checks=self.checks(flow, duration),
            )
        )

    def _close_flow(self, key: FlowKey, reason: FinalizationReason, finalized_at: float | None) -> None:

        flow = self.active_flows[key]

        self._finalize_flow(flow, reason, finalized_at)

        del self.active_flows[key]

    def finalize_all(self) -> None:
        for key in list(self.active_flows):
            self._close_flow(key, FinalizationReason.END_OF_CAPTURE, self.last_observed_timestamp)

    def checks(self, flow: Flow, duration: float | None) -> dict[str, CheckResult]:
        return {"packet_count_consistency": self.check_packet_count(flow),"byte_count_consistency": self.check_byte_count(flow), "duration_validity": self.check_duration(duration)}

    def check_packet_count(self, flow: Flow) -> CheckResult:
        directional = flow.packets_a_to_b + flow.packets_b_to_a

        if directional != flow.packet_count:
            return CheckResult(CheckStatus.INVALID, "directional packet counters do not match the total")

        return CheckResult(CheckStatus.VALID)

    def check_byte_count(self, flow: Flow) -> CheckResult:
        directional = flow.bytes_a_to_b + flow.bytes_b_to_a

        if directional != flow.byte_count:
            return CheckResult(CheckStatus.INVALID, "directional byte counters do not match the total")

        return CheckResult(CheckStatus.VALID)

    def check_duration(self, duration: float | None) -> CheckResult:
        if duration is None:
            return CheckResult(CheckStatus.INCOMPLETE, "duration not available")

        if duration < 0:
            return CheckResult(CheckStatus.INVALID, "negative flow duration")

        return CheckResult(CheckStatus.VALID)
