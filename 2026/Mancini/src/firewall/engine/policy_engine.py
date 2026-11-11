from collections import Counter, deque
from collections.abc import Iterable
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address

from firewall.analysis.util import TCP_FLAGS, is_int, tcp_flag_names, valid_timestamp
from firewall.engine.policy_config import (
    CaptureContext,
    FlowLimits,
    IPDirection,
    PolicyConfig,
    ServiceRule,
    parse_networks,
)

from firewall.schemas.capture_analysis import CaptureAnalysis
from firewall.schemas.flow_analysis import FlowAnalysis
from firewall.schemas.flow import TCPState
from firewall.schemas.indexed_packet import IndexedPacket
from firewall.schemas.packet import Packet
from firewall.schemas.packet_analysis import (
    CheckStatus,
    ICMPInfo,
    OtherTransportInfo,
    PacketAnalysis,
    TCPInfo,
    UDPInfo,
)

from firewall.engine.policy_decision import (
    PolicyAction,
    PolicyDecision,
    PolicyFinding,
    PolicyScope,
)

# policy engine
# IP constraints -> structural data -> forbidden ports -> flags/size -> FLOW limits -> WINDOW limits -> services/replies
# default drop (default deny policy)

# --- CONSTANTS ---

PROTOCOL_NUMBERS = {
    "ICMP": 1,
    "TCP": 6,
    "UDP": 17,
    "ICMPv6": 58,
}

PORT_BASED_PROTOCOLS = frozenset({"TCP", "UDP"})

MAX_PORT = 65535
MAX_PROTOCOL_NUMBER = 255

# checks that must be VALID before a service selector can be applied
AUTHORIZATION_CHECKS = (
    "src_ip_format",
    "dst_ip_format",
    "ip_version_consistency",
    "protocol_fields_consistency",
)

# internal flow invariants
# a non-VALID result is a contract error
FLOW_CHECK_KEYS = (
    "packet_count_consistency",
    "byte_count_consistency",
    "duration_validity",
)

# rule IDs for fixed policy rules
SOURCE_ADDRESS_RESTRICTION = "SOURCE_ADDRESS_RESTRICTION"
BOUNDARY_SOURCE_RESTRICTION = "BOUNDARY_SOURCE_RESTRICTION"
IP_FRAGMENT = "IP_FRAGMENT"

TCP_SYN_FIN = "TCP_SYN_FIN"
TCP_SYN_RST = "TCP_SYN_RST"
TCP_NULL_FLAGS = "TCP_NULL_FLAGS"
TCP_HANDSHAKE_INCOMPLETE = "TCP_HANDSHAKE_INCOMPLETE"
TCP_STATE_ANOMALY = "TCP_STATE_ANOMALY"

L3_SIZE_LIMIT = "L3_SIZE_LIMIT"

FLOW_PACKET_RATE = "FLOW_PACKET_RATE"
FLOW_BYTE_RATE = "FLOW_BYTE_RATE"
FLOW_DURATION = "FLOW_DURATION"
FLOW_BYTE_COUNT = "FLOW_BYTE_COUNT"

WINDOW_PACKET_FLOOD = "WINDOW_PACKET_FLOOD"
WINDOW_SYN_FLOOD = "WINDOW_SYN_FLOOD"
WINDOW_ECHO_FLOOD = "WINDOW_ECHO_FLOOD"
WINDOW_PORT_SCAN = "WINDOW_PORT_SCAN"
WINDOW_UDP_PORT_SCAN = "WINDOW_UDP_PORT_SCAN"
WINDOW_HOST_SCAN = "WINDOW_HOST_SCAN"
WINDOW_SMALL_PACKETS = "WINDOW_SMALL_PACKETS"

DEFAULT_DENY = "DEFAULT_DENY"
INVALID_TIMESTAMP = "INVALID_TIMESTAMP"
UNSUPPORTED_TUNNEL = "UNSUPPORTED_TUNNEL"

WindowKey = tuple[str, str, int]

# --- INTERNAL MODELS ---

@dataclass(frozen=True, slots=True)
class _CompiledServiceRule:
    rule: ServiceRule
    source_networks: tuple[IPv4Network | IPv6Network, ...] | None
    destination_networks: tuple[IPv4Network | IPv6Network, ...] | None
    destination_ports: frozenset[int] | None
    icmp_selectors: frozenset[tuple[int, int]]


@dataclass(frozen=True, slots=True)
class _Finding:
    rule_id: str
    reason: str
    scope: PolicyScope
    evidence: dict[str, object]
    blocking: bool = True

    def public(self) -> PolicyFinding:
        return PolicyFinding(rule_id=self.rule_id, reason=self.reason, scope=self.scope, evidence=self.evidence)


class PolicyContractError(RuntimeError):
    pass


# --- HELPERS ---

def unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def normalize_ip(value: object) -> IPv4Address | IPv6Address | None:
    if not isinstance(value, str):
        return None

    try:
        return ip_address(value)
    except ValueError:
        return None


def is_in_networks(address: IPv4Address | IPv6Address, networks: tuple[IPv4Network | IPv6Network, ...]) -> bool:
    return any(address.version == network.version and address in network for network in networks)


def tcp_flags_state(packet: Packet) -> frozenset[str] | None:
    # missing or unrecognized raw value is not a NULL segment
    raw_flags = packet.tcp_flags

    if raw_flags is None or not isinstance(raw_flags, str):
        return None

    if any(letter not in TCP_FLAGS for letter in raw_flags):
        return None

    return tcp_flag_names(raw_flags)

def check_status(analysis: PacketAnalysis, key: str) -> CheckStatus | None:
    result = analysis.checks.get(key)

    if result is None:
        return None

    return result.status

def check_valid(analysis: PacketAnalysis, key: str) -> bool:
    return check_status(analysis, key) == CheckStatus.VALID


def protocol_number(analysis: PacketAnalysis) -> int | None:
    number = PROTOCOL_NUMBERS.get(analysis.protocol)

    if number is not None:
        return number

    if analysis.protocol == "OTHER" and isinstance(analysis.transport, OtherTransportInfo):
        number = analysis.transport.protocol_number

        if is_int(number) and 0 <= number <= MAX_PROTOCOL_NUMBER:
            return number

    return None


def l3_length(analysis: PacketAnalysis) -> int | None:
    network = analysis.network

    if network.ip_version == 4:
        if not is_int(network.ip_total_length) or network.ip_total_length < 0:
            return None

        # a declared length contradicted by the structural checks is not usable
        if check_status(analysis, "ip_header_length") == CheckStatus.INVALID:
            return None

        if check_status(analysis, "packet_length_consistency") == CheckStatus.INVALID:
            return None

        return network.ip_total_length

    if network.ip_version == 6:
        if not is_int(network.ip_payload_length) or network.ip_payload_length < 0:
            return None

        if check_status(analysis, "ip_header_length") == CheckStatus.INVALID:
            return None

        if check_status(analysis, "ip_extension_headers_length") == CheckStatus.INVALID:
            return None

        # IPv6 base header + declared payload (extension headers included)
        return 40 + network.ip_payload_length

    return None


def prune_timestamps(events: deque[float], cutoff: float) -> None:
    # window is (t-W, t]
    while events and events[0] <= cutoff:
        events.popleft()


def prune_distinct(events: deque, counter: Counter, cutoff: float) -> None:
    while events and events[0][0] <= cutoff:
        _, value = events.popleft()
        counter[value] -= 1
        if counter[value] == 0:
            del counter[value]


def update_distinct(events: deque, counter: Counter, timestamp: float, window: float, value: int | str) -> None:
    prune_distinct(events, counter, timestamp - window)
    events.append((timestamp, value))
    counter[value] += 1


# --- POLICY ENGINE ---

class PolicyEngine:

    def __init__(self, config: PolicyConfig) -> None:
        self.config = config

        self._service_rules: list[_CompiledServiceRule] = [self._compile_service_rule(rule) for rule in config.service_rules]

        self._service_rule_by_id: dict[str, _CompiledServiceRule] = {compiled.rule.rule_id: compiled for compiled in self._service_rules}

        self._blocked_source_ports: list[tuple[str, str, int]] = [(restriction.rule_id, restriction.protocol, restriction.port)
                                                                    for restriction in config.blocked_source_ports]
        
        self._blocked_destination_ports: list[tuple[str, str, int]] = [(restriction.rule_id, restriction.protocol, restriction.port)
                                                                        for restriction in config.blocked_destination_ports]

        self._blocked_networks: list[tuple[str, IPv4Network | IPv6Network, IPDirection]] = [(restriction.rule_id, parse_networks((restriction.network,), restriction.rule_id)[0], restriction.direction)
                                                                                                for restriction in config.blocked_networks]

        self._local_subnets = parse_networks(config.local_subnets, "local_subnets")

        self._boundary_source_networks = (parse_networks(config.boundary_source_networks, "boundary_source_networks")
                                            if config.boundary_source_networks is not None
                                            else None)

        self._fatal_checks = tuple(config.fatal_checks)

        self.reset()

    def _compile_service_rule(self, rule: ServiceRule) -> _CompiledServiceRule:
        source_networks = (parse_networks(rule.source_networks, f"{rule.rule_id}.source_networks")
                            if rule.source_networks is not None
                            else None)
        
        destination_networks = (parse_networks(rule.destination_networks, f"{rule.rule_id}.destination_networks")
                                    if rule.destination_networks is not None
                                    else None)
        
        destination_ports = (frozenset(rule.destination_ports) if rule.destination_ports is not None else None)

        icmp_selectors = frozenset((selector.type, selector.code) for selector in rule.icmp_selectors)

        return _CompiledServiceRule(rule=rule, source_networks=source_networks,destination_networks=destination_networks, destination_ports=destination_ports, icmp_selectors=icmp_selectors)

    def reset(self) -> None:
        # temporal windows
        self._packet_flood: dict[WindowKey, deque[float]] = {}
        self._syn_flood: dict[tuple[str, str, int, int], deque[float]] = {}
        self._echo_flood: dict[tuple[str, str, str], deque[float]] = {}
        self._port_scan: dict[WindowKey, deque[tuple[float, int]]] = {}
        self._port_scan_ports: dict[WindowKey, Counter[int]] = {}
        self._host_scan: dict[tuple[str, int], deque[tuple[float, str]]] = {}
        self._host_scan_hosts: dict[tuple[str, int], Counter[str]] = {}
        self._small_packets: dict[WindowKey, deque[float]] = {}
        self._last_window_sweep: float | None = None

        # service replies
        self._authorized_requests: set[tuple[int, str, int, str, int, str]] = set()

        # flow classifications, calculated once per capture
        self._flow_findings: dict[int, tuple[_Finding, ...]] = {}
        self._flow_unevaluated: dict[int, tuple[str, ...]] = {}

    # --- ENGINE ENTRY POINT ---

    def evaluate(self, capture: CaptureAnalysis) -> dict[int, PolicyDecision]:
        self.reset()

        flow_packets = self.prepare_flows(capture)

        self._flow_findings, self._flow_unevaluated = self.evaluate_flows(capture, flow_packets)

        decisions: dict[int, PolicyDecision] = {}

        valid_packets: list[tuple[float, IndexedPacket]] = []
        invalid_packets: list[IndexedPacket] = []

        for indexed in capture.packets:
            timestamp = valid_timestamp(indexed.packet.timestamp)

            if timestamp is None:
                invalid_packets.append(indexed)
            else:
                valid_packets.append((timestamp, indexed))

        # window order is stable on (timestamp, capture_index)
        valid_packets.sort(key=lambda item: (item[0], item[1].capture_index))

        for _, indexed in valid_packets:
            decisions[indexed.capture_index] = self.evaluate_packet(capture, indexed, ordered=True)

        for indexed in invalid_packets:
            decisions[indexed.capture_index] = self.evaluate_packet(capture, indexed, ordered=False)

        # result follows the original capture order
        return {indexed.capture_index: decisions[indexed.capture_index] for indexed in capture.packets}

    def prepare_flows(self, capture: CaptureAnalysis) -> dict[int, list[tuple[int, Packet, PacketAnalysis]]]:
        flow_packets: dict[int, list[tuple[int, Packet, PacketAnalysis]]] = {}
        indexes: set[int] = set()

        for indexed in capture.packets:
            if indexed.capture_index in indexes:
                raise PolicyContractError(f"duplicate capture index {indexed.capture_index}")
            
            indexes.add(indexed.capture_index)
            analysis = capture.packet_analyses.get(indexed.capture_index)

            if analysis is None:
                raise PolicyContractError(f"missing packet analysis for capture index {indexed.capture_index}")

            result = capture.flow_results.get(indexed.capture_index)

            if result is None:
                raise PolicyContractError(f"missing flow result for capture index {indexed.capture_index}")

            if result.flow_id is None:
                continue

            flow = capture.flows.get(result.flow_id)

            if flow is None:
                raise PolicyContractError(f"packet {indexed.capture_index} references missing flow {result.flow_id}")

            if valid_timestamp(indexed.packet.timestamp) is None:
                raise PolicyContractError(f"packet {indexed.capture_index} is in a flow without a usable timestamp")

            flow_packets.setdefault(result.flow_id, []).append((indexed.capture_index, indexed.packet, analysis))

        for flow_id, flow in capture.flows.items():
            if flow_id != flow.flow_id:
                raise PolicyContractError(f"flow key {flow_id} does not match flow_id {flow.flow_id}")
            
            packets = flow_packets.get(flow_id, [])

            if flow.packet_count != len(packets):
                raise PolicyContractError(f"flow {flow_id}: packet_count {flow.packet_count} does not match {len(packets)} associated packets")

            for key in FLOW_CHECK_KEYS:
                result = flow.checks.get(key)

                if result is None or result.status != CheckStatus.VALID:
                    raise PolicyContractError(f"flow {flow_id}: invariant check {key} is not VALID")

        for packets in flow_packets.values():
            packets.sort(key=lambda item: (valid_timestamp(item[1].timestamp), item[0]))

        return flow_packets

    # --- FLOW RULES ---

    def evaluate_flows(self, capture: CaptureAnalysis, flow_packets: dict[int, list[tuple[int, Packet, PacketAnalysis]]]) -> tuple[dict[int, tuple[_Finding, ...]], dict[int, tuple[str, ...]]]:
        findings: dict[int, tuple[_Finding, ...]] = {}
        unevaluated: dict[int, tuple[str, ...]] = {}

        for flow in capture.flows.values():
            flow_findings, flow_unevaluated = self.flow_rules(flow, flow_packets.get(flow.flow_id, []))

            findings[flow.flow_id] = tuple(flow_findings)
            unevaluated[flow.flow_id] = unique(flow_unevaluated)

        return findings, unevaluated

    def flow_rules(self, flow: FlowAnalysis, packets: list[tuple[int, Packet, PacketAnalysis]]) -> tuple[list[_Finding], list[str]]:
        findings: list[_Finding] = []
        unevaluated: list[str] = []

        self.apply_flow_limits(flow, self.config.flow_limits, findings, unevaluated)

        if flow.key.transport_protocol == "TCP":
            evidence = {"tcp_state": flow.tcp_state.value,
                        "handshake_observed": flow.handshake_observed,
                        "tcp_reset_observed": flow.tcp_reset_observed,
                        "tcp_state_anomalies": flow.tcp_state_anomalies}
            if (flow.tcp_state in (TCPState.SYN_SENT, TCPState.SYN_ACK_SEEN)
                    and not flow.handshake_observed and not flow.tcp_reset_observed):
                findings.append(_Finding(TCP_HANDSHAKE_INCOMPLETE,
                    "tcp_handshake_not_fully_observed", PolicyScope.FLOW, evidence, blocking=False))
            elif flow.tcp_state in (TCPState.NEW, TCPState.UNKNOWN):
                unevaluated.append(TCP_HANDSHAKE_INCOMPLETE)
            if flow.tcp_state_anomalies:
                findings.append(_Finding(TCP_STATE_ANOMALY,
                    "tcp_syn_ack_in_initiator_direction", PolicyScope.FLOW, evidence, blocking=False))
            elif flow.tcp_state in (TCPState.NEW, TCPState.UNKNOWN):
                unevaluated.append(TCP_STATE_ANOMALY)

        for rule in self.config.flow_limit_rules:
            if rule.protocol is not None and rule.protocol != flow.key.transport_protocol:
                continue

            if rule.service_rule_id is not None:
                compiled = self._service_rule_by_id[rule.service_rule_id]
                match = self.flow_service_match(flow, packets, compiled)
                if match is None:
                    unevaluated.append(rule.rule_id)
                    continue
                if not match:
                    continue
            
            selected_findings: list[_Finding] = []
            selected_unevaluated: list[str] = []
            self.apply_flow_limits(flow, rule.limits, selected_findings, selected_unevaluated)

            for finding in selected_findings:
                findings.append(_Finding(rule.rule_id, finding.reason, finding.scope,
                    {**finding.evidence, "configured_rule_id": rule.rule_id,
                     "metric_rule_id": finding.rule_id,
                     "protocol_selector": rule.protocol, "service_rule_id": rule.service_rule_id}, finding.blocking))
                
            if selected_unevaluated:
                unevaluated.append(rule.rule_id)

        return findings, unevaluated

    def apply_flow_limits(self, flow: FlowAnalysis, limits: FlowLimits, findings: list[_Finding], unevaluated: list[str]) -> None:
        self.flow_rate_rules(flow, limits, findings, unevaluated)
        self.flow_volume_rules(flow, limits, findings, unevaluated)

    def flow_service_match(self, flow: FlowAnalysis, packets: list[tuple[int, Packet, PacketAnalysis]], compiled: _CompiledServiceRule) -> bool | None:
        # match in either direction selects bidirectional flow
        if flow.key.transport_protocol != compiled.rule.protocol:
            return False
        if compiled.rule.protocol in PORT_BASED_PROTOCOLS or compiled.rule.protocol == "OTHER":
            a, b = flow.key.endpoint_a, flow.key.endpoint_b
            return (self.direct_service_match(compiled, a.ip, b.ip, b.port, None) or self.direct_service_match(compiled, b.ip, a.ip, a.port, None))
        
        # ICMP type/code are packet facts, absent from the bidirectional flow key.
        evaluable = False
        incomplete = False
        for _, _, analysis in packets:
            fields = self.authorization_fields(analysis)
            if fields is None:
                incomplete = True
                continue
            evaluable = True
            source, destination, _, port, icmp = fields
            if (self.direct_service_match(compiled, source, destination, port, icmp)
                    or self.direct_service_match(compiled, destination, source, port, icmp)):
                return True
        # missing packet could still change the answer
        if incomplete or not evaluable:
            return None
        return False

    def flow_rate_rules(self, flow: FlowAnalysis, limits: FlowLimits, findings: list[_Finding], unevaluated: list[str]) -> None:
        if limits.max_packets_per_second is not None:
            if flow.duration is None or flow.packets_per_second is None:
                unevaluated.append(FLOW_PACKET_RATE)
            elif flow.duration >= limits.rate_min_duration and flow.packet_count >= limits.rate_min_packets:
                if flow.packets_per_second > limits.max_packets_per_second:
                    findings.append(_Finding(FLOW_PACKET_RATE, "flow_packet_rate_exceeded", PolicyScope.FLOW,
                                    {"flow_id": flow.flow_id, "packets_per_second": flow.packets_per_second, "limit": limits.max_packets_per_second}))

        if limits.max_bytes_per_second is not None:
            if flow.duration is None or flow.bytes_per_second is None:
                unevaluated.append(FLOW_BYTE_RATE)
            elif flow.duration >= limits.rate_min_duration and flow.packet_count >= limits.rate_min_packets:
                if flow.bytes_per_second > limits.max_bytes_per_second:
                    findings.append(_Finding(FLOW_BYTE_RATE, "flow_byte_rate_exceeded", PolicyScope.FLOW,
                                    {"flow_id": flow.flow_id, "bytes_per_second": flow.bytes_per_second, "limit": limits.max_bytes_per_second}))

        if limits.max_duration is not None:
            if flow.duration is None:
                unevaluated.append(FLOW_DURATION)
            elif flow.duration > limits.max_duration:
                findings.append(_Finding(FLOW_DURATION, "flow_duration_limit_exceeded", PolicyScope.FLOW,
                                {"flow_id": flow.flow_id, "duration": flow.duration, "limit": limits.max_duration}))

    def flow_volume_rules(self, flow: FlowAnalysis, limits: FlowLimits, findings: list[_Finding], unevaluated: list[str]) -> None:
        if limits.max_flow_bytes is not None and flow.byte_count > limits.max_flow_bytes:
            findings.append(_Finding(FLOW_BYTE_COUNT, "flow_byte_limit_exceeded", PolicyScope.FLOW,
                            {"flow_id": flow.flow_id, "byte_count": flow.byte_count, "limit": limits.max_flow_bytes}))



    # --- PACKET RULES ---

    def evaluate_packet(self, capture: CaptureAnalysis, indexed: IndexedPacket, ordered: bool) -> PolicyDecision:
        analysis = capture.packet_analyses.get(indexed.capture_index)

        if analysis is None:
            raise PolicyContractError(f"missing packet analysis for capture index {indexed.capture_index}")

        packet = indexed.packet
        flow_id = capture.flow_id_for(indexed.capture_index)

        findings: list[_Finding] = []
        unevaluated: list[str] = []

        if valid_timestamp(packet.timestamp) is None:
            # mandatory capture requirement
            findings.append(_Finding(INVALID_TIMESTAMP, "invalid_capture_timestamp", PolicyScope.PACKET,
                            {"timestamp": packet.timestamp}))

        self.packet_rules(packet, analysis, findings, unevaluated)

        if flow_id is not None:
            findings.extend(self._flow_findings.get(flow_id, ()))
            unevaluated.extend(self._flow_unevaluated.get(flow_id, ()))

        if ordered:
            timestamp = valid_timestamp(packet.timestamp)

            if timestamp is None:
                raise PolicyContractError(f"ordered packet {indexed.capture_index} has no usable timestamp")

            if self.should_sweep_windows(timestamp):
                self.sweep_windows(timestamp)

            # count observed traffic, including packets that other rules will DROP
            window_findings, window_unevaluated = self.window_rules(packet, analysis, timestamp)
            findings.extend(window_findings)
            unevaluated.extend(window_unevaluated)


        else:
            # no timestamp: no window or temporal rule is evaluable
            unevaluated.extend(self.enabled_window_rule_ids())

        service_finding, service_unevaluated = self.service_rule_for(analysis, flow_id)
        unevaluated.extend(service_unevaluated)

        if service_finding is not None:
            findings.append(service_finding)

        blocking = [finding for finding in findings if finding.blocking]

        if blocking:
            primary = blocking[0]
            action = PolicyAction.DROP
        elif service_finding is not None:
            primary = service_finding
            action = PolicyAction.ALLOW
        else:
            primary = self.default_deny(analysis)
            findings.append(primary)
            action = PolicyAction.DROP

        # only requests that are actually allowed can authorize replies
        if ordered and action == PolicyAction.ALLOW and service_finding is not None:
            self.record_request(packet, analysis, flow_id, service_finding)

        return PolicyDecision(
            capture_index=indexed.capture_index,
            flow_id=flow_id,
            action=action,
            rule_id=primary.rule_id,
            reason=primary.reason,
            findings=tuple(finding.public() for finding in findings),
            unevaluated_rule_ids=unique(unevaluated),
        )

    def packet_rules(self, packet: Packet, analysis: PacketAnalysis, findings: list[_Finding], unevaluated: list[str],) -> None:
        if "IP_ENCAPSULATION" in analysis.characteristics:
            # unsupported outer tunnels cannot inherit an inner service or OTHER permission
            findings.append(_Finding(UNSUPPORTED_TUNNEL, "unsupported_ip_tunnel", PolicyScope.PACKET,
                            {"protocol_number": protocol_number(analysis)}))
        
        self.ip_rules(analysis, findings, unevaluated)
        self.structural_rules(analysis, findings, unevaluated)
        self.fragment_rules(analysis, findings, unevaluated)
        self.port_rules(analysis, findings, unevaluated)
        self.flag_rules(packet, analysis, findings, unevaluated)
        self.size_rules(analysis, findings, unevaluated)

    def ip_rules(self,analysis: PacketAnalysis, findings: list[_Finding], unevaluated: list[str]) -> None:
        source = normalize_ip(analysis.network.src_ip)
        destination = normalize_ip(analysis.network.dst_ip)

        for rule_id, network, direction in self._blocked_networks:
            matched = False

            if direction in (IPDirection.SOURCE, IPDirection.EITHER):
                if source is None:
                    unevaluated.append(rule_id)
                elif source.version == network.version and source in network:
                    findings.append(_Finding( rule_id,"source_not_allowed",PolicyScope.PACKET, 
                                             {"network": str(network), "address": str(source), "direction": "SOURCE"}))
                    matched = True

            if not matched and direction in (IPDirection.DESTINATION, IPDirection.EITHER):
                if destination is None:
                    unevaluated.append(rule_id)
                elif destination.version == network.version and destination in network:
                    findings.append(_Finding(rule_id, "destination_not_allowed", PolicyScope.PACKET,
                                    {"network": str(network), "address": str(destination), "direction": "DESTINATION"},))

        if self.config.block_special_sources:
            category = self.special_source_category(source)

            if category is not None:
                findings.append(_Finding(SOURCE_ADDRESS_RESTRICTION, "source_not_allowed", PolicyScope.PACKET,
                                        {"address": str(source), "category": category}))
            elif source is None and analysis.network.ip_version in (4, 6):
                unevaluated.append(SOURCE_ADDRESS_RESTRICTION)

        if (self.config.capture_context in (CaptureContext.WAN_INGRESS, CaptureContext.WAN_EGRESS) and self._boundary_source_networks is not None):
            if source is None:
                unevaluated.append(BOUNDARY_SOURCE_RESTRICTION)
            elif not is_in_networks(source, self._boundary_source_networks):
                findings.append(_Finding(BOUNDARY_SOURCE_RESTRICTION, "source_not_allowed", PolicyScope.PACKET,
                                {"address": str(source), "context": self.config.capture_context.value}))

    def special_source_category(self, source: IPv4Address | IPv6Address | None) -> str | None:
        if source is None:
            return None

        if source.is_multicast:
            return "multicast"

        if source.is_loopback and self.config.capture_context not in (CaptureContext.UNKNOWN, CaptureContext.LOOPBACK):
            return "loopback"

        if source.version == 4:
            if source == IPv4Address("255.255.255.255"):
                return "broadcast"

            # directed broadcast from configured subnets, never from a .255 suffix
            for network in self._local_subnets:
                if network.version != 4 or network.prefixlen >= 31:
                    continue

                if source == network.broadcast_address:
                    return "broadcast"

        return None

    def structural_rules(self, analysis: PacketAnalysis, findings: list[_Finding], unevaluated: list[str]) -> None:
        for key in self.config.required_checks:
            status = check_status(analysis, key)
            if status != CheckStatus.VALID:
                reason = "required_check_invalid" if status == CheckStatus.INVALID else "required_check_unverifiable"
                findings.append(_Finding(f"required.{key}", reason, PolicyScope.PACKET,
                                {"check": key, "status": status.value if status is not None else None}))
                if status != CheckStatus.INVALID:
                    unevaluated.append(f"required.{key}")
        for key in self._fatal_checks:
            status = check_status(analysis, key)

            if status is None:
                continue

            if status == CheckStatus.INVALID:
                findings.append(_Finding(f"structural.{key}","structural_check_invalid", PolicyScope.PACKET,
                                {"check": key, "status": status.value}))
                
            elif status in (CheckStatus.INCOMPLETE, CheckStatus.NOT_CHECKED):
                unevaluated.append(f"structural.{key}")

    def fragment_rules(self, analysis: PacketAnalysis, findings: list[_Finding], unevaluated: list[str]) -> None:
        if not self.config.block_fragments:
            return

        if "FRAGMENTED_PACKET" in analysis.characteristics:
            findings.append(_Finding(IP_FRAGMENT, "fragment_not_supported",PolicyScope.PACKET,
                            {"fragment_offset": analysis.network.ip_fragment_offset, "more_fragments": analysis.network.ip_more_fragments}))
            return

        if analysis.network.ip_version in (4, 6):
            status = check_status(analysis, "ip_fragmentation_consistency")

            if status not in (CheckStatus.VALID, CheckStatus.INVALID):
                unevaluated.append(IP_FRAGMENT)
                findings.append(_Finding(IP_FRAGMENT, "fragmentation_unverifiable", PolicyScope.PACKET,
                                {"check": "ip_fragmentation_consistency", "status": status.value if status is not None else None}))
                
            elif status == CheckStatus.INVALID:
                findings.append(_Finding(IP_FRAGMENT, "fragmentation_invalid", PolicyScope.PACKET,
                                {"check": "ip_fragmentation_consistency", "status": status.value}))

    def port_rules(self, analysis: PacketAnalysis, findings: list[_Finding], unevaluated: list[str]) -> None:
        ports = self.transport_ports(analysis)
        source_port, destination_port = ports if ports is not None else (None, None)

        for rule_id, protocol, port in self._blocked_destination_ports:
            if analysis.protocol != protocol:
                continue

            if not is_int(destination_port) or not 0 <= destination_port <= MAX_PORT:
                unevaluated.append(rule_id)
            elif destination_port == port:
                findings.append(_Finding(rule_id, "destination_port_blocked", PolicyScope.PACKET,
                                {"protocol": protocol, "port": port, "direction": "DESTINATION"}))

        for rule_id, protocol, port in self._blocked_source_ports:
            if analysis.protocol != protocol:
                continue

            if not is_int(source_port) or not 0 <= source_port <= MAX_PORT:
                unevaluated.append(rule_id)
            elif source_port == port:
                findings.append(_Finding(rule_id, "source_port_blocked", PolicyScope.PACKET,
                                {"protocol": protocol, "port": port, "direction": "SOURCE"}))

    def flag_rules(self, packet: Packet, analysis: PacketAnalysis, findings: list[_Finding], unevaluated: list[str]) -> None:
        if analysis.protocol != "TCP":
            return

        flags = tcp_flags_state(packet)
        enabled = ((self.config.block_syn_fin, TCP_SYN_FIN), (self.config.block_syn_rst, TCP_SYN_RST), (self.config.block_null_flags, TCP_NULL_FLAGS))

        if flags is None:
            for active, rule_id in enabled:
                if active:
                    unevaluated.append(rule_id)
            return

        if self.config.block_syn_fin and "SYN" in flags and "FIN" in flags:
            findings.append(_Finding(TCP_SYN_FIN, "tcp_flags_disallowed", PolicyScope.PACKET, {"flags": sorted(flags)}))

        if self.config.block_syn_rst and "SYN" in flags and "RST" in flags:
            findings.append(_Finding(TCP_SYN_RST, "tcp_flags_disallowed", PolicyScope.PACKET, {"flags": sorted(flags)}))

        if self.config.block_null_flags and not flags:
            findings.append(_Finding(TCP_NULL_FLAGS, "tcp_flags_disallowed", PolicyScope.PACKET, {"flags": []}))

    def size_rules(self, analysis: PacketAnalysis, findings: list[_Finding], unevaluated: list[str]) -> None:
        limits = self.config.size_limits

        if limits.max_l3_length is not None:
            length = l3_length(analysis)

            if length is None:
                if analysis.network.ip_version in (4, 6):
                    unevaluated.append(L3_SIZE_LIMIT)
            elif length > limits.max_l3_length:
                findings.append(_Finding(L3_SIZE_LIMIT, "l3_length_limit_exceeded", PolicyScope.PACKET, {"l3_length": length, "limit": limits.max_l3_length}))


    # --- WINDOW RULES ---

    def should_sweep_windows(self, timestamp: float) -> bool:
        if not self.enabled_window_rule_ids():
            return False

        return self._last_window_sweep is None or timestamp - self._last_window_sweep >= 1.0

    def sweep_windows(self, timestamp: float) -> None:
        limits = self.config.window_limits

        if limits.packet_flood_window is not None:
            self.sweep_timestamp_map(self._packet_flood, timestamp - limits.packet_flood_window)


        if limits.syn_flood_window is not None:
            self.sweep_timestamp_map(self._syn_flood, timestamp - limits.syn_flood_window)

        if limits.echo_flood_window is not None:
            self.sweep_timestamp_map(self._echo_flood, timestamp - limits.echo_flood_window)

        if limits.port_scan_window is not None or limits.udp_port_scan_window is not None:
            self.sweep_port_scans(timestamp)


        if limits.host_scan_window is not None:
            self.sweep_distinct_map(self._host_scan, self._host_scan_hosts, timestamp - limits.host_scan_window)


        if limits.small_packet_window is not None:
            self.sweep_timestamp_map(self._small_packets, timestamp - limits.small_packet_window)

        self._last_window_sweep = timestamp

    def sweep_timestamp_map(self, state: dict, cutoff: float) -> None:
        for key in list(state):
            prune_timestamps(state[key], cutoff)

            if not state[key]:
                del state[key]


    def sweep_distinct_map(self, state: dict, counters: dict, cutoff: float) -> None:
        for key in list(state):
            events = state[key]
            counter = counters.get(key)

            if counter is None:
                counter = Counter()
                counters[key] = counter

            prune_distinct(events, counter, cutoff)

            if not events:
                del state[key]
                counters.pop(key, None)


    def window_rules(self,packet: Packet, analysis: PacketAnalysis, timestamp: float) -> tuple[list[_Finding], list[str]]:
        findings: list[_Finding] = []
        unevaluated: list[str] = []

        self.packet_flood_rule(analysis, timestamp, findings, unevaluated)
        self.syn_flood_rule(packet, analysis, timestamp, findings, unevaluated)
        self.echo_flood_rule(analysis, timestamp, findings, unevaluated)
        self.port_scan_rule(packet, analysis, timestamp, findings, unevaluated)
        self.host_scan_rule(packet, analysis, timestamp, findings, unevaluated)
        self.small_packet_rule(packet, analysis, timestamp, findings, unevaluated)

        return findings, unevaluated

    def enabled_window_rule_ids(self) -> tuple[str, ...]:
        limits = self.config.window_limits
        enabled: list[str] = []

        if limits.packet_flood_window is not None:
            enabled.append(WINDOW_PACKET_FLOOD)


        if limits.syn_flood_window is not None:
            enabled.append(WINDOW_SYN_FLOOD)

        if limits.echo_flood_window is not None:
            enabled.append(WINDOW_ECHO_FLOOD)

        if limits.port_scan_window is not None:
            enabled.append(WINDOW_PORT_SCAN)

        if limits.udp_port_scan_window is not None:
            enabled.append(WINDOW_UDP_PORT_SCAN)

        if limits.host_scan_window is not None:
            enabled.append(WINDOW_HOST_SCAN)


        if limits.small_packet_window is not None:
            enabled.append(WINDOW_SMALL_PACKETS)

        return tuple(enabled)

    def packet_flood_rule(self, analysis: PacketAnalysis,timestamp: float, findings: list[_Finding], unevaluated: list[str]) -> None:
        limits = self.config.window_limits

        if limits.packet_flood_window is None:
            return

        key = self.window_key(analysis)

        if key is None:
            unevaluated.append(WINDOW_PACKET_FLOOD)
            return

        events = self._packet_flood.setdefault(key, deque())
        prune_timestamps(events, timestamp - limits.packet_flood_window)
        events.append(timestamp)

        if len(events) > limits.packet_flood_max:
            findings.append(_Finding(WINDOW_PACKET_FLOOD, "packet_flood_limit_exceeded", PolicyScope.WINDOW, {"packet_count": len(events), "limit": limits.packet_flood_max}))


    def syn_flood_rule(self, packet: Packet, analysis: PacketAnalysis, timestamp: float, findings: list[_Finding], unevaluated: list[str]) -> None:
        limits = self.config.window_limits

        if limits.syn_flood_window is None or analysis.protocol != "TCP":
            return

        endpoints = self.packet_endpoints(analysis)
        flags = tcp_flags_state(packet)

        if endpoints is None or flags is None:
            unevaluated.append(WINDOW_SYN_FLOOD)
            return

        source_ip, _, destination_ip, destination_port = endpoints

        if "SYN" not in flags or "ACK" in flags:
            return

        if not self.payload_verified_zero(analysis):
            return

        key = (source_ip, destination_ip, PROTOCOL_NUMBERS["TCP"], destination_port)
        events = self._syn_flood.setdefault(key, deque())
        prune_timestamps(events, timestamp - limits.syn_flood_window)
        events.append(timestamp)

        if len(events) > limits.syn_flood_max:
            findings.append(_Finding(WINDOW_SYN_FLOOD, "syn_flood_limit_exceeded", PolicyScope.WINDOW,
                            {"syn_count": len(events), "limit": limits.syn_flood_max}))

    def echo_flood_rule(self, analysis: PacketAnalysis, timestamp: float, findings: list[_Finding], unevaluated: list[str]) -> None:
        limits = self.config.window_limits

        if limits.echo_flood_window is None or analysis.protocol not in ("ICMP", "ICMPv6"):
            return

        if not self.echo_request_valid(analysis):
            if not isinstance(analysis.transport, ICMPInfo):
                unevaluated.append(WINDOW_ECHO_FLOOD)
            elif (not is_int(analysis.transport.type) or not is_int(analysis.transport.code) or not check_valid(analysis, "icmp_fields_completeness")):
                unevaluated.append(WINDOW_ECHO_FLOOD)
            return

        endpoints = self.ip_pair(analysis)

        if endpoints is None:
            unevaluated.append(WINDOW_ECHO_FLOOD)
            return

        source_ip, destination_ip = endpoints
        key = (source_ip, destination_ip, analysis.protocol)
        events = self._echo_flood.setdefault(key, deque())
        prune_timestamps(events, timestamp - limits.echo_flood_window)
        events.append(timestamp)

        if len(events) > limits.echo_flood_max:
            findings.append(_Finding(WINDOW_ECHO_FLOOD,"echo_flood_limit_exceeded", PolicyScope.WINDOW,
                            {"echo_requests": len(events), "limit": limits.echo_flood_max}))

    def port_scan_rule(self, packet: Packet, analysis: PacketAnalysis, timestamp: float, findings: list[_Finding], unevaluated: list[str]) -> None:
        limits = self.config.window_limits
        if analysis.protocol == "TCP":
            window, maximum, rule_id = limits.port_scan_window, limits.port_scan_max_ports, WINDOW_PORT_SCAN
        elif analysis.protocol == "UDP":
            window, maximum, rule_id = limits.udp_port_scan_window, limits.udp_port_scan_max_ports, WINDOW_UDP_PORT_SCAN
        else:
            return
        if window is None:
            return
        endpoints = self.packet_endpoints(analysis)
        flags = tcp_flags_state(packet) if analysis.protocol == "TCP" else frozenset()
        if endpoints is None or flags is None:
            unevaluated.append(rule_id)
            return
        if analysis.protocol == "TCP" and not self.scan_event(flags):
            return
        source_ip, _, destination_ip, destination_port = endpoints
        key = (source_ip, destination_ip, PROTOCOL_NUMBERS[analysis.protocol])
        events = self._port_scan.setdefault(key, deque())
        ports = self._port_scan_ports.setdefault(key, Counter())
        update_distinct(events, ports, timestamp, window, destination_port)
        if len(ports) >= maximum:
            findings.append(_Finding(rule_id, "port_scan_limit_exceeded" if analysis.protocol == "TCP" else "udp_port_scan_limit_exceeded", PolicyScope.WINDOW,
                            {"protocol": analysis.protocol, "distinct_ports": len(ports), "limit": maximum}))

    def sweep_port_scans(self, timestamp: float) -> None:
        limits = self.config.window_limits
        for key in list(self._port_scan):
            window = limits.port_scan_window if key[2] == 6 else limits.udp_port_scan_window
            events, ports = self._port_scan[key], self._port_scan_ports[key]
            prune_distinct(events, ports, timestamp - window)
            if not events:
                del self._port_scan[key]
                del self._port_scan_ports[key]


    def host_scan_rule(self, packet: Packet, analysis: PacketAnalysis, timestamp: float, findings: list[_Finding], unevaluated: list[str]) -> None:
        limits = self.config.window_limits

        if limits.host_scan_window is None:
            return

        endpoints = self.ip_pair(analysis)
        protocol = protocol_number(analysis)

        if endpoints is None or protocol is None:
            unevaluated.append(WINDOW_HOST_SCAN)
            return

        if not self.host_scan_event(packet, analysis):
            if analysis.protocol == "TCP" and tcp_flags_state(packet) is None:
                unevaluated.append(WINDOW_HOST_SCAN)
            elif analysis.protocol in ("ICMP", "ICMPv6"):
                if (not isinstance(analysis.transport, ICMPInfo) or not is_int(analysis.transport.type) or not is_int(analysis.transport.code) or not check_valid(analysis, "icmp_fields_completeness")):
                    unevaluated.append(WINDOW_HOST_SCAN)
            return

        source_ip, destination_ip = endpoints
        key = (source_ip, protocol)
        events = self._host_scan.setdefault(key, deque())
        hosts = self._host_scan_hosts.setdefault(key, Counter())
        update_distinct(events, hosts, timestamp, limits.host_scan_window, destination_ip)

        if len(hosts) >= limits.host_scan_max_hosts:
            findings.append(_Finding(WINDOW_HOST_SCAN, "host_scan_limit_exceeded", PolicyScope.WINDOW,
                            {"distinct_hosts": len(hosts), "limit": limits.host_scan_max_hosts} ))

    def host_scan_event(self, packet: Packet, analysis: PacketAnalysis) -> bool:
        if analysis.protocol == "TCP":
            flags = tcp_flags_state(packet)

            if flags is None:
                return False

            return self.scan_event(flags)

        if analysis.protocol == "UDP":
            return True

        if analysis.protocol in ("ICMP", "ICMPv6"):
            return self.echo_request_valid(analysis)

        return False


    def small_packet_rule(self, packet: Packet, analysis: PacketAnalysis, timestamp: float, findings: list[_Finding], unevaluated: list[str]) -> None:
        limits = self.config.window_limits
        if limits.small_packet_window is None:
            return
        key, length = self.window_key(analysis), l3_length(analysis)
        if key is None or length is None:
            unevaluated.append(WINDOW_SMALL_PACKETS)
            return
        if length > limits.small_packet_max_size or self.pure_ack_candidate(packet, analysis):
            return
        events = self._small_packets.setdefault(key, deque())
        prune_timestamps(events, timestamp - limits.small_packet_window)
        events.append(timestamp)
        if len(events) > limits.small_packet_max:
            findings.append(_Finding(WINDOW_SMALL_PACKETS, "small_packet_limit_exceeded", PolicyScope.WINDOW,
                            {"small_packets": len(events), "limit": limits.small_packet_max, "max_l3_length": limits.small_packet_max_size, "window": limits.small_packet_window}))


    def pure_ack_candidate(self, packet: Packet, analysis: PacketAnalysis) -> bool:
        if analysis.protocol != "TCP":
            return False

        flags = tcp_flags_state(packet)

        if flags is None:
            return False

        # only ACK and a verified empty payload
        if not flags or not flags <= {"ACK", "ECE", "CWR"} or "ACK" not in flags:
            return False

        return self.payload_verified_zero(analysis)


    def service_rule_for(self,analysis: PacketAnalysis, flow_id: int | None) -> tuple[_Finding | None, list[str]]:
        unevaluated: list[str] = []
        authorization = self.authorization_fields(analysis)

        if authorization is None:
            for compiled in self._service_rules:
                if compiled.rule.protocol == analysis.protocol:
                    unevaluated.append(compiled.rule.rule_id)
            return None, unevaluated

        source, destination, source_port, destination_port, icmp = authorization

        # direct service rules, configuration order
        for compiled in self._service_rules:
            if compiled.rule.protocol != analysis.protocol:
                continue

            if self.direct_service_match(compiled, source, destination, destination_port, icmp):
                return self.service_finding(compiled, source, destination, reply=False), unevaluated

        # authorized replies, same flow and inverse endpoints
        if flow_id is not None and analysis.protocol in PORT_BASED_PROTOCOLS:
            for compiled in self._service_rules:
                if compiled.rule.protocol != analysis.protocol or not compiled.rule.allow_replies:
                    continue

                key = (flow_id, destination, destination_port, source, source_port, compiled.rule.rule_id)

                if key in self._authorized_requests:
                    return self.service_finding(compiled, source, destination, reply=True), unevaluated

        return None, unevaluated

    def authorization_fields(self, analysis: PacketAnalysis) -> tuple[str, str, int | None, int | None, tuple[int, int] | None] | None:
        if "NON_INITIAL_FRAGMENT" in analysis.characteristics:
            return None
        for key in AUTHORIZATION_CHECKS:
            if not check_valid(analysis, key):
                return None

        source = normalize_ip(analysis.network.src_ip)
        destination = normalize_ip(analysis.network.dst_ip)

        if source is None or destination is None:
            return None

        source_port = None
        destination_port = None
        icmp = None

        if analysis.protocol in PORT_BASED_PROTOCOLS:
            ports = self.transport_ports(analysis)

            if ports is None:
                return None

            source_port, destination_port = ports

            if not is_int(source_port) or not is_int(destination_port):
                return None

            if not 0 <= source_port <= MAX_PORT or not 0 <= destination_port <= MAX_PORT:
                return None

            required = "tcp_ports_range" if analysis.protocol == "TCP" else "udp_ports_range"

            if not check_valid(analysis, required):
                return None

        if analysis.protocol in ("ICMP", "ICMPv6"):
            if not isinstance(analysis.transport, ICMPInfo):
                return None

            if not is_int(analysis.transport.type) or not is_int(analysis.transport.code):
                return None

            if not check_valid(analysis, "icmp_fields_completeness"):
                return None

            icmp = (analysis.transport.type, analysis.transport.code)

        return str(source), str(destination), source_port, destination_port, icmp

    def direct_service_match(self, compiled: _CompiledServiceRule, source: str, destination: str, destination_port: int | None, icmp: tuple[int, int] | None) -> bool:
        source_address = ip_address(source)
        destination_address = ip_address(destination)

        if compiled.source_networks is not None:
            if not is_in_networks(source_address, compiled.source_networks):
                return False

        if compiled.destination_networks is not None:
            if not is_in_networks(destination_address, compiled.destination_networks):
                return False

        if compiled.rule.protocol in PORT_BASED_PROTOCOLS:
            if not is_int(destination_port):
                return False

            if compiled.destination_ports is not None and destination_port not in compiled.destination_ports:
                return False

        if compiled.rule.protocol in ("ICMP", "ICMPv6"):
            if icmp is None or icmp not in compiled.icmp_selectors:
                return False

        return True

    def service_finding(self, compiled: _CompiledServiceRule, source: str,destination: str, reply: bool) -> _Finding:
        return _Finding(compiled.rule.rule_id,"service_allowed", PolicyScope.SERVICE,
                {"protocol": compiled.rule.protocol, "source": source, "destination": destination, "reply": reply}, blocking=False)

    def default_deny(self, analysis: PacketAnalysis) -> _Finding:
        evidence: dict[str, object] = {"protocol": analysis.protocol}
        source = normalize_ip(analysis.network.src_ip)
        destination = normalize_ip(analysis.network.dst_ip)

        if source is not None:
            evidence["source"] = str(source)

        if destination is not None:
            evidence["destination"] = str(destination)

        return _Finding(DEFAULT_DENY, "no_matching_service_rule", PolicyScope.DEFAULT, evidence)

    def record_request(self, packet: Packet, analysis: PacketAnalysis,flow_id: int | None, finding: _Finding) -> None:
        # Reply permission for an allowed communication, not full protocol state tracking.
        if flow_id is None or analysis.protocol not in PORT_BASED_PROTOCOLS:
            return

        if finding.evidence.get("reply") is not False:
            return

        compiled = self._service_rule_by_id.get(finding.rule_id)

        if compiled is None or not compiled.rule.allow_replies:
            return

        if analysis.protocol == "TCP":
            flags = tcp_flags_state(packet)

            if flags is None or "SYN" not in flags or "ACK" in flags:
                return

        endpoints = self.packet_endpoints(analysis)

        if endpoints is None:
            return

        source_ip, source_port, destination_ip, destination_port = endpoints

        self._authorized_requests.add((flow_id, source_ip, source_port, destination_ip, destination_port, compiled.rule.rule_id))


    def window_key(self, analysis: PacketAnalysis) -> WindowKey | None:
        endpoints = self.ip_pair(analysis)
        protocol = protocol_number(analysis)

        if endpoints is None or protocol is None:
            return None

        return (endpoints[0], endpoints[1], protocol)

    def ip_pair(self, analysis: PacketAnalysis) -> tuple[str, str] | None:
        if not all(check_valid(analysis, key) for key in AUTHORIZATION_CHECKS):
            return None

        source = normalize_ip(analysis.network.src_ip)
        destination = normalize_ip(analysis.network.dst_ip)

        if source is None or destination is None:
            return None

        return str(source), str(destination)

    def transport_ports(self, analysis: PacketAnalysis) -> tuple[int | None, int | None] | None:
        if isinstance(analysis.transport, (TCPInfo, UDPInfo)):
            return analysis.transport.src_port, analysis.transport.dst_port

        return None

    def packet_endpoints(self, analysis: PacketAnalysis) -> tuple[str, int, str, int] | None:
        if analysis.protocol not in PORT_BASED_PROTOCOLS:
            return None

        required = "tcp_ports_range" if analysis.protocol == "TCP" else "udp_ports_range"
        if not check_valid(analysis, required):
            return None

        ports = self.transport_ports(analysis)

        if ports is None:
            return None

        source_port, destination_port = ports

        if (not is_int(source_port) or not is_int(destination_port) or not 0 <= source_port <= MAX_PORT or not 0 <= destination_port <= MAX_PORT):
            return None

        endpoints = self.ip_pair(analysis)

        if endpoints is None:
            return None

        return endpoints[0], source_port, endpoints[1], destination_port

    def payload_verified_zero(self, analysis: PacketAnalysis) -> bool:
        payload = analysis.packet.payload_length

        return (is_int(payload) and payload == 0 and check_valid(analysis, "payload_length_consistency"))

    def echo_request_valid(self, analysis: PacketAnalysis) -> bool:
        if "ECHO_REQUEST" not in analysis.characteristics:
            return False

        if not isinstance(analysis.transport, ICMPInfo):
            return False

        if not is_int(analysis.transport.type) or not is_int(analysis.transport.code):
            return False

        if analysis.transport.code != 0:
            return False

        return check_valid(analysis, "icmp_fields_completeness")

    def scan_event(self, flags: frozenset[str]) -> bool:
        syn_scan = "SYN" in flags and "ACK" not in flags
        fin_scan = "FIN" in flags and "SYN" not in flags and "RST" not in flags and "ACK" not in flags

        return syn_scan or fin_scan

