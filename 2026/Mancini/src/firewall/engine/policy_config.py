from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Network, IPv6Network, ip_network
from math import isfinite

from firewall.analysis.util import is_int
from firewall.schemas.packet import TransportProtocol

# --- CONSTANTS ---

Network = IPv4Network | IPv6Network

# check keys that may be configured as fatal
KNOWN_CHECK_KEYS = frozenset({
    "timestamp_valid",
    "packet_length_consistency",
    "payload_length_consistency",
    "protocol_fields_consistency",
    "src_ip_format",
    "dst_ip_format",
    "ip_version_consistency",
    "ip_header_length",
    "ip_next_header_range",
    "ip_extension_headers_length",
    "ip_last_next_header_range",
    "ip_fragmentation_consistency",
    "tcp_ports_range",
    "tcp_header_length",
    "tcp_sequence_number_range",
    "tcp_ack_number_range",
    "udp_ports_range",
    "udp_length_consistency",
    "icmp_fields_completeness",
    "icmp_message_length",
})

SERVICE_PROTOCOLS = frozenset({"TCP", "UDP", "ICMP", "ICMPv6", "OTHER"})

PORT_PROTOCOLS = frozenset({"TCP", "UDP"})

ICMP_PROTOCOLS = frozenset({"ICMP", "ICMPv6"})

MAX_PORT = 65535
MAX_ICMP_FIELD = 255

# fixed engine identifiers and generated namespaces are not user rule IDs
RESERVED_RULE_IDS = frozenset({
    "TCP_HANDSHAKE_INCOMPLETE", "TCP_STATE_ANOMALY",
    "SOURCE_ADDRESS_RESTRICTION", "BOUNDARY_SOURCE_RESTRICTION", "IP_FRAGMENT",
    "TCP_SYN_FIN", "TCP_SYN_RST", "TCP_NULL_FLAGS", "L3_SIZE_LIMIT",
    "FLOW_PACKET_RATE", "FLOW_BYTE_RATE", "FLOW_DURATION", "FLOW_BYTE_COUNT",
    "WINDOW_PACKET_FLOOD", "WINDOW_SYN_FLOOD", "WINDOW_ECHO_FLOOD",
    "WINDOW_PORT_SCAN", "WINDOW_UDP_PORT_SCAN", "WINDOW_HOST_SCAN", "WINDOW_SMALL_PACKETS",
    "DEFAULT_DENY", "INVALID_TIMESTAMP", "UNSUPPORTED_TUNNEL",
})


class CaptureContext(StrEnum):
    UNKNOWN = "UNKNOWN"
    LAN = "LAN"
    WAN_INGRESS = "WAN_INGRESS"
    WAN_EGRESS = "WAN_EGRESS"
    LOOPBACK = "LOOPBACK"


class IPDirection(StrEnum):
    SOURCE = "SOURCE"
    DESTINATION = "DESTINATION"
    EITHER = "EITHER"


# --- CONFIGURATION MODELS ---

@dataclass(frozen=True, slots=True)
class ICMPSelector:
    type: int
    code: int


@dataclass(frozen=True, slots=True)
class ServiceRule:
    # a selector is universal only when it is explicitly None:
    # an empty tuple is not ANY
    rule_id: str
    protocol: TransportProtocol
    source_networks: tuple[str, ...] | None
    destination_networks: tuple[str, ...] | None
    destination_ports: tuple[int, ...] | None
    icmp_selectors: tuple[ICMPSelector, ...]
    allow_replies: bool = False


@dataclass(frozen=True, slots=True)
class PortRestriction:
    rule_id: str
    protocol: TransportProtocol
    port: int


@dataclass(frozen=True, slots=True)
class IPRestriction:
    rule_id: str
    network: str
    direction: IPDirection = IPDirection.EITHER


@dataclass(frozen=True, slots=True)
class SizeLimits:
    max_l3_length: int | None = None


@dataclass(frozen=True, slots=True)
class FlowLimits:
    max_packets_per_second: float | None = None
    max_bytes_per_second: float | None = None
    max_duration: float | None = None
    max_flow_bytes: int | None = None

    rate_min_duration: float = 1.0
    rate_min_packets: int = 20



@dataclass(frozen=True, slots=True)
class FlowLimitRule:
    rule_id: str
    limits: FlowLimits
    protocol: TransportProtocol | None = None
    service_rule_id: str | None = None


@dataclass(frozen=True, slots=True)
class WindowLimits:
    # flood/small-packet maxima allow equality: block when count > maximum
    packet_flood_window: float | None = None
    packet_flood_max: int | None = None


    syn_flood_window: float | None = None
    syn_flood_max: int | None = None

    echo_flood_window: float | None = None
    echo_flood_max: int | None = None

    port_scan_window: float | None = None
    # scan values are activation thresholds: block when distinct count >= value
    port_scan_max_ports: int | None = None

    udp_port_scan_window: float | None = None
    udp_port_scan_max_ports: int | None = None

    host_scan_window: float | None = None
    host_scan_max_hosts: int | None = None


    small_packet_window: float | None = None
    small_packet_max: int | None = None
    small_packet_max_size: int = 80


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    service_rules: tuple[ServiceRule, ...] = ()

    blocked_source_ports: tuple[PortRestriction, ...] = ()
    blocked_destination_ports: tuple[PortRestriction, ...] = ()
    blocked_networks: tuple[IPRestriction, ...] = ()

    # only INVALID statuses are blocked by these checks
    fatal_checks: tuple[str, ...] = ()
    # explicit authorization requirements: missing or non-VALID means DROP
    required_checks: tuple[str, ...] = ()

    block_fragments: bool = False
    block_syn_fin: bool = False
    block_syn_rst: bool = False
    block_null_flags: bool = False
    block_special_sources: bool = True

    size_limits: SizeLimits = SizeLimits()
    flow_limits: FlowLimits = FlowLimits()
    flow_limit_rules: tuple[FlowLimitRule, ...] = ()
    window_limits: WindowLimits = WindowLimits()


    capture_context: CaptureContext = CaptureContext.UNKNOWN
    # allowed source prefixes for this capture point AND its selected WAN direction
    # ingress and egress may need different prefixes; UNKNOWN does not apply them
    boundary_source_networks: tuple[str, ...] | None = None
    local_subnets: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_policy_config(self)


# --- VALIDATION ---

def is_finite_number(value: object) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False

    try:
        return isfinite(value)
    except OverflowError:
        # integers too large for a float
        return False


def parse_networks(networks: tuple[str, ...], label: str) -> tuple[Network, ...]:
    if not isinstance(networks, tuple):
        raise ValueError(f"{label} must be a tuple of CIDR strings")

    parsed: list[Network] = []

    for value in networks:
        if not isinstance(value, str) or not value:
            raise ValueError(f"{label}: invalid CIDR value {value!r}")

        try:
            # strict=True: no silent host-bit correction
            parsed.append(ip_network(value, strict=True))
        except ValueError as exc:
            raise ValueError(f"{label}: invalid CIDR {value!r}") from exc

    return tuple(parsed)


def validate_networks(networks: tuple[str, ...] | None, label: str) -> None:
    if networks is None:
        return

    if not isinstance(networks, tuple):
        raise ValueError(f"{label} must be None or a tuple of CIDR strings")

    if not networks:
        raise ValueError(f"{label}: an empty selector is not ANY")

    parse_networks(networks, label)


def validate_finite(value: object, label: str, minimum: float | None = None, maximum: float | None = None, strict_minimum: bool = False) -> None:
    if not is_finite_number(value):
        raise ValueError(f"{label} must be a finite number")

    number = float(value)

    if minimum is not None:
        if strict_minimum and number <= minimum:
            raise ValueError(f"{label} must be greater than {minimum}")
        if not strict_minimum and number < minimum:
            raise ValueError(f"{label} must be at least {minimum}")

    if maximum is not None and number > maximum:
        raise ValueError(f"{label} must be at most {maximum}")


def validate_count(value: object, label: str, minimum: int = 0) -> None:
    if not is_int(value) or value < minimum:
        raise ValueError(f"{label} must be an integer >= {minimum}")


def validate_pair(window: object, maximum: object, window_label: str, maximum_label: str, maximum_minimum: int = 1) -> None:
    if (window is None) != (maximum is None):
        raise ValueError(f"{window_label} and {maximum_label} must be set together")

    if window is None:
        return

    validate_finite(window, window_label, minimum=0.0, strict_minimum=True)
    validate_count(maximum, maximum_label, minimum=maximum_minimum)


def validate_rule_id(rule_id: str) -> None:
    if not isinstance(rule_id, str) or not rule_id:
        raise ValueError("rule ID must be a non-empty string")
    
    if rule_id in RESERVED_RULE_IDS or rule_id.startswith(("required.", "structural.")):
        raise ValueError(f"reserved rule ID: {rule_id}")


def validate_service_rule(rule: ServiceRule) -> None:
    validate_rule_id(rule.rule_id)

    if rule.protocol not in SERVICE_PROTOCOLS:
        raise ValueError(f"{rule.rule_id}: unsupported service protocol {rule.protocol}")

    validate_networks(rule.source_networks, f"{rule.rule_id}.source_networks")
    validate_networks(rule.destination_networks, f"{rule.rule_id}.destination_networks")

    if not isinstance(rule.allow_replies, bool):
        raise ValueError(f"{rule.rule_id}.allow_replies must be boolean")

    if rule.allow_replies and rule.protocol not in PORT_PROTOCOLS:
        raise ValueError(f"{rule.rule_id}: allow_replies is only valid for TCP and UDP")

    if rule.protocol in PORT_PROTOCOLS:
        if rule.destination_ports is not None:
            if not isinstance(rule.destination_ports, tuple) or not rule.destination_ports:
                raise ValueError(f"{rule.rule_id}.destination_ports must be None or a non-empty tuple")

            if len(set(rule.destination_ports)) != len(rule.destination_ports):
                raise ValueError(f"{rule.rule_id}.destination_ports contains duplicates")

            for port in rule.destination_ports:
                if not is_int(port) or not 0 <= port <= MAX_PORT:
                    raise ValueError(f"{rule.rule_id}: destination port {port!r} outside 0-{MAX_PORT}")

        if rule.icmp_selectors:
            raise ValueError(f"{rule.rule_id}: ICMP selectors are not valid for {rule.protocol}")
        return

    if rule.destination_ports is not None:
        raise ValueError(f"{rule.rule_id}: destination_ports is only valid for TCP and UDP")

    if rule.protocol in ICMP_PROTOCOLS:
        if not isinstance(rule.icmp_selectors, tuple) or not rule.icmp_selectors:
            raise ValueError(f"{rule.rule_id}: ICMP rules require explicit type/code selectors")

        if any(not isinstance(selector, ICMPSelector) for selector in rule.icmp_selectors):
            raise ValueError(f"{rule.rule_id}: invalid ICMP selector")

        pairs = [(selector.type, selector.code) for selector in rule.icmp_selectors]

        if len(set(pairs)) != len(pairs):
            raise ValueError(f"{rule.rule_id}.icmp_selectors contains duplicates")

        for selector in rule.icmp_selectors:
            if not is_int(selector.type) or not 0 <= selector.type <= MAX_ICMP_FIELD:
                raise ValueError(f"{rule.rule_id}: ICMP type outside 0-{MAX_ICMP_FIELD}")

            if not is_int(selector.code) or not 0 <= selector.code <= MAX_ICMP_FIELD:
                raise ValueError(f"{rule.rule_id}: ICMP code outside 0-{MAX_ICMP_FIELD}")
        return

    # OTHER has neither ports nor type/code
    if rule.icmp_selectors:
        raise ValueError(f"{rule.rule_id}: ICMP selectors are not valid for {rule.protocol}")


def validate_port_restriction(restriction: PortRestriction) -> None:
    validate_rule_id(restriction.rule_id)

    if restriction.protocol not in PORT_PROTOCOLS:
        raise ValueError(f"{restriction.rule_id}: port restrictions require TCP or UDP")

    if not is_int(restriction.port) or not 0 <= restriction.port <= MAX_PORT:
        raise ValueError(f"{restriction.rule_id}: port {restriction.port!r} outside 0-{MAX_PORT}")


def validate_ip_restriction(restriction: IPRestriction) -> None:
    validate_rule_id(restriction.rule_id)

    parse_networks((restriction.network,), f"{restriction.rule_id}.network")

    if not isinstance(restriction.direction, IPDirection):
        raise ValueError(f"{restriction.rule_id}: invalid IP direction")


def validate_size_limits(limits: SizeLimits) -> None:
    if limits.max_l3_length is not None:
        validate_count(limits.max_l3_length, "size_limits.max_l3_length", minimum=1)


def validate_flow_limits(limits: FlowLimits) -> None:
    validate_finite(limits.rate_min_duration, "flow_limits.rate_min_duration", minimum=0.0)
    validate_count(limits.rate_min_packets, "flow_limits.rate_min_packets", minimum=1)
    if limits.max_packets_per_second is not None:
        validate_finite(limits.max_packets_per_second, "flow_limits.max_packets_per_second", minimum=0.0)

    if limits.max_bytes_per_second is not None:
        validate_finite(limits.max_bytes_per_second, "flow_limits.max_bytes_per_second", minimum=0.0)

    if limits.max_duration is not None:
        validate_finite(limits.max_duration, "flow_limits.max_duration", minimum=0.0)

    if limits.max_flow_bytes is not None:
        validate_count(limits.max_flow_bytes, "flow_limits.max_flow_bytes", minimum=0)



def validate_window_limits(limits: WindowLimits) -> None:
    validate_pair(limits.packet_flood_window, limits.packet_flood_max, "window_limits.packet_flood_window", "window_limits.packet_flood_max")


    validate_pair(limits.syn_flood_window, limits.syn_flood_max, "window_limits.syn_flood_window", "window_limits.syn_flood_max")

    validate_pair(limits.echo_flood_window, limits.echo_flood_max, "window_limits.echo_flood_window", "window_limits.echo_flood_max")

    validate_pair(limits.port_scan_window, limits.port_scan_max_ports, "window_limits.port_scan_window", "window_limits.port_scan_max_ports")

    validate_pair(limits.udp_port_scan_window, limits.udp_port_scan_max_ports, "window_limits.udp_port_scan_window", "window_limits.udp_port_scan_max_ports")

    validate_pair(limits.host_scan_window, limits.host_scan_max_hosts, "window_limits.host_scan_window", "window_limits.host_scan_max_hosts")


    validate_pair(limits.small_packet_window, limits.small_packet_max, "window_limits.small_packet_window", "window_limits.small_packet_max")


    validate_count(limits.small_packet_max_size, "window_limits.small_packet_max_size", minimum=0)


def validate_policy_config(config: PolicyConfig) -> None:
    if not isinstance(config.service_rules, tuple):
        raise ValueError("service_rules must be a tuple")

    service_rule_ids: set[str] = set()
    service_rules: dict[str, ServiceRule] = {}

    for rule in config.service_rules:
        if not isinstance(rule, ServiceRule):
            raise ValueError("service_rules must contain ServiceRule objects")

        validate_service_rule(rule)

        if rule.rule_id in service_rule_ids:
            raise ValueError(f"duplicate rule ID: {rule.rule_id}")

        service_rule_ids.add(rule.rule_id)
        service_rules[rule.rule_id] = rule

    port_rule_ids: set[str] = set()

    if not isinstance(config.blocked_source_ports, tuple) or not isinstance(config.blocked_destination_ports, tuple):
        raise ValueError("blocked source and destination ports must be tuples")

    for restriction in config.blocked_source_ports + config.blocked_destination_ports:
        if not isinstance(restriction, PortRestriction):
            raise ValueError("port restrictions must contain PortRestriction objects")

        validate_port_restriction(restriction)

        if restriction.rule_id in port_rule_ids:
            raise ValueError(f"duplicate rule ID: {restriction.rule_id}")

        port_rule_ids.add(restriction.rule_id)

    ip_rule_ids: set[str] = set()

    if not isinstance(config.blocked_networks, tuple):
        raise ValueError("blocked_networks must be a tuple")

    for restriction in config.blocked_networks:
        if not isinstance(restriction, IPRestriction):
            raise ValueError("blocked_networks must contain IPRestriction objects")

        validate_ip_restriction(restriction)

        if restriction.rule_id in ip_rule_ids:
            raise ValueError(f"duplicate rule ID: {restriction.rule_id}")

        ip_rule_ids.add(restriction.rule_id)

    if not isinstance(config.required_checks, tuple):
        raise ValueError("required_checks must be a tuple")
    for key in config.required_checks:
        if not isinstance(key, str) or key not in KNOWN_CHECK_KEYS:
            raise ValueError(f"unknown required check key: {key}")
    if len(set(config.required_checks)) != len(config.required_checks):
        raise ValueError("required_checks contains duplicates")

    if not isinstance(config.fatal_checks, tuple):
        raise ValueError("fatal_checks must be a tuple")

    if len(set(config.fatal_checks)) != len(config.fatal_checks):
        raise ValueError("fatal_checks contains duplicates")

    for key in config.fatal_checks:
        if key not in KNOWN_CHECK_KEYS:
            raise ValueError(f"unknown check key: {key}")

    for label, value in (
        ("block_fragments", config.block_fragments),
        ("block_syn_fin", config.block_syn_fin),
        ("block_syn_rst", config.block_syn_rst),
        ("block_null_flags", config.block_null_flags),
        ("block_special_sources", config.block_special_sources),
    ):
        if not isinstance(value, bool):
            raise ValueError(f"{label} must be boolean")

    if not isinstance(config.size_limits, SizeLimits):
        raise ValueError("size_limits must be a SizeLimits")

    if not isinstance(config.flow_limits, FlowLimits):
        raise ValueError("flow_limits must be a FlowLimits")

    if not isinstance(config.window_limits, WindowLimits):
        raise ValueError("window_limits must be a WindowLimits")

    validate_size_limits(config.size_limits)
    validate_flow_limits(config.flow_limits)
    validate_window_limits(config.window_limits)

    if not isinstance(config.flow_limit_rules, tuple):
        raise ValueError("flow_limit_rules must be a tuple")

    for rule in config.flow_limit_rules:
        if not isinstance(rule, FlowLimitRule):
            raise ValueError("flow_limit_rules must contain FlowLimitRule objects")
        validate_rule_id(rule.rule_id)
        if not isinstance(rule.limits, FlowLimits):
            raise ValueError(f"{rule.rule_id}: limits must be a FlowLimits")
        if rule.protocol is not None and (not isinstance(rule.protocol, str) or rule.protocol not in SERVICE_PROTOCOLS):
            raise ValueError(f"{rule.rule_id}: unsupported flow protocol")
        if rule.protocol is not None and rule.service_rule_id is not None:
            raise ValueError(f"{rule.rule_id}: choose protocol or service, not both")
        if rule.service_rule_id is not None:
            if not isinstance(rule.service_rule_id, str) or rule.service_rule_id not in service_rules:
                raise ValueError(f"{rule.rule_id}: unknown service rule")
        validate_flow_limits(rule.limits)


    # rule IDs are unique across every configurable group
    all_rule_ids = (
        [rule.rule_id for rule in config.service_rules]
        + [rule.rule_id for rule in config.blocked_source_ports]
        + [rule.rule_id for rule in config.blocked_destination_ports]
        + [rule.rule_id for rule in config.blocked_networks]
        + [rule.rule_id for rule in config.flow_limit_rules]
    )

    if len(all_rule_ids) != len(set(all_rule_ids)):
        raise ValueError("duplicate rule ID across configuration groups")

    if not isinstance(config.capture_context, CaptureContext):
        raise ValueError("capture_context must be a CaptureContext")

    parse_networks(config.local_subnets, "local_subnets")

    if config.boundary_source_networks is not None:
        parse_networks(config.boundary_source_networks, "boundary_source_networks")

        if not config.boundary_source_networks:
            raise ValueError("boundary_source_networks: an empty selector is not ANY")

