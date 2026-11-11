from dataclasses import replace

from firewall.engine.policy_config import (
    CaptureContext,
    FlowLimits,
    ICMPSelector,
    IPRestriction,
    PolicyConfig,
    PortRestriction,
    ServiceRule,
    SizeLimits,
    WindowLimits,
)

# --- DEFAULT PROFILE ---

LAN_NETWORK = "192.168.1.0/24"
SERVER_NETWORK = "192.0.2.0/24"      # TEST-NET-1
DNS_NETWORK = "198.51.100.0/24"      # TEST-NET-2

# structural checks enabled for academic checks
DEFAULT_FATAL_CHECKS = (
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
)


def demo_profile() -> PolicyConfig:
    service_rules = (
        ServiceRule(
            rule_id="ALLOW_LAN_WEB",
            protocol="TCP",
            source_networks=(LAN_NETWORK,),
            destination_networks=(SERVER_NETWORK,),
            destination_ports=(80, 443),
            icmp_selectors=(),
            allow_replies=True,
        ),

        ServiceRule(
            rule_id="ALLOW_LAN_DNS",
            protocol="UDP",
            source_networks=(LAN_NETWORK,),
            destination_networks=(DNS_NETWORK,),
            destination_ports=(53,),
            icmp_selectors=(),
            allow_replies=True,
        ),

        ServiceRule(
            rule_id="ALLOW_ICMP_ECHO_REQUEST",
            protocol="ICMP",
            source_networks=(LAN_NETWORK,),
            destination_networks=(SERVER_NETWORK,),
            destination_ports=None,
            icmp_selectors=(ICMPSelector(type=8, code=0),),
        ),
        
        ServiceRule(
            rule_id="ALLOW_ICMP_ECHO_REPLY",
            protocol="ICMP",
            source_networks=(SERVER_NETWORK,),
            destination_networks=(LAN_NETWORK,),
            destination_ports=None,
            icmp_selectors=(ICMPSelector(type=0, code=0),),
        ),
    )

    # the default block is on the destination port; source blocks are separate
    blocked_destination_ports = (
        PortRestriction(rule_id="BLOCK_TCP_TELNET_DEST", protocol="TCP", port=23),
        PortRestriction(rule_id="BLOCK_TCP_RPC_DEST", protocol="TCP", port=135),
        PortRestriction(rule_id="BLOCK_TCP_NETBIOS_DEST", protocol="TCP", port=139),
        PortRestriction(rule_id="BLOCK_TCP_SMB_DEST", protocol="TCP", port=445),
        PortRestriction(rule_id="BLOCK_TCP_RDP_DEST", protocol="TCP", port=3389),
        PortRestriction(rule_id="BLOCK_UDP_RDP_DEST", protocol="UDP", port=3389),
    )

    return PolicyConfig(
        service_rules=service_rules,
        blocked_source_ports=(),
        blocked_destination_ports=blocked_destination_ports,
        blocked_networks=(),
        fatal_checks=DEFAULT_FATAL_CHECKS,
        # protocol-specific authorization checks remain mandatory in the engine
        # no additional capture-dependent checks are required by this profile
        required_checks=(),
        block_fragments=True,
        block_syn_fin=True,
        block_syn_rst=True,
        block_null_flags=True,
        block_special_sources=True,
        size_limits=SizeLimits(
            # optional: it depends on the MTU and requires explicit activation
            max_l3_length=None,
        ),
        flow_limits=FlowLimits(
            max_packets_per_second=1000.0,
            max_bytes_per_second=1_000_000.0,
            max_duration=300.0,
            max_flow_bytes=50_000_000,
        ),
        window_limits=WindowLimits(
            packet_flood_window=1.0,
            packet_flood_max=1000,
            syn_flood_window=1.0,
            syn_flood_max=100,
            echo_flood_window=1.0,
            echo_flood_max=20,
            port_scan_window=10.0,
            port_scan_max_ports=20,
            host_scan_window=10.0,
            host_scan_max_hosts=15,
            small_packet_window=1.0,
            small_packet_max=200,
            small_packet_max_size=80,
        ),
        capture_context=CaptureContext.LAN,
        boundary_source_networks=None,
        local_subnets=(LAN_NETWORK,),
    )

def custom_profile(
    service_rules: tuple[ServiceRule, ...],
    local_subnets: tuple[str, ...],
    *,
    capture_context: CaptureContext = CaptureContext.LAN,
    blocked_source_ports: tuple[PortRestriction, ...] = (),
    blocked_destination_ports: tuple[PortRestriction, ...] = (),
    blocked_networks: tuple[IPRestriction, ...] = (),
    boundary_source_networks: tuple[str, ...] | None = None,
    flow_limits: FlowLimits | None = None,
    window_limits: WindowLimits | None = None,
    size_limits: SizeLimits | None = None,
    block_fragments: bool = True,
) -> PolicyConfig:

    # reuse the demo baseline
    base = demo_profile()

    config = dict(
        service_rules=service_rules,
        local_subnets=local_subnets,
        capture_context=capture_context,
        blocked_source_ports=blocked_source_ports,
        blocked_destination_ports=blocked_destination_ports,
        blocked_networks=blocked_networks,
        boundary_source_networks=boundary_source_networks,
        block_fragments=block_fragments,
    )

    if flow_limits is not None:
        config["flow_limits"] = flow_limits

    if window_limits is not None:
        config["window_limits"] = window_limits

    if size_limits is not None:
        config["size_limits"] = size_limits

    return replace(base, **config)


def example_profile() -> PolicyConfig:
    return custom_profile(
        local_subnets=("192.168.1.0/24",),
        service_rules=(
            ServiceRule(
                rule_id="ALLOW_HOME_WEB",
                protocol="TCP",
                source_networks=("192.168.1.0/24",),
                destination_networks=("0.0.0.0/0",),
                destination_ports=(80, 443),
                icmp_selectors=(),
                allow_replies=True,
            ),
        ),
    )

# --- SYNTHETIC TEST PROFILE ---

def test_profile() -> PolicyConfig:

    test_network = "192.168.10.0/24"

    return custom_profile(
        local_subnets=(test_network,),

        service_rules=(
            # TCP web and synthetic port scans
            ServiceRule(
                rule_id="TEST_ALLOW_TCP",
                protocol="TCP",
                source_networks=(test_network,),
                destination_networks=(test_network,),
                destination_ports=(80, *range(1000, 1012)),
                icmp_selectors=(),
                allow_replies=True,
            ),

            # UDP requests and synthetic port scans
            ServiceRule(
                rule_id="TEST_ALLOW_UDP",
                protocol="UDP",
                source_networks=(test_network,),
                destination_networks=(test_network,),
                destination_ports=(5353, *range(1000, 1012)),
                icmp_selectors=(),
                allow_replies=True,
            ),

            # ICMP Echo Request
            ServiceRule(
                rule_id="TEST_ALLOW_ICMP",
                protocol="ICMP",
                source_networks=(test_network,),
                destination_networks=(test_network,),
                destination_ports=None,
                icmp_selectors=(
                    ICMPSelector(type=8, code=0),
                ),
            ),
        ),

        flow_limits=FlowLimits(
            max_packets_per_second=10000.0,
            max_bytes_per_second=10000000.0,
            max_duration=300.0,
            max_flow_bytes=60000,
        ),

        window_limits=WindowLimits(
            packet_flood_window=2.0,
            packet_flood_max=30,

            syn_flood_window=2.0,
            syn_flood_max=20,

            echo_flood_window=2.0,
            echo_flood_max=20,

            port_scan_window=2.0,
            port_scan_max_ports=10,

            udp_port_scan_window=2.0,
            udp_port_scan_max_ports=10,

            host_scan_window=2.0,
            host_scan_max_hosts=10,

            small_packet_window=2.0,
            small_packet_max=20,
            small_packet_max_size=80,
        ),
    )
