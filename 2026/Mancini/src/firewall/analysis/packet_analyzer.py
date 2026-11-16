from ipaddress import ip_address

from firewall.analysis.util import is_int, tcp_flag_names, valid_timestamp
from firewall.schemas.packet import Packet
from firewall.schemas.packet_analysis import (
    PortRange,
    CheckResult,
    CheckStatus,
    ICMPInfo,
    NetworkInfo,
    OtherTransportInfo,
    PacketAnalysis,
    PacketInfo,
    TCPInfo,
    UDPInfo,
)

# --- CONSTANTS ---

# IP protocol number expected for each interpreted transport protocol
PROTOCOL_NUMBERS = {
    "ICMP": 1,
    "TCP": 6,
    "UDP": 17,
    "ICMPv6": 58,
}

# IPv6 Next Header values that announce an extension header
IPV6_EXTENSION_HEADERS = {0, 43, 44, 51, 60}

REQUIRED_FIELDS = {
    "TCP": (
        "src_port",
        "dst_port",
        "tcp_flags",
        "tcp_header_length",
        "tcp_sequence_number",
        "tcp_ack_number",
    ),
    "UDP": (
        "src_port",
        "dst_port",
        "udp_length",
    ),
    "ICMP": (
        "icmp_type",
        "icmp_code",
    ),
    "ICMPv6": (
        "icmp_type",
        "icmp_code",
    ),
}

MAX_PORT = 65535
MAX_32_BIT = 2**32 - 1
MAX_FRAGMENT_OFFSET = 2**13 - 1
ICMP_HEADER_LENGTH = 8
ETHERNET_HEADER_LENGTH = 14

# ICMP types classified as error messages
ICMPV4_ERROR_TYPES = {3, 4, 5, 11, 12}
ICMPV6_ERROR_TYPES = {1, 2, 3, 4}


def port_range(port: int | None) -> PortRange | None:
    
    if not is_int(port) or port < 0 or port > MAX_PORT:
        return None
    
    if port == 0:
        return "RESERVED"
    
    if port <= 1023:
        return "SYSTEM"
    
    if port <= 49151:
        return "REGISTERED"
    
    return "DYNAMIC"


# --- PACKET ANALYZER ---

class PacketAnalyzer:

    def analyze(self, packet: Packet) -> PacketAnalysis:
        return PacketAnalysis(
            protocol=packet.transport_protocol,
            packet=self.packet_info(packet),
            network=self.network_info(packet),
            transport=self.transport_info(packet),
            checks=self.checks(packet),
            characteristics=self.characteristics(packet),
        )

    # data extraction

    def packet_info(self, packet: Packet) -> PacketInfo:
        return PacketInfo(
            timestamp=packet.timestamp,
            captured_length=packet.captured_length,
            packet_length=packet.packet_length,
            payload_length=packet.payload_length,
        )

    def network_info(self, packet: Packet) -> NetworkInfo:
        return NetworkInfo(
            link_header_length=packet.link_header_length,
            src_mac=packet.src_mac,
            dst_mac=packet.dst_mac,
            ip_version=packet.ip_version,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            ip_next_header=packet.ip_next_header,
            ip_header_length=packet.ip_header_length,
            ip_total_length=packet.ip_total_length,
            ip_payload_length=packet.ip_payload_length,
            ip_extension_headers_length=packet.ip_extension_headers_length,
            ip_last_next_header=packet.ip_last_next_header,
            ip_fragment_offset=packet.ip_fragment_offset,
            ip_more_fragments=packet.ip_more_fragments,
            ip_fragment_header_present=packet.ip_fragment_header_present,
        )

    def transport_info(self, packet: Packet) -> TCPInfo | UDPInfo | ICMPInfo | OtherTransportInfo | None:
        if packet.transport_protocol == "TCP":
            return TCPInfo(
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                flags=tcp_flag_names(packet.tcp_flags),
                header_length=packet.tcp_header_length,
                sequence_number=packet.tcp_sequence_number,
                ack_number=packet.tcp_ack_number,
                src_port_range=port_range(packet.src_port),
                dst_port_range=port_range(packet.dst_port),
            )

        if packet.transport_protocol == "UDP":
            return UDPInfo(
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                length=packet.udp_length,
                src_port_range=port_range(packet.src_port),
                dst_port_range=port_range(packet.dst_port),
            )

        if packet.transport_protocol in ("ICMP", "ICMPv6"):
            return ICMPInfo(
                type=packet.icmp_type,
                code=packet.icmp_code,
            )

        protocol_number = packet.ip_next_header

        if packet.ip_version == 6:
            extension_length = packet.ip_extension_headers_length
            if extension_length is not None:
                if not is_int(extension_length) or extension_length < 0:
                    # Malformed metadata cannot identify the final protocol.
                    protocol_number = None
                elif extension_length > 0:
                    protocol_number = packet.ip_last_next_header

        return OtherTransportInfo(protocol_number=protocol_number)

    # checks

    def checks(self, packet: Packet) -> dict[str, CheckResult]:
        checks: dict[str, CheckResult] = {}

        checks.update(self.check_general(packet))
        checks.update(self.check_network(packet))
        checks.update(self.check_transport(packet))

        return checks

    def check_general(self, packet: Packet) -> dict[str, CheckResult]:

        return {
            "timestamp_valid": self.check_timestamp(packet),
            "packet_length_consistency": self.check_packet_length(packet),
            "payload_length_consistency": self.check_payload_length(packet),
            "protocol_fields_consistency": self.check_protocol_fields(packet),
        }

    def check_timestamp(self, packet: Packet) -> CheckResult:
        timestamp = packet.timestamp

        if timestamp is None:
            return CheckResult(CheckStatus.INCOMPLETE, "timestamp not available")

        if valid_timestamp(timestamp) is not None:
            return CheckResult(CheckStatus.VALID)

        if not isinstance(timestamp, (int, float)) or isinstance(timestamp, bool):
            return CheckResult(CheckStatus.INVALID, "invalid timestamp")

        if timestamp != timestamp:
            return CheckResult(CheckStatus.INVALID, "NaN timestamp")

        if timestamp in (float("inf"), float("-inf")):
            return CheckResult(CheckStatus.INVALID, "infinite timestamp")

        if timestamp < 0:
            return CheckResult(CheckStatus.INVALID, "negative timestamp")

        return CheckResult(CheckStatus.INVALID, "timestamp out of range")

    def check_packet_length(self, packet: Packet) -> CheckResult:
        captured = packet.captured_length
        original = packet.packet_length

        if not is_int(captured) or captured < 0:
            return CheckResult(CheckStatus.INVALID, "invalid captured length")
        
        if captured == 0:
            return CheckResult(CheckStatus.INVALID, "no bytes captured")

        if original is not None:
            if not is_int(original) or original <= 0:
                return CheckResult(CheckStatus.INVALID, "invalid packet length")
            
            if captured > original:
                return CheckResult(CheckStatus.INVALID, "captured bytes exceed packet length")
            
            if packet.ip_total_length is not None:
                if not is_int(packet.ip_total_length):
                    return CheckResult(CheckStatus.INVALID, "invalid ip_total_length")

                if packet.ip_total_length > original:
                    return CheckResult(CheckStatus.INVALID, "ip_total_length exceeds packet length")

        if packet.ip_version == 4 and packet.ip_total_length is not None:
            if not is_int(packet.ip_total_length):
                return CheckResult(CheckStatus.INVALID, "invalid ip_total_length")
            link_length = packet.link_header_length
            if link_length is not None:
                if not is_int(link_length) or link_length < 0:
                    return CheckResult(CheckStatus.INVALID, "invalid link header length")
                declared_length = link_length + packet.ip_total_length
                if original is not None and declared_length > original:
                    return CheckResult(CheckStatus.INVALID, "declared IPv4 length exceeds original frame length")
                if declared_length > captured:
                    return CheckResult(CheckStatus.INCOMPLETE, "IPv4 packet not fully captured")

        if packet.ip_version == 6:
            payload = packet.ip_payload_length
            link_length = packet.link_header_length
            if payload is None:
                return CheckResult(CheckStatus.INCOMPLETE, "IPv6 payload length unavailable")
            if not is_int(payload) or not 0 <= payload <= 65535:
                return CheckResult(CheckStatus.INVALID, "invalid IPv6 payload length")
            if link_length is None:
                return CheckResult(CheckStatus.INCOMPLETE, "link header length unavailable")
            if not is_int(link_length) or link_length < 0:
                return CheckResult(CheckStatus.INVALID, "invalid link header length")
            declared_length = link_length + 40 + payload
            if original is not None and declared_length > original:
                return CheckResult(CheckStatus.INVALID, "declared IPv6 length exceeds original frame length")
            if declared_length > captured:
                return CheckResult(CheckStatus.INCOMPLETE, "IPv6 packet not fully captured")

        # a negative IP payload means the declared lengths contradict each other
        ip_payload = self.ip_payload_available(packet)
        if ip_payload is not None and ip_payload < 0:
            if packet.ip_version == 6:
                return CheckResult(CheckStatus.INVALID, "IPv6 payload smaller than extension headers")
            
            return CheckResult(CheckStatus.INVALID, "ip_total_length smaller than the IP header")

        # The declared protocol needs room for its header even when the reader
        # cannot decode transport fields. Ethernet padding is not IP payload.
        if (packet.ip_version == 4
            and is_int(packet.ip_next_header) and packet.ip_next_header == 17
            and is_int(packet.ip_fragment_offset) and packet.ip_fragment_offset == 0
            and packet.ip_more_fragments is False
            and ip_payload is not None and ip_payload < 8
        ):
            return CheckResult(CheckStatus.INVALID, "declared IPv4 payload shorter than the 8-byte UDP header")

        if original is None:
            return CheckResult(CheckStatus.INCOMPLETE, "packet length unknown")

        if captured < original:
            return CheckResult(CheckStatus.INCOMPLETE, f"truncated capture: {captured} of {original} bytes")

        return CheckResult(CheckStatus.VALID)

    def check_payload_length(self, packet: Packet) -> CheckResult:
        payload = packet.payload_length

        if payload is None:
            if packet.transport_protocol == "OTHER":
                return CheckResult(CheckStatus.NOT_APPLICABLE, "unresolved protocol")
            
            return CheckResult(CheckStatus.INCOMPLETE, "payload length not available")

        if not is_int(payload) or payload < 0:
            return CheckResult(CheckStatus.INVALID, "negative payload length")

        # the ICMP message length is verified by icmp_message_length
        if packet.transport_protocol in ("ICMP", "ICMPv6"):
            return CheckResult(CheckStatus.VALID)

        if packet.transport_protocol not in ("TCP", "UDP"):
            return CheckResult(CheckStatus.VALID)

        if self.is_fragmented(packet):
            return CheckResult(CheckStatus.INCOMPLETE, "fragmented datagram: payload consistency not verifiable")

        expected = self.declared_payload_length(packet)
        if expected is None:
            return CheckResult(CheckStatus.INCOMPLETE, "payload length not determinable")

        if (packet.transport_protocol == "UDP" and is_int(packet.udp_length) and packet.udp_length >= 8):
            source = "declared from UDP header"
        else:
            source = "declared at IP level"

        capture_incomplete = (self.is_truncated(packet) or packet.packet_length is None)

        return self.compare_payload(payload, expected, capture_incomplete, source)

    def compare_payload(self, payload: int, expected: int, capture_incomplete: bool, source: str) -> CheckResult:
        if expected < 0:
            return CheckResult(CheckStatus.INVALID, "negative IP payload or transport header longer than IP payload")
        
        if payload > expected:
            return CheckResult(CheckStatus.INVALID, f"payload longer than {source}")
        
        if payload < expected:
            if capture_incomplete:
                return CheckResult(CheckStatus.INCOMPLETE, "truncated capture")
            
            return CheckResult(CheckStatus.INVALID, f"payload shorter than {source}")
        
        return CheckResult(CheckStatus.VALID)

    def check_protocol_fields(self, packet: Packet) -> CheckResult:
        protocol = packet.transport_protocol

        expected_number = PROTOCOL_NUMBERS.get(protocol)

        if expected_number is not None:
            # a transport protocol must be coherent with the IP layer
            if packet.ip_next_header is None or packet.ip_version is None:
                return CheckResult(CheckStatus.INCOMPLETE, "IP information not available to verify protocol coherence")

            if packet.ip_next_header != expected_number:
                if packet.ip_version != 6:
                    return CheckResult(CheckStatus.INVALID, f"ip_next_header {packet.ip_next_header} not equal to {protocol}")

                # the base Next Header points at an extension header:
                # only the chain can tell where the transport protocol is
                extension_headers = packet.ip_extension_headers_length
                if extension_headers is None:
                    return CheckResult(CheckStatus.INCOMPLETE, "IPv6 extension header length not available")

                if extension_headers == 0:
                    return CheckResult(CheckStatus.INVALID, f"ip_next_header {packet.ip_next_header} not equal to {protocol}")

                if packet.ip_last_next_header is None:
                    return CheckResult(CheckStatus.INCOMPLETE, "IPv6 extension chain not verified")

                if packet.ip_last_next_header != expected_number:
                    return CheckResult(CheckStatus.INVALID, f"IPv6 extension chain ends with {packet.ip_last_next_header}, not equal to {protocol}")

        # fields that contradict the interpreted protocol
        if self.has_foreign_transport_fields(packet):
            return CheckResult(CheckStatus.INVALID, f"fields of other protocols present with {protocol}")

        required = REQUIRED_FIELDS.get(protocol)
        if required is None:
            return CheckResult(CheckStatus.VALID)

        missing = [name for name in required if getattr(packet, name) is None]
        if missing:
            return CheckResult(CheckStatus.INCOMPLETE, f"missing fields for {protocol}: {', '.join(missing)}")

        return CheckResult(CheckStatus.VALID)

    def check_network(self, packet: Packet) -> dict[str, CheckResult]:
        checks: dict[str, CheckResult] = {}

        # checks added only when IP data exists
        if packet.ip_version is not None or packet.src_ip is not None:
            checks["src_ip_format"] = self.check_ip_format(packet.src_ip, packet.ip_version, "source")

        if packet.ip_version is not None or packet.dst_ip is not None:
            checks["dst_ip_format"] = self.check_ip_format(packet.dst_ip, packet.ip_version, "destination")

        if packet.ip_version is not None:
            checks["ip_version_consistency"] = self.check_ip_version(packet)

            if packet.ip_version in (4, 6):
                checks["ip_header_length"] = self.check_ip_header_length(packet)

        if packet.ip_version is not None or packet.ip_next_header is not None:
            checks["ip_next_header_range"] = self.check_ip_next_header(packet)

        if packet.ip_version == 6 or packet.ip_extension_headers_length is not None:
            checks["ip_extension_headers_length"] = self.check_ip_extension_headers_length(packet)

        if packet.ip_last_next_header is not None:
            checks["ip_last_next_header_range"] = self.check_ip_last_next_header_range(packet)

        if (packet.ip_version is not None
            or packet.ip_fragment_offset is not None
            or packet.ip_more_fragments is not None
            or packet.ip_fragment_header_present is not None
        ):
            checks["ip_fragmentation_consistency"] = self.check_ip_fragmentation(packet)

        return checks

    def check_ip_format(self, address: str | None, version: int | None, label: str) -> CheckResult:
        if address is None:
            return CheckResult(CheckStatus.INCOMPLETE, f"IP address {label} not available")

        # ip_address() would accept an integer and read it as a packed address
        if not isinstance(address, str):
            return CheckResult(CheckStatus.INVALID, f"invalid IP address {label}")
        
        try:
            parsed = ip_address(address)
        except (ValueError, TypeError):
            return CheckResult(CheckStatus.INVALID, f"invalid IP address {label}")
        
        if version is not None and parsed.version != version:
            return CheckResult(CheckStatus.INVALID, f"IPv{parsed.version} address with ip_version {version}")
        
        return CheckResult(CheckStatus.VALID)

    def check_ip_version(self, packet: Packet) -> CheckResult:
        if packet.ip_version not in (4, 6):
            return CheckResult(CheckStatus.INVALID, f"unknown IP version: {packet.ip_version}")
        
        if packet.src_ip is None and packet.dst_ip is None:
            return CheckResult(CheckStatus.INCOMPLETE, "IP addresses not available")
        
        for address in (packet.src_ip, packet.dst_ip):
            if address is None:
                continue

            # ip_address() would accept an integer and read it as a packed address
            if not isinstance(address, str):
                return CheckResult(CheckStatus.INVALID, "invalid IP address")

            try:
                parsed = ip_address(address)
            except (ValueError, TypeError):
                return CheckResult(CheckStatus.INVALID, "invalid IP address")
            
            if parsed.version != packet.ip_version:
                return CheckResult(CheckStatus.INVALID, f"IPv{parsed.version} address with ip_version {packet.ip_version}")
        
        return CheckResult(CheckStatus.VALID)

    def check_ip_header_length(self, packet: Packet) -> CheckResult:
        header_length = packet.ip_header_length

        if header_length is None:
            return CheckResult(CheckStatus.INCOMPLETE, "IP header length not available")

        if packet.ip_version == 6:
            # IPv6 has a fixed base header
            if not is_int(header_length) or header_length != 40:
                return CheckResult(CheckStatus.INVALID, "IPv6 base header must be 40 bytes")
        else:
            # IPv4 has a variable header length
            if not is_int(header_length) or header_length < 20:
                return CheckResult(CheckStatus.INVALID, "IP header shorter than 20 bytes")
            
            if header_length % 4 != 0:
                return CheckResult(CheckStatus.INVALID, "IP header not a multiple of 4")
            
            if header_length > 60:
                return CheckResult(CheckStatus.INVALID, "IP header longer than 60 bytes")

            if is_int(packet.ip_total_length) and header_length > packet.ip_total_length:
                return CheckResult(CheckStatus.INVALID, "IP header longer than ip_total_length")

        # an Ethernet frame cannot contain the header if fewer bytes were captured
        if (packet.src_mac is not None
            and is_int(packet.captured_length)
            and packet.captured_length < ETHERNET_HEADER_LENGTH + header_length
        ):
            return CheckResult(CheckStatus.INCOMPLETE, "IP header not fully captured")

        return CheckResult(CheckStatus.VALID)

    def check_ip_next_header(self, packet: Packet) -> CheckResult:
        next_header = packet.ip_next_header

        if next_header is None:
            return CheckResult(CheckStatus.INCOMPLETE, "ip_next_header not available")
        
        if not is_int(next_header) or next_header < 0 or next_header > 255:
            return CheckResult(CheckStatus.INVALID, "ip_next_header out of range 0-255")
        
        return CheckResult(CheckStatus.VALID)

    def check_ip_last_next_header_range(self, packet: Packet) -> CheckResult:
        next_header = packet.ip_last_next_header

        if next_header is None:
            return CheckResult(CheckStatus.INCOMPLETE, "ip_last_next_header not available")
        
        if not is_int(next_header) or next_header < 0 or next_header > 255:
            return CheckResult(CheckStatus.INVALID, "ip_last_next_header out of range 0-255")
        
        return CheckResult(CheckStatus.VALID)

    def check_ip_extension_headers_length(self, packet: Packet) -> CheckResult:
        length = packet.ip_extension_headers_length

        if packet.ip_version == 4:
            if length is None:
                return CheckResult(CheckStatus.VALID)

            # validate the type before comparing with zero (False == 0)
            if not is_int(length) or length < 0:
                return CheckResult(CheckStatus.INVALID, "invalid extension header length")

            if length > 0:
                return CheckResult(CheckStatus.INVALID, "IPv4 packet with IPv6 extension headers")

            return CheckResult(CheckStatus.VALID)

        if packet.ip_version != 6:
            return CheckResult(CheckStatus.INVALID, "extension headers on a non-IP packet")

        if length is None:
            return CheckResult(CheckStatus.INCOMPLETE, "IPv6 extension header length not available")
        
        if not is_int(length) or length < 0:
            return CheckResult(CheckStatus.INVALID, "invalid extension header length")

        if packet.ip_payload_length is not None:
            if not is_int(packet.ip_payload_length):
                return CheckResult(CheckStatus.INVALID, "invalid IPv6 payload length")
            
            if length > packet.ip_payload_length:
                return CheckResult(CheckStatus.INVALID, "extension headers longer than IPv6 payload")

        # a measured extension length must agree with the base Next Header
        if packet.ip_next_header is not None:
            next_header_is_extension = packet.ip_next_header in IPV6_EXTENSION_HEADERS

            if (length > 0) != next_header_is_extension:
                return CheckResult(CheckStatus.INVALID, "extension header length disagrees with ip_next_header")

        # the last Next Header is set exactly when extension headers exist
        if length > 0 and packet.ip_last_next_header is None:
            return CheckResult(CheckStatus.INCOMPLETE, "IPv6 extension chain not verified")

        if length == 0 and packet.ip_last_next_header is not None:
            return CheckResult(CheckStatus.INVALID, "last Next Header set without extension headers")
        
        return CheckResult(CheckStatus.VALID)

    def check_ip_fragmentation(self, packet: Packet) -> CheckResult:
        offset = packet.ip_fragment_offset
        more_fragments = packet.ip_more_fragments
        present = packet.ip_fragment_header_present

        if present is not None and not isinstance(present, bool):
            return CheckResult(CheckStatus.INVALID, "Fragment header presence is not boolean")
        if present is True and packet.ip_version != 6:
            return CheckResult(CheckStatus.INVALID, "IPv6 Fragment header on a non-IPv6 packet")

        if packet.ip_version not in (4, 6):
            return CheckResult(CheckStatus.INVALID, "fragmentation fields on a non-IP packet")

        if offset is None or more_fragments is None:
            return CheckResult(CheckStatus.INCOMPLETE, "IP fragmentation data not available")

        if not is_int(offset) or not 0 <= offset <= MAX_FRAGMENT_OFFSET:
            return CheckResult(CheckStatus.INVALID, f"fragment offset out of range 0-{MAX_FRAGMENT_OFFSET}")

        if not isinstance(more_fragments, bool):
            return CheckResult(CheckStatus.INVALID, "ip_more_fragments is not boolean")

        if (packet.ip_version == 4 and (offset > 0 or more_fragments) and self.ip_payload_available(packet) == 0):
            return CheckResult(CheckStatus.INVALID, "IPv4 fragment has zero declared payload length")

        if packet.ip_version == 6 and present is False and (offset > 0 or more_fragments):
            return CheckResult(CheckStatus.INVALID, "fragmentation contradicts absent IPv6 Fragment header")

        return CheckResult(CheckStatus.VALID)

    def check_transport(self, packet: Packet) -> dict[str, CheckResult]:

        if packet.transport_protocol == "TCP":
            return self.check_tcp(packet)
        
        if packet.transport_protocol == "UDP":
            return self.check_udp(packet)
        
        if packet.transport_protocol in ("ICMP", "ICMPv6"):
            return self.check_icmp(packet)
    
        return {}

    def check_tcp(self, packet: Packet) -> dict[str, CheckResult]:
        return {
            "tcp_ports_range": self.check_ports(packet.src_port, packet.dst_port, "TCP"),
            "tcp_header_length": self.check_tcp_header_length(packet),
            "tcp_sequence_number_range": self.check_uint32(packet.tcp_sequence_number, "sequence number"),
            "tcp_ack_number_range": self.check_uint32(packet.tcp_ack_number, "ACK number"),
        }

    def check_udp(self, packet: Packet) -> dict[str, CheckResult]:
        return {
            "udp_ports_range": self.check_ports(packet.src_port, packet.dst_port, "UDP"),
            "udp_length_consistency": self.check_udp_length(packet),
        }

    def check_icmp(self, packet: Packet) -> dict[str, CheckResult]:
        return {
            "icmp_fields_completeness": self.check_icmp_fields(packet),
            "icmp_message_length": self.check_icmp_message_length(packet),
        }

    def check_ports(self, src_port: int | None, dst_port: int | None, protocol: str) -> CheckResult:
        if src_port is None or dst_port is None:
            return CheckResult(CheckStatus.INCOMPLETE, f"{protocol} ports not available")
        
        for port in (src_port, dst_port):
            if not is_int(port) or port < 0 or port > MAX_PORT:
                return CheckResult(CheckStatus.INVALID, f"{protocol} port out of range 0-{MAX_PORT}")
            
        return CheckResult(CheckStatus.VALID)

    def check_tcp_header_length(self, packet: Packet) -> CheckResult:
        header_length = packet.tcp_header_length

        if header_length is None:
            return CheckResult(CheckStatus.INCOMPLETE, "TCP header length not available")

        if not is_int(header_length) or header_length < 20:
            return CheckResult(CheckStatus.INVALID, "TCP header shorter than 20 bytes")

        if header_length % 4 != 0:
            return CheckResult(CheckStatus.INVALID, "TCP header not a multiple of 4")

        # an incomplete header cannot be judged, neither valid nor malformed
        if not self.tcp_header_captured(packet, header_length):
            return CheckResult(CheckStatus.INCOMPLETE, "TCP header not fully captured")

        if (is_int(packet.ip_fragment_offset) and packet.ip_fragment_offset > 0):
            return CheckResult(CheckStatus.INCOMPLETE, "TCP header cannot be verified in a non-first fragment")

        ip_payload = self.ip_payload_available(packet)

        if ip_payload is not None and ip_payload < 0:
            return CheckResult(CheckStatus.INVALID, "negative IP payload")

        if ip_payload is None:
            return CheckResult(CheckStatus.INCOMPLETE, "TCP segment size not determinable")

        if self.is_fragmented(packet):
            return CheckResult(CheckStatus.INCOMPLETE, "fragmented datagram: TCP header consistency not fully verifiable")

        if header_length > ip_payload:
            return CheckResult(CheckStatus.INVALID, "TCP header longer than IP payload")

        return CheckResult(CheckStatus.VALID)

    def check_uint32(self, value: int | None, label: str) -> CheckResult:
        if value is None:
            return CheckResult(CheckStatus.INCOMPLETE, f"{label} not available")
        
        if not is_int(value) or value < 0 or value > MAX_32_BIT:
            return CheckResult(CheckStatus.INVALID, f"{label} outside 32 bits")
        
        return CheckResult(CheckStatus.VALID)

    def check_udp_length(self, packet: Packet) -> CheckResult:
        udp_length = packet.udp_length

        if udp_length is None:
            return CheckResult(CheckStatus.INCOMPLETE, "UDP length not available")
        
        if not is_int(udp_length) or udp_length < 8:
            return CheckResult(CheckStatus.INVALID, "UDP length shorter than the 8-byte header")

        # udp_length covers the whole datagram, the IP payload only this fragment
        if self.is_fragmented(packet):
            return CheckResult(CheckStatus.INCOMPLETE, "fragmented datagram: UDP length not comparable with fragment payload")

        ip_payload = self.ip_payload_available(packet)

        if ip_payload is None:
            return CheckResult(CheckStatus.INCOMPLETE, "IP payload not determinable")

        if ip_payload < 0:
            return CheckResult(CheckStatus.INVALID, "negative IP payload")

        if udp_length > ip_payload:
            return CheckResult(CheckStatus.INVALID, "UDP length longer than IP payload")

        # on a non-fragmented datagram the UDP length covers the whole IP payload
        if udp_length < ip_payload:
            return CheckResult(CheckStatus.INVALID, "IP payload longer than UDP datagram")
        
        return CheckResult(CheckStatus.VALID)

    def check_icmp_fields(self, packet: Packet) -> CheckResult:
        icmp_type = packet.icmp_type
        icmp_code = packet.icmp_code

        if icmp_type is None or icmp_code is None:
            return CheckResult(CheckStatus.INCOMPLETE, "ICMP type and code not available")
        
        if not is_int(icmp_type) or not 0 <= icmp_type <= 255:
            return CheckResult(CheckStatus.INVALID, "ICMP type out of range")
        
        if not is_int(icmp_code) or not 0 <= icmp_code <= 255:
            return CheckResult(CheckStatus.INVALID, "ICMP code out of range")

        if packet.transport_protocol == "ICMP" and packet.ip_version == 6:
            return CheckResult(CheckStatus.INVALID, "ICMPv4 on an IPv6 packet")
        
        if packet.transport_protocol == "ICMPv6" and packet.ip_version == 4:
            return CheckResult(CheckStatus.INVALID, "ICMPv6 on an IPv4 packet")

        return CheckResult(CheckStatus.VALID)

    def check_icmp_message_length(self, packet: Packet) -> CheckResult:
        ip_payload = self.ip_payload_available(packet)

        if ip_payload is None:
            return CheckResult(CheckStatus.INCOMPLETE, "IP payload not determinable")
        
        if ip_payload < 0:
            return CheckResult(CheckStatus.INVALID, "negative IP payload")

        payload = packet.payload_length

        if payload is None:
            return CheckResult(CheckStatus.INCOMPLETE, "ICMP payload length not available")
        
        if not is_int(payload) or payload < 0:
            return CheckResult(CheckStatus.INVALID, "invalid ICMP payload length")

        message_length = ICMP_HEADER_LENGTH + payload

        # a message longer than the IP payload is demonstrable even on fragments
        if message_length > ip_payload:
            return CheckResult(CheckStatus.INVALID, "ICMP message longer than IP payload")

        if self.is_truncated(packet) or self.is_fragmented(packet):
            return CheckResult(CheckStatus.INCOMPLETE, "ICMP message completeness not verifiable")

        # on a complete datagram the message covers the whole IP payload
        if message_length < ip_payload:
            return CheckResult(CheckStatus.INVALID, "IP payload longer than ICMP message")

        return CheckResult(CheckStatus.VALID)


    # info

    def characteristics(self, packet: Packet) -> frozenset[str]:
        characteristics: set[str] = set()
        number = packet.ip_next_header
        
        if packet.ip_version == 6 and is_int(packet.ip_extension_headers_length) and packet.ip_extension_headers_length > 0:
            number = packet.ip_last_next_header

        if number in (4, 41, 47):
            characteristics.add("IP_ENCAPSULATION")

        if packet.transport_protocol == "TCP":
            characteristics.update(self.analyze_tcp(packet))

        elif packet.transport_protocol == "UDP":
            characteristics.update(self.analyze_udp(packet))

        elif packet.transport_protocol in ("ICMP", "ICMPv6"):
            characteristics.update(self.analyze_icmp(packet))

        characteristics.update(self.payload_characteristics(packet))

        characteristics.update(self.truncation_characteristics(packet))

        characteristics.update(self.fragmentation_characteristics(packet))

        return frozenset(characteristics)

    def analyze_tcp(self, packet: Packet) -> frozenset[str]:
        flags = tcp_flag_names(packet.tcp_flags)
        characteristics: set[str] = set()

        if "SYN" in flags:
            characteristics.add("TCP_SYN_SET")

        if "ACK" in flags:
            characteristics.add("TCP_ACK_SET")

        if "SYN" in flags and "ACK" not in flags:
            characteristics.add("CONNECTION_INITIATION")

        if "SYN" in flags and "ACK" in flags:
            characteristics.add("CONNECTION_RESPONSE")

        if "FIN" in flags:
            characteristics.add("CONNECTION_CLOSE_INDICATED")

        if "RST" in flags:
            characteristics.add("CONNECTION_RESET")

        if "PSH" in flags:
            characteristics.add("PUSH_FLAG_SET")

        if "SYN" in flags and "FIN" in flags:
            characteristics.add("TCP_SYN_AND_FIN_SET")

        return frozenset(characteristics)

    def analyze_udp(self, packet: Packet) -> frozenset[str]:
        # UDP adds no characteristic
        return frozenset()

    def analyze_icmp(self, packet: Packet) -> frozenset[str]:
        characteristics: set[str] = set()
        icmp_type = packet.icmp_type

        if not is_int(icmp_type):
            return frozenset()

        if packet.transport_protocol == "ICMP":
            if icmp_type == 8:
                characteristics.add("ECHO_REQUEST")

            elif icmp_type == 0:
                characteristics.add("ECHO_REPLY")

            elif icmp_type in ICMPV4_ERROR_TYPES:
                characteristics.add("ICMP_ERROR_MESSAGE")
        else:
            if icmp_type == 128:
                characteristics.add("ECHO_REQUEST")

            elif icmp_type == 129:
                characteristics.add("ECHO_REPLY")

            elif icmp_type in ICMPV6_ERROR_TYPES:
                characteristics.add("ICMP_ERROR_MESSAGE")

        return frozenset(characteristics)

    def payload_characteristics(self, packet: Packet) -> frozenset[str]:
        payload = packet.payload_length

        if payload is None or not is_int(payload):
            return frozenset()
        
        if payload > 0:
            return frozenset({"PAYLOAD_PRESENT"})
        
        # an empty payload is a fact only when it is fully determinable:
        # not truncated, not fragmented and the expected length is known
        if (payload == 0 and not self.is_truncated(packet) and not self.is_fragmented(packet)):
            expected = self.declared_payload_length(packet)

            if expected is not None and expected == 0:
                return frozenset({"EMPTY_PAYLOAD"})
            
        return frozenset()

    def truncation_characteristics(self, packet: Packet) -> frozenset[str]:
        if self.is_truncated(packet):
            return frozenset({"CAPTURE_TRUNCATED"})
        
        return frozenset()

    def fragmentation_characteristics(self, packet: Packet) -> frozenset[str]:
        if (packet.ip_version == 6 and packet.ip_fragment_header_present is True and is_int(packet.ip_fragment_offset) and packet.ip_fragment_offset == 0 and packet.ip_more_fragments is False):
            return frozenset({"IPV6_ATOMIC_FRAGMENT"})

        if not self.is_fragmented(packet):
            return frozenset()
        
        characteristics = {"FRAGMENTED_PACKET"}
        if is_int(packet.ip_fragment_offset) and packet.ip_fragment_offset >= 0:
            characteristics.add("INITIAL_FRAGMENT" if packet.ip_fragment_offset == 0 else "NON_INITIAL_FRAGMENT")

        if packet.transport_protocol in ("ICMP", "ICMPv6"):
            characteristics.add("FRAGMENTED_ICMP")
        
        return frozenset(characteristics)

    # utilities

    def is_truncated(self, packet: Packet) -> bool:
        return (is_int(packet.captured_length) and is_int(packet.packet_length) and packet.captured_length < packet.packet_length)

    def is_fragmented(self, packet: Packet) -> bool:
        return ((is_int(packet.ip_fragment_offset) and packet.ip_fragment_offset > 0) or packet.ip_more_fragments is True)

    def tcp_header_captured(self, packet: Packet, header_length: int) -> bool:
        # without Ethernet/IP information the capture cannot be measured
        if packet.src_mac is None:
            return True

        if (not is_int(packet.captured_length)
            or not is_int(packet.ip_header_length)
            or not is_int(header_length)
        ):
            return True

        required = ETHERNET_HEADER_LENGTH + packet.ip_header_length + header_length

        if is_int(packet.ip_extension_headers_length):
            required += packet.ip_extension_headers_length

        return packet.captured_length >= required

    def ip_payload_available(self, packet: Packet) -> int | None:
        # bytes after the base IP header, extension headers excluded
        if packet.ip_version == 4:
            if (not is_int(packet.ip_total_length)
                or not is_int(packet.ip_header_length)
            ):
                return None
            
            return packet.ip_total_length - packet.ip_header_length
        
        if packet.ip_version == 6:
            # the extension header length is subtracted only when measured:
            # the reader always writes it for IPv6 packets (0 = none found)
            if (not is_int(packet.ip_payload_length)
                or not is_int(packet.ip_extension_headers_length)
            ):
                return None
            
            return packet.ip_payload_length - packet.ip_extension_headers_length
        
        return None

    def transport_header_length(self, packet: Packet) -> int | None:

        if packet.transport_protocol == "TCP":
            return packet.tcp_header_length
        
        if packet.transport_protocol == "UDP":
            # fixed UDP header
            return 8
        
        if packet.transport_protocol in ("ICMP", "ICMPv6"):
            return ICMP_HEADER_LENGTH
        
        return None

    def declared_payload_length(self, packet: Packet) -> int | None:
        # payload length declared by the transport/IP headers
        if (packet.transport_protocol == "UDP" and is_int(packet.udp_length) and packet.udp_length >= 8):
            return packet.udp_length - 8

        ip_payload = self.ip_payload_available(packet)
        header_length = self.transport_header_length(packet)

        if ip_payload is None or header_length is None:
            return None
        
        return ip_payload - header_length

    def has_foreign_transport_fields(self, packet: Packet) -> bool:
        protocol = packet.transport_protocol

        tcp_fields = (packet.tcp_flags, packet.tcp_header_length, packet.tcp_sequence_number, packet.tcp_ack_number)
        icmp_fields = (packet.icmp_type, packet.icmp_code)

        ports = (packet.src_port, packet.dst_port)

        if protocol == "TCP":
            return any(value is not None for value in icmp_fields) or (packet.udp_length is not None)
        
        if protocol == "UDP":
            return any(value is not None for value in icmp_fields + tcp_fields)
        
        if protocol in ("ICMP", "ICMPv6"):
            return any(value is not None for value in ports + tcp_fields) or (packet.udp_length is not None)
        
        # OTHER: transport fields should not have been interpreted
        return (any(value is not None for value in ports + tcp_fields + icmp_fields) or packet.udp_length is not None)
