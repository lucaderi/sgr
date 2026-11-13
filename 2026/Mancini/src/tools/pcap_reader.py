from collections.abc import Iterator
from pathlib import Path

from scapy.all import PcapReader

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
# scapy 2.8 exposes the ICMPv6 base class as _ICMPv6
from scapy.layers.inet6 import IPv6, _ICMPv6, _IPv6ExtHdr, IPv6ExtHdrFragment

from firewall.schemas.packet import Packet

# rdpcap for short files
# PcapReader for big files and to reduce RAM use

# --- PCAP FILES READER ---

# stream packets without loading the whole file into RAM

# with PcapReader(data\samples\sample_capture.pcapng) as packets:
    # for pkt in packets:
        # process each packet individually
        # if pkt.haslayer('IP'):
            # extract and put in Packet...

def payload_length(
    observed_length: int,
    ip_payload_available: int | None,
    transport_header_length: int | None,
) -> int:
    # short Ethernet frames are padded after the IP packet
    if ip_payload_available is None or transport_header_length is None:
        return observed_length

    declared_payload = ip_payload_available - transport_header_length
    if declared_payload < 0:
        return observed_length

    return min(observed_length, declared_payload)


def ipv6_extension_headers(ip: IPv6) -> tuple[int, int | None]:
    # length of the extension headers and the Next Header of the last one
    # (None when there are no extension headers)
    length = 0
    last_next_header = None
    layer = ip.payload

    while isinstance(layer, _IPv6ExtHdr):
        length += len(bytes(layer)) - len(bytes(layer.payload))

        # keep the value only when it was actually determined
        if layer.nh is not None:
            last_next_header = int(layer.nh)

        if isinstance(layer, IPv6ExtHdrFragment) and layer.offset > 0:
            # later fragment bytes cannot be interpreted as another header chain
            break

        layer = layer.payload

    return length, last_next_header


def outer_ip(packet) -> tuple[IP | IPv6 | None, int | None]:
    layer = packet
    link_length = 0
    while layer:
        if isinstance(layer, (IP, IPv6)):
            return layer, link_length
        link_length += len(bytes(layer)) - len(bytes(layer.payload))
        layer = layer.payload
    return None, None


def read_packets(path: str | Path) -> Iterator[Packet]:

    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(
            f"PCAP file not found: {path}"
        )

    if not path.is_file():
        raise ValueError(
            f"invalid path: {path}"
        )

    with PcapReader(str(path)) as packets:

        for pkt in packets:

            # lenghts could be different

            captured_length = len(pkt)
            wire_length = getattr(pkt, "wirelen", None)

            fields = {
                "timestamp": float(pkt.time),
                "packet_length": (
                    int(wire_length)
                    if wire_length is not None
                    else captured_length
                ),
                "captured_length": captured_length,
            }

            # ethernet info
            if isinstance(pkt, Ether):
                eth = pkt
                fields["src_mac"] = eth.src
                fields["dst_mac"] = eth.dst

            # IP info
            ip, link_length = outer_ip(pkt)
            fields["link_header_length"] = link_length

            # IPv4
            if isinstance(ip, IP):

                fields["ip_version"] = 4
                fields["src_ip"] = ip.src
                fields["dst_ip"] = ip.dst
                fields["ip_next_header"] = int(ip.proto)

                if ip.ihl is not None:
                    fields["ip_header_length"] = int(ip.ihl) * 4

                if ip.len is not None:
                    fields["ip_total_length"] = int(ip.len)

                fields["ip_fragment_offset"] = int(ip.frag)
                fields["ip_more_fragments"] = bool(ip.flags.MF)

            # IPv6
            elif isinstance(ip, IPv6):

                fields["ip_version"] = 6
                fields["src_ip"] = ip.src
                fields["dst_ip"] = ip.dst
                fields["ip_next_header"] = int(ip.nh)

                # 40 bytes for IPv6 header
                fields["ip_header_length"] = 40

                if ip.plen is not None:
                    fields["ip_payload_length"] = int(ip.plen)

                extension_headers_length, last_next_header = ipv6_extension_headers(ip)

                fields["ip_extension_headers_length"] = extension_headers_length
                fields["ip_last_next_header"] = last_next_header

                # not fragmented unless a Fragment extension header says otherwise
                fields["ip_fragment_offset"] = 0
                fields["ip_more_fragments"] = False
                fields["ip_fragment_header_present"] = False

                # fragmentation lives in the Fragment extension header
                fragment = ip.payload
                while isinstance(fragment, _IPv6ExtHdr) and not isinstance(fragment, IPv6ExtHdrFragment):
                    fragment = fragment.payload
                if isinstance(fragment, IPv6ExtHdrFragment):
                    fields["ip_fragment_header_present"] = True
                    fields["ip_fragment_offset"] = int(fragment.offset)
                    fields["ip_more_fragments"] = bool(fragment.m)
                elif last_next_header == 44 or fields["ip_next_header"] == 44:
                    # Fragment header announced but not available in the capture
                    fields["ip_fragment_header_present"] = None
                    fields["ip_fragment_offset"] = None
                    fields["ip_more_fragments"] = None

            if (fields.get("ip_fragment_offset") or 0) > 0:
                # never extract transport fields from non-initial fragment bytes
                yield Packet(**fields)
                continue

            # bytes after the base IP header, as declared by the IP layer
            ip_payload_available = None

            if fields.get("ip_version") == 4:
                ip_total_length = fields.get("ip_total_length")
                ip_header_length = fields.get("ip_header_length")

                if ip_total_length is not None and ip_header_length is not None:
                    ip_payload_available = ip_total_length - ip_header_length
            
            elif fields.get("ip_version") == 6:
                ip_payload_length = fields.get("ip_payload_length")
                extension_headers_length = fields.get("ip_extension_headers_length") or 0

                if ip_payload_length is not None:
                    ip_payload_available = ip_payload_length - extension_headers_length

            # transport level info
            transport = ip.payload if ip is not None else None
            if isinstance(ip, IPv6):
                while isinstance(transport, _IPv6ExtHdr):
                    transport = transport.payload

            # TCP
            if isinstance(transport, TCP):
                tcp = transport

                fields["transport_protocol"] = "TCP"
                fields["src_port"] = int(tcp.sport)
                fields["dst_port"] = int(tcp.dport)
                fields["tcp_flags"] = str(tcp.flags)

                if tcp.dataofs is not None:
                    fields["tcp_header_length"] = int(tcp.dataofs) * 4

                fields["tcp_sequence_number"] = int(tcp.seq)
                fields["tcp_ack_number"] = int(tcp.ack)

                fields["payload_length"] = payload_length(len(bytes(tcp.payload)), ip_payload_available, fields.get("tcp_header_length"))

            # UDP
            elif isinstance(transport, UDP):
                udp = transport

                fields["transport_protocol"] = "UDP"
                fields["src_port"] = int(udp.sport)
                fields["dst_port"] = int(udp.dport)

                if udp.len is not None:
                    fields["udp_length"] = int(udp.len)

                fields["payload_length"] = payload_length(len(bytes(udp.payload)), ip_payload_available, 8)

            elif isinstance(transport, ICMP):
                icmp = transport

                fields["transport_protocol"] = "ICMP"
                fields["icmp_type"] = int(icmp.type)
                fields["icmp_code"] = int(icmp.code)

                # ICMP echo id/seq are header fields: count only the bytes
                # after the common 8-byte ICMP header
                fields["payload_length"] = payload_length(
                    max(0, len(bytes(icmp)) - 8), ip_payload_available, 8
                )

            # ICMPv6
            elif isinstance(transport, _ICMPv6):
                icmp6 = transport

                fields["transport_protocol"] = "ICMPv6"
                fields["icmp_type"] = int(icmp6.type)
                fields["icmp_code"] = int(icmp6.code)

                fields["payload_length"] = payload_length(
                    max(0, len(bytes(icmp6)) - 8), ip_payload_available, 8
                )

            yield Packet(**fields)
