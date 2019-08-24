from ndpi_typestruct import *

class ndpi_workflow(Structure):
    pass

class ndpi_stats(Structure):
    _fields_ = [
        ('guessed_flow_protocols', c_uint32),
        ('raw_packet_count', c_uint64),
        ('ip_packet_count', c_uint64),
        ('total_wire_bytes', c_uint64),
        ('total_ip_bytes', c_uint64),
        ('total_discarded_bytes', c_uint64),
        ('protocol_counter', c_uint64 * ((ndpi.ndpi_wrap_ndpi_max_supported_protocols() + ndpi.ndpi_wrap_ndpi_max_num_custom_protocols()) + 1)),
        ('protocol_counter_bytes', c_uint64 * ((ndpi.ndpi_wrap_ndpi_max_supported_protocols() + ndpi.ndpi_wrap_ndpi_max_num_custom_protocols()) + 1)),
        ('protocol_flows', c_uint32 * ((ndpi.ndpi_wrap_ndpi_max_supported_protocols() + ndpi.ndpi_wrap_ndpi_max_num_custom_protocols()) + 1)),
        ('ndpi_flow_count', c_uint32),
        ('tcp_count', c_uint64),
        ('udp_count', c_uint64),
        ('mpls_count', c_uint64),
        ('pppoe_count', c_uint64),
        ('vlan_count', c_uint64),
        ('fragmented_count', c_uint64),
        ('packet_len', c_uint64 * 6),
        ('max_packet_len', c_uint16),
]

class ndpi_workflow_prefs(Structure):
    _fields_ = [
        ('decode_tunnels', c_uint8),
        ('quiet_mode', c_uint8),
        ('num_roots', c_uint32),
        ('max_ndpi_flows', c_uint32),
    ]

class ssh_ssl(Structure):
    _fields_ = [
        ("ssl_version", c_uint16),
        ("client_info", c_char * 64),
        ("server_info", c_char * 64),
        ("server_organization", c_char * 64),
        ("ja3_client", c_char * 33),
        ("ja3_server", c_char * 33),
        ("server_cipher", c_uint16),
        ("client_unsafe_cipher", c_int64), #ndpi_cipher_weakness enumerator
        ("server_unsafe_cipher", c_int64),
    ]

class ndpi_flow_info(Structure):
    _fields_ = [
        ("hashval", c_uint32),
        ("src_ip", c_uint32),
        ("dst_ip", c_uint32),
        ("src_port", c_uint16),
        ("dst_port", c_uint16),
        ("detection_completed", c_uint8),
        ("protocol", c_uint8),
        ("bidirectional", c_uint8),
        ("check_extra_packets", c_uint8),
        ("vlan_id", c_uint16),
        ("ndpi_flow", POINTER(ndpi_flow_struct)),
        ("src_name", c_char * 48),
        ("dst_name", c_char * 48),
        ("ip_version", c_uint8),
        ("last_seen", c_uint64),
        ("src2dst_bytes", c_uint64),
        ("dst2src_bytes", c_uint64),
        ("src2dst_packets", c_uint32),
        ("dst2src_packets", c_uint32),

        ("detected_protocol", ndpi_protocol),

        ("info", c_char * 96),
        ("host_server_name", c_char * 256),
        ("bittorent_hash", c_char * 41),
        ("dhcp_fingerprint", c_char * 48),
        ("ssh_ssl", ssh_ssl),
        ("src_id",c_void_p),
        ("dst_id", c_void_p),

    ]

ndpi_workflow_callback_ptr = CFUNCTYPE(None, POINTER(ndpi_workflow), POINTER(ndpi_flow_info), c_void_p)

class pcap_t(Structure):
    pass

ndpi_workflow._fields_ = [
    ('last_time', c_uint64),
    ('prefs', ndpi_workflow_prefs),
    ('stats', ndpi_stats),
    ('__flow_detected_callback', ndpi_workflow_callback_ptr),
    ('__flow_detected_udata', c_void_p),
    ('__flow_giveup_callback', ndpi_workflow_callback_ptr),
    ('__flow_giveup_udata', c_void_p),
    ('pcap_handle', POINTER(pcap_t)), #pcap_t
    ('ndpi_flows_root', POINTER(c_void_p)),
    ('ndpi_struct', POINTER(ndpi_detection_module_struct)),
    ('num_allocated_flows', c_uint32)
]
