/**
 * 
 */
package flow;

/**
 * Questa classe e' in grado di riconoscere un insieme di protocolli noti di livello 4 presenti nel file /etc/protocols 
 * 
 * @author dellanna
 *
 */
final class Protocols {

	
	//a seconda del numero di protocollo restituisce l'acronimo del protocollo corrispondente
	static String protocol(int l4_protocol){
		String protocol;
		switch (l4_protocol) {
		case   0: protocol="IP"; break;			// internet protocol, pseudo protocol number
		case   1: protocol="ICMP"; break;   		// internet control message protocol
		case   2: protocol="IGMP"; break;			// Internet Group Management
		case   3: protocol="GGP"; break;			// gateway-gateway protocol
		case   4: protocol="IP-ENCAP"; break;		// IP encapsulated in IP (officially ``IP'')
		case   5: protocol="ST"; break;			// ST datagram mode
		case   6: protocol="TCP"; break;			// transmission control protocol
		case   8: protocol="EGP"; break;			// exterior gateway protocol
		case   9: protocol="IGP"; break;			// any private interior gateway (Cisco)
		case  12: protocol="PUP"; break;			// PARC universal packet protocol
		case  17: protocol="UDP"; break;			// user datagram protocol
		case  20: protocol="HMP"; break;			// host monitoring protocol
		case  22: protocol="XNS-IDP"; break;		// Xerox NS IDP
		case  27: protocol="RDP"; break;			// "reliable datagram" protocol
		case  29: protocol="ISO-TP4"; break;		// ISO Transport Protocol class 4 [RFC905]
		case  36: protocol="XTP"; break;			// Xpress Transfer Protocol
		case  37: protocol="DDP"; break;			// Datagram Delivery Protocol
		case  38: protocol="IDPR-CMTP"; break;	// IDPR Control Message Transport
		case  41: protocol="IPv6"; break; 		// Internet Protocol, version 6
		case  43: protocol="IPv6-Route"; break;	// Routing Header for IPv6
		case  44: protocol="IPv6-Frag"; break;	// Fragment Header for IPv6
		case  45: protocol="IDRP"; break;			// Inter-Domain Routing Protocol
		case  46: protocol="RSVP"; break;			// Reservation Protocol
		case  47: protocol="GRE"; break;			// General Routing Encapsulation
		case  50: protocol="IPSEC-ESP"; break;	// Encap Security Payload [RFC2406]
		case  51: protocol="IPSEC-AH"; break;		// Authentication Header [RFC2402]
		case  57: protocol="SKIP"; break;			// SKIP
		case  58: protocol="IPv6-ICMP"; break; 	// ICMP for IPv6
		case  59: protocol="IPv6-NoNxt"; break;	// No Next Header for IPv6
		case  60: protocol="IPv6-Opts"; break;	// Destination Options for IPv6
		case  73: protocol="RSPF CPHB"; break;	// Radio Shortest Path First (officially CPHB)
		case  81: protocol="VMTP"; break;			// Versatile Message Transport
		case  88: protocol="EIGRP"; break;		// Enhanced Interior Routing Protocol (Cisco)
		case  89: protocol="OSPFIGP"; break;		// Open Shortest Path First IGP
		case  93: protocol="AX.25"; break;		// AX.25 frames
		case  94: protocol="IPIP"; break;			// IP-within-IP Encapsulation Protocol
		case  97: protocol="ETHERIP"; break;		// Ethernet-within-IP Encapsulation [RFC3378]
		case  98: protocol="ENCAP"; break;		// Yet Another IP encapsulation [RFC1241]
		case 103: protocol="PIM"; break;			// Protocol Independent Multicast
		case 108: protocol="IPCOMP"; break;		// IP Payload Compression Protocol
		case 112: protocol="VRRP"; break;			// Virtual Router Redundancy Protocol
		case 115: protocol="L2TP"; break;			// Layer Two Tunneling Protocol [RFC2661]
		case 124: protocol="ISIS"; break;			// IS-IS over IPv4
		case 132: protocol="SCTP"; break;			// Stream Control Transmission Protocol
		case 133: protocol="FC"; break;			// Fibre Channel
		case 136: protocol="UDPLite"; break;		// UDP-Lite
		case 137: protocol="MPLS-in-IP"; break;	// MPLS-in-IP [RFC4023]
		case 138: protocol="manet"; break;		// MANET Protocols
		case 139: protocol="HIP"; break;			// Host Identity Protocol
			default: protocol=l4_protocol+": PROTOCOL UNKNOWN!"; 
		}
		return protocol;
	}
	
}
