/*
 * dns.c
 *
 * Copyright (C) 2012-18 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_DNS

#include "ndpi_api.h"


#define FLAGS_MASK 0x8000

/* #define DNS_DEBUG 1 */

/* *********************************************** */

static u_int16_t get16(int *i, const u_int8_t *payload) {
  u_int16_t v = *(u_int16_t*)&payload[*i];

  (*i) += 2;

  return(ntohs(v));
}

/* *********************************************** */

static u_int getNameLength(u_int i, const u_int8_t *payload, u_int payloadLen) {
  if(payload[i] == 0x00)
    return(1);
  else if(payload[i] == 0xC0)
    return(2);
  else {
    u_int8_t len = payload[i];
    u_int8_t off = len + 1;

    if(off == 0) /* Bad packet */
      return(0);
    else
      return(off + getNameLength(i+off, payload, payloadLen));
  }
}
/* 
 allowed chars for dns names A-Z 0-9 _ -  
 Perl script for generation map:
   my @M;
   for(my $ch=0; $ch < 256; $ch++) {
      $M[$ch >> 5] |= 1 << ($ch & 0x1f) if chr($ch) =~ /[a-z0-9_-]/i;
   }
   print join(',', map { sprintf "0x%08x",$_ } @M),"\n";
 */

static uint32_t dns_validchar[8] = {
	0x00000000,0x03ff2000,0x87fffffe,0x07fffffe,0,0,0,0
};
/* *********************************************** */

void ndpi_search_dns(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  int x, payload_offset;
  u_int8_t is_query;
  u_int16_t s_port = 0, d_port = 0;

  NDPI_LOG_DBG(ndpi_struct, "search DNS\n");

  if(flow->packet.udp != NULL) {
    s_port = ntohs(flow->packet.udp->source);
    d_port = ntohs(flow->packet.udp->dest);
    payload_offset = 0;
  } else if(flow->packet.tcp != NULL) /* pkt size > 512 bytes */ {
    s_port = ntohs(flow->packet.tcp->source);
    d_port = ntohs(flow->packet.tcp->dest);
    payload_offset = 2;
  } else {
    NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
    return;
  }

  x = payload_offset;

  if((s_port == 53 || d_port == 53 || d_port == 5355)
     && (flow->packet.payload_packet_len > sizeof(struct ndpi_dns_packet_header)+x)) {
    struct ndpi_dns_packet_header dns_header;
    int invalid = 0;

    memcpy(&dns_header, (struct ndpi_dns_packet_header*) &flow->packet.payload[x], sizeof(struct ndpi_dns_packet_header));
    dns_header.tr_id = ntohs(dns_header.tr_id);
    dns_header.flags = ntohs(dns_header.flags);
    dns_header.num_queries = ntohs(dns_header.num_queries);
    dns_header.num_answers = ntohs(dns_header.num_answers);
    dns_header.authority_rrs = ntohs(dns_header.authority_rrs);
    dns_header.additional_rrs = ntohs(dns_header.additional_rrs);
    x += sizeof(struct ndpi_dns_packet_header);

    /* 0x0000 QUERY */
    if((dns_header.flags & FLAGS_MASK) == 0x0000)
      is_query = 1;
    /* 0x8000 RESPONSE */
    else if((dns_header.flags & FLAGS_MASK) == 0x8000)
      is_query = 0;
    else
      invalid = 1;

    if(!invalid) {
      int j = 0, max_len, off;
      if(is_query) {
	/* DNS Request */
	if((dns_header.num_queries > 0) && (dns_header.num_queries <= NDPI_MAX_DNS_REQUESTS)
	   && (((dns_header.flags & 0x2800) == 0x2800 /* Dynamic DNS Update */)
	       || ((dns_header.num_answers == 0) && (dns_header.authority_rrs == 0)))) {
	  /* This is a good query */

	  if(dns_header.num_queries > 0) {
	    while(x < flow->packet.payload_packet_len) {
	      if(flow->packet.payload[x] == '\0') {
		x++;
		flow->protos.dns.query_type = get16(&x, flow->packet.payload);
#ifdef DNS_DEBUG
    		NDPI_LOG_DBG2(ndpi_struct, "query_type=%2d\n", flow->protos.dns.query_type);
#endif
		break;
	      } else
		x++;
	    }
	  }
	} else
	  invalid = 1;
      } else {
	/* DNS Reply */

	flow->protos.dns.reply_code = dns_header.flags & 0x0F;

	if((dns_header.num_queries > 0) && (dns_header.num_queries <= NDPI_MAX_DNS_REQUESTS) /* Don't assume that num_queries must be zero */
	   && (((dns_header.num_answers > 0) && (dns_header.num_answers <= NDPI_MAX_DNS_REQUESTS))
	       || ((dns_header.authority_rrs > 0) && (dns_header.authority_rrs <= NDPI_MAX_DNS_REQUESTS))
	       || ((dns_header.additional_rrs > 0) && (dns_header.additional_rrs <= NDPI_MAX_DNS_REQUESTS)))
	   ) {
	  /* This is a good reply: we dissect it both for request and response */

	  /* Leave the statement below commented necessary in case of call to ndpi_get_partial_detection() */
	  /* if(ndpi_struct->dns_dont_dissect_response == 0) */ {
	    x++;

	    if(flow->packet.payload[x] != '\0') {
	      while((x < flow->packet.payload_packet_len)
		    && (flow->packet.payload[x] != '\0')) {
		x++;
	      }

	      x++;
	    }

	    x += 4;

	    if(dns_header.num_answers > 0) {
	      u_int16_t rsp_type;
	      u_int16_t num;

	      for(num = 0; num < dns_header.num_answers; num++) {
		u_int16_t data_len;

		if((x+6) >= flow->packet.payload_packet_len) {
		  break;
		}

		if((data_len = getNameLength(x, flow->packet.payload, flow->packet.payload_packet_len)) == 0) {
		  break;
		} else
		  x += data_len;

		rsp_type = get16(&x, flow->packet.payload);
		flow->protos.dns.rsp_type = rsp_type;

		/* here x points to the response "class" field */
		if((x+12) <= flow->packet.payload_packet_len) {
		  x += 6;
		  data_len = get16(&x, flow->packet.payload);

		  if(((x + data_len) <= flow->packet.payload_packet_len)
		    && (((rsp_type == 0x1) && (data_len == 4)) /* A */
#ifdef NDPI_DETECTION_SUPPORT_IPV6
		       || ((rsp_type == 0x1c) && (data_len == 16)) /* AAAA */
#endif
		  )) {
		    memcpy(&flow->protos.dns.rsp_addr, flow->packet.payload + x, data_len);
		  }
		}

		break;
	      }
	    }
	  }
	} else
	  invalid = 1;
      }

      if(invalid) {
	NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
	return;
      }

      /* extract host name server */
      max_len = sizeof(flow->host_server_name)-1;
      off = sizeof(struct ndpi_dns_packet_header) + payload_offset;

      while(j < max_len && off < flow->packet.payload_packet_len && flow->packet.payload[off] != '\0') {
	uint8_t c,cl = flow->packet.payload[off++];
	if( (cl & 0xc0) != 0 || // we not support compressed names in query
	     off + cl  >= flow->packet.payload_packet_len) {
		j = 0; break;
	}
	if(j && j < max_len) flow->host_server_name[j++] = '.';
	while(j < max_len && cl != 0) {
	  c = flow->packet.payload[off++];
	  flow->host_server_name[j++] = dns_validchar[c >> 5] & (1 << (c & 0x1f)) ? c:'_';
	  cl--;
	}
      }
      flow->host_server_name[j] = '\0';

      if(is_query && (ndpi_struct->dns_dont_dissect_response == 0)) {
	// dpi_set_detected_protocol(ndpi_struct, flow, (d_port == 5355) ? NDPI_PROTOCOL_LLMNR : NDPI_PROTOCOL_DNS, NDPI_PROTOCOL_UNKNOWN);	
	return; /* The response will set the verdict */
      }

      flow->protos.dns.num_queries = (u_int8_t)dns_header.num_queries,
      flow->protos.dns.num_answers = (u_int8_t) (dns_header.num_answers + dns_header.authority_rrs + dns_header.additional_rrs);

      if(j > 0) {
	ndpi_protocol_match_result ret_match;

	ndpi_match_host_subprotocol(ndpi_struct, flow,
				    (char *)flow->host_server_name,
				    strlen((const char*)flow->host_server_name),
				    &ret_match,
				    NDPI_PROTOCOL_DNS);
      }

#ifdef DNS_DEBUG
      NDPI_LOG_DBG2(ndpi_struct, "[num_queries=%d][num_answers=%d][reply_code=%u][rsp_type=%u][host_server_name=%s]\n",
	     flow->protos.dns.num_queries, flow->protos.dns.num_answers,
	     flow->protos.dns.reply_code, flow->protos.dns.rsp_type, flow->host_server_name
	     );
#endif

      if(flow->packet.detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN) {
	/**
	   Do not set the protocol with DNS if ndpi_match_host_subprotocol() has
	   matched a subprotocol
	**/
	NDPI_LOG_INFO(ndpi_struct, "found DNS\n");
	ndpi_set_detected_protocol(ndpi_struct, flow, (d_port == 5355) ? NDPI_PROTOCOL_LLMNR : NDPI_PROTOCOL_DNS, NDPI_PROTOCOL_UNKNOWN);
      } else {
	NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
      }
    }
  }
}

void init_dns_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("DNS", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_DNS,
				      ndpi_search_dns,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}
