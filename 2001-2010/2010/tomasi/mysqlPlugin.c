/*
 *  Copyright (C) 2010 Emanuele Tomai <tomasi@cli.di.unipi.it>
 *
 *  		       http://www.ntop.org/
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include "nprobe.h"

#define BASE_ID            NTOP_BASE_ID+195
#define DEBUG

/* Used by mysqlPlugin_delete() */
#define MYSQL_FREE(ptr) if ( ptr != NULL ) free(ptr)

/* Used by mysql_dissect_handshake() */
#define MYSQL_CHECK_BUFFER_OVERFLOW(size) if ( (packet + size) > (p_data->tcp_info.firstPktPayload \
								  + p_data->tcp_info.firstPktPayloadLen) ) return

/* Used by mysql_dissect_handshake() */
#define MYSQL_KEEP_VALUE_IN_SAFE_MODE(rcp) MYSQL_CHECK_BUFFER_OVERFLOW(0); \
  i = strlen((char *)packet);						\
  MYSQL_CHECK_BUFFER_OVERFLOW(i);					\
  if ( ! (rcp = malloc(i+1)) )						\
    return;								\
  memcpy(rcp, (char *)packet, i);					\
  rcp[i] = '\0';							\
  packet += i + 1

#define MYSQL_MAX_LEN            32     /* Max lenght for string */
#define MYSQL_TCP_PKT_MAX_SIZE  255     /* Max length fot tcp packet */
#define MYSQL_SERVER_PORT      3306

/* Capabilities */
#define MYSQL_CAPS_CWDB      0x0008    /* if there is DB name in client logging package (only for protocol >= 4.1) */
#define MYSQL_CAPS_41        0x0200    /* if used protocol >= 4.1 */

/* Command (in "Command Packet") */
#define MYSQL_COMM_INIT_DB        2
#define MYSQL_COMM_QUERY          3

static const char *mysql_command[] = /* Translate command (use with p_data->mysql_command) */
  {
    "SLEEP",                /* 0x00 */
    "Quit",
    "Use Database",
    "Query",
    "Show Fields",
    "Create Database",
    "Drop Database",
    "Refresh",
    "Shutdown",
    "Statistics",
    "Process List",
    "Connect",
    "Kill Server Thread",
    "Dump Debuginfo",
    "Ping",
    "Time",
    "Insert Delayed",
    "Change User",
    "Send Binlog",
    "Send Table",
    "Slave Connect",
    "Register Slave",
    "Prepare Statement",
    "Execute Statement",
    "Send BLOB",
    "Close Statement",
    "Reset Statement",
    "Set Option",
    "Fetch Data",           /* 0x1c */
  };
#define MYSQL_COMM_UNKOWN 0x1d

static V9V10TemplateElementId mysqlPlugin_template[] =
  {
    { FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID,   VARIABLE_FIELD_LEN, MYSQL_MAX_LEN, ascii_format, dump_as_ascii, "MYSQL_SERVER_VERSION", "MySQL server version" },
    { FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+1, VARIABLE_FIELD_LEN, MYSQL_MAX_LEN, ascii_format, dump_as_ascii, "MYSQL_USERNAME", "MySQL username" },
    { FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+2, VARIABLE_FIELD_LEN, MYSQL_MAX_LEN, ascii_format, dump_as_ascii, "MYSQL_REQUEST", "MySQL request" },
    { FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+3, VARIABLE_FIELD_LEN, MYSQL_MAX_LEN, ascii_format, dump_as_ascii, "MYSQL_DB", "MySQL database in use" },
    { FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+4, VARIABLE_FIELD_LEN, MYSQL_MAX_LEN, ascii_format, dump_as_ascii, "MYSQL_QUERY", "MySQL Query" },
    { FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID+5, STATIC_FIELD_LEN, 1, numeric_format, dump_as_uint, "MYSQL_RESPONSE", "MySQL server response" },
    { FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, 0, STATIC_FIELD_LEN, 0, 0, 0, NULL, NULL }
  };

struct mysql_packet_header
{
  u_int32_t length; /* only 24 bit */
  u_char number;
};

struct mysql_connection_info
{
  char *mysql_server_version;
  char *mysql_username;
  u_int16_t s_caps;
  u_int16_t c_caps;
  u_int16_t c_ext_caps;
};

struct mysql_tcp_info
{
  u_short src_port;
  u_int32_t firstPktSeqNum;
  u_char firstPktPayload[MYSQL_TCP_PKT_MAX_SIZE+1];
  int firstPktPayloadLen;
  u_char wasDissected;
};

struct plugin_data
{
  char *mysql_db;
  u_int8_t mysql_command;
  char *mysql_query;
  int16_t mysql_response;
  struct mysql_connection_info c_info;
  struct mysql_tcp_info tcp_info;
};

/* Internal function prototypes */
static void mysql_keep_tcp_packet(struct plugin_data *, u_int32_t, u_char *, int);
static void mysql_dissect_packet(FlowHashBucket *, struct plugin_data *, u_char);
static void mysql_dissect_handshake(FlowHashBucket *, struct mysql_packet_header *, struct plugin_data *, u_char *, u_char);
static void mysql_dissect_command(FlowHashBucket *, struct mysql_packet_header *, struct plugin_data *, u_char *, u_char);
static inline void mysql_reset_info(struct plugin_data *p_data);
static void mysql_export_string(V9V10TemplateElementId *, char *, char *, uint *, uint *, const char *);

/* *********************************************** */

static PluginInfo mysqlPlugin; /* Forward */

/* ******************************************* */

static void
mysqlPlugin_init(int argc, char *argv[])
{
  traceEvent(TRACE_INFO, "Initialized MySQL plugin");
}

/* *********************************************** */

/* Handler called whenever an incoming packet is received */

static void
mysqlPlugin_packet(u_char new_bucket, void *pluginData,
		   FlowHashBucket* bkt,
		   FlowDirection flow_direction,
		   u_short proto, u_char isFragment,
		   u_short numPkts, u_char tos,
		   u_short vlanId, struct eth_header *ehdr,
		   IpAddress *src, u_short sport,
		   IpAddress *dst, u_short dport,
		   u_int plen, u_int8_t flags,
		   u_int32_t tcpSeqNum, u_int8_t icmpType,
		   u_short numMplsLabels,
		   u_char mplsLabels[MAX_NUM_MPLS_LABELS][MPLS_LABEL_LEN],
		   const struct pcap_pkthdr *h, const u_char *p,
		   u_char *payload, int payloadLen)
{
  struct plugin_data *p_data;

  if ( sport != MYSQL_SERVER_PORT && dport != MYSQL_SERVER_PORT )
    return; /* Nothing to be done */

  p_data = (struct plugin_data*)pluginData;

  if ( new_bucket )
    {
      PluginInformation *info;

      if( ! (info = (PluginInformation*)malloc(sizeof(PluginInformation))) )
	{
	  traceEvent(TRACE_ERROR, "Not enough memory?");
	  return; /* Not enough memory */
	}

      info->pluginPtr  = (void*)&mysqlPlugin;
      if ( ! (p_data = info->pluginData = malloc(sizeof(struct plugin_data))) )
	{
	  traceEvent(TRACE_ERROR, "Not enough memory?");
	  free(info);
	  return; /* Not enough memory */
	}
      memset(p_data, 0, sizeof(struct plugin_data));
      memset(&(p_data->c_info), 0, sizeof (struct mysql_connection_info));
      memset(&(p_data->tcp_info), 0, sizeof (struct mysql_tcp_info));

      mysql_reset_info(p_data);

      info->next = bkt->plugin;
      bkt->plugin = info;
    }

  if ( payloadLen > 0 )
    {
      if ( sport != p_data->tcp_info.src_port ) /* Changing direction */
	{
	  mysql_dissect_packet(bkt, p_data, 1);
	  p_data->tcp_info.src_port = sport;
	  mysql_keep_tcp_packet(p_data, tcpSeqNum, payload, payloadLen);
	}
      else
      	/* Check for a new TCP first packet. tcpSeqNum can rewind. If it rewinds, the new tcpSeqNum
	 * is smaller then p_data->firstPktSeqNum, but new tcpSeqNum + 2^23 (8388608) isn't
	 * greater then p_data->firstPktSeqNum.
      	 */
      	if ( tcpSeqNum < p_data->tcp_info.firstPktSeqNum &&
	     (tcpSeqNum + 8388608) > p_data->tcp_info.firstPktSeqNum )
	  mysql_keep_tcp_packet(p_data, tcpSeqNum, payload, payloadLen);
    }
}

/* *********************************************** */

/* Handler called when the flow is deleted (after export) */

static void
mysqlPlugin_delete(FlowHashBucket *bkt, void *pluginData)
{
  struct plugin_data *p_data = (struct plugin_data*)pluginData;

  if ( p_data != NULL )
    {
      struct mysql_connection_info *c_info = &(p_data->c_info);

      MYSQL_FREE(p_data->mysql_db);
      MYSQL_FREE(p_data->mysql_query);
      MYSQL_FREE(c_info->mysql_server_version);
      MYSQL_FREE(c_info->mysql_username);

      free(p_data);
    }
}

/* *********************************************** */

/* Handler called at startup when the template is read */

static V9V10TemplateElementId *
mysqlPlugin_get_template(char *template_name)
{
  int i;

  for ( i=0; mysqlPlugin_template[i].templateElementId != 0; i++ )
    if ( !strcmp(template_name, mysqlPlugin_template[i].templateElementName) )
      return &mysqlPlugin_template[i];

  return NULL; /* Unknown */
}

/* *********************************************** */

/* Handler called whenever a flow attribute needs to be exported */

static int
mysqlPlugin_export(void *pluginData, V9V10TemplateElementId *theTemplate,
		   FlowDirection direction /* 0 = src->dst, 1 = dst->src */,
		   FlowHashBucket *bkt, char *outBuffer,
		   uint* outBufferBegin, uint* outBufferMax)
{
  int i;

  for ( i=0; mysqlPlugin_template[i].templateElementId != 0; i++ )
    {
      if ( theTemplate->templateElementId == mysqlPlugin_template[i].templateElementId )
	{
	  struct plugin_data *p_data = (struct plugin_data *)pluginData;

	  if ( (*outBufferBegin)+mysqlPlugin_template[i].templateElementLen > (*outBufferMax) )
	    return -2; /* Too long */

	  if ( ! p_data->tcp_info.wasDissected )
	    mysql_dissect_packet(bkt, p_data, 0);

	  if ( p_data )
	    {
	      switch ( mysqlPlugin_template[i].templateElementId )
		{
		case BASE_ID: /* MYSQL_SERVER_VERSION */
		  mysql_export_string(&mysqlPlugin_template[i], p_data->c_info.mysql_server_version,
				      outBuffer, outBufferBegin, outBufferMax, "==> Server Version=");
		  break;

		case BASE_ID+1: /* MYSQL_USERNAME */
		  mysql_export_string(&mysqlPlugin_template[i], p_data->c_info.mysql_username,
				      outBuffer, outBufferBegin, outBufferMax, "==> Username=");
		  break;

		case BASE_ID+2: /* MYSQL_REQUEST */
		  mysql_export_string(&mysqlPlugin_template[i], (char *) mysql_command[p_data->mysql_command],
				      outBuffer, outBufferBegin, outBufferMax, "==> Command=");
		  break;

		case BASE_ID+3: /* MYSQL_DB */
		  mysql_export_string(&mysqlPlugin_template[i], p_data->mysql_db, outBuffer,
				      outBufferBegin, outBufferMax, "==> DB=");
		  break;

		case BASE_ID+4: /* MYSQL_QUERY */
		  mysql_export_string(&mysqlPlugin_template[i], p_data->mysql_query, outBuffer,
				      outBufferBegin, outBufferMax, "==> Query=");
		  break;

		case BASE_ID+5: /* MYSQL_RESPONSE */
		  copyInt8(p_data->mysql_response, outBuffer, outBufferBegin, outBufferMax);
#ifdef DEBUG
		  traceEvent(TRACE_INFO, "==> Response='%d'", p_data->mysql_response);
#endif
		  break;

		default:
		  return -1; /* Not handled */
		}

	      return 0;
	    }
	}
    }

  return -1; /* Not handled */
}

/* *********************************************** */

/* Handler called whenever a flow attribute needs to be printed on file */

static int
mysqlPlugin_print(void *pluginData, V9V10TemplateElementId *theTemplate,
		  FlowDirection direction /* 0 = src->dst, 1 = dst->src */,
		  FlowHashBucket *bkt, char *line_buffer, uint line_buffer_len)
{
  int i;

  for ( i=0; mysqlPlugin_template[i].templateElementId != 0; i++ )
    {
      if ( theTemplate->templateElementId == mysqlPlugin_template[i].templateElementId )
	{
	  struct plugin_data *p_data = (struct plugin_data *)pluginData;
	  if ( p_data )
	    {
	      struct mysql_connection_info *c_info = &(p_data->c_info);

	      if ( ! p_data->tcp_info.wasDissected )
		mysql_dissect_packet(bkt, p_data, 0);

	      switch ( mysqlPlugin_template[i].templateElementId )
		{
		case BASE_ID: /* MYSQL_SERVER_VERSION */
		  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s",
			   c_info->mysql_server_version ? c_info->mysql_server_version : "");
		  break;

		case BASE_ID+1: /* MYSQL_USERNAME */
		  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s",
			   c_info->mysql_username ? c_info->mysql_username : "");
		  break;

		case BASE_ID+2: /* MYSQL_REQUEST */
		  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s",
			   ( p_data->mysql_command < MYSQL_COMM_UNKOWN ) ? mysql_command[p_data->mysql_command] : "");
		  break;

		case BASE_ID+3: /* MYSQL_DB */
		  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s",
			   p_data->mysql_db ? p_data->mysql_db : "");
		  break;

		case BASE_ID+4: /* MYSQL_QUERY */
		  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%s",
			   p_data->mysql_query ? p_data->mysql_query : "");
		  break;

		case BASE_ID+5: /* MYSQL_RESPONSE */
		  snprintf(&line_buffer[strlen(line_buffer)], (line_buffer_len-strlen(line_buffer)), "%d",
			   p_data->mysql_response);
		  break;

		default:
		  return -1; /* Not handled */
		}

	      return 0;
	    }
	}
    }

  return -1; /* Not handled */
}

/* *********************************************** */

static V9V10TemplateElementId *
mysqlPlugin_conf(void)
{
  return mysqlPlugin_template;
}

/* *********************************************** */

/* Plugin entrypoint */
static PluginInfo mysqlPlugin =
  {
    NPROBE_REVISION,
    "MySQL Protocol Dissector",
    "0.1",
    "Handle MySQL protocol",
    "E.Tomasi <tomasi@cli.di.unipi.it>",
    0 /* not always enabled */, 1, /* enabled */
    mysqlPlugin_init,
    NULL, /* Term */
    mysqlPlugin_conf,
    mysqlPlugin_delete,
    1, /* call packetFlowFctn for each packet */
    mysqlPlugin_packet,
    mysqlPlugin_get_template,
    mysqlPlugin_export,
    mysqlPlugin_print,
    NULL, /* Setup */
    NULL /* Help */
  };

/* *********************************************** */

/* Plugin entry fctn */
#ifdef MAKE_STATIC_PLUGINS
PluginInfo *mysqlPluginEntryFctn(void)
#else
PluginInfo *PluginEntryFctn(void)
#endif
{
  return &mysqlPlugin;
}

/* *********************************************** */

/* Internal functions */

/* Used by mysqlPlugin_packet() */
static void
mysql_keep_tcp_packet(struct plugin_data *p_data, u_int32_t tcpSeqNum, u_char *payload, int payloadLen)
{
  int i ;

  if ( payloadLen < 5 ) /* mmm... packet is too small */
    {
      p_data->tcp_info.firstPktPayload[0] = '\0';
      return;
    }

  i = min(MYSQL_TCP_PKT_MAX_SIZE, payloadLen);

  memcpy((char *)p_data->tcp_info.firstPktPayload, (char *)payload, i+1);
  p_data->tcp_info.firstPktPayload[i] = '\0'; /* strlen() don't go in buffer overflow */

  p_data->tcp_info.firstPktPayloadLen = i;

  p_data->tcp_info.firstPktSeqNum = tcpSeqNum;

  p_data->tcp_info.wasDissected = 0;
}

/* Used by mysqlPlugin_packet() */
static void
mysql_dissect_packet(FlowHashBucket *bkt, struct plugin_data *p_data, u_char export)
{
  struct mysql_packet_header pkt_header;
  void (*dissect_function)(FlowHashBucket *, struct mysql_packet_header *, struct plugin_data *, u_char *, u_char);

  if ( p_data->tcp_info.firstPktPayload == NULL || *(p_data->tcp_info.firstPktPayload) == '\0' )
    return;

  /* Keep header info */
  pkt_header.length = (p_data->tcp_info.firstPktPayload[0]&0xFF) + ((p_data->tcp_info.firstPktPayload[1]&0xFF) << 8)
    + ((p_data->tcp_info.firstPktPayload[2]&0xFF) << 16);
  pkt_header.number = p_data->tcp_info.firstPktPayload[3];

  dissect_function = NULL;
  switch ( pkt_header.number )
    {
    case 0:
      if ( p_data->tcp_info.src_port == MYSQL_SERVER_PORT )
	dissect_function = mysql_dissect_handshake;
      else
	dissect_function = mysql_dissect_command;
      break;

    case 1:
      if ( p_data->tcp_info.src_port == MYSQL_SERVER_PORT )
	dissect_function = mysql_dissect_command;
      else
	dissect_function = mysql_dissect_handshake;
      break;

    case 2:
      if ( p_data->tcp_info.src_port == MYSQL_SERVER_PORT )
	dissect_function = mysql_dissect_handshake;
      break;
    }

  p_data->tcp_info.wasDissected = 1;

  if ( dissect_function != NULL )
    dissect_function(bkt, &pkt_header, p_data, (p_data->tcp_info.firstPktPayload + 4), export);
}

/* Used by mysql_dissect_packet() */
static void
mysql_dissect_handshake(FlowHashBucket *bkt, struct mysql_packet_header *pkt_header,
			struct plugin_data *p_data, u_char *packet, u_char export)
{
  uint i;
  struct mysql_connection_info *c_info = &(p_data->c_info);

  switch ( pkt_header->number )
    {
    case 0: /* "Initialization Packet" (greeting packet) */
      packet += 1 ; /* Skip protocol version */

      /* Keep server version */
      MYSQL_KEEP_VALUE_IN_SAFE_MODE(c_info->mysql_server_version);

      packet += 4 + 8 + 1; /* Skip thread_id + scramble_buff + filler */

      /* Keep server_capabilities */
      MYSQL_CHECK_BUFFER_OVERFLOW(2);
      memcpy(&(c_info->s_caps), packet, 2);
      packet += 2;
      break;

    case 1: /* "Client authentication packet" (login packet) */
      MYSQL_CHECK_BUFFER_OVERFLOW(2);
      memcpy(&(c_info->c_caps), packet, 2); /* Keep client capabilities */
      packet += 2;

      if ( c_info->c_caps & MYSQL_CAPS_41 ) /* New protocol 4.1 */
	{
	  MYSQL_CHECK_BUFFER_OVERFLOW(2);
	  memcpy(&(c_info->c_ext_caps), packet, 2); /* Keep extended client capabilities */
	  packet += 2;

	  packet += 4 + 1 + 23; /* Skip max_packet_size + charset_number + filler */
	}
      else
	packet += 3; /* Skip max_packet_size */

      /* Keep username */
      MYSQL_KEEP_VALUE_IN_SAFE_MODE(c_info->mysql_username);

      if ( c_info->c_caps & MYSQL_CAPS_41 && c_info->c_caps & MYSQL_CAPS_CWDB ) /* Protocol 4.1 and connect with db */
	{
	  /* Skip password */
	  MYSQL_CHECK_BUFFER_OVERFLOW(0);
	  i = strlen((char *)packet) + 1;
	  packet += i;

	  /* Keep database name */
	  MYSQL_KEEP_VALUE_IN_SAFE_MODE(p_data->mysql_db);
	}
      break;

    case 2: /* "Server Response */
      p_data->mysql_response = (*packet)&0xFF;

      if ( c_info->c_caps & MYSQL_CAPS_41 && c_info->c_caps & MYSQL_CAPS_CWDB  /* Protocol 4.1 and connect with db */
	   && export )
	{
	  exportBucket(bkt, 0);
	  mysql_reset_info(p_data);
	}

      break;
    }
}

/* Used by mysql_dissect_packet() */
static void
mysql_dissect_command(FlowHashBucket *bkt, struct mysql_packet_header *pkt_header,
		      struct plugin_data *p_data, u_char *packet, u_char export)
{
  char **buff;
  u_char keep;

  keep = 0;
  switch ( pkt_header->number )
    {
    case 0: /* Command Packet */
      p_data->mysql_command = (u_int8_t)*packet; /* Keep and skip command */
      packet++;

      switch ( p_data->mysql_command )
	{
	case MYSQL_COMM_INIT_DB: /* Use DB */
	  buff = &(p_data->mysql_db);
	  keep = 1;
	  break;

	case MYSQL_COMM_QUERY:
	  buff = &(p_data->mysql_query);
	  keep = 1;
	  break;
	}

      if ( keep )
	{
	  int i = p_data->tcp_info.firstPktPayloadLen - 4;
	  if ( (*buff = realloc(*buff, i)) == NULL )
	    {
	      if ( *buff != NULL )
		*(*buff) = '\0';
	      return;
	    }
	  memcpy(*buff, (char *)packet, i-1);
	  (*buff)[i-1] = '\0';
	}
      break;

    case 1: /* Response Packet */
      p_data->mysql_response = (int)*packet;

      if ( export )
	{
	  exportBucket(bkt, 0);
	  mysql_reset_info(p_data);
	}
      break;
    }
}

static inline void
mysql_reset_info(struct plugin_data *p_data)
{
  p_data->mysql_command = MYSQL_COMM_UNKOWN;

  if ( p_data->mysql_query != NULL )
    p_data->mysql_query = '\0';

  p_data->mysql_response = -1; /* Unknown value, response range [0-255] */

  p_data->tcp_info.wasDissected = 0;
}

/* Used by mysqlPlugin_export() */
static void
mysql_export_string(V9V10TemplateElementId *mysqlPlugin_template, char *string,
		    char *outBuffer, uint* outBufferBegin, uint* outBufferMax, const char* t_event)
{
  char buff[512] = { 0 };
  uint len;

  snprintf(buff, sizeof(buff), "%s", string ? string : "");

  if((readOnlyGlobals.netFlowVersion == 10)
     && (mysqlPlugin_template->variableFieldLength == VARIABLE_FIELD_LEN))
    {
      len = min(strlen(buff), mysqlPlugin_template->templateElementLen);

      if(len < 255)
	copyInt8(len, outBuffer, outBufferBegin, outBufferMax);
      else
	{
	  copyInt8(255, outBuffer, outBufferBegin, outBufferMax);
	  copyInt16(len, outBuffer, outBufferBegin, outBufferMax);
	}
    }
  else
    len = mysqlPlugin_template->templateElementLen;

  memcpy(&outBuffer[*outBufferBegin], buff, len);
  (*outBufferBegin) += len;

#ifdef DEBUG
  traceEvent(TRACE_INFO, "%s'%s'", t_event, buff);
#endif
}