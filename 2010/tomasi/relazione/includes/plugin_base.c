#include "nprobe.h" /* Include anche engine.h */

#define BASE_ID            NTOP_BASE_ID+195
#define STRING_MAX_LEN     32     /* Massima dimensione per le stringhe */

static V9V10TemplateElementId myPlugin_template[] =
  {
    { FLOW_TEMPLATE, LONG_SNAPLEN, NTOP_ENTERPRISE_ID, BASE_ID, VARIABLE_FIELD_LEN,
      STRING_MAX_LEN, ascii_format, dump_as_ascii, "MY_INFO", "Info from packet" },
    { FLOW_TEMPLATE, NTOP_ENTERPRISE_ID, 0, STATIC_FIELD_LEN, 0, 0, 0, NULL, NULL }
  };

static PluginInfo myPlugin; /* Definita successivamente */

/* Invocata quando il plugin viene inizializzato */
static void
myPlugin_init(int argc, char *argv[])
{}

/* Invocata quando il plugin viene terminato */
static void
myPlugin_term(void)
{}

/* Invocata per prelevare gli attributi sulle informazioni esportate dal plugin */
static V9V10TemplateElementId *
myPlugin_conf(void)
{
  return(myPlugin_template);
}

/* Invocata quando un flusso viene eliminato */
static void
myPlugin_delete(FlowHashBucket *bkt, void *pluginData)
{}

/* Invocata quando un pacchetto viene ricevuto */
static void
myPlugin_packet(u_char new_bucket, void *pluginData,
		   FlowHashBucket *bkt,
		   u_short proto, u_char isFragment,
		   u_short numPkts, u_char tos,
		   u_short vlanId, struct eth_header *ehdr,
		   IpAddress *src, u_short sport,
		   IpAddress *dst, u_short dport,
		   u_int len, u_int8_t flags, u_int8_t icmpType,
		   u_short numMplsLabels,
		   u_char mplsLabels[MAX_NUM_MPLS_LABELS][MPLS_LABEL_LEN],
		   char *fingerprint,
		   const struct pcap_pkthdr *h, const u_char *p,
		   u_char *payload, int payloadLen)
{}

/* Invocata all'inizio per capire se il plugin dev'essere attivato */
static V9V10TemplateElementId *
myPlugin_get_template(char *template_name)
{
  int i;

  for(i=0; myPlugin_template[i].templateElementId != 0; i++)
    if(!strcmp(template_name, myPlugin_template[i].templateElementName))
      return(&myPlugin_template[i]);

  return(NULL); /* Unknown */
}

/* Invocata quando il flusso viene esportato */
static int
myPlugin_export(void *pluginData, V9V10TemplateElementId *theTemplate,
		   int direction /* 0 = src->dst, 1 = dst->src */,
		   FlowHashBucket *bkt, char *outBuffer,
		   uint* outBufferBegin, uint* outBufferMax)
{}

/* Invocata quando il flusso viene stampato su di un file */
static int
myPlugin_print(void *pluginData, V9V10TemplateElementId *theTemplate,
		  int direction /* 0 = src->dst, 1 = dst->src */,
		  FlowHashBucket *bkt, char *line_buffer, uint line_buffer_len)
{}

/* FIXME(invocata quando?) */
static void
myPlugin_setup(void)
{}

/* FIXME(invocata quando?) */
static void
myPlugin_help(void)
{}

/* La struttura PluginInfo da far avere a nProbe per fargli conoscere
 * gli indirizzi delle funzioni di interfacciamento */
static PluginInfo myPlugin =
  {
    NPROBE_REVISION,
    "My Protocol Dissector",
    "0.1",
    "Handle My protocol",
    "My <my.email@my.domain.org>",
    0 /* non sempre abilitato */, 1, /* abilitato */
    myPlugin_init,
    myPlugin_term,
    myPlugin_conf,
    myPlugin_delete,
    1, /* invoca la funzione packetFlowFctn per ogni pacchetto del flusso */
    myPlugin_packet,
    myPlugin_get_template,
    myPlugin_export,
    myPlugin_print,
    myPlugin_setup,
    myPlugin_help
  };

/* La "funzione cerniera" tra nProbe e il plugin (ritorna la struttura PluginInfo) */
#ifdef MAKE_STATIC_PLUGINS
PluginInfo *myPluginEntryFctn(void)  /* Se il plugin è inserito staticamente nel sorgente di nProbe */
#else
PluginInfo *PluginEntryFctn(void) /* Se il plugin viene caricato dinamicamente a run-time */
#endif
{
  return(&myPlugin);
}